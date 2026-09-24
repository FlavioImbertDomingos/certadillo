"""Validate OpenID Connect / JWT bearer tokens from an external identity
provider (Microsoft Entra ID, HashiCorp Vault's OIDC provider, or any standard
OIDC issuer).

The token is the credential: a short-lived, signed assertion that the IdP
already authenticated the caller. Certadillo verifies the signature against the
issuer's published keys and checks the standard claims, then maps the claims to
a role. Nothing is stored in Certadillo's database, so there is no long-lived
secret here to steal, and the IdP's own controls (MFA, conditional access,
session revocation) gate access.

Signature and claim validation is delegated to PyJWT rather than hand-rolled:
the failure modes (algorithm confusion, alg=none, unchecked audience) are
exactly where a hand-written validator goes wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import jwt


class TokenError(Exception):
    """Any reason a token is not accepted. Always fail closed."""


@dataclass
class OidcConfig:
    issuer: str
    audience: str
    jwks_uri: str
    algorithms: list[str] = field(default_factory=lambda: ["RS256"])
    username_claim: str = "sub"
    role_claim: str = "roles"
    app_claim: str = "app"
    role_map: dict[str, str] = field(default_factory=dict)  # claim value -> certadillo role
    clock_skew: int = 60

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.audience and self.jwks_uri)


# Highest privilege first: when a token carries several mapped roles, the most
# privileged wins (a union of grants, not the weakest).
_ROLE_PRIORITY = ["admin", "operator", "approver", "gateway", "auditor", "app"]


class OidcValidator:
    def __init__(self, config: OidcConfig, jwk_client=None):
        self.config = config
        if jwk_client is not None:
            self._jwks = jwk_client
        else:
            # PyJWKClient fetches the issuer's keys over HTTPS and caches them,
            # refetching when it sees an unknown key id (key rotation).
            self._jwks = jwt.PyJWKClient(config.jwks_uri, cache_keys=True, lifespan=3600)

    def validate(self, token: str) -> dict:
        """Return the verified claims, or raise TokenError. PyJWT checks the
        signature, the issuer, the audience and exp/nbf/iat (with leeway), and
        rejects alg=none because 'none' is never in the allowed algorithms."""
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            key = getattr(signing_key, "key", signing_key)
            claims = jwt.decode(
                token,
                key,
                algorithms=self.config.algorithms,
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew,
                options={"require": ["exp", "iat"], "verify_aud": True, "verify_iss": True},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc
        except Exception as exc:  # a JWKS fetch failure, a malformed key: fail closed
            raise TokenError(f"could not verify token: {exc}") from exc
        return claims

    def role_for(self, claims: dict) -> str | None:
        """Map the token's role/group claim to a Certadillo role, most
        privileged wins. Returns None when nothing maps (the token is valid but
        grants no access here)."""
        values = claims.get(self.config.role_claim, [])
        if isinstance(values, str):
            values = [values]
        mapped = {self.config.role_map[v] for v in values if v in self.config.role_map}
        for role in _ROLE_PRIORITY:
            if role in mapped:
                return role
        return None

    def username(self, claims: dict) -> str:
        return str(claims.get(self.config.username_claim) or claims.get("sub") or "unknown")

    def app_ref(self, claims: dict):
        return claims.get(self.config.app_claim)
