"""Authentication: the API-key store plus optional OIDC/JWT from an external IdP.

`build_authenticators(settings)` returns the ordered chain for a deployment.
The OIDC validator (and its JWKS cache) is built once per settings object and
reused across requests, so keys are not refetched on every call.
"""
from __future__ import annotations

from certadillo.auth.base import ApiKeyAuthenticator, Authenticator, Credential, OidcAuthenticator
from certadillo.auth.oidc import OidcConfig, OidcValidator

__all__ = ["Credential", "Authenticator", "build_authenticators", "oidc_config_from_settings"]

_cache: dict[int, list] = {}


def oidc_config_from_settings(settings) -> OidcConfig | None:
    """Resolve the OIDC config, applying the Entra / Vault presets so an
    operator sets a tenant or a Vault issuer rather than URLs by hand."""
    provider = (settings.oidc_provider or "").lower()
    issuer = settings.oidc_issuer
    jwks_uri = settings.oidc_jwks_uri

    if provider == "entra" and settings.oidc_entra_tenant:
        tenant = settings.oidc_entra_tenant
        issuer = issuer or f"https://login.microsoftonline.com/{tenant}/v2.0"
        jwks_uri = jwks_uri or f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    elif provider == "vault" and settings.oidc_vault_issuer:
        base = settings.oidc_vault_issuer.rstrip("/")
        issuer = issuer or base
        jwks_uri = jwks_uri or f"{base}/.well-known/keys"

    if not (issuer and settings.oidc_audience and jwks_uri):
        return None

    cfg = OidcConfig(
        issuer=issuer,
        audience=settings.oidc_audience,
        jwks_uri=jwks_uri,
        algorithms=settings.oidc_algorithms or ["RS256"],
        username_claim=settings.oidc_username_claim or "sub",
        role_claim=settings.oidc_role_claim or "roles",
        app_claim=settings.oidc_app_claim or "app",
        role_map=settings.oidc_role_map,
        clock_skew=settings.oidc_clock_skew,
    )
    return cfg


def build_authenticators(settings, jwk_client=None) -> list[Authenticator]:
    """OIDC first (when configured) so a token is preferred, then the API key
    as the fallback for machines that cannot get a token."""
    key = id(settings)
    if jwk_client is None and key in _cache:
        return _cache[key]

    chain: list[Authenticator] = []
    cfg = oidc_config_from_settings(settings)
    if cfg is not None:
        chain.append(OidcAuthenticator(OidcValidator(cfg, jwk_client=jwk_client)))
    chain.append(ApiKeyAuthenticator())

    if jwk_client is None:
        _cache[key] = chain
    return chain


def reset_authenticators() -> None:
    _cache.clear()
