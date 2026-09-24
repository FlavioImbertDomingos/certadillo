"""Zero-trust access: validate OIDC/JWT bearer tokens from an external IdP.

The unit tests hammer the fail-closed paths (bad signature, wrong issuer or
audience, expired, alg=none, missing claims). The API tests prove a token
authorizes real calls and that an app token is scoped to its app, with the API
key still working alongside.
"""
from __future__ import annotations

import contextlib
import datetime
import tempfile
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from conftest import ADMIN, make_settings, make_csr
from certadillo.api.app import create_app
from certadillo.auth.oidc import OidcConfig, OidcValidator, TokenError

ISSUER = "https://login.microsoftonline.com/tenant-abc/v2.0"
AUDIENCE = "api://certadillo"
KID = "test-key-1"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwkClient:
    """Stands in for PyJWKClient: returns a fixed public key for the token's kid."""

    def __init__(self, public_key):
        self._key = public_key

    def get_signing_key_from_jwt(self, token):
        class _K:
            key = self._key
        return _K()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def mint(claims=None, key=_KEY, alg="RS256", exp_delta=3600, include_iat=True, include_exp=True):
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice@bank.example"}
    if include_iat:
        body["iat"] = int(_now().timestamp())
    if include_exp:
        body["exp"] = int((_now() + datetime.timedelta(seconds=exp_delta)).timestamp())
    if claims:
        body.update(claims)
    key_arg = "" if alg == "none" else key
    return jwt.encode(body, key_arg, algorithm=alg, headers={"kid": KID})


def make_validator(role_map=None, **kw):
    cfg = OidcConfig(issuer=ISSUER, audience=AUDIENCE, jwks_uri="https://fake/keys",
                     algorithms=["RS256"], role_map=role_map or {"PKI-Admins": "admin"}, **kw)
    return OidcValidator(cfg, jwk_client=FakeJwkClient(_KEY.public_key()))


# --------------------------------------------------------------------------- unit: accept
def test_valid_token_accepts_and_maps_role():
    v = make_validator()
    claims = v.validate(mint({"roles": ["PKI-Admins"]}))
    assert claims["sub"] == "alice@bank.example"
    assert v.role_for(claims) == "admin"
    assert v.username(claims) == "alice@bank.example"


def test_most_privileged_role_wins():
    v = make_validator(role_map={"A": "auditor", "B": "admin", "C": "operator"})
    claims = v.validate(mint({"roles": ["A", "B", "C"]}))
    assert v.role_for(claims) == "admin"


def test_unmapped_role_is_none():
    v = make_validator(role_map={"PKI-Admins": "admin"})
    claims = v.validate(mint({"roles": ["SomeOtherGroup"]}))
    assert v.role_for(claims) is None


# --------------------------------------------------------------------------- unit: fail closed
def test_bad_signature_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"roles": ["PKI-Admins"]}, key=_OTHER_KEY))


def test_wrong_issuer_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"iss": "https://evil.example", "roles": ["PKI-Admins"]}))


def test_wrong_audience_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"aud": "api://someone-else"}))


def test_expired_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"roles": ["PKI-Admins"]}, exp_delta=-3600))


def test_alg_none_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"roles": ["PKI-Admins"]}, alg="none"))


def test_missing_exp_rejected():
    v = make_validator()
    with pytest.raises(TokenError):
        v.validate(mint({"roles": ["PKI-Admins"]}, include_exp=False))


def test_disallowed_algorithm_rejected():
    # A token signed with HS256 must be rejected when only RS256 is allowed
    # (this is the guard against the RS256->HS256 confusion attack).
    v = make_validator()
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker", "roles": ["PKI-Admins"],
         "iat": int(_now().timestamp()), "exp": int((_now() + datetime.timedelta(hours=1)).timestamp())},
        "a-long-symmetric-secret-value-32b!!", algorithm="HS256", headers={"kid": KID},
    )
    with pytest.raises(TokenError):
        v.validate(forged)


# --------------------------------------------------------------------------- provider presets
def test_entra_preset_builds_urls():
    from certadillo.auth import oidc_config_from_settings

    s = make_settings_oidc(provider="entra", entra_tenant="tenant-abc", audience=AUDIENCE)
    cfg = oidc_config_from_settings(s)
    assert cfg.issuer == "https://login.microsoftonline.com/tenant-abc/v2.0"
    assert cfg.jwks_uri == "https://login.microsoftonline.com/tenant-abc/discovery/v2.0/keys"


def test_vault_preset_builds_jwks():
    from certadillo.auth import oidc_config_from_settings

    s = make_settings_oidc(provider="vault", vault_issuer="https://vault.bank.internal/v1/identity/oidc/provider/certadillo",
                           audience=AUDIENCE)
    cfg = oidc_config_from_settings(s)
    assert cfg.jwks_uri.endswith("/.well-known/keys")


def test_no_oidc_config_returns_none():
    from certadillo.auth import oidc_config_from_settings

    assert oidc_config_from_settings(make_settings_oidc()) is None


# --------------------------------------------------------------------------- API integration
def make_settings_oidc(tmp=None, provider=None, entra_tenant=None, vault_issuer=None, audience=None, role_map=None):
    kw = {}
    if provider:
        kw["oidc_provider"] = provider
    if entra_tenant:
        kw["oidc_entra_tenant"] = entra_tenant
    if vault_issuer:
        kw["oidc_vault_issuer"] = vault_issuer
    if audience:
        kw["oidc_audience"] = audience
    if role_map is not None:
        kw["oidc_role_map"] = role_map
    return make_settings(tmp or Path(tempfile.mkdtemp()), **kw)


@pytest.fixture
def oidc_client(tmp_path):
    settings = make_settings(
        tmp_path,
        oidc_issuer=ISSUER, oidc_audience=AUDIENCE, oidc_jwks_uri="https://fake/keys",
        oidc_algorithms=["RS256"], oidc_role_claim="roles", oidc_app_claim="app",
        oidc_role_map={"PKI-Admins": "admin", "PKI-Approvers": "approver", "App-Cards": "app"},
    )
    app = create_app(settings, background=False)
    # inject the fake JWKS client into every Platform this session builds
    from certadillo.runtime import get_runtime
    from certadillo.auth import reset_authenticators

    reset_authenticators()
    rt = get_runtime()
    orig = rt.platform

    @contextlib.contextmanager
    def patched():
        with orig() as p:
            p._jwk_client = FakeJwkClient(_KEY.public_key())
            yield p

    rt.platform = patched
    with TestClient(app) as c:
        yield c
    reset_authenticators()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_oidc_admin_token_authorizes(oidc_client):
    tok = mint({"roles": ["PKI-Admins"]})
    r = oidc_client.post("/api/v1/teams", json={"name": "team-oidc", "contact_email": "t@e.com"}, headers=bearer(tok))
    assert r.status_code == 201, r.text
    # the audit actor is the IdP subject
    me = oidc_client.get("/api/v1/me", headers=bearer(tok)).json()
    assert me["name"] == "idp:alice@bank.example"
    assert me["role"] == "admin"


def test_oidc_unmapped_role_is_401(oidc_client):
    tok = mint({"roles": ["Random-Group"]})
    r = oidc_client.get("/api/v1/teams", headers=bearer(tok))
    assert r.status_code == 401


def test_oidc_expired_is_401(oidc_client):
    tok = mint({"roles": ["PKI-Admins"]}, exp_delta=-60)
    assert oidc_client.get("/api/v1/teams", headers=bearer(tok)).status_code == 401


def test_api_key_still_works_with_oidc_enabled(oidc_client):
    # the bootstrap admin key authenticates even though OIDC is configured
    assert oidc_client.get("/api/v1/teams", headers=ADMIN).status_code == 200


def test_oidc_app_token_scoped_to_its_app(oidc_client):
    # onboard an app with the admin key
    team = oidc_client.post("/api/v1/teams", json={"name": "t-cards", "contact_email": "t@e.com"},
                            headers=ADMIN).json()["id"]
    oidc_client.post("/api/v1/apps", json={"team_id": team, "name": "cards-api", "environment": "dev",
                                            "profile": "tls-server", "allowed_domains": ["*.cards.bank.internal"]},
                     headers=ADMIN)
    # an app-role token naming that app can request a certificate for it
    tok = mint({"roles": ["App-Cards"], "app": "cards-api"})
    _, csr = make_csr("api.cards.bank.internal", dns=["api.cards.bank.internal"])
    r = oidc_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=bearer(tok))
    assert r.status_code == 201, r.text
    # a token naming a different (nonexistent) app is refused
    tok2 = mint({"roles": ["App-Cards"], "app": "ghost-app"})
    assert oidc_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=bearer(tok2)).status_code == 401


def test_oidc_app_token_without_app_claim_refused(oidc_client):
    tok = mint({"roles": ["App-Cards"]})  # app role but no app claim
    _, csr = make_csr("x.cards.bank.internal", dns=["x.cards.bank.internal"])
    assert oidc_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=bearer(tok)).status_code == 401


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
