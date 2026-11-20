"""Console single sign-on: OIDC authorization code flow with PKCE against a
fake identity provider, the session cookie, CSRF rules and logout."""
from __future__ import annotations

import base64
import datetime
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.auth import reset_authenticators, sso
from conftest import make_settings

ISSUER = "https://idp.bank.example"
CLIENT_ID = "certadillo-console"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
WRONG_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwk:
    def get_signing_key_from_jwt(self, token):
        class K:
            key = KEY.public_key()
        return K()


class FakeIdp:
    """Discovery document and token endpoint. Records what Certadillo sent."""

    def __init__(self):
        self.claims = {"sub": "alice@bank.example", "roles": ["PKI-Admins"]}
        self.key = KEY
        self.token_requests = []
        self.nonce = None

    def handler(self, request: httpx.Request):
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token"})
        if request.url.path == "/token":
            form = parse_qs(request.content.decode())
            self.token_requests.append(form)
            now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            body = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": self.nonce, **self.claims}
            return httpx.Response(200, json={"id_token": jwt.encode(body, self.key, algorithm="RS256"),
                                             "access_token": "opaque", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def c(tmp_path, idp):
    s = make_settings(tmp_path, oidc_issuer=ISSUER, oidc_jwks_uri=f"{ISSUER}/keys", oidc_audience="api://certadillo",
                      oidc_role_map={"PKI-Admins": "admin", "PKI-Auditors": "auditor", "Robots": "app"},
                      sso_client_id=CLIENT_ID, base_url="https://pki.bank.example")
    sso._discovered.clear()
    sso.test_hooks.update(http=httpx.Client(transport=httpx.MockTransport(idp.handler)), jwk=FakeJwk())
    reset_authenticators()
    with TestClient(create_app(s, background=False), base_url="https://pki.bank.example") as client:
        yield client
    sso.test_hooks.update(http=None, jwk=None)
    reset_authenticators()


def _login(c, idp, tamper_state=False):
    r = c.get("/auth/login", follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlsplit(r.headers["location"]).query)
    idp.nonce = q["nonce"][0]
    state = "forged" if tamper_state else q["state"][0]
    return c.get("/auth/callback", params={"code": "the-code", "state": state}, follow_redirects=False), q


def test_config_and_login_redirect(c, idp):
    assert c.get("/auth/config").json() == {"sso": True, "login_url": "/auth/login", "provider": "oidc"}
    r = c.get("/auth/login", follow_redirects=False)
    url = urlsplit(r.headers["location"])
    q = parse_qs(url.query)
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{ISSUER}/authorize"
    assert q["response_type"] == ["code"] and q["client_id"] == [CLIENT_ID]
    assert q["redirect_uri"] == ["https://pki.bank.example/auth/callback"]
    assert q["code_challenge_method"] == ["S256"] and q["scope"] == ["openid profile email"]
    tx = r.cookies.get(sso.TX_COOKIE)
    assert tx and "state" not in tx  # signed, opaque
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "Path=/auth" in cookie


def test_full_sign_in_creates_a_session(c, idp):
    r, q = _login(c, idp)
    assert r.status_code == 302 and r.headers["location"] == "/"
    # PKCE: the verifier Certadillo sent hashes to the challenge it advertised
    verifier = idp.token_requests[0]["code_verifier"][0]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == q["code_challenge"][0]
    cookie = [h for h in r.headers.get_list("set-cookie") if h.startswith(sso.SESSION_COOKIE)][0]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    me = c.get("/api/v1/me").json()
    assert me == {"name": "idp:alice@bank.example", "role": "admin", "app_id": None, "via": "session"}
    audit = c.get("/api/v1/audit").json()
    assert any(e["action"] == "console.login" and e["actor"] == "idp:alice@bank.example" for e in audit)


def test_changes_need_the_csrf_header_and_same_origin(c, idp):
    _login(c, idp)
    body = {"name": "team-sso", "contact_email": "t@bank.example"}
    assert c.post("/api/v1/teams", json=body).status_code == 403
    assert c.post("/api/v1/teams", json=body, headers={"X-Certadillo-CSRF": "1",
                                                       "Origin": "https://evil.example"}).status_code == 403
    r = c.post("/api/v1/teams", json=body, headers={"X-Certadillo-CSRF": "1", "Origin": "https://pki.bank.example"})
    assert r.status_code == 201, r.text


def test_logout_ends_the_session(c, idp):
    _login(c, idp)
    token = c.cookies.get(sso.SESSION_COOKIE)
    assert c.post("/auth/logout").status_code == 403  # no CSRF header
    assert c.post("/auth/logout", headers={"X-Certadillo-CSRF": "1"}).json() == {"logged_out": True}
    c.cookies.set(sso.SESSION_COOKIE, token)  # a copied cookie is dead too
    assert c.get("/api/v1/me").status_code == 401


@pytest.mark.parametrize("change,message", [
    (lambda idp: setattr(idp, "key", WRONG_KEY), "not accepted"),
    (lambda idp: idp.claims.update(roles=["Nobody"]), "no role"),
    (lambda idp: idp.claims.update(roles=["Robots"]), "for machines"),
])
def test_bad_id_tokens_are_refused(c, idp, change, message):
    change(idp)
    r, _ = _login(c, idp)
    assert r.status_code == 403 and message in r.text
    assert c.get("/api/v1/me").status_code == 401


def test_forged_state_and_replayed_nonce_are_refused(c, idp):
    r, _ = _login(c, idp, tamper_state=True)
    assert r.status_code == 403 and "state does not match" in r.text
    r = c.get("/auth/login", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    idp.nonce = "some-other-nonce"
    r = c.get("/auth/callback", params={"code": "x", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 403 and "nonce" in r.text
    c.cookies.clear()
    r = c.get("/auth/callback", params={"code": "x", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 403 and "start again" in r.text


def test_idle_and_absolute_expiry(c, idp):
    from certadillo.db import ConsoleSession, get_session

    _login(c, idp)
    with get_session() as s:
        row = s.query(ConsoleSession).one()
        row.last_seen_at = row.last_seen_at - datetime.timedelta(minutes=61)
        s.commit()
    assert c.get("/api/v1/me").status_code == 401
    with get_session() as s:
        assert s.query(ConsoleSession).count() == 0  # the expired row is gone


def test_api_key_still_works_and_wins_over_the_cookie(c, idp):
    _login(c, idp)
    me = c.get("/api/v1/me", headers={"X-API-Key": "admin-key"}).json()
    assert me["name"] == "bootstrap-admin" and me["via"] == "credential"


def test_sso_off_without_a_client_id(tmp_path):
    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        assert c.get("/auth/config").json()["sso"] is False
        assert c.get("/auth/login", follow_redirects=False).status_code == 404
