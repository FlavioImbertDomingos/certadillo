"""Single sign-on for the web console: OpenID Connect authorization code flow
with PKCE, run by the server (the browser never holds a token).

1. /auth/login makes a state, a nonce and a PKCE verifier, keeps them in a
   short-lived signed cookie, and sends the browser to the IdP.
2. /auth/callback checks the state, exchanges the code (with the verifier,
   and the client secret when there is one) at the IdP's token endpoint,
   validates the ID token (signature against the issuer's keys, issuer,
   audience = our client id, expiry, nonce) and maps its role claim exactly
   like a bearer token (CERTADILLO_OIDC_ROLE_MAP). App roles are refused: the
   console is for people.
3. The browser gets an HttpOnly, SameSite=Strict session cookie holding a
   random token; the database keeps only its hash, with an absolute lifetime
   (CERTADILLO_SSO_SESSION_HOURS) and an idle timeout (_SSO_IDLE_MINUTES).
   Logging out deletes the row.

A request authenticated by the session cookie that changes something must
also carry the X-Certadillo-CSRF header (which a cross-site page cannot add
without a CORS preflight that is never granted) and, when the browser sends
Origin, come from Certadillo's own origin.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from certadillo.auth.oidc import OidcConfig, OidcValidator, TokenError

SESSION_COOKIE = "cdl_session"
TX_COOKIE = "cdl_sso_tx"
CSRF_HEADER = "x-certadillo-csrf"
TX_SECONDS = 600


class SsoError(Exception):
    pass


# tests swap in a fake IdP: {"http": httpx.Client, "jwk": a PyJWKClient stand-in}
test_hooks: dict = {"http": None, "jwk": None}


def enabled(settings) -> bool:
    from certadillo.auth import oidc_config_from_settings

    return bool(settings.sso_client_id) and oidc_config_from_settings(settings) is not None


def redirect_uri(settings) -> str:
    return settings.base_url.rstrip("/") + "/auth/callback"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _tx_key(settings) -> bytes:
    from certadillo.integrity import derive_key

    return hmac.new(derive_key(settings), b"certadillo-sso-tx", hashlib.sha256).digest()


def sign_tx(settings, data: dict) -> str:
    body = _b64(json.dumps({**data, "exp": int(time.time()) + TX_SECONDS}, separators=(",", ":")).encode())
    mac = _b64(hmac.new(_tx_key(settings), body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def read_tx(settings, value: str | None) -> dict:
    try:
        body, mac = (value or "").split(".")
    except ValueError:
        raise SsoError("the sign-in attempt expired or was not started here; start again") from None
    want = _b64(hmac.new(_tx_key(settings), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, want):
        raise SsoError("the sign-in state was tampered with")
    data = json.loads(_unb64(body))
    if data.get("exp", 0) < time.time():
        raise SsoError("the sign-in attempt expired; start again")
    return data


# ------------------------------------------------------------------ IdP endpoints
_discovered: dict[str, dict] = {}


def endpoints(settings, http=None) -> tuple[str, str]:
    """(authorize URL, token URL): set explicitly, from the Entra preset, or
    from the issuer's OpenID discovery document."""
    from certadillo import egress
    from certadillo.auth import oidc_config_from_settings

    if settings.sso_authorize_url and settings.sso_token_url:
        return settings.sso_authorize_url, settings.sso_token_url
    if (settings.oidc_provider or "").lower() == "entra" and settings.oidc_entra_tenant:
        base = f"https://login.microsoftonline.com/{settings.oidc_entra_tenant}/oauth2/v2.0"
        return settings.sso_authorize_url or f"{base}/authorize", settings.sso_token_url or f"{base}/token"
    issuer = oidc_config_from_settings(settings).issuer.rstrip("/")
    if issuer not in _discovered:
        client = http or test_hooks["http"] or egress.client("sso", timeout=10)
        r = client.get(f"{issuer}/.well-known/openid-configuration")
        r.raise_for_status()
        _discovered[issuer] = r.json()
    doc = _discovered[issuer]
    return (settings.sso_authorize_url or doc["authorization_endpoint"],
            settings.sso_token_url or doc["token_endpoint"])


def login_redirect(settings, http=None) -> tuple[str, str]:
    """(URL to send the browser to, value of the transaction cookie)."""
    authorize, _ = endpoints(settings, http)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    query = urlencode({
        "response_type": "code", "client_id": settings.sso_client_id, "redirect_uri": redirect_uri(settings),
        "scope": settings.sso_scopes, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    sep = "&" if urlsplit(authorize).query else "?"
    return f"{authorize}{sep}{query}", sign_tx(settings, {"state": state, "nonce": nonce, "verifier": verifier})


def _validator(settings, jwk_client=None) -> OidcValidator:
    from certadillo.auth import oidc_config_from_settings

    base = oidc_config_from_settings(settings)
    cfg = OidcConfig(issuer=base.issuer, audience=settings.sso_client_id, jwks_uri=base.jwks_uri,
                     algorithms=base.algorithms, username_claim=base.username_claim, role_claim=base.role_claim,
                     app_claim=base.app_claim, role_map=base.role_map, clock_skew=base.clock_skew)
    return OidcValidator(cfg, jwk_client=jwk_client)


def complete(settings, code: str, state: str, tx_cookie: str | None, http=None, jwk_client=None) -> tuple[str, str]:
    """Finish the flow. Returns (subject, role)."""
    from certadillo import egress

    tx = read_tx(settings, tx_cookie)
    if not hmac.compare_digest(state or "", tx["state"]):
        raise SsoError("the sign-in state does not match; start again")
    _, token_url = endpoints(settings, http)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(settings),
            "client_id": settings.sso_client_id, "code_verifier": tx["verifier"]}
    if settings.sso_client_secret:
        form["client_secret"] = settings.sso_client_secret
    client = http or test_hooks["http"] or egress.client("sso", timeout=15)
    r = client.post(token_url, data=form, headers={"Accept": "application/json"})
    if r.status_code != 200:
        raise SsoError(f"the identity provider refused the code (HTTP {r.status_code})")
    id_token = r.json().get("id_token")
    if not id_token:
        raise SsoError("the identity provider returned no ID token; is the openid scope requested?")
    v = _validator(settings, jwk_client or test_hooks["jwk"])
    try:
        claims = v.validate(id_token)
    except TokenError as exc:
        raise SsoError(f"the ID token was not accepted: {exc}") from None
    if not hmac.compare_digest(str(claims.get("nonce", "")), tx["nonce"]):
        raise SsoError("the ID token's nonce does not match this sign-in")
    role = v.role_for(claims)
    if role is None:
        raise SsoError("your account has no role that maps to access here (CERTADILLO_OIDC_ROLE_MAP)")
    if role in ("app", "agent", "gateway"):
        raise SsoError(f"the {role} role is for machines and cannot sign in to the console")
    return v.username(claims), role


# ------------------------------------------------------------------ sessions
def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(session, settings, subject: str, role: str) -> str:
    from certadillo.db import ConsoleSession

    token = "cdls_" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session.query(ConsoleSession).filter(ConsoleSession.expires_at < now).delete(synchronize_session=False)
    session.add(ConsoleSession(token_hash=_hash(token), subject=subject, role=role, created_at=now,
                               last_seen_at=now, expires_at=now + timedelta(hours=settings.sso_session_hours)))
    session.flush()
    return token


def lookup(session, settings, token: str | None):
    """The live session for a cookie value, or None. Touches last_seen at most once a minute."""
    from certadillo.db import ConsoleSession, as_utc

    if not token or not token.startswith("cdls_"):
        return None
    row = session.get(ConsoleSession, _hash(token))
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    if as_utc(row.expires_at) <= now or now - as_utc(row.last_seen_at) > timedelta(minutes=settings.sso_idle_minutes):
        session.delete(row)
        session.commit()
        return None
    if now - as_utc(row.last_seen_at) > timedelta(minutes=1):
        row.last_seen_at = now
        session.commit()
    return row


def end_session(session, token: str | None):
    from certadillo.db import ConsoleSession

    row = session.get(ConsoleSession, _hash(token)) if token else None
    if row is not None:
        session.delete(row)
        session.flush()
    return row


def same_origin(settings, origin: str | None) -> bool:
    if not origin:
        return True  # same-origin fetches may omit it; SameSite=Strict and the CSRF header still apply
    base = urlsplit(settings.base_url)
    o = urlsplit(origin)
    return (o.scheme, o.hostname, o.port) == (base.scheme, base.hostname, base.port)
