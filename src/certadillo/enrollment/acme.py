"""ACME (RFC 8555) server for internal automation (certbot, lego, cert-manager,
acme.sh, win-acme).

External Account Binding is mandatory: every ACME account belongs to an
onboarded app, so the RA scope (allowed domains, profile, environment) set
during onboarding applies to ACME orders too.

Challenge modes (`CERTADILLO_ACME_CHALLENGE`):
  http-01    fetch http://<name>/.well-known/acme-challenge/<token> (default)
  ra-scope   skip the network check for names already inside the app's
             approved domain scope; ownership was proven at onboarding
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from certadillo.api.deps import platform
from certadillo.db import (
    AcmeAccount,
    AcmeAuthz,
    AcmeEab,
    AcmeNonce,
    AcmeOrder,
    App,
    Certificate,
    CertificateAuthority,
    as_utc,
)
from certadillo.policy.engine import PolicyError, domain_allowed
from certadillo.services import Actor, Platform

router = APIRouter(prefix="/acme", tags=["ACME"])
ERR = "urn:ietf:params:acme:error:"


class AcmeError(Exception):
    def __init__(self, kind: str, detail: str, status: int = 400):
        self.kind, self.detail, self.status = kind, detail, status


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_to_key(jwk: dict):
    if jwk.get("kty") == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_dec(jwk["x"]), "big"), int.from_bytes(b64u_dec(jwk["y"]), "big"), curve
        ).public_key()
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(
            int.from_bytes(b64u_dec(jwk["e"]), "big"), int.from_bytes(b64u_dec(jwk["n"]), "big")
        ).public_key()
    raise AcmeError("badPublicKey", "unsupported JWK")


def thumbprint(jwk: dict) -> str:
    """RFC 7638."""
    req = ("crv", "kty", "x", "y") if jwk["kty"] == "EC" else ("e", "kty", "n")
    canon = json.dumps({k: jwk[k] for k in req}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())


def verify_jws_sig(alg: str, key, signing_input: bytes, sig: bytes) -> None:
    try:
        if alg in ("ES256", "ES384"):
            n = 32 if alg == "ES256" else 48
            der = encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256() if alg == "ES256" else hashes.SHA384()))
        elif alg == "RS256":
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise AcmeError("badSignatureAlgorithm", f"{alg} not supported")
    except InvalidSignature:
        raise AcmeError("malformed", "JWS signature invalid") from None


def base(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/acme"


def new_nonce(p: Platform) -> str:
    v = secrets.token_urlsafe(24)
    p.s.add(AcmeNonce(value=v))
    p.s.flush()
    return v


def _resp(p: Platform, request: Request, body=None, status: int = 200, location: str | None = None,
          media: str = "application/json", up: str | None = None) -> Response:
    link = f'<{base(request)}/directory>;rel="index"'
    if up:
        link += f', <{up}>;rel="up"'
    headers = {"Replay-Nonce": new_nonce(p), "Link": link, "Cache-Control": "no-store"}
    if location:
        headers["Location"] = location
    p.commit()
    if body is None:
        return Response(status_code=status, headers=headers)
    if isinstance(body, (bytes, str)):
        return Response(content=body, status_code=status, headers=headers, media_type=media)
    return JSONResponse(body, status_code=status, headers=headers)


def _problem(p: Platform, request: Request, e: AcmeError) -> Response:
    p.s.rollback()  # the consumed nonce was already committed in _parse
    fresh = new_nonce(p)
    p.commit()
    return JSONResponse(
        {"type": ERR + e.kind, "detail": e.detail, "status": e.status},
        status_code=e.status,
        media_type="application/problem+json",
        headers={"Replay-Nonce": fresh, "Link": f'<{base(request)}/directory>;rel="index"'},
    )


async def _parse(p: Platform, request: Request, need_jwk: bool = False):
    try:
        body = json.loads(await request.body())
        protected = json.loads(b64u_dec(body["protected"]))
        payload_raw = body["payload"]
        sig = b64u_dec(body["signature"])
    except Exception:
        raise AcmeError("malformed", "request is not a flattened JWS") from None
    nonce = p.s.get(AcmeNonce, protected.get("nonce", ""))
    if nonce is None:
        raise AcmeError("badNonce", "nonce unknown or already used")
    p.s.delete(nonce)
    p.commit()  # a nonce is spent even if the request later fails
    if urlparse(protected.get("url", "")).path != request.url.path:
        raise AcmeError("unauthorized", "JWS url does not match request URL", 401)
    signing_input = f"{body['protected']}.{payload_raw}".encode()
    account = None
    if "jwk" in protected:
        if not need_jwk:
            raise AcmeError("malformed", "use kid for this request")
        key = jwk_to_key(protected["jwk"])
    elif "kid" in protected:
        if need_jwk:
            raise AcmeError("malformed", "newAccount requires jwk")
        acct_id = protected["kid"].rstrip("/").rsplit("/", 1)[-1]
        account = p.s.get(AcmeAccount, int(acct_id)) if acct_id.isdigit() else None
        if account is None or account.status != "valid":
            raise AcmeError("accountDoesNotExist", "unknown account", 400)
        key = jwk_to_key(account.jwk)
    else:
        raise AcmeError("malformed", "jwk or kid required")
    verify_jws_sig(protected.get("alg", ""), key, signing_input, sig)
    payload = json.loads(b64u_dec(payload_raw)) if payload_raw else None
    return protected, payload, account


def _app_actor(p: Platform, account: AcmeAccount) -> Actor:
    app = p.s.get(App, account.app_id)
    if app is None or app.status != "active":
        raise AcmeError("unauthorized", "the app bound to this account is not active", 403)
    return Actor(f"acme:{account.id}:{app.name}", "app", app.id)


# ---------------------------------------------------------------- directory
@router.get("/directory")
def directory(request: Request):
    b = base(request)
    return {
        "newNonce": f"{b}/new-nonce",
        "newAccount": f"{b}/new-account",
        "newOrder": f"{b}/new-order",
        "revokeCert": f"{b}/revoke-cert",
        "keyChange": f"{b}/key-change",
        "meta": {"externalAccountRequired": True, "website": str(request.base_url)},
    }


@router.get("/new-nonce", operation_id="acme_new_nonce_get")
@router.head("/new-nonce", operation_id="acme_new_nonce_head")
def nonce(request: Request, p: Platform = Depends(platform)):
    return _resp(p, request, status=200 if request.method == "HEAD" else 204)


# ---------------------------------------------------------------- accounts
@router.post("/new-account")
async def new_account(request: Request, p: Platform = Depends(platform)):
    try:
        protected, payload, _ = await _parse(p, request, need_jwk=True)
        jwk = protected["jwk"]
        tp = thumbprint(jwk)
        existing = p.s.query(AcmeAccount).filter_by(thumbprint=tp).one_or_none()
        if existing:
            return _resp(p, request, _acct_json(existing, request), 200, f"{base(request)}/acct/{existing.id}")
        if payload.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "no account for this key")
        eab = payload.get("externalAccountBinding")
        if not eab:
            raise AcmeError("externalAccountRequired", "register with an EAB credential from your app onboarding")
        eab_prot = json.loads(b64u_dec(eab["protected"]))
        cred = p.s.get(AcmeEab, eab_prot.get("kid", ""))
        if cred is None or cred.used:
            raise AcmeError("unauthorized", "EAB key id unknown or already used", 401)
        mac = hmac.new(b64u_dec(cred.hmac_key_b64), f"{eab['protected']}.{eab['payload']}".encode(), hashlib.sha256)
        if eab_prot.get("alg") != "HS256" or not hmac.compare_digest(mac.digest(), b64u_dec(eab["signature"])):
            raise AcmeError("unauthorized", "EAB signature invalid", 401)
        if json.loads(b64u_dec(eab["payload"])) != jwk:
            raise AcmeError("malformed", "EAB payload must be the account JWK")
        cred.used = True
        acct = AcmeAccount(thumbprint=tp, jwk=jwk, app_id=cred.app_id, contact=payload.get("contact", []))
        p.s.add(acct)
        p.s.flush()
        from certadillo.audit.log import record

        record(p.s, f"acme:{acct.id}", "acme.account.create", f"app:{cred.app_id}", {"thumbprint": tp, "eab_kid": cred.kid})
        return _resp(p, request, _acct_json(acct, request), 201, f"{base(request)}/acct/{acct.id}")
    except AcmeError as e:
        return _problem(p, request, e)


def _acct_json(a: AcmeAccount, request: Request) -> dict:
    return {"status": a.status, "contact": a.contact, "orders": f"{base(request)}/acct/{a.id}/orders"}


@router.post("/acct/{acct_id}")
async def account(acct_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, payload, acct = await _parse(p, request)
        if acct.id != acct_id:
            raise AcmeError("unauthorized", "not your account", 403)
        if payload and payload.get("status") == "deactivated":
            acct.status = "deactivated"
        return _resp(p, request, _acct_json(acct, request))
    except AcmeError as e:
        return _problem(p, request, e)


# ---------------------------------------------------------------- orders
def _order_json(o: AcmeOrder, p: Platform, request: Request) -> dict:
    b = base(request)
    authz = p.s.query(AcmeAuthz).filter_by(order_id=o.id).all()
    d = {
        "status": o.status,
        "expires": as_utc(o.expires).isoformat().replace("+00:00", "Z"),
        "identifiers": [{"type": "dns", "value": v} for v in o.identifiers],
        "authorizations": [f"{b}/authz/{a.id}" for a in authz],
        "finalize": f"{b}/order/{o.id}/finalize",
    }
    if o.certificate_id:
        d["certificate"] = f"{b}/cert/{o.certificate_id}"
    if o.error:
        d["error"] = {"type": ERR + "badCSR", "detail": o.error}
    return d


@router.post("/new-order")
async def new_order(request: Request, p: Platform = Depends(platform)):
    try:
        _, payload, acct = await _parse(p, request)
        who = _app_actor(p, acct)
        app = p.s.get(App, who.app_id)
        idents = payload.get("identifiers", [])
        if not idents or any(i.get("type") != "dns" for i in idents):
            raise AcmeError("unsupportedIdentifier", "only dns identifiers are supported")
        names = sorted({i["value"].lower() for i in idents})
        outside = [n for n in names if not domain_allowed(n, app.allowed_domains)]
        if outside:
            from certadillo.audit.log import record

            record(p.s, who.name, "certificate.rejected", app.name,
                   {"protocol": "acme", "violations": [["san_scope", n] for n in outside]})
            p.commit()
            raise AcmeError("rejectedIdentifier", f"outside app scope: {', '.join(outside)}", 403)
        order = AcmeOrder(account_id=acct.id, identifiers=names, expires=datetime.now(timezone.utc) + timedelta(hours=8))
        p.s.add(order)
        p.s.flush()
        ra_scope = os.environ.get("CERTADILLO_ACME_CHALLENGE", "http-01") == "ra-scope"
        for n in names:
            status = "valid" if ra_scope else "pending"
            p.s.add(AcmeAuthz(order_id=order.id, identifier=n, token=secrets.token_urlsafe(32), status=status,
                              challenge_status=status))
        if ra_scope:
            order.status = "ready"
        p.s.flush()
        return _resp(p, request, _order_json(order, p, request), 201, f"{base(request)}/order/{order.id}")
    except AcmeError as e:
        return _problem(p, request, e)


def _own_order(p: Platform, acct: AcmeAccount, order_id: int, live: bool = False) -> AcmeOrder:
    o = p.s.get(AcmeOrder, order_id)
    if o is None or o.account_id != acct.id:
        raise AcmeError("unauthorized", "order not found", 404)
    if live and o.status not in ("valid", "invalid") and as_utc(o.expires) < datetime.now(timezone.utc):
        o.status = "invalid"
        o.error = "order expired"
        p.commit()
        raise AcmeError("malformed", "order expired; create a new order", 403)
    return o


@router.post("/order/{order_id}")
async def get_order(order_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, _, acct = await _parse(p, request)
        return _resp(p, request, _order_json(_own_order(p, acct, order_id), p, request))
    except AcmeError as e:
        return _problem(p, request, e)


@router.post("/authz/{authz_id}")
async def get_authz(authz_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, _, acct = await _parse(p, request)
        a = p.s.get(AcmeAuthz, authz_id)
        if a is None:
            raise AcmeError("unauthorized", "authorization not found", 404)
        o = _own_order(p, acct, a.order_id)
        return _resp(p, request, _authz_json(a, o, request))
    except AcmeError as e:
        return _problem(p, request, e)


def _authz_json(a: AcmeAuthz, o: AcmeOrder, request: Request) -> dict:
    ch = {"type": "http-01", "url": f"{base(request)}/chall/{a.id}", "token": a.token, "status": a.challenge_status}
    if a.validated_at:
        ch["validated"] = as_utc(a.validated_at).isoformat().replace("+00:00", "Z")
    return {
        "status": a.status,
        "expires": as_utc(o.expires).isoformat().replace("+00:00", "Z"),
        "identifier": {"type": "dns", "value": a.identifier},
        "challenges": [ch],
    }


def http01_fetch(domain: str, token: str) -> str:
    """Overridable in tests."""
    r = httpx.get(f"http://{domain}/.well-known/acme-challenge/{token}", timeout=10, follow_redirects=True)
    r.raise_for_status()
    return r.text.strip()


@router.post("/chall/{authz_id}")
async def challenge(authz_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, _, acct = await _parse(p, request)
        a = p.s.get(AcmeAuthz, authz_id)
        if a is None:
            raise AcmeError("unauthorized", "challenge not found", 404)
        o = _own_order(p, acct, a.order_id, live=True)
        if a.challenge_status == "pending":
            expected = f"{a.token}.{acct.thumbprint}"
            try:
                # off the event loop: a slow or hostile target must not stall OCSP and enrollment
                got = await asyncio.to_thread(http01_fetch, a.identifier, a.token)
            except Exception as e:  # noqa: BLE001
                got = f"error: {e}"
            if hmac.compare_digest(got.encode("utf-8", "replace"), expected.encode()):
                a.challenge_status = a.status = "valid"
                a.validated_at = datetime.now(timezone.utc)
            else:
                a.challenge_status = a.status = "invalid"
                o.status = "invalid"
            siblings = p.s.query(AcmeAuthz).filter_by(order_id=o.id).all()
            if all(s.status == "valid" for s in siblings) and o.status == "pending":
                o.status = "ready"
        p.s.flush()
        body = _authz_json(a, o, request)["challenges"][0]
        return _resp(p, request, body, up=f"{base(request)}/authz/{a.id}")
    except AcmeError as e:
        return _problem(p, request, e)


@router.post("/order/{order_id}/finalize")
async def finalize(order_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, payload, acct = await _parse(p, request)
        o = _own_order(p, acct, order_id, live=True)
        if o.status != "ready":
            raise AcmeError("orderNotReady", f"order is {o.status}", 403)
        try:
            csr = x509.load_der_x509_csr(b64u_dec(payload["csr"]))
        except Exception:
            raise AcmeError("badCSR", "CSR is not valid DER") from None
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = sorted({n.lower() for n in san.get_values_for_type(x509.DNSName)})
        except x509.ExtensionNotFound:
            names = []
        cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn and cn[0].value.lower() not in o.identifiers:
            raise AcmeError("badCSR", "CSR common name is not in the order")
        if names != o.identifiers:
            raise AcmeError("badCSR", f"CSR names {names} do not match order {o.identifiers}")
        who = _app_actor(p, acct)
        o.status = "processing"
        try:
            result = p.request_certificate(who, who.app_id, csr.public_bytes(serialization.Encoding.PEM).decode(),
                                           protocol="acme")
        except PolicyError as e:
            o.status = "invalid"
            o.error = str(e)
            p.commit()
            raise AcmeError("badCSR", str(e)) from None
        if not isinstance(result, Certificate):
            raise AcmeError("unauthorized", "this profile needs dual control; use the REST API", 403)
        o.certificate_id = result.id
        o.status = "valid"
        p.s.flush()
        return _resp(p, request, _order_json(o, p, request), location=f"{base(request)}/order/{o.id}")
    except AcmeError as e:
        return _problem(p, request, e)


@router.post("/cert/{cert_id}")
async def get_cert(cert_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, _, acct = await _parse(p, request)
        row = p.s.get(Certificate, cert_id)
        if row is None or row.app_id != acct.app_id:
            raise AcmeError("unauthorized", "certificate not found", 404)
        chain = p.ca.chain(p.s.get(CertificateAuthority, row.ca_id)) if row.ca_id else []
        pem = row.pem + "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain[:-1])
        return _resp(p, request, pem, media="application/pem-certificate-chain")
    except AcmeError as e:
        return _problem(p, request, e)


@router.post("/revoke-cert")
async def revoke_cert(request: Request, p: Platform = Depends(platform)):
    try:
        _, payload, acct = await _parse(p, request)
        cert = x509.load_der_x509_certificate(b64u_dec(payload["certificate"]))
        row = p.s.query(Certificate).filter_by(serial_hex=format(cert.serial_number, "x")).one_or_none()
        if row is None or row.app_id != acct.app_id:
            raise AcmeError("unauthorized", "certificate not issued to this account's app", 403)
        if row.status == "revoked":
            raise AcmeError("alreadyRevoked", "certificate already revoked")
        codes = {0: "unspecified", 1: "key_compromise", 3: "affiliation_changed", 4: "superseded",
                 5: "cessation_of_operation"}
        p.revoke(_app_actor(p, acct), row.id, codes.get(payload.get("reason", 0), "unspecified"))
        return _resp(p, request)
    except AcmeError as e:
        return _problem(p, request, e)


@router.post("/key-change")
async def key_change(request: Request, p: Platform = Depends(platform)):
    return _problem(p, request, AcmeError("malformed", "key rollover is not implemented yet; create a new account", 501))
