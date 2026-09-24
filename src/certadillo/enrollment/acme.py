"""ACME (RFC 8555) server for internal automation (certbot, lego, cert-manager,
acme.sh, win-acme).

External Account Binding is mandatory: every ACME account belongs to an
onboarded app, so the RA scope (allowed domains, profile, environment) set
during onboarding applies to ACME orders too.

Challenges (`CERTADILLO_ACME_CHALLENGE`):
  http-01    (default) each authorization offers http-01 and dns-01; wildcard
             names get dns-01 only, as RFC 8555 requires. dns-01 lookups go to
             the resolvers configured per zone (acme_dns.py, split-horizon).
  ra-scope   skip the network check for names already inside the app's
             approved domain scope; ownership was proven at onboarding

Also implemented: ARI renewal information (RFC 9773) with the `replaces`
order field, account key rollover, and account and authorization
deactivation.
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
from certadillo.audit.log import record
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
from certadillo.enrollment import acme_dns, ari
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


async def _parse(p: Platform, request: Request, need_jwk: bool = False, allow_jwk: bool = False):
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
        if not (need_jwk or allow_jwk):
            raise AcmeError("malformed", "use kid for this request")
        key = jwk_to_key(protected["jwk"])
    elif "kid" in protected:
        if need_jwk:
            raise AcmeError("malformed", "newAccount requires jwk")
        acct_id = protected["kid"].rstrip("/").rsplit("/", 1)[-1]
        account = p.s.get(AcmeAccount, int(acct_id)) if acct_id.isdigit() else None
        if account is None:
            raise AcmeError("accountDoesNotExist", "unknown account", 400)
        if account.status != "valid":
            raise AcmeError("unauthorized", f"account is {account.status}", 401)
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
        "renewalInfo": f"{b}/renewal-info",
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
            if existing.status != "valid":
                raise AcmeError("unauthorized", f"the account for this key is {existing.status}", 401)
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
        mac = hmac.new(b64u_dec(p.eab_hmac_key(cred)), f"{eab['protected']}.{eab['payload']}".encode(), hashlib.sha256)
        if eab_prot.get("alg") != "HS256" or not hmac.compare_digest(mac.digest(), b64u_dec(eab["signature"])):
            raise AcmeError("unauthorized", "EAB signature invalid", 401)
        if json.loads(b64u_dec(eab["payload"])) != jwk:
            raise AcmeError("malformed", "EAB payload must be the account JWK")
        cred.used = True
        acct = AcmeAccount(thumbprint=tp, jwk=jwk, app_id=cred.app_id, contact=payload.get("contact", []))
        p.s.add(acct)
        p.s.flush()
        record(p.s, f"acme:{acct.id}", "acme.account.create", f"app:{cred.app_id}", {"thumbprint": tp, "eab_kid": cred.kid})
        return _resp(p, request, _acct_json(acct, request), 201, f"{base(request)}/acct/{acct.id}")
    except AcmeError as e:
        return _problem(p, request, e)


def deactivate_account(p: Platform, acct: AcmeAccount) -> dict:
    """RFC 8555 7.3.6: the account is gone for good, and so are its open
    authorizations and orders."""
    acct.status = "deactivated"
    orders = p.s.query(AcmeOrder).filter(AcmeOrder.account_id == acct.id,
                                         AcmeOrder.status.in_(("pending", "ready", "processing"))).all()
    authz_n = 0
    for o in orders:
        o.status, o.error = "invalid", "account deactivated"
        for a in p.s.query(AcmeAuthz).filter_by(order_id=o.id).all():
            if a.status in ("pending", "valid"):
                a.status = "deactivated"
                authz_n += 1
    record(p.s, f"acme:{acct.id}", "acme.account.deactivate", f"app:{acct.app_id}",
           {"orders_closed": len(orders), "authorizations_deactivated": authz_n})
    return {"orders": len(orders), "authorizations": authz_n}


def _acct_json(a: AcmeAccount, request: Request) -> dict:
    return {"status": a.status, "contact": a.contact, "orders": f"{base(request)}/acct/{a.id}/orders"}


@router.post("/acct/{acct_id}")
async def account(acct_id: int, request: Request, p: Platform = Depends(platform)):
    try:
        _, payload, acct = await _parse(p, request)
        if acct.id != acct_id:
            raise AcmeError("unauthorized", "not your account", 403)
        if payload and payload.get("status") == "deactivated":
            deactivate_account(p, acct)
        elif payload and "contact" in payload:
            acct.contact = list(payload["contact"])
            record(p.s, f"acme:{acct.id}", "acme.account.update", f"app:{acct.app_id}", {"contact": acct.contact})
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
        names = sorted({i["value"].lower().rstrip(".") for i in idents})
        violations = [["san_scope", n] for n in names if not domain_allowed(n, app.allowed_domains)]
        wild = [n for n in names if n.startswith("*.")]
        if any("*" in n[2:] for n in wild) or any("*" in n for n in names if not n.startswith("*.")):
            raise AcmeError("rejectedIdentifier", "a wildcard is only allowed as the whole leftmost label")
        if wild and not p.engine.profile(app.profile).get("allow_wildcard", False):
            violations += [["wildcard", n] for n in wild]
        if violations:
            record(p.s, who.name, "certificate.rejected", app.name, {"protocol": "acme", "violations": violations})
            p.commit()
            detail = "; ".join(f"{n}: {'outside app scope' if r == 'san_scope' else 'wildcards not allowed for profile ' + app.profile}"
                               for r, n in violations)
            raise AcmeError("rejectedIdentifier", detail, 403)
        replaced = None
        if payload.get("replaces"):
            replaced = _check_replaces(p, acct, payload["replaces"])
        order = AcmeOrder(account_id=acct.id, identifiers=names, expires=datetime.now(timezone.utc) + timedelta(hours=8),
                          replaces=payload.get("replaces"), replaces_cert_id=replaced.id if replaced else None)
        p.s.add(order)
        p.s.flush()
        ra_scope = os.environ.get("CERTADILLO_ACME_CHALLENGE", "http-01") == "ra-scope"
        for n in names:
            status = "valid" if ra_scope else "pending"
            is_wild = n.startswith("*.")
            p.s.add(AcmeAuthz(order_id=order.id, identifier=n[2:] if is_wild else n, wildcard=is_wild,
                              token=secrets.token_urlsafe(32), status=status, challenge_status=status,
                              challenge_type="ra-scope" if ra_scope else None))
        if ra_scope:
            order.status = "ready"
        p.s.flush()
        return _resp(p, request, _order_json(order, p, request), 201, f"{base(request)}/order/{order.id}")
    except AcmeError as e:
        return _problem(p, request, e)


def _check_replaces(p: Platform, acct: AcmeAccount, value: str) -> Certificate:
    """RFC 9773 section 5: the certificate an order replaces must belong to
    the same app and must not already be replaced."""
    try:
        row = ari.find_by_cert_id(p.s, value)
    except ValueError as e:
        raise AcmeError("malformed", f"replaces: {e}") from None
    if row is None or row.app_id != acct.app_id:
        raise AcmeError("malformed", "replaces: no certificate with this CertID for this account's app")
    if row.status == "superseded" or row.replaced_by:
        raise AcmeError("alreadyReplaced", "this certificate has already been replaced", 409)
    open_order = (p.s.query(AcmeOrder)
                  .filter(AcmeOrder.replaces_cert_id == row.id, AcmeOrder.status.in_(("pending", "ready", "processing")),
                          AcmeOrder.expires > datetime.now(timezone.utc))
                  .first())
    if open_order is not None:
        raise AcmeError("alreadyReplaced", f"order {open_order.id} is already replacing this certificate", 409)
    return row


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
        _, payload, acct = await _parse(p, request)
        a = p.s.get(AcmeAuthz, authz_id)
        if a is None:
            raise AcmeError("unauthorized", "authorization not found", 404)
        o = _own_order(p, acct, a.order_id)
        if payload and payload.get("status") == "deactivated":
            # RFC 8555 7.5.2: a client gives up an authorization it no longer wants
            if a.status not in ("pending", "valid"):
                raise AcmeError("malformed", f"authorization is {a.status}")
            a.status = "deactivated"
            if o.status in ("pending", "ready"):
                o.status, o.error = "invalid", "an authorization was deactivated"
            record(p.s, f"acme:{acct.id}", "acme.authz.deactivate", a.identifier, {"order": o.id})
        return _resp(p, request, _authz_json(a, o, request))
    except AcmeError as e:
        return _problem(p, request, e)


def _challenge_types(a: AcmeAuthz) -> list[str]:
    if a.challenge_type == "ra-scope":
        return ["http-01"]
    return ["dns-01"] if a.wildcard else ["http-01", "dns-01"]


def _authz_json(a: AcmeAuthz, o: AcmeOrder, request: Request) -> dict:
    challenges = []
    for t in _challenge_types(a):
        # a challenge that was not the one attempted stays pending (RFC 8555 7.1.4)
        attempted = a.challenge_type in (t, "ra-scope") or (a.challenge_type is None and t == "http-01"
                                                           and a.challenge_status != "pending")
        status = a.challenge_status if attempted else "pending"
        ch = {"type": t, "url": f"{base(request)}/chall/{a.id}/{t}", "token": a.token, "status": status}
        if attempted and a.validated_at:
            ch["validated"] = as_utc(a.validated_at).isoformat().replace("+00:00", "Z")
        if attempted and a.error:
            ch["error"] = {"type": ERR + ("dns" if t == "dns-01" else "incorrectResponse"), "detail": a.error}
        challenges.append(ch)
    d = {
        "status": a.status,
        "expires": as_utc(o.expires).isoformat().replace("+00:00", "Z"),
        "identifier": {"type": "dns", "value": a.identifier},
        "challenges": challenges,
    }
    if a.wildcard:
        d["wildcard"] = True
    return d


def http01_fetch(domain: str, token: str) -> str:
    """Overridable in tests."""
    r = httpx.get(f"http://{domain}/.well-known/acme-challenge/{token}", timeout=10, follow_redirects=True)
    r.raise_for_status()
    return r.text.strip()


def dns01_lookup(name: str, settings) -> tuple[list[str], str]:
    """TXT values at name and the DNS view that answered. Overridable in tests."""
    return acme_dns.lookup_txt(name, settings)


def _validate(p: Platform, a: AcmeAuthz, acct: AcmeAccount, ctype: str) -> tuple[bool, str | None]:
    if ctype == "http-01":
        expected = f"{a.token}.{acct.thumbprint}"
        try:
            got = http01_fetch(a.identifier, a.token)
        except Exception as e:  # noqa: BLE001
            return False, f"fetching http://{a.identifier}/.well-known/acme-challenge/{a.token}: {e}"
        if hmac.compare_digest(got.encode("utf-8", "replace"), expected.encode()):
            return True, None
        return False, "the response did not match the key authorization"
    expected = acme_dns.key_authorization_digest(a.token, acct.thumbprint)
    qname = f"_acme-challenge.{a.identifier}"
    try:
        values, view = dns01_lookup(qname, p.settings)
    except acme_dns.DnsLookupError as e:
        return False, str(e)
    if any(hmac.compare_digest(v.encode(), expected.encode()) for v in values):
        return True, None
    return False, f"no TXT record at {qname} matches the key authorization ({len(values)} found in the {view} view)"


@router.post("/chall/{authz_id}")
async def challenge_legacy(authz_id: int, request: Request, p: Platform = Depends(platform)):
    """Challenge URL from before dns-01 support; always http-01."""
    return await challenge(authz_id, "http-01", request, p)


@router.post("/chall/{authz_id}/{ctype}")
async def challenge(authz_id: int, ctype: str, request: Request, p: Platform = Depends(platform)):
    try:
        _, _, acct = await _parse(p, request)
        a = p.s.get(AcmeAuthz, authz_id)
        if a is None or ctype not in _challenge_types(a):
            raise AcmeError("unauthorized", "challenge not found", 404)
        o = _own_order(p, acct, a.order_id, live=True)
        if a.challenge_status == "pending" and a.status == "pending":
            # off the event loop: a slow or hostile target must not stall OCSP and enrollment
            ok, why = await asyncio.to_thread(_validate, p, a, acct, ctype)
            a.challenge_type = ctype
            if ok:
                a.challenge_status = a.status = "valid"
                a.validated_at = datetime.now(timezone.utc)
                a.error = None
            else:
                a.challenge_status = a.status = "invalid"
                a.error = why
                o.status = "invalid"
                o.error = f"{a.identifier}: {why}"
            siblings = p.s.query(AcmeAuthz).filter_by(order_id=o.id).all()
            if all(s.status == "valid" for s in siblings) and o.status == "pending":
                o.status = "ready"
        p.s.flush()
        body = next(c for c in _authz_json(a, o, request)["challenges"] if c["type"] == ctype)
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
        previous = p.s.get(Certificate, o.replaces_cert_id) if o.replaces_cert_id else None
        if previous is not None and previous.status != "active":
            previous = None  # revoked meanwhile: issue a fresh one without the renewal link
        try:
            result = p.request_certificate(who, who.app_id, csr.public_bytes(serialization.Encoding.PEM).decode(),
                                           protocol="acme", previous=previous)
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
        protected, payload, acct = await _parse(p, request, allow_jwk=True)
        cert = x509.load_der_x509_certificate(b64u_dec(payload["certificate"]))
        row = p.s.query(Certificate).filter_by(fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex()).one_or_none()
        if row is None:
            raise AcmeError("unauthorized", "certificate not issued here", 403)
        if acct is None:
            # RFC 8555 7.6: signed with the certificate's own key, e.g. after the account key is lost
            if thumbprint(protected["jwk"]) != thumbprint(_pub_jwk(cert.public_key())):
                raise AcmeError("unauthorized", "the JWS key is not the certificate's key", 403)
            who = Actor(f"acme:cert-key:{row.serial_hex}", "app", row.app_id)
        elif row.app_id != acct.app_id:
            raise AcmeError("unauthorized", "certificate not issued to this account's app", 403)
        else:
            who = _app_actor(p, acct)
        if row.status == "revoked":
            raise AcmeError("alreadyRevoked", "certificate already revoked")
        codes = {0: "unspecified", 1: "key_compromise", 3: "affiliation_changed", 4: "superseded",
                 5: "cessation_of_operation"}
        reason = payload.get("reason", 0)
        if reason not in codes:
            raise AcmeError("badRevocationReason", f"reason code {reason} is not accepted")
        p.revoke(who, row.id, codes[reason])
        return _resp(p, request)
    except AcmeError as e:
        return _problem(p, request, e)


def _pub_jwk(pub) -> dict:
    nums = pub.public_numbers()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        size = (pub.curve.key_size + 7) // 8
        crv = {"secp256r1": "P-256", "secp384r1": "P-384"}.get(pub.curve.name, pub.curve.name)
        return {"kty": "EC", "crv": crv, "x": b64u(nums.x.to_bytes(size, "big")), "y": b64u(nums.y.to_bytes(size, "big"))}
    return {"kty": "RSA", "n": b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}


@router.post("/key-change")
async def key_change(request: Request, p: Platform = Depends(platform)):
    """Account key rollover (RFC 8555 7.3.5). The outer JWS is signed by the
    current key; its payload is an inner JWS signed by the new key."""
    try:
        protected, inner, acct = await _parse(p, request)
        try:
            iprot = json.loads(b64u_dec(inner["protected"]))
            ipayload = json.loads(b64u_dec(inner["payload"]))
            isig = b64u_dec(inner["signature"])
        except Exception:
            raise AcmeError("malformed", "payload must be a flattened JWS signed by the new key") from None
        if "jwk" not in iprot or "kid" in iprot:
            raise AcmeError("malformed", "the inner JWS must carry the new key as jwk")
        if "nonce" in iprot:
            raise AcmeError("malformed", "the inner JWS must not have a nonce")
        if iprot.get("url") != protected.get("url"):
            raise AcmeError("malformed", "inner and outer url differ")
        new_key = jwk_to_key(iprot["jwk"])
        verify_jws_sig(iprot.get("alg", ""), new_key, f"{inner['protected']}.{inner['payload']}".encode(), isig)
        if ipayload.get("account") != protected.get("kid"):
            raise AcmeError("malformed", "inner payload account does not match the outer kid")
        old = ipayload.get("oldKey") or {}
        try:
            old_tp = thumbprint(old)
        except KeyError:
            raise AcmeError("malformed", "oldKey is not a JWK") from None
        if old_tp != acct.thumbprint:
            raise AcmeError("unauthorized", "oldKey is not this account's current key", 401)
        new_tp = thumbprint(iprot["jwk"])
        clash = p.s.query(AcmeAccount).filter_by(thumbprint=new_tp).one_or_none()
        if clash is not None:
            p.s.rollback()
            fresh = new_nonce(p)
            p.commit()
            return JSONResponse({"type": ERR + "conflict", "detail": "the new key already belongs to an account",
                                 "status": 409}, status_code=409, media_type="application/problem+json",
                                headers={"Replay-Nonce": fresh, "Location": f"{base(request)}/acct/{clash.id}"})
        acct.jwk, acct.thumbprint = iprot["jwk"], new_tp
        record(p.s, f"acme:{acct.id}", "acme.account.key_change", f"app:{acct.app_id}",
               {"old_thumbprint": old_tp, "new_thumbprint": new_tp})
        return _resp(p, request, _acct_json(acct, request))
    except AcmeError as e:
        return _problem(p, request, e)


# ---------------------------------------------------------------- ARI (RFC 9773)
@router.get("/renewal-info/{cert_id}")
def renewal_info(cert_id: str, p: Platform = Depends(platform)):
    try:
        row = ari.find_by_cert_id(p.s, cert_id)
    except ValueError as e:
        return JSONResponse({"type": ERR + "malformed", "detail": str(e), "status": 400}, 400,
                            media_type="application/problem+json")
    if row is None:
        return JSONResponse({"type": ERR + "malformed", "detail": "no certificate with this CertID", "status": 404},
                            404, media_type="application/problem+json")
    start, end, explanation = ari.suggested_window(p.s, row)
    body = {"suggestedWindow": {"start": start.isoformat().replace("+00:00", "Z"),
                                "end": end.isoformat().replace("+00:00", "Z")}}
    if explanation:
        body["explanationURL"] = explanation
    retry = p.settings.ari_retry_after_seconds
    if p.s.get(ari.RenewalAdvice, row.id) is not None:
        retry = min(retry, 3600)  # during a campaign, check back hourly
    return JSONResponse(body, headers={"Retry-After": str(retry), "Cache-Control": f"public, max-age={retry}"})


# ---------------------------------------------------------------- cleanup
def housekeeping(session, now: datetime | None = None) -> dict:
    """Expire stale orders and authorizations, drop spent state."""
    now = now or datetime.now(timezone.utc)
    expired = 0
    for o in session.query(AcmeOrder).filter(AcmeOrder.status.in_(("pending", "ready", "processing")),
                                             AcmeOrder.expires < now).all():
        o.status, o.error = "invalid", o.error or "order expired"
        for a in session.query(AcmeAuthz).filter_by(order_id=o.id, status="pending").all():
            a.status = "expired"
        expired += 1
    old = now - timedelta(days=30)
    purged = 0
    for o in session.query(AcmeOrder).filter(AcmeOrder.status == "invalid", AcmeOrder.expires < old).all():
        session.query(AcmeAuthz).filter_by(order_id=o.id).delete()
        session.delete(o)
        purged += 1
    nonces = session.query(AcmeNonce).filter(AcmeNonce.created_at < now - timedelta(hours=1)).delete()
    session.flush()
    return {"orders_expired": expired, "orders_purged": purged, "nonces_dropped": nonces}
