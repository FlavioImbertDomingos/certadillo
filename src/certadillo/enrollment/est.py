"""EST (RFC 7030) enrollment for devices and appliances.

Authentication, any one of:
  - HTTP Basic with the app credential as password (RFC 7030 3.2.3)
  - a TLS client certificate issued here (re-enrollment, RFC 7030 3.3.2)
  - a manufacturer (IDevID) certificate from a CA registered for the app,
    for devices bootstrapping into an app without a shared secret

Certadillo runs behind a TLS terminator, so client certificates arrive from
the load balancer in a header (CERTADILLO_EST_CLIENT_CERT_HEADER). The header
is believed only from the load balancer: either the request carries the
shared secret the load balancer adds (CERTADILLO_EST_PROXY_SECRET, header
X-Certadillo-Proxy-Auth), or it comes straight from an address in
CERTADILLO_EST_TRUSTED_PROXIES. The load balancer must also strip any copy
of the header sent by clients.

Also: /csrattrs tells devices which key and signature algorithm to use, and
/serverkeygen generates the key on the server for devices that cannot
(only for profiles with allow_server_keygen: true).
"""
from __future__ import annotations

import base64
import hmac
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from certadillo.api.deps import _raw_key, platform
from certadillo.audit.log import record
from certadillo.db import App, Certificate, CertificateAuthority, EstTrustAnchor
from certadillo.policy.engine import PolicyError
from certadillo.services import Actor, Platform

log = logging.getLogger("certadillo.est")
router = APIRouter(prefix="/.well-known/est", tags=["EST"])
PROXY_AUTH_HEADER = "x-certadillo-proxy-auth"


def _p7(certs: list[x509.Certificate]) -> Response:
    der = pkcs7.serialize_certificates(certs, serialization.Encoding.DER)
    return Response(
        content=base64.encodebytes(der),
        media_type="application/pkcs7-mime; smime-type=certs-only",
        headers={"Content-Transfer-Encoding": "base64"},
    )


def _csr_from_body(body: bytes) -> x509.CertificateSigningRequest:
    try:
        return x509.load_der_x509_csr(base64.b64decode(b"".join(body.split())))
    except Exception:
        raise HTTPException(400, "body must be a base64 DER PKCS#10 request") from None


# ------------------------------------------------------------------ client certificate from the load balancer
def parse_forwarded_cert(value: str) -> x509.Certificate | None:
    """Accepts the formats common load balancers use:
    nginx $ssl_client_escaped_cert and AWS ALB (URL-encoded PEM), Envoy
    x-forwarded-client-cert (Cert="<URL-encoded PEM>"), Traefik
    passTLSClientCert (URL-encoded base64 DER, no PEM markers), and a plain PEM
    or base64 DER."""
    if not value:
        return None
    m = re.search(r'Cert="([^"]+)"', value)
    if m:
        value = m.group(1)
    value = unquote(value).strip()
    if not value:
        return None
    try:
        if "-----BEGIN" in value:
            # some proxies fold the PEM onto one line with spaces or tabs
            body = re.sub(r"-----(BEGIN|END) CERTIFICATE-----", "", value)
            der = base64.b64decode("".join(body.split()))
        else:
            der = base64.b64decode("".join(value.split(",")[0].split()))
        return x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return None


def _from_trusted_proxy(request: Request, settings) -> bool:
    secret = settings.est_proxy_secret
    if secret:
        return hmac.compare_digest(request.headers.get(PROXY_AUTH_HEADER, ""), secret)
    peer = request.client.host if request.client else None
    if not peer or not settings.est_trusted_proxies:
        return False
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c, strict=False) for c in settings.est_trusted_proxies)


def client_certificate(request: Request, settings) -> x509.Certificate | None:
    name = settings.est_client_cert_header
    if not name or name.lower() not in request.headers:
        return None
    if not _from_trusted_proxy(request, settings):
        log.warning("client certificate header ignored: request did not come through the trusted load balancer")
        return None
    return parse_forwarded_cert(request.headers[name])


def _valid_now(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def identify(p: Platform, request: Request) -> tuple[Actor, Certificate | None, str]:
    """Return (actor, the Certificate row if the client cert was issued here, how).
    how is one of: basic, certificate, idevid."""
    cert = client_certificate(request, p.settings)
    if cert is not None and _valid_now(cert):
        fp = cert.fingerprint(hashes.SHA256()).hex()
        row = p.s.query(Certificate).filter_by(fingerprint_sha256=fp, source="issued").one_or_none()
        if row is not None and row.ca_id is not None:
            ca = p.s.get(CertificateAuthority, row.ca_id)
            try:
                cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.cert_pem.encode()))
            except Exception:  # noqa: BLE001
                row = None
            if row is not None and row.status == "active" and row.app_id:
                app = p.s.get(App, row.app_id)
                if app is not None and app.status == "active":
                    return Actor(f"est-cert:{row.serial_hex}", "app", app.id), row, "certificate"
        # a manufacturer (IDevID) certificate from a CA registered for an app
        for anchor in p.s.query(EstTrustAnchor).all():
            ca_cert = x509.load_pem_x509_certificate(anchor.cert_pem.encode())
            if cert.issuer != ca_cert.subject:
                continue
            try:
                cert.verify_directly_issued_by(ca_cert)
            except Exception:  # noqa: BLE001
                continue
            app = p.s.get(App, anchor.app_id)
            if app is not None and app.status == "active":
                return Actor(f"est-idevid:{cert.subject.rfc4514_string()[:80]}", "app", app.id), None, "idevid"
    a = p.authenticate(_raw_key(request))
    if a is None:
        raise HTTPException(401, "authenticate with a client certificate or HTTP Basic (the app credential)",
                            headers={"WWW-Authenticate": 'Basic realm="certadillo-est"'})
    return a, None, "basic"


# ------------------------------------------------------------------ endpoints
@router.get("/cacerts")
def cacerts(p: Platform = Depends(platform)):
    return _p7(p.ca.chain(p.ca.default_issuing()))


def _enroll(p: Platform, who: Actor, csr, how: str, previous: Certificate | None = None):
    if who.role != "app" or who.app_id is None:
        raise HTTPException(403, "EST enrollment requires an app credential or client certificate")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    try:
        result = p.request_certificate(who, who.app_id, csr_pem, protocol="est", previous=previous)
    except PolicyError as e:
        raise HTTPException(400, str(e)) from None
    if isinstance(result, Certificate):
        record(p.s, who.name, "est.enroll", result.serial_hex, {"auth": how, "reenroll": previous is not None})
    p.commit()
    if not isinstance(result, Certificate):
        # RFC 7030 4.2.3: 202 + Retry-After when manual approval is pending.
        return Response(status_code=202, headers={"Retry-After": "3600"})
    return _p7([x509.load_pem_x509_certificate(result.pem.encode())])


@router.post("/simpleenroll")
async def simpleenroll(request: Request, p: Platform = Depends(platform)):
    who, _, how = identify(p, request)
    return _enroll(p, who, _csr_from_body(await request.body()), how)


def _names(obj) -> tuple[x509.Name, list[str]]:
    try:
        san = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = sorted(str(n.value) for n in san)
    except x509.ExtensionNotFound:
        names = []
    return obj.subject, names


@router.post("/simplereenroll")
async def simplereenroll(request: Request, p: Platform = Depends(platform)):
    who, current, how = identify(p, request)
    csr = _csr_from_body(await request.body())
    if current is not None:
        # RFC 7030 4.2.2: subject and SAN must match the certificate being renewed
        cert = x509.load_pem_x509_certificate(current.pem.encode())
        csr_subject, csr_names = _names(csr)
        cn = csr_subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cert_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        _, cert_names = _names(cert)
        if (cn[0].value if cn else None) != (cert_cn[0].value if cert_cn else None) or \
                (csr_names and csr_names != cert_names):
            raise HTTPException(400, "re-enrollment must keep the subject and names of the current certificate")
        return _enroll(p, who, csr, how, previous=current)
    if how == "idevid":
        raise HTTPException(403, "a manufacturer certificate can enroll, not re-enroll")
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    prev = (
        p.s.query(Certificate)
        .filter_by(app_id=who.app_id, status="active", common_name=cn[0].value if cn else "")
        .order_by(Certificate.not_after.desc())
        .first()
    )
    if prev is None:
        raise HTTPException(400, "no active certificate with this subject to re-enroll")
    return _enroll(p, who, csr, how, previous=prev)


# ------------------------------------------------------------------ csrattrs (RFC 7030 4.5)
OIDS = {
    "id-ecPublicKey": "1.2.840.10045.2.1",
    "rsaEncryption": "1.2.840.113549.1.1.1",
    "ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
    "ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
    "sha256WithRSAEncryption": "1.2.840.113549.1.1.11",
    "secp256r1": "1.2.840.10045.3.1.7",
    "secp384r1": "1.3.132.0.34",
    "extensionRequest": "1.2.840.113549.1.9.14",
    "subjectAltName": "2.5.29.17",
}


def csr_attributes(profile: dict) -> bytes:
    """CsrAttrs for a profile: the preferred key type (as an attribute carrying
    the curve or key size), the signature algorithm, and for profiles that
    need DNS names, a hint that the SAN extension is expected."""
    from asn1crypto import core

    class _AttrValues(core.SetOf):
        _child_spec = core.Any

    class _Attribute(core.Sequence):
        _fields = [("type", core.ObjectIdentifier), ("values", _AttrValues)]

    class _AttrOrOID(core.Choice):
        _alternatives = [("oid", core.ObjectIdentifier), ("attribute", _Attribute)]

    class _CsrAttrs(core.SequenceOf):
        _child_spec = _AttrOrOID

    keys = profile.get("allowed_keys", {})
    curves = keys.get("ec_curves", [])
    items = []
    if curves:
        curve = "secp384r1" if curves == ["secp384r1"] else curves[0]
        items.append(_AttrOrOID(name="attribute", value={
            "type": OIDS["id-ecPublicKey"], "values": [core.ObjectIdentifier(OIDS[curve])]}))
        items.append(_AttrOrOID(name="oid", value=OIDS["ecdsa-with-SHA384" if curve == "secp384r1" else "ecdsa-with-SHA256"]))
    else:
        bits = keys.get("rsa_min_bits", 2048)
        items.append(_AttrOrOID(name="attribute", value={
            "type": OIDS["rsaEncryption"], "values": [core.Integer(bits)]}))
        items.append(_AttrOrOID(name="oid", value=OIDS["sha256WithRSAEncryption"]))
    if profile.get("require_dns_san"):
        items.append(_AttrOrOID(name="attribute", value={
            "type": OIDS["extensionRequest"], "values": [core.ObjectIdentifier(OIDS["subjectAltName"])]}))
    return _CsrAttrs(items).dump()


@router.get("/csrattrs")
def csrattrs(request: Request, p: Platform = Depends(platform)):
    """With credentials, the attributes of the caller's profile; without, a
    default that every built-in profile accepts (EC P-256, ECDSA-SHA256)."""
    profile = {"allowed_keys": {"ec_curves": ["secp256r1"]}}
    try:
        who, _, _ = identify(p, request)
        if who.app_id:
            profile = p.engine.profile(p.s.get(App, who.app_id).profile)
    except HTTPException:
        pass
    return Response(base64.encodebytes(csr_attributes(profile)), media_type="application/csrattrs",
                    headers={"Content-Transfer-Encoding": "base64"})


# ------------------------------------------------------------------ serverkeygen (RFC 7030 4.4)
def _generate_key(profile: dict):
    keys = profile.get("allowed_keys", {})
    curves = keys.get("ec_curves", [])
    if curves:
        return ec.generate_private_key(ec.SECP384R1() if curves == ["secp384r1"] else ec.SECP256R1())
    return rsa.generate_private_key(65537, max(3072, keys.get("rsa_min_bits", 2048)))


@router.post("/serverkeygen")
async def serverkeygen(request: Request, p: Platform = Depends(platform)):
    who, _, how = identify(p, request)
    if who.role != "app" or who.app_id is None:
        raise HTTPException(403, "EST enrollment requires an app credential or client certificate")
    template = _csr_from_body(await request.body())
    app = p.s.get(App, who.app_id)
    profile = p.engine.profile(app.profile)
    if not profile.get("allow_server_keygen"):
        raise HTTPException(403, f"profile {app.profile} does not allow server-side key generation")
    if profile.get("dual_control"):
        raise HTTPException(400, "server-generated keys cannot wait for approval; use simpleenroll")
    # The request only supplies the subject and names. Its signature proves
    # nothing about the key the device will use, because that key is made here.
    key = _generate_key(profile)
    b = x509.CertificateSigningRequestBuilder().subject_name(template.subject)
    try:
        san = template.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        b = b.add_extension(san.value, critical=san.critical)
    except x509.ExtensionNotFound:
        pass
    csr = b.sign(key, hashes.SHA256() if not isinstance(key, ec.EllipticCurvePrivateKey)
                 or key.curve.key_size < 384 else hashes.SHA384())
    try:
        result = p.request_certificate(who, who.app_id, csr.public_bytes(serialization.Encoding.PEM).decode(),
                                       protocol="est")
    except PolicyError as e:
        raise HTTPException(400, str(e)) from None
    record(p.s, who.name, "est.serverkeygen", result.serial_hex,
           {"auth": how, "key": result.key_type + "-" + str(result.key_size), "stored": False})
    p.commit()
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    certs = pkcs7.serialize_certificates([x509.load_pem_x509_certificate(result.pem.encode())],
                                         serialization.Encoding.DER)
    boundary = "est-" + os.urandom(8).hex()

    def b64(data: bytes) -> str:
        return "\r\n".join(base64.encodebytes(data).decode().split())

    # MIME wants CRLF line ends and a CRLF before every boundary (RFC 2046 5.1.1)
    body = (
        f"--{boundary}\r\nContent-Type: application/pkcs8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        f"{b64(pkcs8)}\r\n"
        f"--{boundary}\r\nContent-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n{b64(certs)}\r\n"
        f"--{boundary}--\r\n"
    )
    return Response(body.encode(), media_type=f"multipart/mixed; boundary={boundary}",
                    headers={"Cache-Control": "no-store"})
