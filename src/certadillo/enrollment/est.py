"""EST (RFC 7030) enrollment for devices and appliances.

Authentication is HTTP Basic with the app credential as password (RFC 7030
section 3.2.3). Put a TLS terminator in front; EST requires HTTPS."""
from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from certadillo.api.deps import actor, platform
from certadillo.db import Certificate
from certadillo.policy.engine import PolicyError
from certadillo.services import Actor, Platform

router = APIRouter(prefix="/.well-known/est", tags=["EST"])


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


@router.get("/cacerts")
def cacerts(p: Platform = Depends(platform)):
    return _p7(p.ca.chain(p.ca.default_issuing()))


def _enroll(p: Platform, who: Actor, csr, previous: Certificate | None = None):
    if who.role != "app" or who.app_id is None:
        raise HTTPException(403, "EST enrollment requires an app credential")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    try:
        result = p.request_certificate(who, who.app_id, csr_pem, protocol="est", previous=previous)
    except PolicyError as e:
        raise HTTPException(400, str(e)) from None
    p.commit()
    if not isinstance(result, Certificate):
        # RFC 7030 4.2.3: 202 + Retry-After when manual approval is pending.
        return Response(status_code=202, headers={"Retry-After": "3600"})
    return _p7([x509.load_pem_x509_certificate(result.pem.encode())])


@router.post("/simpleenroll")
async def simpleenroll(request: Request, p: Platform = Depends(platform), who: Actor = Depends(actor)):
    return _enroll(p, who, _csr_from_body(await request.body()))


@router.post("/simplereenroll")
async def simplereenroll(request: Request, p: Platform = Depends(platform), who: Actor = Depends(actor)):
    csr = _csr_from_body(await request.body())
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    prev = (
        p.s.query(Certificate)
        .filter_by(app_id=who.app_id, status="active", common_name=cn[0].value if cn else "")
        .order_by(Certificate.not_after.desc())
        .first()
    )
    if prev is None:
        raise HTTPException(400, "no active certificate with this subject to re-enroll")
    return _enroll(p, who, csr, previous=prev)
