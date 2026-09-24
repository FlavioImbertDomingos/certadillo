"""RFC 6960 OCSP responder using a delegated responder certificate."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp

from certadillo.ca.authority import REASONS
from certadillo.db import Certificate, CertificateAuthority, as_utc
from certadillo.observability.metrics import OCSP_REQUESTS


def _key_bits(pub) -> bytes:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)


def _hash(alg: hashes.HashAlgorithm, data: bytes) -> bytes:
    return hashlib.new(alg.name, data).digest()


def respond(session, ca_service, der_request: bytes) -> bytes:
    try:
        req = ocsp.load_der_ocsp_request(der_request)
    except Exception:
        OCSP_REQUESTS.labels(status="malformed").inc()
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(
            serialization.Encoding.DER
        )

    target = None
    for ca in session.query(CertificateAuthority).filter_by(is_root=False).all():
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        if _hash(req.hash_algorithm, _key_bits(ca_cert.public_key())) == req.issuer_key_hash:
            target = (ca, ca_cert)
            break
    if target is None or not target[0].ocsp_cert_pem:
        OCSP_REQUESTS.labels(status="unauthorized").inc()
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(
            serialization.Encoding.DER
        )
    ca, ca_cert = target
    responder_cert = x509.load_pem_x509_certificate(ca.ocsp_cert_pem.encode())
    if responder_cert.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=2):
        ca_service.rotate_ocsp_signer(ca)
        responder_cert = x509.load_pem_x509_certificate(ca.ocsp_cert_pem.encode())
    responder_key = ca_service.ocsp_keystore.load(ca.ocsp_key_ref).private_key

    serial_hex = format(req.serial_number, "x")
    row = session.query(Certificate).filter_by(serial_hex=serial_hex, ca_id=ca.id).one_or_none()
    now = datetime.now(timezone.utc)
    rev_time = rev_reason = None
    from certadillo import integrity

    if row is None:
        status = ocsp.OCSPCertStatus.UNKNOWN
    elif row.status != "revoked" and integrity.trusted_status(session, row) == "revoked":
        # The status row was changed outside the application (for example a
        # revoked certificate set back to active, or an old copy restored). Fail closed.
        status = ocsp.OCSPCertStatus.REVOKED
        rev_time = as_utc(row.revoked_at) or now
        rev_reason = REASONS["unspecified"]
    elif row.status == "revoked":
        status = ocsp.OCSPCertStatus.REVOKED
        rev_time = as_utc(row.revoked_at)
        rev_reason = REASONS[row.revocation_reason or "unspecified"]
    else:
        status = ocsp.OCSPCertStatus.GOOD

    b = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=req.issuer_name_hash,
            issuer_key_hash=req.issuer_key_hash,
            serial_number=req.serial_number,
            algorithm=req.hash_algorithm,
            cert_status=status,
            this_update=now,
            next_update=now + timedelta(hours=4),
            revocation_time=rev_time,
            revocation_reason=rev_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
        .certificates([responder_cert])
    )
    try:
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce)
        b = b.add_extension(nonce.value, critical=False)
    except x509.ExtensionNotFound:
        pass
    OCSP_REQUESTS.labels(status=status.name.lower()).inc()
    return b.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
