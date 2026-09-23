"""SCEP end to end with a minimal RFC 8894 client written against the spec."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from asn1crypto import algos, cms, core
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AttributeOID

from certadillo.enrollment.scep import OID, _attr, parse_pki_message
from conftest import ADMIN, onboard


def _client_identity():
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "scep-client-temp")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    return key, cert


def _pkcs_req(ra_cert, key, cert, cn, challenge):
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
           .add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge.encode())
           .sign(key, hashes.SHA256()))
    envelope = (pkcs7.PKCS7EnvelopeBuilder().set_data(csr.public_bytes(serialization.Encoding.DER))
                .add_recipient(ra_cert).encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    nonce = secrets.token_bytes(16)
    attrs = cms.CMSAttributes([
        _attr("1.2.840.113549.1.9.3", cms.ContentType("data")),
        _attr("1.2.840.113549.1.9.4", core.OctetString(hashlib.sha256(envelope).digest())),
        _attr("message_type", core.PrintableString("19")),
        _attr("transaction_id", core.PrintableString(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())),
        _attr("sender_nonce", core.OctetString(nonce)),
    ])
    sig = key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    ac = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    signer = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": ac.issuer, "serial_number": ac.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": sig,
    })
    sd = cms.SignedData({"version": "v1", "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
                         "encap_content_info": {"content_type": "data", "content": envelope},
                         "certificates": [ac], "signer_infos": [signer]})
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump(), nonce


def _enroll(client, cn, challenge):
    caps = client.get("/scep?operation=GetCACaps").text
    assert "POSTPKIOperation" in caps and "AES" in caps
    r = client.get("/scep?operation=GetCACert")
    assert r.headers["content-type"] == "application/x-x509-ca-ra-cert"
    certs = pkcs7.load_der_pkcs7_certificates(r.content)
    ra_cert = next(c for c in certs if c.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment)
    key, cert = _client_identity()
    msg, nonce = _pkcs_req(ra_cert, key, cert, cn, challenge)
    r = client.post("/scep?operation=PKIOperation", content=msg, headers={"Content-Type": "application/x-pki-message"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/x-pki-message"
    _, _, signer_cert, attrs, content = parse_pki_message(r.content)  # verifies the RA's signature
    assert signer_cert == ra_cert
    status = attrs[OID["pki_status"]].parse(core.PrintableString).native
    assert attrs[OID["recipient_nonce"]].parse(core.OctetString).native == nonce
    if status != "0":
        return status, None
    degenerate = pkcs7.pkcs7_decrypt_der(content, cert, key, [])
    return status, pkcs7.load_der_pkcs7_certificates(degenerate)[0]


def test_scep_enrollment_with_one_time_challenge(client):
    app_id, _ = onboard(client, "branch-routers", profile="tls-client", domains=["*.routers.bank.internal"])
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    status, issued = _enroll(client, "rtr-0042.routers.bank.internal", challenge)
    assert status == "0"
    sub = x509.load_pem_x509_certificate(client.get("/pki/ca/issuing-ca-1.pem").text.encode())
    issued.verify_directly_issued_by(sub)
    assert issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["rtr-0042.routers.bank.internal"]
    rows = client.get("/api/v1/certificates", headers=ADMIN).json()
    assert rows[0]["protocol"] == "scep"
    # the challenge is single use
    assert _enroll(client, "rtr-0043.routers.bank.internal", challenge)[0] == "2"


def test_scep_rejects_out_of_scope_and_unknown_challenge(client):
    app_id, _ = onboard(client, "branch-routers", profile="tls-client", domains=["*.routers.bank.internal"])
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    assert _enroll(client, "evil.other.example", challenge)[0] == "2"
    assert _enroll(client, "rtr-1.routers.bank.internal", "not-a-real-challenge")[0] == "2"
    reasons = [e["details"].get("reason", "") for e in client.get("/api/v1/audit", headers=ADMIN).json()
               if e["action"] == "certificate.rejected"]
    assert any("san_scope" in r for r in reasons) and any("challenge" in r for r in reasons)
