"""SCEP: PENDING and CertPoll for dual-control profiles, RenewalReq signed by
the current certificate, and the Intune-style validation webhook."""
from __future__ import annotations

import hashlib
import secrets

import pytest
from asn1crypto import algos, cms, core
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AttributeOID
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.enrollment import scep as scep_mod
from certadillo.enrollment.scep import OID, _attr, parse_pki_message
from conftest import ADMIN, APPROVER, make_settings, onboard
from test_scep import _client_identity


def _ra(client, path="/scep"):
    certs = pkcs7.load_der_pkcs7_certificates(client.get(f"{path}?operation=GetCACert").content)
    return next(c for c in certs if c.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment)


def _csr(key, cn, challenge=None):
    b = (x509.CertificateSigningRequestBuilder()
         .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False))
    if challenge:
        b = b.add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge.encode())
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _message(ra_cert, signer_key, signer_cert, mtype, inner: bytes, txid: str):
    envelope = (pkcs7.PKCS7EnvelopeBuilder().set_data(inner).add_recipient(ra_cert)
                .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    nonce = secrets.token_bytes(16)
    attrs = cms.CMSAttributes([
        _attr("1.2.840.113549.1.9.3", cms.ContentType("data")),
        _attr("1.2.840.113549.1.9.4", core.OctetString(hashlib.sha256(envelope).digest())),
        _attr("message_type", core.PrintableString(mtype)),
        _attr("transaction_id", core.PrintableString(txid)),
        _attr("sender_nonce", core.OctetString(nonce)),
    ])
    sig = signer_key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    ac = ax509.Certificate.load(signer_cert.public_bytes(serialization.Encoding.DER))
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
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def _send(client, msg, key, cert, path="/scep"):
    r = client.post(f"{path}?operation=PKIOperation", content=msg)
    assert r.status_code == 200, r.text
    _, _, _, attrs, content = parse_pki_message(r.content)
    status = attrs[OID["pki_status"]].parse(core.PrintableString).native
    if status != "0":
        return status, None
    degenerate = pkcs7.pkcs7_decrypt_der(content, cert, key, [])
    return status, pkcs7.load_der_pkcs7_certificates(degenerate)[0]


def test_pending_then_certpoll(client):
    # code signing needs a second person for every certificate
    app_id, _ = onboard(client, "firmware-signing", profile="code-signing", domains=["*.build.bank.internal"])
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    ra = _ra(client)
    key, cert = _client_identity()
    csr_key = rsa.generate_private_key(65537, 3072)
    txid = secrets.token_hex(16)
    msg = _message(ra, key, cert, "19", _csr(csr_key, "fw.build.bank.internal", challenge), txid)
    status, _ = _send(client, msg, key, cert)
    assert status == "3"  # PENDING
    approvals = client.get("/api/v1/approvals?status=pending", headers=ADMIN).json()
    assert approvals[0]["action"] == "issue_certificate" and approvals[0]["payload"]["protocol"] == "scep"

    issuer_and_subject = b"\x30\x00"  # the server finds the request by transactionID
    poll = lambda k, c: _send(client, _message(ra, k, c, "20", issuer_and_subject, txid), k, c)  # noqa: E731
    assert poll(key, cert)[0] == "3"
    # someone else polling the same transaction gets nothing
    other_key, other_cert = _client_identity()
    assert poll(other_key, other_cert)[0] == "2"

    assert client.post(f"/api/v1/approvals/{approvals[0]['id']}/approve", headers=APPROVER).status_code == 200
    status, issued = poll(key, cert)
    assert status == "0"
    assert issued.public_key().public_numbers() == csr_key.public_key().public_numbers()


def test_rejected_request_fails_on_poll(client):
    app_id, _ = onboard(client, "firmware-signing", profile="code-signing", domains=["*.build.bank.internal"])
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    ra = _ra(client)
    key, cert = _client_identity()
    txid = secrets.token_hex(16)
    _send(client, _message(ra, key, cert, "19", _csr(rsa.generate_private_key(65537, 3072), "x.build.bank.internal",
                                                     challenge), txid), key, cert)
    approval = client.get("/api/v1/approvals?status=pending", headers=ADMIN).json()[0]
    client.post(f"/api/v1/approvals/{approval['id']}/reject", headers=APPROVER, json={"comment": "not scheduled"})
    assert _send(client, _message(ra, key, cert, "20", b"\x30\x00", txid), key, cert)[0] == "2"


def test_renewal_signed_by_current_certificate(client):
    app_id, _ = onboard(client, "branch-routers", profile="tls-client", domains=["*.routers.bank.internal"])
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    ra = _ra(client)
    tmp_key, tmp_cert = _client_identity()
    dev_key = rsa.generate_private_key(65537, 2048)
    msg = _message(ra, tmp_key, tmp_cert, "19", _csr(dev_key, "rtr-9.routers.bank.internal", challenge), "t1")
    status, current = _send(client, msg, tmp_key, tmp_cert)
    assert status == "0"
    caps = client.get("/scep?operation=GetCACaps").text
    assert "Renewal" in caps

    # RenewalReq: signed with the current certificate and key, no challenge, new key in the CSR
    new_key = rsa.generate_private_key(65537, 2048)
    msg = _message(ra, dev_key, current, "17", _csr(new_key, "rtr-9.routers.bank.internal"), "t2")
    status, renewed = _send(client, msg, dev_key, current)
    assert status == "0"
    assert renewed.public_key().public_numbers() == new_key.public_key().public_numbers()
    rows = {c["serial"]: c for c in client.get("/api/v1/certificates", headers=ADMIN).json()}
    assert rows[format(current.serial_number, "x")]["status"] == "superseded"

    # the replaced certificate cannot renew again, a self-signed one never can,
    # and renewal cannot change the name
    again = _message(ra, dev_key, current, "17", _csr(rsa.generate_private_key(65537, 2048), "rtr-9.routers.bank.internal"), "t3")
    assert _send(client, again, dev_key, current)[0] == "2"
    k, c = _client_identity()
    assert _send(client, _message(ra, k, c, "17", _csr(k, "rtr-9.routers.bank.internal"), "t4"), k, c)[0] == "2"
    rename = _message(ra, new_key, renewed, "17", _csr(rsa.generate_private_key(65537, 2048), "rtr-10.routers.bank.internal"), "t5")
    assert _send(client, rename, new_key, renewed)[0] == "2"


@pytest.fixture
def hook_client(tmp_path):
    s = make_settings(tmp_path, scep_validation_url="https://mdm-connector.bank.internal/scep/validate",
                      scep_validation_token="t0ken")
    with TestClient(create_app(s, background=False)) as c:
        yield c


def test_validation_webhook(hook_client, monkeypatch):
    calls = []

    def fake(url, token, payload):
        calls.append(payload)
        if payload["event"] == "validate":
            ok = payload["challenge"] == "mdm-issued-challenge" and payload["sans"] == ["laptop-77.corp.bank.internal"]
            return {"valid": ok, "reason": None if ok else "unknown device"}
        return {}

    monkeypatch.setattr(scep_mod, "validation_call", fake)
    app_id, _ = onboard(hook_client, "corp-laptops", profile="tls-client", domains=["*.corp.bank.internal"])
    r = hook_client.put(f"/api/v1/apps/{app_id}/options", headers=ADMIN, json={"scep_validation": "webhook"})
    assert r.json()["options"] == {"scep_validation": "webhook"}
    path = "/scep/corp-laptops"
    ra = _ra(hook_client, path)
    key, cert = _client_identity()
    dev = rsa.generate_private_key(65537, 2048)
    msg = _message(ra, key, cert, "19", _csr(dev, "laptop-77.corp.bank.internal", "mdm-issued-challenge"), "tx-77")
    status, issued = _send(hook_client, msg, key, cert, path)
    assert status == "0"
    assert [c["event"] for c in calls] == ["validate", "success"]
    assert calls[0]["transactionId"] == "tx-77" and calls[1]["serial"] == format(issued.serial_number, "x")

    calls.clear()
    msg = _message(ra, key, cert, "19", _csr(dev, "laptop-78.corp.bank.internal", "mdm-issued-challenge"), "tx-78")
    assert _send(hook_client, msg, key, cert, path)[0] == "2"
    assert [c["event"] for c in calls] == ["validate"]

    # webhook down: fail closed
    monkeypatch.setattr(scep_mod, "validation_call", lambda *a: (_ for _ in ()).throw(ConnectionError("down")))
    msg = _message(ra, key, cert, "19", _csr(dev, "laptop-77.corp.bank.internal", "mdm-issued-challenge"), "tx-79")
    assert _send(hook_client, msg, key, cert, path)[0] == "2"
    reasons = [e["details"].get("reason", "") for e in hook_client.get("/api/v1/audit", headers=ADMIN).json()
               if e["action"] == "certificate.rejected"]
    assert any("unavailable" in r for r in reasons) and any("unknown device" in r for r in reasons)


def test_per_app_url_checks_the_challenge_owner(client):
    a1, _ = onboard(client, "routers-a", profile="tls-client", domains=["*.a.bank.internal"])
    a2, _ = onboard(client, "routers-b", profile="tls-client", domains=["*.a.bank.internal"])
    ch = client.post(f"/api/v1/apps/{a1}/scep-challenge", headers=ADMIN).json()["challenge"]
    ra = _ra(client, "/scep/routers-b")
    key, cert = _client_identity()
    msg = _message(ra, key, cert, "19", _csr(key, "r1.a.bank.internal", ch), "x1")
    assert _send(client, msg, key, cert, "/scep/routers-b")[0] == "2"
    assert _send(client, _message(ra, key, cert, "19", _csr(key, "r1.a.bank.internal", ch), "x2"), key, cert,
                 "/scep/routers-a")[0] == "0"
