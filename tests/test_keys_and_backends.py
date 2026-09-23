"""Key custody (PKCS#11 HSM, external signing path) and issuer backends."""
from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from fastapi.testclient import TestClient

from certadillo.ca.backends import VaultPKIBackend
from certadillo.crypto.signers import ExternalOnlySigner, sign_x509
from certadillo.policy.engine import Decision
from conftest import ADMIN, issue, make_csr, make_settings, onboard

SOFTHSM_LIBS = ["/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"]


def test_external_signing_path_produces_valid_certs_and_crls():
    """The HSM code path (sign tbs bytes elsewhere, rebuild DER) must produce
    byte-valid X.509 for both EC and RSA keys."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    for key in (ec.generate_private_key(ec.SECP384R1()), rsa.generate_private_key(65537, 3072)):
        signer = ExternalOnlySigner("test", key)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ext-signer")])
        import datetime as dt

        now = dt.datetime.now(dt.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), True))
        cert = sign_x509(b, signer)
        cert.verify_directly_issued_by(cert)
        crl = sign_x509(x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now)
                        .next_update(now + timedelta(hours=1)), signer)
        assert crl.is_signature_valid(key.public_key())


@pytest.fixture
def softhsm(tmp_path, monkeypatch):
    lib = next((p for p in SOFTHSM_LIBS if Path(p).exists()), None)
    if lib is None or shutil.which("softhsm2-util") is None:
        pytest.skip("SoftHSM2 not installed")
    pytest.importorskip("pkcs11")
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "certadillo", "--pin", "1234",
                    "--so-pin", "5678"], check=True, capture_output=True)
    return lib


def test_ca_keys_in_pkcs11_hsm(tmp_path, softhsm):
    settings = make_settings(tmp_path / "data", signer="pkcs11", pkcs11_lib=softhsm, pkcs11_pin="1234")
    from certadillo.api.app import create_app

    with TestClient(create_app(settings, background=False)) as client:
        cas = client.get("/api/v1/cas", headers=ADMIN).json()
        assert {c["signer"] for c in cas} == {"pkcs11"}
        _, h = onboard(client)
        _, body = issue(client, h)
        root = x509.load_pem_x509_certificate(client.get("/pki/ca/root-ca.pem").text.encode())
        sub = x509.load_pem_x509_certificate(client.get("/pki/ca/issuing-ca-1.pem").text.encode())
        leaf = x509.load_pem_x509_certificate(body["pem"].encode())
        root.verify_directly_issued_by(root)
        sub.verify_directly_issued_by(root)
        leaf.verify_directly_issued_by(sub)
        client.post(f"/api/v1/certificates/{body['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
        crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
        assert crl.is_signature_valid(sub.public_key())
        req = ocsp.OCSPRequestBuilder().add_certificate(leaf, sub, hashes.SHA1()).build()
        resp = ocsp.load_der_ocsp_response(client.post("/pki/ocsp", content=req.public_bytes(serialization.Encoding.DER)).content)
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        resp.certificates[0].verify_directly_issued_by(sub)

    # CA private keys exist only on the token, marked sensitive and non-extractable.
    import pkcs11
    from pkcs11 import Attribute, KeyType, ObjectClass

    token = pkcs11.lib(softhsm).get_token(token_label="certadillo")
    with token.open(user_pin="1234") as s:
        k = s.get_key(label="issuing-ca-1", key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY)
        assert k[Attribute.SENSITIVE] and not k[Attribute.EXTRACTABLE]
    assert not (tmp_path / "data" / "keys").exists()  # no CA key files on disk


def test_vault_backend_contract():
    """Vault/OpenBao sign/:role and revoke calls, against a mock that signs with a test CA."""
    import datetime as dt

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Vault Test CA")])
    now = dt.datetime.now(dt.timezone.utc)
    seen = {}

    def handler(req: httpx.Request):
        seen[req.url.path] = req
        if req.url.path.endswith("/sign/certadillo"):
            body = __import__("json").loads(req.content)
            csr = x509.load_pem_x509_csr(body["csr"].encode())
            leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_name).public_key(csr.public_key())
                    .serial_number(0xABCDEF).not_valid_before(now).not_valid_after(now + timedelta(days=1))
                    .sign(ca_key, hashes.SHA256()))
            return httpx.Response(200, json={"data": {"certificate": leaf.public_bytes(serialization.Encoding.PEM).decode(),
                                                      "ca_chain": []}})
        return httpx.Response(200, json={"data": {}})

    be = VaultPKIBackend("https://vault.bank.internal:8200", "s.token", namespace="pki-team",
                         client=httpx.Client(transport=httpx.MockTransport(handler)))
    _, csr_pem = make_csr("svc.bank.internal", dns=["svc.bank.internal"])
    leaf, _ = be.sign(x509.load_pem_x509_csr(csr_pem.encode()),
                      Decision("tls-server", timedelta(days=1), ["svc.bank.internal"], common_name="svc.bank.internal"))
    assert leaf.serial_number == 0xABCDEF
    req = seen["/v1/pki/sign/certadillo"]
    assert req.headers["X-Vault-Token"] == "s.token" and req.headers["X-Vault-Namespace"] == "pki-team"
    be.revoke("abcdef", "superseded")
    assert __import__("json").loads(seen["/v1/pki/revoke"].content) == {"serial_number": "ab:cd:ef"}
