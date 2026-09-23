"""EST, ACME and SSH certificate enrollment."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs7, ssh

from certadillo.enrollment import acme as acme_mod
from conftest import ADMIN, onboard


# ------------------------------------------------------------------ EST
def test_est_cacerts_and_enroll(client):
    _, h = onboard(client, "atm-fleet", domains=["*.atm.bank.internal"])
    key = h["X-API-Key"]
    r = client.get("/.well-known/est/cacerts")
    assert r.status_code == 200
    certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(r.content))
    assert len(certs) == 2

    ec_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "atm-0042.atm.bank.internal")]))
           .sign(ec_key, hashes.SHA256()))
    body = base64.encodebytes(csr.public_bytes(serialization.Encoding.DER))
    basic = "Basic " + base64.b64encode(f"atm-0042:{key}".encode()).decode()
    r = client.post("/.well-known/est/simpleenroll", content=body,
                    headers={"Authorization": basic, "Content-Type": "application/pkcs10"})
    assert r.status_code == 200, r.text
    leaf = pkcs7.load_der_pkcs7_certificates(base64.b64decode(r.content))[0]
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["atm-0042.atm.bank.internal"]

    # re-enroll rotates the key and supersedes the old certificate
    new_key = ec.generate_private_key(ec.SECP256R1())
    csr2 = (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "atm-0042.atm.bank.internal")]))
            .sign(new_key, hashes.SHA256()))
    r = client.post("/.well-known/est/simplereenroll", content=base64.encodebytes(csr2.public_bytes(serialization.Encoding.DER)),
                    headers={"Authorization": basic})
    assert r.status_code == 200
    statuses = sorted(c["status"] for c in client.get("/api/v1/certificates", headers=h).json())
    assert statuses == ["active", "superseded"]

    r = client.post("/.well-known/est/simpleenroll", content=body, headers={"Authorization": "Basic " + base64.b64encode(b"x:bad").decode()})
    assert r.status_code == 401


# ------------------------------------------------------------------ ACME client (test only)
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class MiniAcme:
    """Just enough RFC 8555 client to drive the server end to end."""

    def __init__(self, client):
        self.c = client
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        self.kid = None
        self.dir = client.get("/acme/directory").json()
        self.nonce = client.head(self.dir["newNonce"]).headers["Replay-Nonce"]

    def thumbprint(self):
        return b64u(hashlib.sha256(json.dumps(self.jwk, sort_keys=True, separators=(",", ":")).encode()).digest())

    def post(self, url, payload, use_jwk=False, nonce=None):
        prot = {"alg": "ES256", "nonce": nonce or self.nonce, "url": url}
        if use_jwk:
            prot["jwk"] = self.jwk
        else:
            prot["kid"] = self.kid
        p64 = b64u(json.dumps(prot).encode())
        pay64 = "" if payload is None else b64u(json.dumps(payload).encode())
        der = self.key.sign(f"{p64}.{pay64}".encode(), ec.ECDSA(hashes.SHA256()))
        r_, s_ = decode_dss_signature(der)
        sig = b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))
        r = self.c.post(url, content=json.dumps({"protected": p64, "payload": pay64, "signature": sig}),
                        headers={"Content-Type": "application/jose+json"})
        self.nonce = r.headers.get("Replay-Nonce", self.nonce)
        return r

    def register(self, kid, hmac_key):
        url = self.dir["newAccount"]
        eab_prot = b64u(json.dumps({"alg": "HS256", "kid": kid, "url": url}).encode())
        eab_pay = b64u(json.dumps(self.jwk).encode())
        mac = hmac.new(base64.urlsafe_b64decode(hmac_key + "=" * (-len(hmac_key) % 4)),
                       f"{eab_prot}.{eab_pay}".encode(), hashlib.sha256).digest()
        r = self.post(url, {"termsOfServiceAgreed": True, "contact": ["mailto:pki@bank.example"],
                            "externalAccountBinding": {"protected": eab_prot, "payload": eab_pay, "signature": b64u(mac)}},
                      use_jwk=True)
        if r.status_code in (200, 201):
            self.kid = r.headers["Location"]
        return r


@pytest.fixture
def acme_app(client):
    app_id, _ = onboard(client, "web-portal", domains=["*.portal.bank.internal"])
    eab = client.post(f"/api/v1/apps/{app_id}/acme-eab", headers=ADMIN).json()
    return app_id, eab


def test_acme_requires_eab(client, acme_app):
    a = MiniAcme(client)
    r = a.post(a.dir["newAccount"], {"termsOfServiceAgreed": True}, use_jwk=True)
    assert r.status_code == 400 and r.json()["type"].endswith("externalAccountRequired")
    _, eab = acme_app
    assert a.register(eab["kid"], "AAAA" + eab["hmac_key"][4:]).status_code == 401


def test_acme_full_flow(client, acme_app, monkeypatch):
    _, eab = acme_app
    a = MiniAcme(client)
    r = a.register(eab["kid"], eab["hmac_key"])
    assert r.status_code == 201, r.text

    # nonce replay is rejected
    stale = a.nonce
    a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "www.portal.bank.internal"}]})
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "www.portal.bank.internal"}]}, nonce=stale)
    assert r.json()["type"].endswith("badNonce")

    # identifiers outside the app's onboarded scope are refused up front
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "www.google.com"}]})
    assert r.status_code == 403 and r.json()["type"].endswith("rejectedIdentifier")

    names = ["www.portal.bank.internal", "api.portal.bank.internal"]
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})
    assert r.status_code == 201, r.text
    order_url, order = r.headers["Location"], r.json()

    served = {}

    def fake_fetch(domain, token):
        return served[token]

    monkeypatch.setattr(acme_mod, "http01_fetch", fake_fetch)
    for authz_url in order["authorizations"]:
        authz = a.post(authz_url, None).json()
        ch = authz["challenges"][0]
        assert ch["type"] == "http-01"
        served[ch["token"]] = f"{ch['token']}.{a.thumbprint()}"
        assert a.post(ch["url"], {}).json()["status"] == "valid"

    assert a.post(order_url, None).json()["status"] == "ready"
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
           .sign(key, hashes.SHA256()))
    r = a.post(order["finalize"], {"csr": b64u(csr.public_bytes(serialization.Encoding.DER))})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "valid"
    r = a.post(r.json()["certificate"], None)
    assert r.headers["content-type"].startswith("application/pem-certificate-chain")
    chain = x509.load_pem_x509_certificates(r.content)
    assert len(chain) == 2
    chain[0].verify_directly_issued_by(chain[1])

    # revoke through ACME
    r = a.post(a.dir["revokeCert"], {"certificate": b64u(chain[0].public_bytes(serialization.Encoding.DER)), "reason": 4})
    assert r.status_code == 200
    rows = client.get("/api/v1/certificates?status=revoked", headers=ADMIN).json()
    assert rows and rows[0]["protocol"] == "acme"
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
    assert crl.get_revoked_certificate_by_serial_number(chain[0].serial_number) is not None


def test_acme_failed_http01(client, acme_app, monkeypatch):
    _, eab = acme_app
    a = MiniAcme(client)
    a.register(eab["kid"], eab["hmac_key"])
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "x.portal.bank.internal"}]}).json()
    monkeypatch.setattr(acme_mod, "http01_fetch", lambda d, t: "wrong")
    authz = a.post(order["authorizations"][0], None).json()
    assert a.post(authz["challenges"][0]["url"], {}).json()["status"] == "invalid"


# ------------------------------------------------------------------ SSH
def test_ssh_user_and_host_certs(client):
    _, h = onboard(client, "bastion", domains=["*.ops.bank.internal"])
    ca_line = client.get("/api/v1/ssh/ca").text.strip()
    assert ca_line.startswith("ssh-ed25519 ")
    user_key = ed25519.Ed25519PrivateKey.generate()
    pub = user_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    r = client.post("/api/v1/ssh/certificates", json={"public_key": pub, "cert_type": "user",
                                                      "principals": ["alice", "deploy"], "key_id": "alice@bank",
                                                      "validity_hours": 4, "source_address": "10.0.0.0/8"}, headers=h)
    assert r.status_code == 201, r.text
    cert = ssh.load_ssh_public_identity(r.json()["certificate"].encode())
    assert isinstance(cert, ssh.SSHCertificate)
    assert cert.valid_principals == [b"alice", b"deploy"]
    assert cert.critical_options == {b"source-address": b"10.0.0.0/8"}
    cert.verify_cert_signature()
    ca_pub = ssh.load_ssh_public_key(" ".join(ca_line.split()[:2]).encode())
    assert cert.signature_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH) == \
        ca_pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    assert cert.valid_before - int(datetime.now(timezone.utc).timestamp()) <= 4 * 3600 + 5

    r = client.post("/api/v1/ssh/certificates", json={"public_key": pub, "cert_type": "user", "principals": ["root"],
                                                      "key_id": "x", "validity_hours": 72}, headers=h)
    assert r.status_code == 422
    r = client.post("/api/v1/ssh/certificates", json={"public_key": pub, "cert_type": "host",
                                                      "principals": ["web01.ops.bank.internal"], "key_id": "web01"},
                    headers=h)
    assert r.status_code == 201


def test_acme_expired_order_is_refused(client, acme_app, monkeypatch):
    from datetime import timedelta

    from certadillo.db import AcmeOrder
    from certadillo.runtime import get_runtime

    _, eab = acme_app
    a = MiniAcme(client)
    a.register(eab["kid"], eab["hmac_key"])
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "late.portal.bank.internal"}]}).json()
    with get_runtime().platform() as p:
        for o in p.s.query(AcmeOrder).all():
            o.expires = datetime.now(timezone.utc) - timedelta(minutes=1)
    monkeypatch.setattr(acme_mod, "http01_fetch", lambda d, t: "x")
    authz = a.post(order["authorizations"][0], None).json()
    r = a.post(authz["challenges"][0]["url"], {})
    assert r.status_code == 403 and "expired" in r.json()["detail"]
