from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.config import Settings

ADMIN = {"X-API-Key": "admin-key"}
APPROVER = {"X-API-Key": "approver-key"}
SOFTHSM_LIBS = ["/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"]


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


def make_settings(tmp_path, **kw) -> Settings:
    kw.setdefault("dev_domains", ["bank.internal", "bank.example"])
    return Settings(
        data_dir=tmp_path,
        bootstrap_admin_key="admin-key",
        bootstrap_approver_key="approver-key",
        base_url="http://testserver",
        **kw,
    )


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path), background=False)
    with TestClient(app) as c:
        yield c


def make_csr(cn: str | None = None, dns=(), uris=(), emails=(), key=None, key_type="ec"):
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1()) if key_type == "ec" else rsa.generate_private_key(65537, 2048)
    names = [x509.DNSName(d) for d in dns] + [x509.UniformResourceIdentifier(u) for u in uris]
    names += [x509.RFC822Name(e) for e in emails]
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)] if cn else [])
    )
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    csr = b.sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def onboard(client, name="card-api", env="dev", profile="tls-server", domains=("*.pay.bank.internal",), team=None):
    if team is None:
        r = client.post("/api/v1/teams", json={"name": f"team-{name}", "contact_email": "t@example.com"}, headers=ADMIN)
        assert r.status_code == 201, r.text
        team = r.json()["id"]
    r = client.post("/api/v1/apps", json={"team_id": team, "name": name, "environment": env, "profile": profile,
                                          "allowed_domains": list(domains)}, headers=ADMIN)
    assert r.status_code == 201, r.text
    app = r.json()
    if app["status"] == "pending_approval":
        assert client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER).status_code == 200
    key = client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]
    return app["id"], {"X-API-Key": key}


def issue(client, app_headers, cn="api.pay.bank.internal", **kw):
    key, csr = make_csr(cn, dns=[cn], **kw)
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=app_headers)
    assert r.status_code == 201, r.text
    return key, r.json()
