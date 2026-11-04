"""Upstream issuers behind Certadillo's policy.

ACME runs against Pebble (Let's Encrypt's test CA) with its DNS test server,
over real dns-01; AWS Private CA against moto; DigiCert CertCentral and EJBCA
against fakes of their REST APIs that sign with a throwaway CA."""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.ca.backends import clear_backends, get_backend
from conftest import ADMIN, make_csr, make_settings, onboard

GOBIN = Path(os.environ.get("GOBIN", Path.home() / "go" / "bin"))
PEBBLE = shutil.which("pebble") or str(GOBIN / "pebble")
CHALLTEST = shutil.which("pebble-challtestsrv") or str(GOBIN / "pebble-challtestsrv")


def _pebble_certs() -> Path | None:
    root = Path(os.environ.get("GOMODCACHE", Path.home() / "go" / "pkg" / "mod")) / "github.com" / "letsencrypt"
    found = sorted(root.glob("pebble/v2@*/test/certs")) if root.exists() else []
    return found[-1] if found else None


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(port: int) -> None:
    end = time.time() + 10
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} never opened")


def _policy_file(tmp_path, issuers: dict, folder_issuer: str | None = None) -> str:
    from importlib import resources

    pol = yaml.safe_load(resources.files("certadillo").joinpath("default_policies.yaml").read_text())
    pol["issuers"] = issuers
    path = tmp_path / "policies.yaml"
    path.write_text(yaml.safe_dump(pol))
    return str(path)


@pytest.fixture(autouse=True)
def _fresh_registry():
    clear_backends()
    yield
    clear_backends()


def _route_to(client, issuer: str) -> int:
    """A folder that sends its apps to an upstream issuer (policy changes approved inline here)."""
    r = client.post("/api/v1/folders", json={"name": f"via-{issuer}", "settings": {
        "issuer": {"value": issuer, "locked": True}}}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["folder_id"]


def _app_in(client, folder, domains):
    team = client.post("/api/v1/teams", json={"name": f"team-{folder}", "contact_email": "t@example.com"},
                       headers=ADMIN).json()["id"]
    app = client.post("/api/v1/apps", json={"team_id": team, "name": f"app-{folder}", "environment": "dev",
                                            "profile": "tls-server", "allowed_domains": domains,
                                            "folder_id": folder}, headers=ADMIN).json()
    key = client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]
    return app["id"], {"X-API-Key": key}


# ------------------------------------------------------------------ ACME against Pebble
@pytest.fixture
def pebble(tmp_path):
    certs = _pebble_certs()
    if not (Path(PEBBLE).exists() and Path(CHALLTEST).exists() and certs):
        pytest.skip("pebble and pebble-challtestsrv are needed (go install github.com/letsencrypt/pebble/v2/cmd/...)")
    acme_port, mgmt_port, dns_port, hook_port = _port(), _port(), _port(), _port()
    cfg = {"pebble": {"listenAddress": f"127.0.0.1:{acme_port}", "managementListenAddress": f"127.0.0.1:{mgmt_port}",
                      "certificate": str(certs / "localhost" / "cert.pem"),
                      "privateKey": str(certs / "localhost" / "key.pem"),
                      "httpPort": _port(), "tlsPort": _port(), "ocspResponderURL": "",
                      "externalAccountBindingRequired": False}}
    (tmp_path / "pebble.json").write_text(json.dumps(cfg))
    env = {**os.environ, "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_VA_ALWAYS_VALID": "0"}
    dns = subprocess.Popen([CHALLTEST, "-management", f"127.0.0.1:{hook_port}", "-dns01", f"127.0.0.1:{dns_port}",
                            "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca = subprocess.Popen([PEBBLE, "-config", str(tmp_path / "pebble.json"), "-dnsserver", f"127.0.0.1:{dns_port}"],
                          env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait(hook_port)
        _wait(acme_port)
        yield {"directory": f"https://localhost:{acme_port}/dir", "ca_bundle": str(certs / "pebble.minica.pem"),
               "hook": f"http://127.0.0.1:{hook_port}", "mgmt": f"https://localhost:{mgmt_port}"}
    finally:
        for p in (ca, dns):
            p.terminate()


def test_acme_ca_issues_through_dns01_and_revokes(tmp_path, pebble, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    issuers = {"public-acme": {
        "type": "acme", "directory": pebble["directory"], "ca_bundle": pebble["ca_bundle"],
        "contact": "mailto:pki@bank.example", "poll_interval": 0.2,
        "dns": {"provider": "http-hook", "set_url": pebble["hook"] + "/set-txt",
                "clear_url": pebble["hook"] + "/clear-txt"}}}
    s = make_settings(tmp_path, policy_file=_policy_file(tmp_path, issuers), dual_control_actions=[])
    with TestClient(create_app(s, background=False)) as c:
        folder = _route_to(c, "public-acme")
        _, h = _app_in(c, folder, ["*.pay.bank.internal"])
        _, csr = make_csr("www.pay.bank.internal", dns=["www.pay.bank.internal", "api.pay.bank.internal"])
        r = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
        assert r.status_code == 201, r.text
        cert = r.json()
        assert cert["backend"] == "public-acme" and "Pebble" in cert["issuer"]
        assert "BEGIN CERTIFICATE" in cert["chain_pem"]  # the upstream chain, not Certadillo's
        leaf = x509.load_pem_x509_certificate(cert["pem"].encode())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sorted(sans.get_values_for_type(x509.DNSName)) == ["api.pay.bank.internal", "www.pay.bank.internal"]
        # policy still runs first: a name outside the app's scope never reaches the CA
        _, bad = make_csr("www.other.example", dns=["www.other.example"])
        assert c.post("/api/v1/certificates", json={"csr_pem": bad}, headers=h).status_code == 422

        assert c.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "key_compromise"},
                      headers=h).status_code == 200
        serial = format(leaf.serial_number, "x")
        import ssl

        ctx = ssl.create_default_context(cafile=pebble["ca_bundle"])
        status = httpx.get(f"{pebble['mgmt']}/cert-status-by-serial/{serial}", verify=ctx).json()
        assert status["Status"] == "Revoked"
        # the account key stays in the data directory, encrypted
        key_file = tmp_path / "acme-accounts" / "public-acme.pem"
        assert b"ENCRYPTED" in key_file.read_bytes() and (key_file.stat().st_mode & 0o777) == 0o600


# ------------------------------------------------------------------ a throwaway upstream CA for the fakes
class TinyCA:
    def __init__(self, name="Upstream Test CA"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        now = datetime.now(timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                     .not_valid_after(now + timedelta(days=365))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(self.key, hashes.SHA256()))

    def sign(self, csr_pem: str, extra_names=(), other_key=None) -> x509.Certificate:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.cert.subject)
                .public_key(other_key.public_key() if other_key else csr.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now)
                .not_valid_after(now + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in [*names, *extra_names]]), False)
                .sign(self.key, hashes.SHA256()))


def pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


# ------------------------------------------------------------------ DigiCert CertCentral (fake)
class FakeCertCentral:
    def __init__(self, immediate=True, misbehave=None):
        self.ca, self.immediate, self.misbehave = TinyCA("DigiCert Test CA"), immediate, misbehave
        self.orders: dict[int, dict] = {}
        self.revoked: list[tuple[str, dict]] = []
        self.keys: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.keys.append(request.headers.get("x-dc-devkey", ""))
        path = request.url.path.replace("/services/v2", "")
        if request.method == "POST" and path.startswith("/order/certificate/"):
            body = json.loads(request.content)
            extra = ["evil.example"] if self.misbehave == "names" else ()
            other = ec.generate_private_key(ec.SECP256R1()) if self.misbehave == "key" else None
            leaf = self.ca.sign(body["certificate"]["csr"], extra, other)
            oid = len(self.orders) + 1
            self.orders[oid] = {"leaf": leaf, "body": body, "polls": 0}
            out = {"id": oid, "certificate_id": 9000 + oid}
            if self.immediate:
                out["certificate_chain"] = [{"pem": pem(leaf)}, {"pem": pem(self.ca.cert)}]
            return httpx.Response(201, json=out)
        if request.method == "GET" and path.startswith("/order/certificate/"):
            o = self.orders[int(path.rsplit("/", 1)[1])]
            o["polls"] += 1
            status = "issued" if o["polls"] >= 2 else "pending"
            return httpx.Response(200, json={"status": status, "certificate": {"id": 9000 + int(path.rsplit("/", 1)[1])}})
        if request.method == "GET" and path.endswith("/download/format/pem_all"):
            oid = int(path.split("/")[2]) - 9000
            return httpx.Response(200, text=pem(self.orders[oid]["leaf"]) + pem(self.ca.cert))
        if request.method == "PUT" and path.endswith("/revoke"):
            self.revoked.append((path.split("/")[2], json.loads(request.content)))
            return httpx.Response(201, json={})
        return httpx.Response(404, json={"errors": [{"code": "not_found"}]})


def _with_issuer(tmp_path, monkeypatch, issuers, transport_for=None):
    import certadillo.ca.issuers as reg

    if transport_for:
        real = reg.build

        def build(name, cfg, settings=None):
            obj = real(name, cfg, settings)
            obj.transport = transport_for
            return obj
        monkeypatch.setattr(reg, "build", build)
    return make_settings(tmp_path, policy_file=_policy_file(tmp_path, issuers), dual_control_actions=[])


@pytest.mark.parametrize("immediate", [True, False])
def test_digicert_orders_issue_and_revoke(tmp_path, monkeypatch, immediate):
    fake = FakeCertCentral(immediate=immediate)
    monkeypatch.setenv("CERTADILLO_TEST_DC_KEY", "dc-api-key")
    s = _with_issuer(tmp_path, monkeypatch, {"digicert": {
        "type": "digicert", "product": "ssl_basic", "organization_id": 112233,
        "api_key_ref": "env:CERTADILLO_TEST_DC_KEY", "poll_interval": 0}}, httpx.MockTransport(fake.handler))
    with TestClient(create_app(s, background=False)) as c:
        _, h = _app_in(c, _route_to(c, "digicert"), ["*.pay.bank.internal"])
        _, csr = make_csr("www.pay.bank.internal", dns=["www.pay.bank.internal"])
        cert = c.post("/api/v1/certificates", json={"csr_pem": csr, "validity_days": 30}, headers=h).json()
        assert cert["backend"] == "digicert" and "DigiCert Test CA" in cert["issuer"]
        order = fake.orders[1]["body"]
        assert order["organization"]["id"] == 112233 and order["skip_approval"] is True
        assert order["order_validity"]["days"] == 30
        assert set(fake.keys) == {"dc-api-key"}
        c.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "superseded"}, headers=h)
        assert fake.revoked == [("9001", {"reason": "superseded", "skip_approval": True,
                                          "comments": "revoked through Certadillo (superseded)"})]


@pytest.mark.parametrize("misbehave", ["names", "key"])
def test_an_upstream_ca_that_changes_the_request_is_refused(tmp_path, monkeypatch, misbehave):
    fake = FakeCertCentral(misbehave=misbehave)
    monkeypatch.setenv("CERTADILLO_TEST_DC_KEY", "k")
    s = _with_issuer(tmp_path, monkeypatch, {"digicert": {
        "type": "digicert", "product": "ssl_basic", "organization_id": 1, "api_key_ref": "env:CERTADILLO_TEST_DC_KEY"}},
        httpx.MockTransport(fake.handler))
    with TestClient(create_app(s, background=False), raise_server_exceptions=False) as c:
        _, h = _app_in(c, _route_to(c, "digicert"), ["*.pay.bank.internal"])
        _, csr = make_csr("www.pay.bank.internal", dns=["www.pay.bank.internal"])
        r = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
        assert r.status_code >= 500
        assert c.get("/api/v1/certificates?source=issued", headers=ADMIN).json() == []


# ------------------------------------------------------------------ EJBCA (fake)
def test_ejbca_enrolls_with_pkcs10_and_revokes(tmp_path, monkeypatch):
    ca = TinyCA("EJBCA Test CA")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/certificate/pkcs10enroll"):
            body = json.loads(request.content)
            seen["enroll"] = body
            leaf = ca.sign(body["certificate_request"])
            return httpx.Response(201, json={
                "certificate": base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode(),
                "certificate_chain": [base64.b64encode(ca.cert.public_bytes(serialization.Encoding.DER)).decode()],
                "serial_number": format(leaf.serial_number, "X")})
        if request.url.path.endswith("/revoke"):
            seen["revoke"] = (request.url.path, dict(request.url.params))
            return httpx.Response(200, json={"revoked": True})
        return httpx.Response(404)

    s = _with_issuer(tmp_path, monkeypatch, {"ejbca": {
        "type": "ejbca", "url": "https://ejbca.bank.internal/ejbca/ejbca-rest-api", "ca_name": "Bank Issuing",
        "certificate_profile": "TLS_SERVER", "end_entity_profile": "CERTADILLO"}}, httpx.MockTransport(handler))
    with TestClient(create_app(s, background=False)) as c:
        _, h = _app_in(c, _route_to(c, "ejbca"), ["*.pay.bank.internal"])
        _, csr = make_csr("svc.pay.bank.internal", dns=["svc.pay.bank.internal"])
        cert = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).json()
        assert cert["backend"] == "ejbca"
        chain = x509.load_pem_x509_certificates(cert["chain_pem"].encode())
        assert chain[0].subject.rfc4514_string() == "CN=EJBCA Test CA"
        assert seen["enroll"]["certificate_profile_name"] == "TLS_SERVER"
        assert seen["enroll"]["certificate_authority_name"] == "Bank Issuing"
        c.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
        path, params = seen["revoke"]
        assert path.endswith(f"/{cert['serial']}/revoke") and params == {"reason": "KEY_COMPROMISE"}


# ------------------------------------------------------------------ AWS Private CA (moto)
def test_aws_private_ca_issues_and_revokes(tmp_path, monkeypatch):
    moto = pytest.importorskip("moto")
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        import boto3

        pca = boto3.client("acm-pca", region_name="us-east-1")
        arn = pca.create_certificate_authority(
            CertificateAuthorityConfiguration={"KeyAlgorithm": "EC_prime256v1", "SigningAlgorithm": "SHA256WITHECDSA",
                                               "Subject": {"CommonName": "Bank PCA"}},
            CertificateAuthorityType="SUBORDINATE")["CertificateAuthorityArn"]
        # activate it: sign its CSR with a parent and import the result, as an admin would
        root = TinyCA("Bank Root")
        sub_csr = x509.load_pem_x509_csr(pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"].encode())
        now = datetime.now(timezone.utc)
        sub = (x509.CertificateBuilder().subject_name(sub_csr.subject).issuer_name(root.cert.subject)
               .public_key(sub_csr.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(root.key, hashes.SHA256()))
        pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=pem(sub).encode(),
                                                     CertificateChain=pem(root.cert).encode())
        s = _with_issuer(tmp_path, monkeypatch, {"aws-pca": {"type": "aws-pca", "ca_arn": arn, "region": "us-east-1"}})
        with TestClient(create_app(s, background=False)) as c:
            _, h = _app_in(c, _route_to(c, "aws-pca"), ["*.pay.bank.internal"])
            _, csr = make_csr("pca.pay.bank.internal", dns=["pca.pay.bank.internal"])
            r = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
            assert r.status_code == 201, r.text
            assert r.json()["backend"] == "aws-pca"
            assert c.post(f"/api/v1/certificates/{r.json()['id']}/revoke", json={"reason": "superseded"},
                          headers=h).status_code == 200


# ------------------------------------------------------------------ configuration
def test_issuer_config_is_checked_at_startup(tmp_path):
    from certadillo.ca.issuers import build

    with pytest.raises(ValueError):
        build("x", {"type": "acme", "directory": "http://plain"})
    with pytest.raises(ValueError):
        build("x", {"type": "digicert", "product": "ssl_basic", "organization_id": 1, "api_key_ref": "the-key"})
    with pytest.raises(ValueError):
        build("x", {"type": "nope"})


def test_a_folder_can_only_route_to_a_configured_issuer(client):
    r = client.post("/api/v1/folders", json={"name": "X", "settings": {"issuer": {"value": "made-up"}}},
                    headers=ADMIN)
    assert r.status_code == 400 and "not a configured upstream issuer" in r.text
    assert get_backend("made-up") is None


def test_issuer_inventory_shows_routing_and_never_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("CERTADILLO_TEST_DC_KEY", "dc-api-key-should-not-leak")
    issuers = {
        "digicert": {"type": "digicert", "product": "ssl_basic", "organization_id": 1234,
                     "api_key_ref": "env:CERTADILLO_TEST_DC_KEY"},
        "public-acme": {"type": "acme", "directory": "https://acme.example/directory", "contact": "mailto:pki@x",
                        "dns": {"provider": "rfc2136", "server": "10.1.0.53", "zone": "bank.example.",
                                "tsig_name": "certadillo-acme.", "tsig_secret_ref": "vault:secret/data/dns#tsig"}},
    }
    s = make_settings(tmp_path, policy_file=_policy_file(tmp_path, issuers), dual_control_actions=[])
    with TestClient(create_app(s, background=False)) as c:
        _route_to(c, "public-acme")
        r = c.get("/api/v1/issuers", headers=ADMIN)
        assert r.status_code == 200, r.text
        by = {i["name"]: i for i in r.json()}
        assert set(by) == {"local", "adcs", "digicert", "public-acme"}
        assert by["local"]["config"]["default_issuing_ca"] == "issuing-ca-1" and "tls-server" in by["local"]["profiles"]
        assert by["adcs"]["profiles"] == ["adcs-user"]
        assert by["public-acme"]["folders"] == ["\\via-public-acme"]
        assert by["public-acme"]["config"]["dns"] == {"provider": "rfc2136", "server": "10.1.0.53",
                                                      "zone": "bank.example.", "tsig_name": "certadillo-acme."}
        assert by["public-acme"]["credentials"] == {"dns.tsig_secret_ref": "vault reference"}
        assert by["digicert"]["credentials"] == {"api_key_ref": "env reference"}
        body = r.text
        assert "dc-api-key" not in body and "CERTADILLO_TEST_DC_KEY" not in body and "secret/data/dns" not in body
        # roles: apps and agents cannot read it
        _, h = onboard(c, "issuer-viewer", domains=("*.iv.bank.internal",))
        assert c.get("/api/v1/issuers", headers=h).status_code == 403
