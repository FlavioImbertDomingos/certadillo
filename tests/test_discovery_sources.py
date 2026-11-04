"""Wider discovery: the host agent, cloud certificate stores, and Certificate
Transparency monitoring."""
from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.discovery import sources as disc
from conftest import ADMIN, issue, make_settings, onboard


def _cert(cn: str, days: int = 90, serial: int | None = None, poison: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(serial or x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
         .not_valid_after(now + timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False))
    if poison:
        b = b.add_extension(x509.UnrecognizedExtension(disc.POISON, b"\x05\x00"), critical=True)
    return key, b.sign(key, hashes.SHA256())


def _pem(c) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def _agent_key(client) -> dict:
    r = client.post("/api/v1/principals", json={"name": "agent-web1", "role": "agent"}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return {"X-API-Key": r.json()["api_key"]}


# ------------------------------------------------------------------ host agent
@pytest.fixture
def host_tree(tmp_path):
    root = tmp_path / "etc"
    (root / "nginx" / "tls").mkdir(parents=True)
    key, cert = _cert("www.pay.bank.internal")
    (root / "nginx" / "tls" / "www.crt").write_text(_pem(cert))
    leaky = root / "nginx" / "tls" / "www.key"
    leaky.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    os.chmod(leaky, 0o644)
    _, der = _cert("api.pay.bank.internal")
    (root / "api.der").write_bytes(der.public_bytes(serialization.Encoding.DER))
    k3, c3 = _cert("batch.pay.bank.internal")
    (root / "batch.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"batch", k3, c3, None, serialization.BestAvailableEncryption(b"s3cret")))
    os.chmod(root / "batch.p12", 0o600)
    return root


def test_agent_finds_pem_der_and_pkcs12_and_never_sends_keys(host_tree, tmp_path):
    from certadillo.discovery.agent import scan

    pw = tmp_path / "pw"
    pw.write_text("wrong\ns3cret\n")
    found = scan([str(host_tree)], ["wrong", "s3cret"])
    formats = sorted({c["format"] for c in found["certificates"]})
    assert formats == ["der", "pem", "pkcs12"]
    assert all("PRIVATE KEY" not in c["pem"] for c in found["certificates"])
    keys = {Path(k["path"]).name: k for k in found["key_files"]}
    assert keys["www.key"]["world_readable"] is True and keys["batch.p12"]["world_readable"] is False

    r = CliRunner().invoke(__import__("certadillo.cli", fromlist=["main"]).main,
                           ["agent", "scan", "--dry-run", "--path", str(host_tree), "--password-file", str(pw)])
    assert r.exit_code == 0, r.output
    assert "PRIVATE KEY" not in r.output and "www.key" in r.output


def test_agent_report_fills_inventory_and_flags_readable_keys(client, host_tree):
    from certadillo.api.app import run_housekeeping
    from certadillo.discovery.agent import scan

    agent = _agent_key(client)
    found = scan([str(host_tree)], ["s3cret"])
    body = {"host": "web1.bank.internal", "certificates": found["certificates"], "key_files": found["key_files"]}
    r = client.post("/api/v1/discovery/agent-report", json=body, headers=agent)
    assert r.status_code == 200 and r.json() == {"certificates": 3, "new": 3, "keys_exposed": 1}
    inv = client.get("/api/v1/certificates?source=agent", headers=ADMIN).json()
    assert {c["location"].split(":", 1)[0] for c in inv} == {"web1.bank.internal"}
    run_housekeeping()
    alerts = {a["rule"]: a for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert alerts["PrivateKeyExposed"]["severity"] == "critical"

    # the key is fixed on the host; the next report closes the finding
    os.chmod(host_tree / "nginx" / "tls" / "www.key", 0o600)
    found = scan([str(host_tree)], ["s3cret"])
    body["key_files"] = found["key_files"]
    assert client.post("/api/v1/discovery/agent-report", json=body, headers=agent).json()["keys_exposed"] == 0
    assert client.get("/api/v1/discovery/findings?kind=key_readable", headers=ADMIN).json() == []
    # an agent key can report and nothing else
    for path in ("/api/v1/teams", "/api/v1/certificates", "/api/v1/approvals", "/api/v1/apps",
                 f"/api/v1/certificates/{inv[0]['id']}", "/api/v1/targets", "/api/v1/discovery/findings"):
        assert client.get(path, headers=agent).status_code == 403, path


# ------------------------------------------------------------------ cloud sources and CT
def _with_sources(tmp_path, sources: dict):
    from importlib import resources

    pol = yaml.safe_load(resources.files("certadillo").joinpath("default_policies.yaml").read_text())
    pol["discovery"] = {"sources": sources}
    (tmp_path / "policies.yaml").write_text(yaml.safe_dump(pol))
    return make_settings(tmp_path, policy_file=str(tmp_path / "policies.yaml"))


def test_aws_acm_source_across_regions(tmp_path, monkeypatch):
    moto = pytest.importorskip("moto")
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        import boto3

        for region, cn in (("us-east-1", "edge.bank.example"), ("us-west-2", "dr.bank.example")):
            key, cert = _cert(cn)
            boto3.client("acm", region_name=region).import_certificate(
                Certificate=_pem(cert).encode(),
                PrivateKey=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        s = _with_sources(tmp_path, {"acm": {"type": "aws-acm", "regions": ["us-east-1", "us-west-2"]}})
        with TestClient(create_app(s, background=False)) as c:
            r = c.post("/api/v1/discovery/sources/acm/run", headers=ADMIN)
            assert r.status_code == 200 and r.json()["found"] == 2 and r.json()["new"] == 2
            inv = c.get("/api/v1/certificates?source=cloud", headers=ADMIN).json()
            assert sorted(x["common_name"] for x in inv) == ["dr.bank.example", "edge.bank.example"]
            assert all(x["location"].startswith("acm:arn:aws:acm:") for x in inv)
            again = c.post("/api/v1/discovery/sources/acm/run", headers=ADMIN).json()
            assert again["found"] == 2 and again["new"] == 0  # de-duplicated by fingerprint


def test_azure_key_vault_and_gcp_sources(tmp_path, monkeypatch):
    _, a1 = _cert("kv1.bank.example")
    _, a2 = _cert("kv2.bank.example")
    _, g1 = _cert("lb.bank.example")

    def azure(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer az-token"
        path = request.url.path
        if path == "/certificates" and "skiptoken" not in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "https://kv.vault.azure.net/certificates/one"}],
                                             "nextLink": "https://kv.vault.azure.net/certificates?api-version=7.4&skiptoken=x"})
        if path == "/certificates":
            return httpx.Response(200, json={"value": [{"id": "https://kv.vault.azure.net/certificates/two"}]})
        cert = a1 if path.endswith("/one") else a2
        return httpx.Response(200, json={"cer": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()})

    def gcp(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/projects/bank-edge/locations/global/certificates"
        return httpx.Response(200, json={"certificates": [{"name": "projects/bank-edge/locations/global/certificates/lb",
                                                           "pemCertificate": _pem(g1)}]})

    monkeypatch.setitem(disc.test_transports, "azure-keyvault", httpx.MockTransport(azure))
    monkeypatch.setitem(disc.test_transports, "gcp-certmanager", httpx.MockTransport(gcp))
    monkeypatch.setenv("CERTADILLO_TEST_AZ", "az-token")
    monkeypatch.setenv("CERTADILLO_TEST_GCP", "gcp-token")
    s = _with_sources(tmp_path, {
        "kv": {"type": "azure-keyvault", "vault_url": "https://kv.vault.azure.net", "token_ref": "env:CERTADILLO_TEST_AZ"},
        "gcp": {"type": "gcp-certmanager", "project": "bank-edge", "token_ref": "env:CERTADILLO_TEST_GCP"}})
    with TestClient(create_app(s, background=False)) as c:
        assert c.post("/api/v1/discovery/sources/kv/run", headers=ADMIN).json()["found"] == 2  # both pages
        assert c.post("/api/v1/discovery/sources/gcp/run", headers=ADMIN).json()["found"] == 1
        names = sorted(x["common_name"] for x in c.get("/api/v1/certificates?source=cloud", headers=ADMIN).json())
        assert names == ["kv1.bank.example", "kv2.bank.example", "lb.bank.example"]


def test_ct_monitoring_flags_public_certificates_nobody_requested(tmp_path, monkeypatch):
    s = _with_sources(tmp_path, {"ct": {"type": "ct", "zones": ["bank.example"], "provider": "certspotter",
                                        "token_ref": "env:CERTADILLO_TEST_CS"}})
    monkeypatch.setenv("CERTADILLO_TEST_CS", "cs-token")
    with TestClient(create_app(s, background=False)) as c:
        _, h = onboard(c, "edge", domains=["*.pay.bank.internal"])
        _, ours = issue(c, h)  # issued here: CT seeing it is expected
        ours_cert = x509.load_pem_x509_certificate(ours["pem"].encode())
        _, rogue = _cert("login.bank.example")
        _, rogue_pre = _cert("vpn.bank.example", poison=True)
        _, old = _cert("old.bank.example", days=-1)
        now = datetime.now(timezone.utc)

        def entry(i, cert, names, days=60):
            return {"id": str(i), "dns_names": names, "issuer": {"friendly_name": "Some Public CA"},
                    "not_after": (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"),
                    "cert": {"data": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()}}

        feed = [entry(1, ours_cert, ["api.pay.bank.internal"]), entry(2, rogue, ["login.bank.example"]),
                entry(3, rogue_pre, ["vpn.bank.example"]), entry(4, old, ["old.bank.example"], days=-2)]

        def certspotter(request: httpx.Request) -> httpx.Response:
            assert request.headers["authorization"] == "Bearer cs-token"
            assert request.url.params["domain"] == "bank.example"
            return httpx.Response(200, json=feed)

        monkeypatch.setitem(disc.test_transports, "ct", httpx.MockTransport(certspotter))
        r = c.post("/api/v1/discovery/sources/ct/run", headers=ADMIN).json()
        assert r["status"] == "ok" and r["found"] == 3 and r["new"] == 2
        findings = c.get("/api/v1/discovery/findings?kind=unknown_public_cert", headers=ADMIN).json()
        assert sorted(f["detail"]["dns_names"][0] for f in findings) == ["login.bank.example", "vpn.bank.example"]
        ct_inv = [x["common_name"] for x in c.get("/api/v1/certificates?source=ct", headers=ADMIN).json()]
        assert ct_inv == ["login.bank.example"]  # the precertificate is a finding, not inventory

        from certadillo.api.app import run_housekeeping

        run_housekeeping()
        rules = [a["rule"] for a in c.get("/api/v1/alerts", headers=ADMIN).json()]
        assert rules.count("UnknownPublicCertificate") == 2
        fid = findings[0]["id"]
        assert c.post(f"/api/v1/discovery/findings/{fid}/acknowledge", json={"comment": "marketing site, CHG-1"},
                      headers=ADMIN).status_code == 200
        assert len(c.get("/api/v1/discovery/findings?kind=unknown_public_cert", headers=ADMIN).json()) == 1


def test_sources_run_on_their_schedule_and_failures_alert(tmp_path, monkeypatch):
    monkeypatch.setitem(disc.test_transports, "gcp-certmanager",
                        httpx.MockTransport(lambda r: httpx.Response(403, json={})))
    monkeypatch.setenv("CERTADILLO_TEST_GCP", "t")
    s = _with_sources(tmp_path, {"gcp": {"type": "gcp-certmanager", "project": "p", "interval_hours": 6,
                                         "token_ref": "env:CERTADILLO_TEST_GCP"}})
    with TestClient(create_app(s, background=False)) as c:
        from certadillo.api.app import run_housekeeping
        from certadillo.runtime import get_runtime

        run_housekeeping()
        rt = get_runtime()
        with rt.platform() as p:
            assert disc.run_due(p, rt.discovery_sources) == []  # ran a moment ago; next one in 6h
            later = datetime.now(timezone.utc) + timedelta(hours=7)
            assert [x["source"] for x in disc.run_due(p, rt.discovery_sources, later)] == ["gcp"]
        status = c.get("/api/v1/discovery/sources", headers=ADMIN).json()[0]
        assert status["last_run"]["status"] == "failed" and "403" in status["last_run"]["error"]
        run_housekeeping()
        assert "DiscoverySourceFailing" in [a["rule"] for a in c.get("/api/v1/alerts", headers=ADMIN).json()]


def test_source_config_is_checked(tmp_path):
    with pytest.raises(ValueError):
        disc.build("x", {"type": "ct"})
    with pytest.raises(ValueError):
        disc.build("x", {"type": "azure-keyvault", "vault_url": "http://plain", "token_ref": "env:X"})
    with pytest.raises(ValueError):
        disc.build("x", {"type": "gcp-certmanager", "project": "p", "token_ref": "literal-token"})


def test_service_roles_read_only_what_they_need(client):
    """Agent and gateway keys sit on servers; if one leaks it must not expose the
    inventory, approvals or configuration. Sweep every GET endpoint."""
    import re

    from certadillo.api.app import create_app as _  # noqa: F401 - routes come from the running app

    allowed = {"agent": {"/api/v1/me", "/api/v1/profiles", "/api/v1/ssh/ca", "/api/v1/folders/settings",
                         "/api/v1/provisioning/kinds"},
               "gateway": {"/api/v1/me", "/api/v1/profiles", "/api/v1/ssh/ca", "/api/v1/folders/settings",
                           "/api/v1/provisioning/kinds", "/api/v1/adcs/gateway/jobs"}}
    for role, ok in allowed.items():
        key = client.post("/api/v1/principals", json={"name": f"svc-{role}", "role": role}, headers=ADMIN).json()["api_key"]
        readable = set()
        for route in client.app.routes:
            path = getattr(route, "path", "")
            if path.startswith("/api/v1") and "GET" in getattr(route, "methods", set()):
                if client.get(re.sub(r"\{[^}]+\}", "1", path), headers={"X-API-Key": key}).status_code == 200:
                    readable.add(path)
        assert readable <= ok, (role, sorted(readable - ok))
