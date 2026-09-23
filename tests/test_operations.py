"""Discovery, alerting, notifications, metrics, audit integrity, reports."""
from __future__ import annotations

import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from certadillo.alerting import evaluator
from certadillo.alerting.notifiers import JiraNotifier, ServiceNowNotifier, SlackNotifier, WebhookNotifier, Alert
from certadillo.db import AuditEvent, get_session
from certadillo.discovery.connectors import KubernetesTLSSecrets, VaultPKIInventory
from conftest import ADMIN, issue, onboard


def self_signed(cn: str, days_valid: int, days_ago: int = 1, key=None, hash_alg=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=days_ago)).not_valid_after(now - timedelta(days=days_ago) + timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
            .sign(key, hash_alg or hashes.SHA256()))
    return key, cert


def tls_server(key, cert):
    """One-shot local TLS listener serving `cert`."""
    import tempfile

    d = tempfile.mkdtemp()
    kp, cp = f"{d}/k.pem", f"{d}/c.pem"
    from pathlib import Path

    Path(kp).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    Path(cp).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]

    def serve():
        for _ in range(3):
            try:
                conn, _ = sock.accept()
                with ctx.wrap_socket(conn, server_side=True) as t:
                    t.recv(1)
            except Exception:
                pass

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_discovery_scan_finds_unmanaged_expiring_cert(client):
    key, cert = self_signed("legacy.bank.internal", days_valid=90, days_ago=85)
    port = tls_server(key, cert)
    r = client.post("/api/v1/discovery/scan", json={"targets": [f"127.0.0.1:{port}", "127.0.0.1:1"], "timeout": 2},
                    headers=ADMIN)
    assert r.status_code == 200, r.text
    found, failed = r.json()
    assert found["new"] and found["common_name"] == "legacy.bank.internal"
    assert "error" in failed
    rows = client.get("/api/v1/certificates?source=discovered", headers=ADMIN).json()
    assert rows[0]["location"] == f"127.0.0.1:{port}"

    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    rules = {(a["rule"], a["severity"]) for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert ("CertificateExpiringSoon", "critical") in rules  # 5 days left of 90 -> inside the 7d critical window
    assert ("UnmanagedCertificate", "info") in rules


def test_import_expired_and_weak(client):
    _, expired = self_signed("old.bank.internal", days_valid=30, days_ago=40)
    _, weak = self_signed("weak.bank.internal", days_valid=365, key=rsa.generate_private_key(65537, 1024))
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in (expired, weak))
    r = client.post("/api/v1/inventory/import", json={"pem": pem, "location": "f5-prod-01"}, headers=ADMIN)
    assert [x["new"] for x in r.json()] == [True, True]
    assert "weak_key" in r.json()[1]["findings"]
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    rules = {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert {"CertificateExpired", "WeakCryptography"} <= rules


def test_alert_lifecycle_and_routing(client, monkeypatch):
    """New alert -> notify once -> no repeat -> resolve -> resolved notice; team webhook gets its own copy."""
    sent: list[dict] = []
    transport = httpx.MockTransport(lambda req: (sent.append({"url": str(req.url), **json.loads(req.content)}),
                                                 httpx.Response(200))[1])
    monkeypatch.setattr(evaluator, "_team_notifier", lambda url: WebhookNotifier(url, httpx.Client(transport=transport)))
    team = client.post("/api/v1/teams", json={"name": "cards", "contact_email": "c@x", "webhook_url": "https://hooks.example/cards"},
                       headers=ADMIN).json()
    app_id, h = onboard(client, "cards-api", team=team["id"])
    # short validity so it is inside the critical window right away
    _, cert = issue(client, h)
    from certadillo.runtime import get_runtime

    rt = get_runtime()
    with rt.platform() as p:
        from certadillo.db import Certificate

        row = p.s.get(Certificate, cert["id"])
        row.not_before = datetime.now(timezone.utc) - timedelta(days=29)
        row.not_after = datetime.now(timezone.utc) + timedelta(hours=12)
    for _ in range(2):
        client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    team_msgs = [m for m in sent if m["url"].endswith("/cards")]
    assert len(team_msgs) == 1
    assert team_msgs[0]["alerts"][0]["labels"]["alertname"] == "CertificateExpiringSoon"
    assert team_msgs[0]["alerts"][0]["labels"]["team"] == "cards"
    client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "superseded"}, headers=h)
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    assert sent[-1]["alerts"][0]["status"] == "resolved"


def test_ticketing_notifiers():
    calls = []

    def handler(req):
        calls.append((req.url.path, json.loads(req.content)))
        return httpx.Response(201, json={})

    c = httpx.Client(transport=httpx.MockTransport(handler))
    a = Alert("fp1", "CertificateExpired", "critical", "api.bank.internal expired", {"team": "cards"}, runbook="rb")
    JiraNotifier("https://jira.example", "bot", "tok", "PKI", client=c).send([a])
    ServiceNowNotifier("https://bank.service-now.com", "u", "p", "PKI Ops", client=c).send([a])
    SlackNotifier("https://hooks.slack.com/x", client=c).send([a])
    warning = Alert("fp2", "CertificateExpiringSoon", "warning", "soon", {})
    JiraNotifier("https://jira.example", "bot", "tok", "PKI", client=c).send([warning])  # warnings do not open tickets
    paths = [p for p, _ in calls]
    assert paths == ["/rest/api/2/issue", "/api/now/table/incident", "/x"]
    assert calls[0][1]["fields"]["project"]["key"] == "PKI"
    assert calls[1][1]["correlation_id"] == "fp1"


def test_audit_chain_detects_tampering(client):
    onboard(client)
    assert client.get("/api/v1/audit/verify", headers=ADMIN).json()["valid"]
    with get_session() as s:
        ev = s.query(AuditEvent).order_by(AuditEvent.id).offset(2).first()
        ev.details = {**ev.details, "tampered": True}
        s.commit()
    res = client.get("/api/v1/audit/verify", headers=ADMIN).json()
    assert res == {"valid": False, "events": 3, "broken_at": 3}
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    assert "AuditChainBroken" in {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert "certadillo_audit_chain_valid 0.0" in client.get("/metrics").text


def test_metrics_exposition(client):
    _, h = onboard(client)
    issue(client, h)
    text = client.get("/metrics").text
    for name in ("certadillo_certificate_expiry_timestamp_seconds{", "certadillo_certificate_lifetime_seconds{",
                 "certadillo_issuance_total{", "certadillo_ca_expiry_timestamp_seconds{",
                 "certadillo_signing_duration_seconds_bucket", "certadillo_http_request_duration_seconds_bucket",
                 "certadillo_certificates_quantum_vulnerable{"):
        assert name in text, name
    assert 'app="card-api"' in text


def test_reports(client):
    _, h = onboard(client)
    issue(client, h)
    cbom = client.get("/api/v1/reports/cbom", headers=ADMIN).json()
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    types = {c["cryptoProperties"]["assetType"] for c in cbom["components"]}
    assert types == {"certificate", "algorithm", "related-crypto-material"}
    crypto = client.get("/api/v1/reports/crypto", headers=ADMIN).json()
    assert crypto["quantum_vulnerable"] == 1
    assert any(r["outlives_2035_cutoff"] for r in crypto["certificate_authorities"])
    csv_text = client.get("/api/v1/reports/pci-inventory?format=csv", headers=ADMIN).text
    assert csv_text.splitlines()[0].startswith("common_name,sans,serial")
    s = client.get("/api/v1/reports/summary", headers=ADMIN).json()
    assert s["certificates"]["active"] == 1 and s["automation_coverage"] == 1.0


def test_inventory_connectors():
    _, cert = self_signed("vault-issued.bank.internal", 30)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    def vault(req):
        if req.method == "LIST":
            return httpx.Response(200, json={"data": {"keys": ["aa-bb"]}})
        return httpx.Response(200, json={"data": {"certificate": pem}})

    got = list(VaultPKIInventory("https://vault", "t", client=httpx.Client(transport=httpx.MockTransport(vault))).collect())
    assert got[0][1] == "vault:pki/aa-bb"

    import base64

    def k8s(req):
        assert req.url.params["fieldSelector"] == "type=kubernetes.io/tls"
        return httpx.Response(200, json={"items": [{"metadata": {"namespace": "payments", "name": "card-api-tls"},
                                                    "data": {"tls.crt": base64.b64encode(pem.encode()).decode()}}]})

    got = list(KubernetesTLSSecrets("https://k8s", "t", client=httpx.Client(transport=httpx.MockTransport(k8s))).collect())
    assert got[0][1] == "k8s:payments/card-api-tls"


def test_rescan_retires_replaced_endpoint_cert(client):
    key, old = self_signed("rotating.bank.internal", days_valid=30, days_ago=35)  # expired
    port = tls_server(key, old)
    client.post("/api/v1/discovery/scan", json={"targets": [f"127.0.0.1:{port}"]}, headers=ADMIN)
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    assert "CertificateExpired" in {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    # the endpoint now serves a fresh certificate on the same host:port label
    key2, new = self_signed("rotating.bank.internal", days_valid=90)
    port2 = tls_server(key2, new)
    from certadillo.runtime import get_runtime
    from certadillo.db import Certificate

    with get_runtime().platform() as p:  # simulate same endpoint: relabel the old row's location
        p.s.query(Certificate).filter_by(source="discovered").update({"location": f"127.0.0.1:{port2}"})
    client.post("/api/v1/discovery/scan", json={"targets": [f"127.0.0.1:{port2}"]}, headers=ADMIN)
    rows = {r["status"] for r in client.get("/api/v1/certificates?source=discovered", headers=ADMIN).json()}
    assert rows == {"active", "superseded"}
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    assert "CertificateExpired" not in {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
