"""AD CS gateway: RA-side policy with async issuance through a domain-joined
worker, dedupe, revocation forwarding, inventory ingest and authorization."""
from __future__ import annotations

import pytest

from adcs_fake_gateway import FakeMicrosoftCA, run_once
from conftest import ADMIN, make_csr
from cryptography import x509


def onboard_adcs(client, name="corp-users", domains=("*.corp.bank.internal",)):
    r = client.post("/api/v1/teams", json={"name": f"t-{name}", "contact_email": "t@e.com"}, headers=ADMIN)
    team = r.json()["id"]
    r = client.post("/api/v1/apps", json={"team_id": team, "name": name, "environment": "dev",
                                          "profile": "adcs-user", "allowed_domains": list(domains)}, headers=ADMIN)
    app = r.json()
    key = client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]
    return app["id"], {"X-API-Key": key}


def gateway_headers(client):
    raw = client.post("/api/v1/principals", json={"name": "gw-1", "role": "gateway"}, headers=ADMIN).json()["api_key"]
    return {"X-API-Key": raw}


def test_issue_through_gateway(client):
    app_id, hdr = onboard_adcs(client)
    _, csr = make_csr("bob.corp.bank.internal", dns=["bob.corp.bank.internal"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "gateway_queued"
    job_id = body["job_id"]

    # requester sees it pending
    poll = client.get(f"/api/v1/adcs/gateway/jobs/{job_id}", headers=hdr).json()
    assert poll["status"] == "pending"

    # the gateway worker runs
    gw = gateway_headers(client)
    ca = FakeMicrosoftCA()
    done = run_once(client, gw, ca)
    assert done[0]["status"] == "done"

    # requester now gets the certificate
    poll = client.get(f"/api/v1/adcs/gateway/jobs/{job_id}", headers=hdr).json()
    assert poll["status"] == "done"
    cert = x509.load_pem_x509_certificate(poll["certificate"]["pem"].encode())
    assert cert.issuer.rfc4514_string() == "CN=Corp Issuing CA"
    assert poll["certificate"]["backend"] == "adcs"
    assert poll["certificate"]["location"].startswith("adcs:")
    assert poll["certificate"]["app_id"] == app_id


def test_duplicate_csr_is_deduped(client):
    _, hdr = onboard_adcs(client)
    _, csr = make_csr("dup.corp.bank.internal", dns=["dup.corp.bank.internal"])
    j1 = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr).json()["job_id"]
    j2 = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr).json()["job_id"]
    assert j1 == j2


def test_revoke_forwards_to_gateway(client):
    _, hdr = onboard_adcs(client)
    _, csr = make_csr("rev.corp.bank.internal", dns=["rev.corp.bank.internal"])
    job_id = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr).json()["job_id"]
    gw = gateway_headers(client)
    ca = FakeMicrosoftCA()
    run_once(client, gw, ca)
    cert_id = client.get(f"/api/v1/adcs/gateway/jobs/{job_id}", headers=hdr).json()["certificate"]["id"]

    r = client.post(f"/api/v1/certificates/{cert_id}/revoke", json={"reason": "superseded"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    # a revoke job is now queued for the gateway
    jobs = client.get("/api/v1/adcs/gateway/jobs?status=pending", headers=gw).json()
    assert any(j["type"] == "revoke" and j["serial"] for j in jobs)
    done = run_once(client, gw, ca)
    assert all(d["status"] == "done" for d in done)


def test_inventory_ingest_maps_template_to_app(client):
    app_id, hdr = onboard_adcs(client)
    gw = gateway_headers(client)
    r = client.post("/api/v1/adcs/inventory", json={"ca": "CA01\\Corp Issuing CA"}, headers=ADMIN)
    assert r.status_code == 202
    # gateway completes the inventory job with one certificate on the CertadilloUser template
    ca = FakeMicrosoftCA()
    _, csr = make_csr("inv.corp.bank.internal", dns=["inv.corp.bank.internal"])
    pem, _ = ca.issue(csr)
    claimed = client.post("/api/v1/adcs/gateway/jobs/claim", headers=gw).json()["jobs"]
    inv = [j for j in claimed if j["type"] == "inventory"][0]
    client.post(f"/api/v1/adcs/gateway/jobs/{inv['id']}/complete",
                json={"certificates": [{"certificate_pem": pem, "template": "CertadilloUser"}]}, headers=gw)
    # the certificate is now in inventory, owned by the app the template maps to
    certs = client.get("/api/v1/certificates?source=imported", headers=ADMIN).json()
    assert any(c["app_id"] == app_id and (c["location"] or "").startswith("adcs:") for c in certs)


def test_app_cannot_claim_jobs(client):
    _, hdr = onboard_adcs(client)
    r = client.post("/api/v1/adcs/gateway/jobs/claim", headers=hdr)
    assert r.status_code == 403


def test_stuck_job_alerts(client, monkeypatch):
    _, hdr = onboard_adcs(client)
    _, csr = make_csr("stuck.corp.bank.internal", dns=["stuck.corp.bank.internal"])
    client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    # age the job past the 1h threshold
    from datetime import datetime, timedelta, timezone
    from certadillo.runtime import get_runtime
    from certadillo.db import AdcsJob

    with get_runtime().platform() as p:
        job = p.s.query(AdcsJob).first()
        job.created_at = datetime.now(timezone.utc) - timedelta(hours=3)
        p.commit()
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    rules = {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert "AdcsGatewayJobStuck" in rules


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
