"""Crypto-agility drill: freeze a set of certificates, move them to a new
issuing CA through an ARI campaign, and measure time to 50/90/99/100%."""
from __future__ import annotations

from certadillo.ca import agility
from certadillo.cli import _drill_summary
from certadillo.runtime import get_runtime
from conftest import ADMIN, APPROVER, issue, make_csr, onboard


def _new_ca(client, name, alg="ml-dsa-65"):
    r = client.post("/api/v1/cas", json={"name": name, "alg": alg}, headers=ADMIN)
    assert r.status_code == 202, r.text
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200


def _renew(client, h, cert_id, cn):
    _, csr = make_csr(cn, dns=[cn])
    r = client.post(f"/api/v1/certificates/{cert_id}/renew", json={"csr_pem": csr}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def _pinned_app(client, name, ca, domains):
    r = client.post("/api/v1/folders", headers=ADMIN, json={
        "name": f"Pinned{name}", "settings": {"issuing_ca": {"value": ca, "locked": False}}})
    assert r.status_code == 202, r.text
    folder = client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve",
                         headers=APPROVER).json()["payload"]["folder_id"]
    team = client.post("/api/v1/teams", json={"name": f"team-{name}", "contact_email": "t@example.com"},
                       headers=ADMIN).json()["id"]
    app = client.post("/api/v1/apps", headers=ADMIN, json={
        "team_id": team, "name": name, "environment": "dev", "profile": "tls-server",
        "allowed_domains": domains, "folder_id": folder}).json()
    if app["status"] == "pending_approval":
        client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER)
    return {"X-API-Key": client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]}


def test_drill_moves_the_estate_and_names_what_blocks_it(client):
    _, ha = onboard(client, "card-api", domains=("*.pay.bank.internal",))
    certs = [issue(client, ha, cn=f"api{i}.pay.bank.internal")[1] for i in range(3)]
    hb = _pinned_app(client, "legacy-api", "issuing-ca-1", ["*.legacy.bank.internal"])
    legacy = issue(client, hb, cn="old.legacy.bank.internal")[1]

    _new_ca(client, "issuing-pq")  # newest issuing CA: the default for new certificates
    r = client.post("/api/v1/agility-drills", headers=ADMIN, json={
        "name": "pq move", "target_ca": "issuing-pq", "renew_within_hours": 48})
    assert r.status_code == 201, r.text
    st = r.json()
    assert st["counts"] == {"total": 4, "moved": 0, "elsewhere": 0, "remaining": 4, "gone": 0}
    assert st["source_cas"] == ["issuing-ca-1"] and st["progress"] == 0.0 and not st["complete"]
    # the pinned folder keeps legacy-api on the old CA: renewing alone will not move it
    [blocked] = st["blocked"]
    assert (blocked["app"], blocked["next_ca"], blocked["certificates"]) == ("legacy-api", "issuing-ca-1", 1)
    assert blocked["set_by"].startswith("folder ")

    # clients see the campaign through ARI and renew early
    info = client.get(f"/api/v1/certificates/{certs[0]['id']}/renewal-info", headers=ha).json()
    assert info["renew_now"] is True

    for c, i in zip(certs[:2], range(2)):
        _renew(client, ha, c["id"], f"api{i}.pay.bank.internal")
    st = client.get(f"/api/v1/agility-drills/{st['id']}", headers=ADMIN).json()
    assert st["counts"]["moved"] == 2 and st["progress"] == 0.5
    assert st["time_to_seconds"]["50%"] is not None and st["time_to_seconds"]["100%"] is None

    _renew(client, ha, certs[2]["id"], "api2.pay.bank.internal")
    _renew(client, hb, legacy["id"], "old.legacy.bank.internal")  # renewed, but from the pinned old CA
    st = client.get(f"/api/v1/agility-drills/{st['id']}", headers=ADMIN).json()
    assert st["counts"] == {"total": 4, "moved": 3, "elsewhere": 1, "remaining": 0, "gone": 0}
    assert st["progress"] == 0.75 and st["time_to_seconds"]["90%"] is None
    first = st["certificates"][0]
    assert first["state"] == "elsewhere" and first["replaced_by_ca"] == "issuing-ca-1"
    assert st["remaining_by_team"] == {"team-legacy-api": 1}
    assert "blocked: legacy-api would renew from issuing-ca-1" in _drill_summary(st)


def test_drill_reaches_100_percent_stops_the_clock_and_closes(client):
    _, h = onboard(client)
    certs = [issue(client, h, cn=f"svc{i}.pay.bank.internal")[1] for i in range(2)]
    _new_ca(client, "issuing-ca-2", alg="ec-p384")  # a drill does not have to change algorithm
    drill = client.post("/api/v1/agility-drills", headers=ADMIN, json={
        "name": "rotate", "target_ca": "issuing-ca-2", "source_cas": ["issuing-ca-1"]}).json()
    renewed = _renew(client, h, certs[0]["id"], "svc0.pay.bank.internal")
    _renew(client, h, renewed["id"], "svc0.pay.bank.internal")  # renewed twice: counts by its latest successor
    _renew(client, h, certs[1]["id"], "svc1.pay.bank.internal")
    st = client.get(f"/api/v1/agility-drills/{drill['id']}", headers=ADMIN).json()
    assert st["complete"] and st["progress"] == 1.0 and st["counts"]["moved"] == 2
    t = st["time_to_seconds"]
    assert t["50%"] <= t["90%"] <= t["99%"] <= t["100%"] == st["elapsed_seconds"]

    metrics = client.get("/metrics").text
    assert 'certadillo_agility_drill_progress_ratio{drill="rotate",target_ca="issuing-ca-2"} 1.0' in metrics

    closed = client.post(f"/api/v1/agility-drills/{drill['id']}/close", headers=ADMIN).json()
    assert closed["status"] == "closed" and closed["result"]["complete"] is True
    camp = client.get(f"/api/v1/renewal-campaigns/{drill['campaign_id']}", headers=ADMIN).json()
    assert camp["status"] == "closed"
    again = client.post(f"/api/v1/agility-drills/{drill['id']}/close", headers=ADMIN)
    assert again.status_code == 400
    assert client.get("/api/v1/agility-drills", headers=ADMIN).json()[0]["status"] == "closed"


def test_revoked_certificates_leave_the_denominator(client):
    _, h = onboard(client)
    a = issue(client, h, cn="a.pay.bank.internal")[1]
    b = issue(client, h, cn="b.pay.bank.internal")[1]
    _new_ca(client, "issuing-ca-2", alg="ec-p256")
    drill = client.post("/api/v1/agility-drills", headers=ADMIN,
                        json={"name": "gone", "target_ca": "issuing-ca-2"}).json()
    client.post(f"/api/v1/certificates/{a['id']}/revoke", json={"reason": "cessation_of_operation"}, headers=h)
    _renew(client, h, b["id"], "b.pay.bank.internal")
    st = client.get(f"/api/v1/agility-drills/{drill['id']}", headers=ADMIN).json()
    assert st["counts"]["gone"] == 1 and st["complete"] and st["progress"] == 1.0


def test_drill_refuses_bad_targets_and_empty_sets(client):
    r = client.post("/api/v1/agility-drills", headers=ADMIN, json={"name": "bad", "target_ca": "root-ca"})
    assert r.status_code == 400 and "not an issuing CA" in r.text
    r = client.post("/api/v1/agility-drills", headers=ADMIN, json={
        "name": "self", "target_ca": "issuing-ca-1", "source_cas": ["issuing-ca-1"]})
    assert r.status_code == 400 and "cannot also be a source" in r.text
    _new_ca(client, "issuing-ca-2", alg="ec-p256")
    r = client.post("/api/v1/agility-drills", headers=ADMIN, json={"name": "empty", "target_ca": "issuing-ca-2"})
    assert r.status_code == 400 and "nothing to move" in r.text
    _, h = onboard(client)
    r = client.post("/api/v1/agility-drills", headers=h, json={"name": "app", "target_ca": "issuing-ca-2"})
    assert r.status_code == 403


def test_next_ca_follows_the_issuance_routing(client):
    _new_ca(client, "issuing-ca-2", alg="ec-p256")
    with get_runtime().platform() as p:
        assert agility.next_ca(p, None, "tls-server") == {
            "kind": "local", "name": "issuing-ca-2", "set_by": "default (newest issuing CA)"}
