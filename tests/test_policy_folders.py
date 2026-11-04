"""The policy tree: inherited and locked folder settings, applied at onboarding
and at every issuance, changed only through a second person."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from conftest import ADMIN, APPROVER, make_csr, make_settings


def _folder(client, name, parent=None, settings=None):
    r = client.post("/api/v1/folders", json={"name": name, "parent_id": parent, "settings": settings or {}},
                    headers=ADMIN)
    assert r.status_code == 202, r.text  # a policy change waits for a second person
    approved = client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER)
    assert approved.status_code == 200, approved.text
    return approved.json()["payload"]["folder_id"]


def _app(client, name, folder, domains, profile="tls-server"):
    team = client.post("/api/v1/teams", json={"name": f"team-{name}", "contact_email": "t@example.com"},
                       headers=ADMIN).json()["id"]
    r = client.post("/api/v1/apps", json={"team_id": team, "name": name, "environment": "dev", "profile": profile,
                                          "allowed_domains": domains, "folder_id": folder}, headers=ADMIN)
    return r


def _key(client, app_id):
    return {"X-API-Key": client.post(f"/api/v1/apps/{app_id}/credentials", headers=ADMIN).json()["api_key"]}


def _issue(client, h, cn, key=None, days=None):
    _, csr = make_csr(cn, dns=[cn], key=key)
    body = {"csr_pem": csr}
    if days:
        body["validity_days"] = days
    return client.post("/api/v1/certificates", json=body, headers=h)


def _tree(client):
    """\\Bank (zones bank.internal, RSA 3072+, both locked; 200 days) > Payments (30 days, TLS profiles)."""
    bank = _folder(client, "Bank", settings={
        "allowed_zones": {"value": ["bank.internal"], "locked": True},
        "rsa_min_bits": {"value": 3072, "locked": True},
        "max_validity_days": {"value": 200, "locked": False}})
    pay = _folder(client, "Payments", bank, {
        "max_validity_days": {"value": 30, "locked": False},
        "allowed_profiles": {"value": ["tls-server", "tls-client"], "locked": False}})
    return bank, pay


def test_folder_rules_narrow_issuance(client):
    bank, pay = _tree(client)
    r = _app(client, "card-api", pay, ["*.pay.bank.internal"])
    assert r.status_code == 201 and r.json()["folder_id"] == pay
    h = _key(client, r.json()["id"])

    ok = _issue(client, h, "a.pay.bank.internal")
    assert ok.status_code == 201, ok.text
    lifetime = (ok.json()["not_after"], ok.json()["not_before"])
    from datetime import datetime
    days = (datetime.fromisoformat(lifetime[0]) - datetime.fromisoformat(lifetime[1])).days
    assert days <= 30  # the profile default was longer; the folder shortened it

    too_long = _issue(client, h, "b.pay.bank.internal", days=60)
    assert too_long.status_code == 422 and "folder_validity" in too_long.text

    weak = _issue(client, h, "c.pay.bank.internal", key=rsa.generate_private_key(65537, 2048))
    assert weak.status_code == 422
    assert weak.json()["violations"][0]["message"].endswith("required by \\Bank")  # names the folder


def test_locked_settings_cannot_be_overridden_below(client):
    bank, _ = _tree(client)
    r = client.post("/api/v1/folders", json={"name": "Lax", "parent_id": bank,
                                             "settings": {"rsa_min_bits": {"value": 1024}}}, headers=ADMIN)
    assert r.status_code == 400 and "locked at \\\\Bank" in r.text
    # an unlocked one can be changed by a child
    r = client.post("/api/v1/folders", json={"name": "Short", "parent_id": bank,
                                             "settings": {"max_validity_days": {"value": 30}}}, headers=ADMIN)
    assert r.status_code == 202


def test_onboarding_and_moves_must_fit_the_folder(client):
    _, pay = _tree(client)
    outside = _app(client, "elsewhere", pay, ["*.example.com"])
    assert outside.status_code == 422 and "folder_zone" in outside.text
    wrong_profile = _app(client, "signer", pay, ["release.bank.internal"], profile="code-signing")
    assert wrong_profile.status_code == 422 and "folder_profile" in wrong_profile.text

    free = _app(client, "free-app", None, ["*.example.com"])
    assert free.status_code == 201
    r = client.post(f"/api/v1/apps/{free.json()['id']}/move", json={"folder_id": pay}, headers=ADMIN)
    assert r.status_code == 422 and "folder_zone" in r.text


def test_policy_changes_need_a_second_person_and_are_audited(client):
    bank, _ = _tree(client)
    r = client.put(f"/api/v1/folders/{bank}/settings", headers=ADMIN, json={"settings": {
        "allowed_zones": {"value": ["bank.internal"], "locked": True},
        "rsa_min_bits": {"value": 2048, "locked": True}}})
    assert r.status_code == 202
    folders = {f["id"]: f for f in client.get("/api/v1/folders", headers=ADMIN).json()}
    assert folders[bank]["settings"]["rsa_min_bits"]["value"] == 3072  # not yet
    # the admin who asked cannot approve
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=ADMIN).status_code == 403
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
    folders = {f["id"]: f for f in client.get("/api/v1/folders", headers=ADMIN).json()}
    assert folders[bank]["settings"]["rsa_min_bits"]["value"] == 2048
    actions = [e["action"] for e in client.get("/api/v1/audit?limit=200", headers=ADMIN).json()]
    assert "policy.folder.update" in actions and actions.count("policy.folder.create") == 2


def test_folder_can_choose_the_issuing_ca(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, dual_control_actions=[]), background=False)) as c:
        sub = c.post("/api/v1/cas", json={"name": "payments-ca", "parent": "root-ca"}, headers=ADMIN)
        if sub.status_code == 202:
            c.post(f"/api/v1/approvals/{sub.json()['approval_id']}/approve", headers=APPROVER)
        r = c.post("/api/v1/folders", json={"name": "Payments", "settings": {
            "issuing_ca": {"value": "payments-ca", "locked": True}}}, headers=ADMIN)
        assert r.status_code == 201, r.text  # dual control for policy changes switched off here
        app = _app(c, "card-api", r.json()["folder_id"], ["*.pay.bank.internal"]).json()
        cert = _issue(c, _key(c, app["id"]), "a.pay.bank.internal", key=ec.generate_private_key(ec.SECP256R1()))
        assert cert.status_code == 201, cert.text
        assert "payments-ca" in cert.json()["issuer"]
        bad = c.post("/api/v1/folders", json={"name": "X", "settings": {"issuing_ca": {"value": "root-ca"}}},
                     headers=ADMIN)
        assert bad.status_code == 400


def test_effective_policy_is_visible_per_app(client):
    _, pay = _tree(client)
    app = _app(client, "card-api", pay, ["*.pay.bank.internal"]).json()
    pol = client.get(f"/api/v1/apps/{app['id']}/policy", headers=ADMIN).json()
    assert pol["folder"] == "\\Bank\\Payments"
    assert pol["folder_rules"]["rsa_min_bits"] == {"value": 3072, "locked": True, "folder": "\\Bank"}
    assert pol["folder_rules"]["max_validity_days"] == {"value": 30, "locked": False, "folder": "\\Bank\\Payments"}


def test_an_app_moved_in_sql_cannot_issue(client):
    from sqlalchemy import text

    from certadillo.db import get_session

    _, pay = _tree(client)
    app = _app(client, "card-api", pay, ["*.pay.bank.internal"]).json()
    h = _key(client, app["id"])
    with get_session() as s:  # escape the folder, or widen the scope, behind Certadillo's back
        s.execute(text("UPDATE apps SET folder_id = NULL WHERE id = :i"), {"i": app["id"]})
        s.commit()
    r = _issue(client, h, "a.pay.bank.internal")
    assert r.status_code == 403 and "integrity" in r.text


def test_upgrade_seals_existing_apps_once(tmp_path):
    """A deployment sealed before apps were: its marker lists no kinds. The next
    start seals the apps it finds and leaves the already-sealed kinds alone."""
    from sqlalchemy import text

    from certadillo import integrity
    from certadillo.db import get_session
    from conftest import onboard

    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, background=False)) as c:
        app_id, h = onboard(c)
    with get_session() as s:
        s.execute(text("UPDATE apps SET seal = NULL"))
        s.commit()
    (tmp_path / integrity.MARKER).write_text("2026-09-24T00:00:00+00:00\n")  # the old marker format
    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        assert _issue(c, h, "a.pay.bank.internal").status_code == 201
        assert "kinds:" in (tmp_path / integrity.MARKER).read_text()
        assert c.get("/api/v1/integrity", headers=ADMIN).json()["ok"]
