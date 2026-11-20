"""Self-service onboarding from a ServiceNow catalog item: the request, the
approval recorded in both systems, and the work notes written back."""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from certadillo.api.app import create_app, run_housekeeping
from certadillo.integrations import servicenow
from conftest import ADMIN, APPROVER, make_settings

SYS_ID = "0123456789abcdef0123456789abcdef"


class FakeSnow:
    def __init__(self):
        self.notes: list[tuple[str, str]] = []
        self.down = False

    def handler(self, request: httpx.Request):
        if self.down:
            return httpx.Response(503)
        assert request.method == "PATCH" and request.url.path.startswith("/api/now/table/sc_req_item/")
        assert request.headers["authorization"].startswith("Basic ")
        self.notes.append((request.url.path.rsplit("/", 1)[1], json.loads(request.content)["work_notes"]))
        return httpx.Response(200, json={"result": {}})


@pytest.fixture
def snow():
    return FakeSnow()


@pytest.fixture
def c(tmp_path, snow):
    servicenow.test_transport["http"] = httpx.MockTransport(snow.handler)
    s = make_settings(tmp_path, snow_url="https://bank.service-now.com", snow_user="certadillo",
                      snow_password="pw")  # noqa: S106
    with TestClient(create_app(s, background=False)) as client:
        r = client.post("/api/v1/principals", json={"name": "servicenow", "role": "operator"}, headers=ADMIN)
        client.integration = {"X-API-Key": r.json()["api_key"]}
        client.post("/api/v1/teams", json={"name": "payments-platform", "contact_email": "pay@bank.example"},
                    headers=ADMIN)
        yield client
    servicenow.test_transport["http"] = None


def _request(ritm="RITM0010001", domains=("*.pay.bank.prod",), env="prod", approved_by="bob@bank.example", **kw):
    return {"ritm": ritm, "sys_id": SYS_ID, "requested_for": "alice@bank.example", "team": "payments-platform",
            "app_name": "card-auth", "environment": env, "profile": "tls-server", "allowed_domains": list(domains),
            "snow_approval": {"state": "approved", "approved_by": approved_by}, **kw}


def test_prod_request_waits_for_a_certadillo_approver_and_both_decisions_reach_the_ticket(c, snow):
    r = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending_approval" and body["approval_id"] and body["app"]["status"] == "pending_approval"
    assert snow.notes[0][0] == SYS_ID and "waiting for a Certadillo approver" in snow.notes[0][1]
    assert "approval by bob@bank.example recorded" in snow.notes[0][1]

    # Certadillo's approval queue shows where the request came from
    appr = c.get("/api/v1/approvals", headers=APPROVER).json()
    mine = next(a for a in appr if a["id"] == body["approval_id"])
    assert mine["payload"]["servicenow"]["ritm"] == "RITM0010001"

    assert c.post(f"/api/v1/approvals/{body['approval_id']}/approve", headers=APPROVER).status_code == 200
    assert "Approved in Certadillo by bootstrap-approver" in snow.notes[-1][1]
    assert "Credentials are not sent to ServiceNow" in snow.notes[-1][1]
    assert c.get(f"/api/v1/apps/{body['app_id']}", headers=ADMIN).json()["status"] == "active"
    rows = c.get("/api/v1/integrations/servicenow/requests", headers=ADMIN).json()
    assert rows[0]["status"] == "active" and rows[0]["notes_pending"] == 0
    audit = c.get("/api/v1/audit", headers=ADMIN).json()
    ev = next(e for e in audit if e["action"] == "servicenow.onboarding")
    assert ev["details"]["snow_approved_by"] == "bob@bank.example" and ev["target"] == "RITM0010001"
    # nothing secret ever goes to ServiceNow
    assert not any("cdl_" in n for _, n in snow.notes)


def test_rejection_is_written_back(c, snow):
    body = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration).json()
    r = c.post(f"/api/v1/approvals/{body['approval_id']}/reject", json={"comment": "scope too broad"},
               headers=APPROVER)
    assert r.status_code == 200
    assert "Rejected in Certadillo by bootstrap-approver" in snow.notes[-1][1] and "scope too broad" in snow.notes[-1][1]


def test_dev_scope_is_active_at_once(c, snow):
    r = c.post("/api/v1/integrations/servicenow/onboarding", headers=c.integration,
               json=_request(ritm="RITM0010002", domains=("*.card.bank.internal",), env="dev"))
    assert r.json()["status"] == "active" and r.json()["approval_id"] is None
    assert "no second approval was needed" in snow.notes[-1][1]


def test_the_same_ritm_twice_returns_what_it_created(c, snow):
    first = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration).json()
    again = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration).json()
    assert again["app_id"] == first["app_id"] and len(c.get("/api/v1/apps", headers=ADMIN).json()) == 1


@pytest.mark.parametrize("change,message", [
    (lambda b: b["snow_approval"].update(state="requested"), "not approved in ServiceNow"),
    (lambda b: b["snow_approval"].update(approved_by="alice@bank.example"), "requested for"),
    (lambda b: b.update(team="no-such-team"), "does not exist"),
])
def test_requests_that_are_not_ready_are_refused(c, change, message):
    b = _request()
    change(b)
    r = c.post("/api/v1/integrations/servicenow/onboarding", json=b, headers=c.integration)
    assert r.status_code in (400, 404) and message in r.text


def test_the_requester_cannot_approve_it_in_certadillo(c, snow):
    body = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration).json()
    # alice (the person the item was requested for) holds an approver key
    r = c.post("/api/v1/principals", json={"name": "alice@bank.example", "role": "approver"}, headers=ADMIN)
    alice = {"X-API-Key": r.json()["api_key"]}
    r = c.post(f"/api/v1/approvals/{body['approval_id']}/approve", headers=alice)
    assert r.status_code == 403 and "requested for you" in r.text


def test_apps_cannot_call_it(c):
    from conftest import onboard

    _, h = onboard(c)
    assert c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=h).status_code == 403


def test_undelivered_notes_are_retried_by_housekeeping(c, snow):
    snow.down = True
    body = c.post("/api/v1/integrations/servicenow/onboarding", json=_request(), headers=c.integration).json()
    assert body["status"] == "pending_approval"  # onboarding does not depend on ServiceNow being up
    rows = c.get("/api/v1/integrations/servicenow/requests", headers=ADMIN).json()
    assert rows[0]["notes_pending"] == 1 and "503" in rows[0]["last_error"]
    snow.down = False
    run_housekeeping()
    rows = c.get("/api/v1/integrations/servicenow/requests", headers=ADMIN).json()
    assert rows[0]["notes_pending"] == 0 and rows[0]["last_error"] is None
    assert "waiting for a Certadillo approver" in snow.notes[-1][1]
