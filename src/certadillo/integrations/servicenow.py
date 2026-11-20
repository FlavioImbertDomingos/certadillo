"""ServiceNow catalog item for self-service onboarding.

A team asks for a new application in the ServiceNow service catalog. ServiceNow
runs its own approval (the requester's manager, the PKI group); when the
requested item (RITM) is approved, a ServiceNow flow calls
POST /api/v1/integrations/servicenow/onboarding with the form's answers and
who approved it. Certadillo then onboards the app through the normal path:

- the ServiceNow approval is a precondition and is recorded in Certadillo
  (on the request row and in the audit trail), but it does not replace
  Certadillo's own dual control: a production scope still waits for a
  Certadillo approver, and that approver may not be the person the item
  was requested for;
- every step is written back to the RITM as a work note (received, waiting
  for approval #N, approved or rejected by whom, active), so the ticket shows
  Certadillo's decision next to ServiceNow's;
- credentials are never written to ServiceNow. The work note says where to
  get them.

Work notes that cannot be delivered (ServiceNow down) are kept on the request
row and retried by housekeeping.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from certadillo.audit.log import record
from certadillo.db import App, ServiceNowRequest, Team

log = logging.getLogger("certadillo")
RITM = re.compile(r"^RITM\d{4,20}$")
test_transport: dict = {"http": None}


class ServiceNowClient:
    def __init__(self, settings, http=None):
        from certadillo import egress

        if not settings.snow_url:
            raise RuntimeError("CERTADILLO_SNOW_URL is not set")
        self.base = settings.snow_url.rstrip("/")
        self.auth = (settings.snow_user or "", settings.snow_password or "")
        self.http = http or egress.client("servicenow", timeout=15, transport=test_transport["http"])

    def work_note(self, sys_id: str, text: str) -> None:
        r = self.http.patch(f"{self.base}/api/now/table/sc_req_item/{sys_id}", json={"work_notes": text},
                            auth=self.auth, headers={"Accept": "application/json"})
        r.raise_for_status()


def _note(row: ServiceNowRequest, text: str) -> None:
    row.notes_pending = [*(row.notes_pending or []), f"[Certadillo] {text}"]
    row.updated_at = datetime.now(timezone.utc)


def submit(p, actor, body: dict) -> tuple[ServiceNowRequest, App, object | None]:
    """Onboard an app from an approved RITM. Repeating a RITM returns what it created."""
    actor.require("admin", "operator")
    ritm = str(body["ritm"]).strip().upper()
    if not RITM.match(ritm):
        raise ValueError("ritm must look like RITM0012345")
    existing = p.s.get(ServiceNowRequest, ritm)
    if existing is not None:
        return existing, p.s.get(App, existing.app_id), None
    approval = body.get("snow_approval") or {}
    if str(approval.get("state", "")).lower() != "approved":
        raise ValueError("the requested item is not approved in ServiceNow yet; send it once it is")
    approved_by = str(approval.get("approved_by") or "").strip()
    requested_for = str(body.get("requested_for") or "").strip()
    if not approved_by or not requested_for:
        raise ValueError("requested_for and snow_approval.approved_by are required")
    if approved_by.lower() == requested_for.lower():
        raise ValueError("the ServiceNow approver is the person the item was requested for")
    team = p.s.query(Team).filter_by(name=body["team"]).one_or_none()
    if team is None:
        raise LookupError(f"team {body['team']!r} does not exist in Certadillo; create it first")
    app, pending = p.onboard_app(actor, team.id, body["app_name"], body["environment"], body["profile"],
                                 list(body["allowed_domains"]), body.get("data_classification", "internal"),
                                 body.get("folder_id"))
    row = ServiceNowRequest(ritm=ritm, sys_id=str(body["sys_id"]), app_id=app.id,
                            approval_id=pending.id if pending else None, requested_for=requested_for,
                            snow_approved_by=approved_by, status=app.status, notes_pending=[])
    p.s.add(row)
    if pending is not None:
        pending.payload = {**pending.payload, "servicenow": {"ritm": ritm, "requested_for": requested_for,
                                                             "approved_by": approved_by}}
        _note(row, f"Received. App {app.name} (#{app.id}) is waiting for a Certadillo approver "
                   f"(approval #{pending.id}); ServiceNow approval by {approved_by} recorded.")
    else:
        _note(row, f"Received and active: app {app.name} (#{app.id}). Its scope is inside the development zones, "
                   "so no second approval was needed. " + _credentials_hint(app))
    p.s.flush()
    record(p.s, actor.name, "servicenow.onboarding", ritm, {
        "app": app.name, "app_id": app.id, "status": app.status, "requested_for": requested_for,
        "snow_approved_by": approved_by, "approval_id": row.approval_id, "sys_id": row.sys_id})
    return row, app, pending


def _credentials_hint(app: App) -> str:
    return (f"Credentials are not sent to ServiceNow: the team gets them from Certadillo "
            f"(console, or POST /api/v1/apps/{app.id}/credentials by an operator; ACME EAB for ACME clients).")


def check_approver(p, req, actor) -> None:
    """Called before a Certadillo approver decides an onboarding: the person the
    ServiceNow item was requested for may not approve it here."""
    from certadillo.services import Forbidden

    if req.action != "onboard_prod_app":
        return
    row = p.s.query(ServiceNowRequest).filter_by(app_id=req.payload.get("app_id")).one_or_none()
    if row is None:
        return
    who = actor.name.lower().removeprefix("idp:")
    if who == row.requested_for.lower():
        raise Forbidden("maker-checker: the ServiceNow item was requested for you, so you cannot approve it")


def on_decision(p, req) -> None:
    """After a Certadillo approver decided an onboarding that came from ServiceNow."""
    if req.action != "onboard_prod_app":
        return
    row = p.s.query(ServiceNowRequest).filter_by(app_id=req.payload.get("app_id")).one_or_none()
    if row is None:
        return
    app = p.s.get(App, row.app_id)
    row.status = app.status
    if req.status == "approved":
        _note(row, f"Approved in Certadillo by {req.decided_by} (approval #{req.id}). App {app.name} (#{app.id}) "
                   f"is active. " + _credentials_hint(app))
    else:
        why = f": {req.comment}" if req.comment else ""
        _note(row, f"Rejected in Certadillo by {req.decided_by} (approval #{req.id}){why}.")


def flush_notes(session, settings, http=None) -> dict:
    """Deliver queued work notes. Failures stay queued for the next try."""
    if not settings.snow_url:
        return {"sent": 0, "failed": 0, "skipped": "CERTADILLO_SNOW_URL not set"}
    rows = session.query(ServiceNowRequest).all()
    rows = [r for r in rows if r.notes_pending]
    if not rows:
        return {"sent": 0, "failed": 0}
    client = ServiceNowClient(settings, http)
    sent = failed = 0
    for row in rows:
        try:
            client.work_note(row.sys_id, "\n".join(row.notes_pending))
        except Exception as exc:  # noqa: BLE001 - ServiceNow down or refusing: keep the notes and retry
            row.last_error = str(exc)[:500]
            failed += 1
            log.warning("servicenow work note failed", extra={"ritm": row.ritm, "error": row.last_error})
            continue
        sent += len(row.notes_pending)
        row.notes_pending, row.last_error = [], None
    session.flush()
    return {"sent": sent, "failed": failed}


def request_json(row: ServiceNowRequest) -> dict:
    return {"ritm": row.ritm, "sys_id": row.sys_id, "app_id": row.app_id, "approval_id": row.approval_id,
            "status": row.status, "requested_for": row.requested_for, "snow_approved_by": row.snow_approved_by,
            "notes_pending": len(row.notes_pending or []), "last_error": row.last_error,
            "created_at": row.created_at.isoformat() if row.created_at else None}
