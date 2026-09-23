"""Tamper-evident audit trail.

Each event stores the SHA-256 of (previous hash + canonical event body). Any
edit or deletion in the middle of the table breaks every later hash, which
/api/v1/audit/verify and the certadillo_audit_chain_valid metric detect.
Ship events to a SIEM / WORM bucket as well; the chain proves integrity, it
does not replace off-host retention (PCI DSS 10.3, SP 800-53 AU-9)."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone

from sqlalchemy import text

from certadillo.db import AuditEvent, as_utc

GENESIS = "0" * 64
_lock = threading.Lock()
log = logging.getLogger("certadillo.audit")


def _digest(prev: str, ts: datetime, actor: str, action: str, target: str, details: dict) -> str:
    body = json.dumps(
        {
            "ts": as_utc(ts).isoformat(timespec="microseconds"),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev + body).encode()).hexdigest()


def record(session, actor: str, action: str, target: str, details: dict | None = None) -> AuditEvent:
    details = json.loads(json.dumps(details or {}, default=str))
    if session.get_bind().dialect.name == "postgresql":
        # serialize chain appends across replicas until this transaction ends
        session.execute(text("SELECT pg_advisory_xact_lock(7243901)"))
    with _lock:
        last = session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev = last.hash if last else GENESIS
        ts = datetime.now(timezone.utc)
        ev = AuditEvent(
            ts=ts,
            actor=actor,
            action=action,
            target=target,
            details=details,
            prev_hash=prev,
            hash=_digest(prev, ts, actor, action, target, details),
        )
        session.add(ev)
        session.flush()
    log.info("audit", extra={"audit": {"actor": actor, "action": action, "target": target, **details}})
    return ev


def verify_chain(session) -> dict:
    prev = GENESIS
    n = 0
    for ev in session.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500):
        n += 1
        if ev.prev_hash != prev or ev.hash != _digest(prev, ev.ts, ev.actor, ev.action, ev.target, ev.details):
            return {"valid": False, "events": n, "broken_at": ev.id}
        prev = ev.hash
    return {"valid": True, "events": n, "head": prev}
