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
    last_id = None
    for ev in session.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500):
        n += 1
        if ev.prev_hash != prev or ev.hash != _digest(prev, ev.ts, ev.actor, ev.action, ev.target, ev.details):
            return {"valid": False, "events": n, "broken_at": ev.id}
        prev = ev.hash
        last_id = ev.id
    return {"valid": True, "events": n, "head": prev, "head_id": last_id}


# ------------------------------------------------------------------ anchoring
# The hash chain proves the history was not edited by someone who cannot
# rewrite the whole table. Someone who can (a DB owner) could recompute every
# hash. Anchoring closes that gap: the chain head is sent off the host
# regularly, and a rewritten history no longer contains the anchored hashes.

def _canonical_anchor(a: dict) -> bytes:
    body = {k: a[k] for k in ("event_id", "hash", "events", "anchored_at", "instance")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def make_anchor(session, instance: str) -> dict | None:
    """The current verified chain head, with a MAC under the seal key so a
    receiver (or a later verifier) can tell a genuine anchor from a forged one.
    None when the chain is empty or already broken (anchoring a broken chain
    would legitimize it)."""
    from certadillo import integrity

    res = verify_chain(session)
    if not res["valid"] or not res["events"]:
        return None
    anchor = {"event_id": res["head_id"], "hash": res["head"], "events": res["events"],
              "anchored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "instance": instance}
    anchor["mac"] = integrity.mac_hex(_canonical_anchor(anchor))
    return anchor


def publish_anchor(anchor: dict, settings, http=None) -> list[str]:
    """Append to the anchor file and/or POST to the anchor URL. Returns the sinks
    that accepted it. The file is meant to be shipped to WORM storage (S3 Object
    Lock and the like); a local file alone does not survive host root."""
    import httpx

    done = []
    if settings.audit_anchor_file:
        with open(settings.audit_anchor_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(anchor, sort_keys=True) + "\n")
        done.append("file")
    if settings.audit_anchor_url:
        client = http or httpx.Client(timeout=10)
        try:
            client.post(settings.audit_anchor_url, json=anchor).raise_for_status()
            done.append("url")
        except httpx.HTTPError as exc:
            log.error("audit anchor POST failed: %s", exc)
    return done


def load_anchors(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def verify_against_anchors(session, anchors: list[dict], check_mac: bool = True) -> dict:
    """Every anchored (event_id, hash) must still be in a valid chain. A history
    rewritten after an anchor was taken fails here even if it re-hashes cleanly."""
    from certadillo import integrity

    chain = verify_chain(session)
    mismatches = []
    for a in anchors:
        if check_mac and a.get("mac") and integrity.mac_hex(_canonical_anchor(a)) != a["mac"]:
            mismatches.append({"event_id": a.get("event_id"), "problem": "anchor MAC does not verify"})
            continue
        ev = session.get(AuditEvent, a["event_id"])
        if ev is None:
            mismatches.append({"event_id": a["event_id"], "problem": "anchored event no longer exists"})
        elif ev.hash != a["hash"]:
            mismatches.append({"event_id": a["event_id"], "problem": "event hash differs from the anchor"})
    return {"valid": chain["valid"] and not mismatches, "chain_valid": chain["valid"],
            "anchors_checked": len(anchors), "mismatches": mismatches}


_last_anchor = {"at": None}


def maybe_anchor(session, settings, http=None) -> dict | None:
    """Called from housekeeping: anchor when one is due and a sink is configured."""
    if not (settings.audit_anchor_file or settings.audit_anchor_url):
        return None
    now = datetime.now(timezone.utc)
    last = _last_anchor["at"]
    if last is not None and (now - last).total_seconds() < settings.audit_anchor_hours * 3600:
        return None
    anchor = make_anchor(session, settings.base_url)
    if anchor is None:
        return None
    sinks = publish_anchor(anchor, settings, http=http)
    if sinks:
        _last_anchor["at"] = now
        record(session, "system", "audit.anchor", f"event:{anchor['event_id']}",
               {"hash": anchor["hash"], "sinks": sinks})
    return anchor
