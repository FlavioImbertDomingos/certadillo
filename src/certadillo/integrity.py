"""Integrity seals for the rows that decide access.

Principals (who may log in, with which role), approval requests (dual control)
and certificate status (what OCSP and the CRL say) are all database rows. An
attacker who can write to the database, but cannot run code in Certadillo,
could otherwise insert an admin, approve their own request or flip a revoked
certificate back to active.

Each of those rows carries an HMAC over its security-relevant fields, keyed with
a secret that is not in the database. Every change the application makes goes
through the ORM and is resealed in a before_flush hook; a change made directly
in SQL is not, so the seal no longer matches and the row is treated as
tampered:

- a principal with a broken seal cannot authenticate,
- an approval with a broken seal is refused,
- a certificate with a broken seal is reported as revoked by OCSP and the CRL
  (fail closed), and IntegritySealBroken fires.

The hook also refuses to reseal a row whose stored state was already broken, so
a legitimate later update cannot launder a tampered row.

A seal prevents forging a new state, not restoring an old one: someone with a
copy of the row from before a revocation could put that copy back.
`scan()` catches that case by cross-checking active certificates against the
revocation events in the (anchored) audit trail.

What seals do not protect against: code running inside Certadillo, which holds
the key. That is what HSM-held CA keys are for.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from certadillo.db import ApprovalRequest, AuditEvent, Certificate, Principal

log = logging.getLogger("certadillo.integrity")

MARKER = "integrity.epoch"

# Fields covered per model. Timestamps are left out on purpose: their precision
# and time-zone handling differ between databases, and they do not decide access.
FIELDS = {
    Principal: ("name", "role", "key_hash", "app_id", "active", "created_by"),
    ApprovalRequest: ("action", "payload", "requested_by", "status", "decided_by"),
    Certificate: ("fingerprint_sha256", "serial_hex", "ca_id", "app_id", "status", "revocation_reason", "source",
                  "backend"),
}
KIND = {Principal: "principal", ApprovalRequest: "approval", Certificate: "certificate"}

_state = {"key": None, "previous": None, "enforce": False}


def _parse_key(raw: str) -> bytes:
    raw = raw.strip()
    try:
        if len(raw) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in raw):
            return bytes.fromhex(raw)
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
    except ValueError:
        return raw.encode()


def derive_key(settings) -> bytes:
    if settings.seal_key:
        return _parse_key(settings.seal_key)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"certadillo-integrity",
                info=b"seal-v1").derive(settings.key_passphrase.encode())


def configure(settings) -> None:
    """Set the seal key for this process and install the flush hook once."""
    _state["key"] = derive_key(settings)
    _state["previous"] = _parse_key(settings.seal_key_previous) if settings.seal_key_previous else None
    marker = Path(settings.data_dir) / MARKER
    _state["enforce"] = marker.exists()
    if not event.contains(Session, "before_flush", _reseal):
        event.listen(Session, "before_flush", _reseal)


def reset() -> None:
    _state.update(key=None, previous=None, enforce=False)


def mac_hex(data: bytes) -> str | None:
    """HMAC with the seal key, for things that leave the host (audit anchors)."""
    if _state["key"] is None:
        return None
    return hmac.new(_state["key"], data, hashlib.sha256).hexdigest()


def _canonical(obj, values: dict) -> bytes:
    body = {"k": KIND[type(obj)], **values}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def _values(obj) -> dict:
    return {f: getattr(obj, f) for f in FIELDS[type(obj)]}


def _mac(key: bytes, obj, values: dict) -> str:
    return hmac.new(key, _canonical(obj, values), hashlib.sha256).hexdigest()


def compute(obj, values: dict | None = None) -> str | None:
    if _state["key"] is None:
        return None
    return _mac(_state["key"], obj, values if values is not None else _values(obj))


def _matches(obj, values: dict, seal: str | None) -> bool:
    if seal is None:
        # Rows from before sealing existed are sealed once by backfill(); after
        # that, a missing seal is as bad as a wrong one.
        return not _state["enforce"]
    for key in (_state["key"], _state["previous"]):
        if key is not None and hmac.compare_digest(_mac(key, obj, values), seal):
            return True
    return False


def verify(obj) -> bool:
    """True if the row's stored state carries a valid seal (or sealing is off)."""
    if _state["key"] is None or obj is None:
        return True
    return _matches(obj, _values(obj), obj.seal)


def _committed(obj, attr):
    hist = inspect(obj).attrs[attr].history
    if hist.deleted:
        return hist.deleted[0]
    if hist.unchanged:
        return hist.unchanged[0]
    return getattr(obj, attr)


def _apply_defaults(obj) -> None:
    """Column defaults (status="active", active=True, ...) are applied during the
    INSERT, after before_flush. Apply the scalar ones now so the seal covers
    the values that will actually be stored."""
    cols = type(obj).__table__.columns
    for f in FIELDS[type(obj)]:
        if getattr(obj, f) is None:
            default = cols[f].default
            if default is not None and default.is_scalar:
                setattr(obj, f, default.arg)


def _reseal(session, flush_context, instances) -> None:
    if _state["key"] is None:
        return
    for obj in list(session.new):
        if type(obj) in FIELDS:
            _apply_defaults(obj)
            obj.seal = compute(obj)
    for obj in list(session.dirty):
        if type(obj) not in FIELDS or not session.is_modified(obj, include_collections=False):
            continue
        original = {f: _committed(obj, f) for f in FIELDS[type(obj)]}
        if not _matches(obj, original, _committed(obj, "seal")):
            # The stored row was already tampered with. Keep the broken seal so
            # it stays visible; do not let this update launder it.
            log.error("refusing to reseal tampered %s id=%s", KIND[type(obj)], getattr(obj, "id", None))
            continue
        obj.seal = compute(obj)


def backfill(session, settings) -> int:
    """Seal every existing row once, then switch to enforcing. Idempotent: the
    marker lives in the data directory, not the database, so a database-only
    attacker cannot delete it to get their changes sealed at the next start."""
    marker = Path(settings.data_dir) / MARKER
    if marker.exists():
        _state["enforce"] = True
        return 0
    n = 0
    for model in FIELDS:
        for obj in session.query(model).yield_per(500):
            obj.seal = compute(obj)
            n += 1
    session.flush()
    marker.write_text(datetime.now(timezone.utc).isoformat() + "\n")
    _state["enforce"] = True
    log.info("integrity seals backfilled", extra={"rows": n})
    return n


def revoked_in_audit(session, serial_hex: str) -> bool:
    """True if the audit trail records this serial's revocation (indexed lookup)."""
    return session.query(AuditEvent.id).filter(AuditEvent.action == "certificate.revoke",
                                               AuditEvent.target == serial_hex).first() is not None


def revoked_serials(session) -> set[str]:
    return {t for (t,) in session.query(AuditEvent.target).filter(AuditEvent.action == "certificate.revoke")}


def trusted_status(session, cert) -> str:
    """The status OCSP and the CRL should report. 'revoked' when the row was
    tampered with, or when the audit trail says it was revoked but the row says
    otherwise (a restored old copy). Otherwise the row's own status."""
    if not verify(cert):
        return "revoked"
    if cert.status != "revoked" and _state["key"] is not None and revoked_in_audit(session, cert.serial_hex):
        return "revoked"
    return cert.status


def scan(session) -> list[dict]:
    """Every row with a broken seal, plus active certificates the audit trail
    says were revoked (a rollback from an old copy of the row)."""
    if _state["key"] is None:
        return []
    out = []
    for model in FIELDS:
        for obj in session.query(model).yield_per(500):
            if not verify(obj):
                label = getattr(obj, "name", None) or getattr(obj, "serial_hex", None) or f"#{obj.id}"
                out.append({"kind": KIND[model], "id": obj.id, "label": label, "problem": "seal does not match"})
    revoked_serials = {e.target for e in session.query(AuditEvent).filter(AuditEvent.action == "certificate.revoke")}
    if revoked_serials:
        for c in session.query(Certificate).filter(Certificate.status != "revoked",
                                                   Certificate.serial_hex.in_(revoked_serials)):
            out.append({"kind": "certificate", "id": c.id, "label": c.serial_hex,
                        "problem": f"status is {c.status} but the audit trail records its revocation"})
    return out


def reseal_all(session) -> dict:
    """After rotating the seal key: rows valid under the current or previous
    key are resealed with the current key; broken rows are left broken."""
    done = broken = 0
    for model in FIELDS:
        for obj in session.query(model).yield_per(500):
            if _matches(obj, _values(obj), obj.seal):
                obj.seal = compute(obj)
                done += 1
            else:
                broken += 1
    session.flush()
    return {"resealed": done, "broken": broken}
