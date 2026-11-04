"""Ship the audit trail off the host, in order, tamper-evident.

Every audit event is sent to each configured sink as a record that carries its
place in the hash chain (prev_hash, hash) and an HMAC under the seal key, which
lives outside the database. A receiver can therefore check, without trusting
Certadillo's database:

  - that no record was edited (the hash recomputes from the fields),
  - that none was dropped or inserted (each prev_hash is the hash before it),
  - that the records came from this Certadillo: each record is signed with an
    Ed25519 key that never leaves the host. The receiver needs only the public
    key (`certadillo audit signing-key`), so it can check records but cannot
    forge them. The HMAC under the seal key is kept as a second check for a
    verifier that runs with Certadillo's own key material.

`certadillo audit verify-export` does those checks on a JSONL copy, which is
what a file, S3 or SIEM export gives you. Delivery is at least once: a batch is
sent, then the sink's cursor moves; receivers de-duplicate on `hash`.

Sinks (CERTADILLO_AUDIT_SHIP, comma-separated):

  file:/var/log/certadillo/audit.jsonl   append, for a log forwarder to tail
  syslog+tls://siem.bank.internal:6514   RFC 5424 over TLS (RFC 5425 framing)
  syslog+tcp://host:514                  the same without TLS, for a local relay
  splunk+https://splunk:8088             Splunk HTTP Event Collector
  https://collector.bank.internal/audit  JSON batches to any HTTPS endpoint
  s3://bucket/prefix                     one object per batch, S3 Object Lock
                                         (COMPLIANCE mode) so nobody can delete
                                         or overwrite it before retention ends
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from certadillo.audit.log import GENESIS, _digest
from certadillo.db import AuditEvent, AuditShipCursor, as_utc

log = logging.getLogger("certadillo.audit.shipping")
BATCH = 500
# Tests put an httpx transport here.
test_transport = {"http": None}
SIGNING_KEY_FILE = "audit-signing.key.pem"
_signer: dict = {"path": None, "key": None}


# ------------------------------------------------------------------ signing key
def signing_key(settings):
    """The Ed25519 key that signs shipped records. Created on first use in the
    data directory, encrypted under the key passphrase like the CA keys."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = Path(settings.data_dir) / SIGNING_KEY_FILE
    if _signer["path"] == path and _signer["key"] is not None:
        return _signer["key"]
    pw = settings.key_passphrase.encode()
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), pw)
    else:
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(pw)))
        log.info("created the audit signing key %s", key_id(key.public_key()))
    _signer.update(path=path, key=key)
    return key


def public_key_pem(settings) -> str:
    from cryptography.hazmat.primitives import serialization

    return signing_key(settings).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def key_id(public_key) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


# ------------------------------------------------------------------ records
def _canonical(rec: dict) -> bytes:
    body = {k: rec[k] for k in ("id", "ts", "actor", "action", "target", "details", "prev_hash", "hash", "instance")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def to_record(ev: AuditEvent, instance: str, key=None) -> dict:
    from certadillo import integrity

    rec = {"id": ev.id, "ts": as_utc(ev.ts).isoformat(timespec="microseconds"), "actor": ev.actor,
           "action": ev.action, "target": ev.target, "details": ev.details, "prev_hash": ev.prev_hash,
           "hash": ev.hash, "instance": instance}
    body = _canonical(rec)
    rec["mac"] = integrity.mac_hex(body)
    if key is not None:
        rec["kid"] = key_id(key.public_key())
        rec["sig"] = base64.b64encode(key.sign(body)).decode()
    return rec


def load_public_key(pem: bytes):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("the audit signing key is Ed25519; this is a different key type")
    return key


def _sig_ok(public_key, rec: dict) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(base64.b64decode(rec.get("sig") or ""), _canonical(rec))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_records(records: list[dict], check_mac: bool = True, public_key=None) -> dict:
    """Check an exported run of records on its own: hashes, links, MACs and,
    given the public key, signatures. The first record may start anywhere in the
    chain; from there on there must be no gap. Records already seen
    (at-least-once delivery) are skipped."""
    from certadillo import integrity

    problems = []
    seen: set[str] = set()
    prev = None
    n = 0
    for rec in records:
        if rec.get("hash") in seen:
            continue
        seen.add(rec["hash"])
        n += 1
        ts = datetime.fromisoformat(rec["ts"])
        if _digest(rec["prev_hash"], ts, rec["actor"], rec["action"], rec["target"], rec["details"]) != rec["hash"]:
            problems.append({"id": rec.get("id"), "problem": "record was changed (hash does not recompute)"})
        if prev is not None and rec["prev_hash"] != prev:
            problems.append({"id": rec.get("id"), "problem": "gap or reordering: prev_hash does not match"})
        if check_mac and integrity.mac_hex(b"") is not None:
            if not rec.get("mac") or not hmac.compare_digest(integrity.mac_hex(_canonical(rec)), rec["mac"]):
                problems.append({"id": rec.get("id"), "problem": "MAC does not verify (not from this Certadillo)"})
        if public_key is not None and not _sig_ok(public_key, rec):
            problems.append({"id": rec.get("id"), "problem": "signature does not verify (not from this Certadillo)"})
        prev = rec["hash"]
    starts_at_genesis = bool(records) and records[0]["prev_hash"] == GENESIS
    return {"valid": not problems, "records": n, "problems": problems[:50],
            "first_id": records[0]["id"] if records else None, "last_id": records[-1]["id"] if records else None,
            "from_genesis": starts_at_genesis, "signatures_checked": public_key is not None,
            "macs_checked": bool(check_mac and integrity.mac_hex(b"") is not None)}


# ------------------------------------------------------------------ sinks
class Sink:
    def __init__(self, spec: str, settings):
        self.spec, self.settings = spec, settings

    def send(self, records: list[dict]) -> None:
        raise NotImplementedError


class FileSink(Sink):
    def send(self, records):
        path = self.spec[len("file:"):]
        with open(path, "a", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, sort_keys=True) + "\n")


class SyslogSink(Sink):
    """RFC 5424 messages with octet-counting framing (RFC 6587 / RFC 5425).
    Facility 13 (log audit), severity 5 (notice)."""

    def send(self, records):
        u = urlsplit(self.spec)
        host, port = u.hostname, u.port or (6514 if u.scheme == "syslog+tls" else 514)
        raw = socket.create_connection((host, port), timeout=10)
        try:
            if u.scheme == "syslog+tls":
                ctx = ssl.create_default_context(cafile=self.settings.audit_ship_cacert) \
                    if self.settings.audit_ship_cacert else ssl.create_default_context()
                raw = ctx.wrap_socket(raw, server_hostname=host)
            me = socket.gethostname()
            for r in records:
                msg = (f"<109>1 {r['ts']} {me} certadillo - {r['action'][:32]} - "
                       + json.dumps(r, sort_keys=True, separators=(",", ":"))).encode()
                raw.sendall(f"{len(msg)} ".encode() + msg)
            # Close gracefully so the tail is not lost to a reset: syslog has no
            # acknowledgement, so an abrupt close can drop records the receiver
            # had not read yet. TLS sends close_notify; plain TCP half-closes and drains.
            raw.settimeout(5)
            if isinstance(raw, ssl.SSLSocket):
                try:
                    raw = raw.unwrap()
                except (ssl.SSLError, OSError):
                    pass
            try:
                raw.shutdown(socket.SHUT_WR)
                while raw.recv(4096):
                    pass
            except OSError:
                pass
        finally:
            raw.close()


class HttpSink(Sink):
    def _token(self) -> str | None:
        from certadillo.provisioning import credentials

        return credentials.resolve(self.settings.audit_ship_token_ref, self.settings) \
            if self.settings.audit_ship_token_ref else None

    def _client(self) -> httpx.Client:
        verify = ssl.create_default_context(cafile=self.settings.audit_ship_cacert) \
            if self.settings.audit_ship_cacert else True
        return httpx.Client(timeout=20, verify=verify, transport=test_transport["http"])

    def send(self, records):
        headers = {"Content-Type": "application/json"}
        token = self._token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with self._client() as c:
            r = c.post(self.spec, content=json.dumps({"records": records}), headers=headers)
            if r.status_code >= 300:
                raise RuntimeError(f"{self.spec} returned {r.status_code}")


class SplunkSink(HttpSink):
    def send(self, records):
        base = "https://" + self.spec[len("splunk+https://"):].rstrip("/")
        token = self._token()
        if not token:
            raise RuntimeError("Splunk HEC needs CERTADILLO_AUDIT_SHIP_TOKEN_REF")
        events = []
        for r in records:
            ev = {"time": datetime.fromisoformat(r["ts"]).timestamp(), "host": socket.gethostname(),
                  "source": "certadillo", "sourcetype": "certadillo:audit", "event": r}
            if self.settings.audit_ship_splunk_index:
                ev["index"] = self.settings.audit_ship_splunk_index
            events.append(json.dumps(ev, separators=(",", ":")))
        with self._client() as c:
            resp = c.post(f"{base}/services/collector/event", content="\n".join(events),
                          headers={"Authorization": f"Splunk {token}"})
            if resp.status_code >= 300:
                raise RuntimeError(f"Splunk HEC returned {resp.status_code}: {resp.text[:200]}")


class S3ObjectLockSink(Sink):
    def send(self, records):
        import boto3

        u = urlsplit(self.spec)
        bucket, prefix = u.netloc, u.path.strip("/")
        key = f"{prefix + '/' if prefix else ''}{records[0]['id']:012d}-{records[-1]['id']:012d}.jsonl"
        body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records).encode()
        until = datetime.now(timezone.utc) + timedelta(days=self.settings.audit_ship_s3_retention_days)
        boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/x-ndjson",
                                      ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until,
                                      ChecksumAlgorithm="SHA256")


def build(spec: str, settings) -> Sink:
    if spec.startswith("file:"):
        return FileSink(spec, settings)
    if spec.startswith(("syslog+tls://", "syslog+tcp://")):
        return SyslogSink(spec, settings)
    if spec.startswith("splunk+https://"):
        return SplunkSink(spec, settings)
    if spec.startswith("https://"):
        return HttpSink(spec, settings)
    if spec.startswith("s3://"):
        return S3ObjectLockSink(spec, settings)
    raise ValueError(f"audit sink {spec!r}: use file:, syslog+tls://, syslog+tcp://, splunk+https://, https:// or s3://")


def check_config(settings) -> None:
    for spec in settings.audit_ship:
        build(spec, settings)


# ------------------------------------------------------------------ the shipper
def ship(session, settings, max_batches: int = 20) -> dict:
    """Send what each sink has not seen yet. Returns {sink: sent_count or error}."""
    out = {}
    key = signing_key(settings) if settings.audit_ship else None
    for spec in settings.audit_ship:
        sink = build(spec, settings)
        cur = session.query(AuditShipCursor).filter_by(sink=spec).one_or_none()
        if cur is None:
            cur = AuditShipCursor(sink=spec, last_event_id=0)
            session.add(cur)
            session.flush()
        sent = 0
        try:
            for _ in range(max_batches):
                evs = (session.query(AuditEvent).filter(AuditEvent.id > cur.last_event_id)
                       .order_by(AuditEvent.id).limit(BATCH).all())
                if not evs:
                    break
                if cur.last_hash is not None and evs[0].prev_hash != cur.last_hash:
                    # the database no longer continues the chain we already shipped
                    raise RuntimeError(f"chain break after event {cur.last_event_id}: the history was changed "
                                       "after it was shipped")
                sink.send([to_record(e, settings.base_url, key) for e in evs])
                cur.last_event_id, cur.last_hash = evs[-1].id, evs[-1].hash
                sent += len(evs)
            cur.failures, cur.last_error = 0, None
            out[spec] = sent
        except Exception as exc:  # noqa: BLE001 - recorded on the cursor and alerted on
            cur.failures = (cur.failures or 0) + 1
            cur.last_error = f"{type(exc).__name__}: {exc}"[:500]
            out[spec] = cur.last_error
            log.error("audit shipping to %s failed: %s", _safe(spec), cur.last_error)
        cur.updated_at = datetime.now(timezone.utc)
    return out


def _safe(spec: str) -> str:
    u = urlsplit(spec)
    return f"{u.scheme}://{u.hostname or ''}{u.path if u.scheme in ('file', 's3') else ''}"


def lag(session, settings) -> list[dict]:
    """Per sink: events not yet shipped and how old the oldest one is."""
    out = []
    head = session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    for spec in settings.audit_ship:
        cur = session.query(AuditShipCursor).filter_by(sink=spec).one_or_none()
        last = cur.last_event_id if cur else 0
        oldest = session.query(AuditEvent).filter(AuditEvent.id > last).order_by(AuditEvent.id).first()
        out.append({"sink": _safe(spec), "spec": spec, "behind": (head.id - last) if head else 0,
                    "oldest_unsent": as_utc(oldest.ts).isoformat() if oldest else None,
                    "failures": cur.failures if cur else 0, "last_error": cur.last_error if cur else None})
    return out
