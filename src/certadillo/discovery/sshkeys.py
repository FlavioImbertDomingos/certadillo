"""Static SSH keys reported by host agents: inventory, ownership and findings.

A static authorized key is a credential that never expires and is often
copied between accounts and hosts. Certadillo cannot rotate those yet, but it
can say where each one opens a door, who owns it, and which ones need action:

  ssh_weak_key          DSA, or RSA below CERTADILLO_SSH_RSA_MIN_BITS (2048)
  ssh_shared_key        the same key authorized for more than one account or host
  ssh_root_unrestricted a key that logs in as root with no from= restriction
  ssh_orphaned_key      a key for an account that does not exist on the host
  ssh_rotation_due      an authorized key not changed for CERTADILLO_SSH_KEY_MAX_AGE_DAYS (365)

Findings close on their own once the next report no longer shows the problem.
The long-term fix for most of these is SSH certificates (see the SSH guide).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from certadillo.db import DiscoveryFinding, SshKey, as_utc

KINDS = ("ssh_weak_key", "ssh_shared_key", "ssh_root_unrestricted", "ssh_orphaned_key", "ssh_rotation_due")


def ingest(p, actor: str, host: str, keys: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    seen_ids = set()
    new = 0
    for k in keys:
        fp, path = str(k.get("fingerprint", ""))[:64], str(k.get("path", ""))[:512]
        if not fp.startswith("SHA256:") or not path:
            raise ValueError("each SSH key needs a SHA256 fingerprint and a path")
        row = p.s.query(SshKey).filter_by(host=host, path=path, fingerprint=fp).one_or_none()
        if row is None:
            row = SshKey(host=host, path=path, fingerprint=fp, first_seen=now)
            p.s.add(row)
            new += 1
        row.key_type = str(k.get("key_type", "?"))[:48]
        row.bits = int(k["bits"]) if isinstance(k.get("bits"), int) else None
        row.comment = (k.get("comment") or "")[:200] or None
        row.kind = "host" if k.get("kind") == "host" else "authorized"
        row.account = (k.get("user") or None) and str(k["user"])[:120]
        row.account_exists = bool(k.get("user_exists", True))
        row.options = {str(n)[:40]: (v if isinstance(v, bool) else str(v)[:300])
                       for n, v in (k.get("options") or {}).items()}
        mt = k.get("file_mtime")
        row.file_mtime = datetime.fromtimestamp(mt, timezone.utc) if isinstance(mt, (int, float)) else None
        row.last_seen, row.status = now, "present"
        p.s.flush()
        seen_ids.add(row.id)
    removed = 0
    for row in p.s.query(SshKey).filter_by(host=host, status="present").all():
        if row.id not in seen_ids:
            row.status = "removed"
            removed += 1
    p.s.flush()
    refresh_findings(p)
    return {"ssh_keys": len(keys), "new": new, "removed": removed}


def refresh_findings(p) -> None:
    """Recompute every SSH finding from the current inventory."""
    st = p.settings
    now = datetime.now(timezone.utc)
    present = p.s.query(SshKey).filter_by(status="present").all()
    wanted: dict[str, tuple[str, str, dict]] = {}

    def want(kind, key, location, detail):
        wanted[f"{kind}:{key}"[:255]] = (kind, location[:512], detail)

    places = defaultdict(set)
    for k in present:
        loc = f"{k.host}:{k.path}"
        base = {"host": k.host, "account": k.account, "fingerprint": k.fingerprint, "key_type": k.key_type,
                "bits": k.bits, "comment": k.comment, "ssh_key_id": k.id}
        if k.key_type == "ssh-dss" or (k.key_type == "ssh-rsa" and (k.bits or 0) < st.ssh_rsa_min_bits):
            want("ssh_weak_key", f"{loc}:{k.fingerprint}", loc, base)
        if k.kind != "authorized":
            continue
        places[k.fingerprint].add((k.host, k.account))
        if k.account == "root" and "from" not in (k.options or {}):
            want("ssh_root_unrestricted", f"{loc}:{k.fingerprint}", loc, base)
        if not k.account_exists:
            want("ssh_orphaned_key", f"{loc}:{k.fingerprint}", loc, base)
        changed = as_utc(k.file_mtime) or as_utc(k.first_seen)
        if changed and now - changed > timedelta(days=st.ssh_key_max_age_days):
            want("ssh_rotation_due", f"{loc}:{k.fingerprint}", loc, {**base, "unchanged_days": (now - changed).days})
    for fp, where in places.items():
        if len(where) > 1:
            spots = sorted(f"{a or '?'}@{h}" for h, a in where)
            want("ssh_shared_key", fp, ", ".join(spots), {"fingerprint": fp, "authorized_for": spots})

    existing = {f.key: f for f in p.s.query(DiscoveryFinding).filter(DiscoveryFinding.kind.in_(KINDS)).all()}
    for key, (kind, location, detail) in wanted.items():
        f = existing.get(key)
        if f is None:
            p.s.add(DiscoveryFinding(kind=kind, key=key, location=location, detail=detail, first_seen=now,
                                     last_seen=now))
        else:
            f.location, f.detail, f.last_seen = location, detail, now
            if f.status == "resolved":
                f.status = "open"
    for key, f in existing.items():
        if key not in wanted and f.status == "open":
            f.status = "resolved"
    p.s.flush()


def as_json(k: SshKey) -> dict:
    return {"id": k.id, "fingerprint": k.fingerprint, "key_type": k.key_type, "bits": k.bits, "comment": k.comment,
            "kind": k.kind, "host": k.host, "account": k.account, "account_exists": k.account_exists, "path": k.path,
            "options": k.options, "file_mtime": as_utc(k.file_mtime).isoformat() if k.file_mtime else None,
            "first_seen": as_utc(k.first_seen).isoformat(), "last_seen": as_utc(k.last_seen).isoformat(),
            "status": k.status, "owner": k.owner, "owner_note": k.owner_note}
