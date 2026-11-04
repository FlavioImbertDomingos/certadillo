"""Import a keycensus inventory (inventory.json).

keycensus (github.com/FlavioImbertDomingos/keycensus) inventories the keys
Certadillo never sees: HSM objects over PKCS#11, AWS KMS, Vault, Voltage, plus
certificates from files and TLS scans, and links each one to the applications
that use it from their SBOMs. Importing its export gives one place to answer
"which applications depend on this key or certificate":

  - every asset is stored with its algorithm, size, location, state and the
    applications keycensus linked to it;
  - a certificate keycensus saw is matched to Certadillo's inventory by SHA-256
    fingerprint, so the applications show up on that certificate;
  - a certificate keycensus saw that Certadillo does not know opens an
    `untracked_certificate` finding: it was issued outside the platform;
  - assets missing from a later export are marked removed, not deleted;
  - the keys go into the CycloneDX CBOM next to the certificates.
"""
from __future__ import annotations

from datetime import datetime, timezone

from certadillo.db import Certificate, DiscoveryFinding, ExternalAsset, as_utc

SOURCE = "keycensus"
MAX_ASSETS = 100_000


def _dt(v):
    if not isinstance(v, str) or not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _fp(v) -> str | None:
    if not isinstance(v, str):
        return None
    h = v.replace(":", "").strip().lower()
    return h if len(h) == 64 and all(c in "0123456789abcdef" for c in h) else None


def _s(v, n):
    return str(v)[:n] if v not in (None, "") else None


def import_inventory(p, actor: str, doc: dict) -> dict:
    from certadillo.audit.log import record

    if not isinstance(doc, dict) or doc.get("tool") != "keycensus" or not isinstance(doc.get("assets"), list):
        raise ValueError("not a keycensus inventory.json (expected tool: keycensus and an assets list)")
    assets = doc["assets"]
    if len(assets) > MAX_ASSETS:
        raise ValueError(f"more than {MAX_ASSETS} assets in one import")
    now = datetime.now(timezone.utc)
    by_fp = {c.fingerprint_sha256: c for c in p.s.query(Certificate).all()}
    seen, new, matched, untracked = set(), 0, 0, []
    for a in assets:
        if not isinstance(a, dict) or not a.get("id") or a.get("kind") not in ("key", "certificate", "protocol"):
            raise ValueError("each asset needs an id and a kind of key, certificate or protocol")
        aid = _s(a["id"], 64)
        row = p.s.query(ExternalAsset).filter_by(source=SOURCE, asset_id=aid).one_or_none()
        if row is None:
            row = ExternalAsset(source=SOURCE, asset_id=aid, first_seen=now)
            p.s.add(row)
            new += 1
        row.kind = a["kind"]
        row.name = _s(a.get("name"), 255) or aid
        row.origin, row.origin_type = _s(a.get("source"), 255), _s(a.get("source_type"), 32)
        row.algorithm, row.curve = _s(a.get("algorithm"), 32), _s(a.get("curve"), 32)
        row.key_size = a.get("key_size") if isinstance(a.get("key_size"), int) else None
        row.location, row.state = _s(a.get("location"), 512), _s(a.get("state"), 32)
        row.hardware_backed = a.get("hardware_backed") if isinstance(a.get("hardware_backed"), bool) else None
        row.exportable = a.get("exportable") if isinstance(a.get("exportable"), bool) else None
        row.expires, row.last_rotated = _dt(a.get("expires")), _dt(a.get("last_rotated"))
        row.fingerprint_sha256 = _fp(a.get("fingerprint_sha256"))
        row.applications = [str(x)[:120] for x in (a.get("applications") or [])][:200]
        row.used_by = [{k: str(v)[:200] for k, v in u.items()} for u in (a.get("used_by") or [])
                       if isinstance(u, dict)][:200]
        row.status, row.last_seen = "present", now
        cert = by_fp.get(row.fingerprint_sha256) if row.kind == "certificate" and row.fingerprint_sha256 else None
        row.certificate_id = cert.id if cert else None
        p.s.flush()
        seen.add(row.id)
        if cert is not None:
            matched += 1
        elif row.kind == "certificate" and row.fingerprint_sha256 and \
                (row.expires is None or row.expires > now):
            untracked.append(row)
    removed = 0
    for row in p.s.query(ExternalAsset).filter_by(source=SOURCE, status="present").all():
        if row.id not in seen:
            row.status = "removed"
            removed += 1
    _findings(p, untracked, now)
    res = {"assets": len(assets), "new": new, "removed": removed, "certificates_matched": matched,
           "certificates_untracked": len(untracked), "generated_at": _s(doc.get("generated_at"), 40)}
    record(p.s, actor, "inventory.keycensus.import", SOURCE, res)
    return res


def _findings(p, untracked, now) -> None:
    keys = set()
    for row in untracked:
        key = f"untracked_certificate:{row.fingerprint_sha256}"
        keys.add(key)
        detail = {"name": row.name, "fingerprint": row.fingerprint_sha256, "origin": row.origin,
                  "location": row.location, "applications": row.applications,
                  "expires": as_utc(row.expires).isoformat() if row.expires else None}
        f = p.s.query(DiscoveryFinding).filter_by(key=key).one_or_none()
        if f is None:
            p.s.add(DiscoveryFinding(kind="untracked_certificate", key=key, first_seen=now, last_seen=now,
                                     location=f"keycensus:{row.origin}:{row.location or row.name}"[:512],
                                     detail=detail))
        else:
            f.detail, f.last_seen = detail, now
            if f.status == "resolved":
                f.status = "open"
    for f in p.s.query(DiscoveryFinding).filter_by(kind="untracked_certificate", status="open").all():
        if f.key not in keys:
            f.status = "resolved"
    p.s.flush()


def as_json(a: ExternalAsset) -> dict:
    return {"id": a.id, "asset_id": a.asset_id, "kind": a.kind, "name": a.name, "origin": a.origin,
            "origin_type": a.origin_type, "algorithm": a.algorithm, "key_size": a.key_size, "curve": a.curve,
            "location": a.location, "state": a.state, "hardware_backed": a.hardware_backed,
            "exportable": a.exportable, "expires": as_utc(a.expires).isoformat() if a.expires else None,
            "last_rotated": as_utc(a.last_rotated).isoformat() if a.last_rotated else None,
            "fingerprint_sha256": a.fingerprint_sha256, "applications": a.applications, "used_by": a.used_by,
            "certificate_id": a.certificate_id, "status": a.status}


def cbom_components(s) -> list[dict]:
    """Keys from keycensus as CycloneDX 1.6 cryptographic assets."""
    out = []
    for a in s.query(ExternalAsset).filter_by(status="present", kind="key").all():
        props = [{"name": "keycensus:id", "value": a.asset_id},
                 {"name": "keycensus:source", "value": f"{a.origin_type or ''}:{a.origin or ''}"},
                 {"name": "keycensus:location", "value": a.location or ""}]
        props += [{"name": "keycensus:application", "value": app} for app in a.applications]
        material = {"type": "secret-key" if (a.algorithm or "").upper() in ("AES", "3DES", "HMAC", "DES")
                    else "private-key", "size": a.key_size or 0}
        if a.state in ("pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed"):
            material["state"] = a.state
        out.append({"type": "cryptographic-asset", "bom-ref": f"keycensus:{a.asset_id}",
                    "name": f"{a.name} ({a.algorithm or 'unknown'}{'-' + str(a.key_size) if a.key_size else ''})",
                    "cryptoProperties": {"assetType": "related-crypto-material",
                                         "relatedCryptoMaterialProperties": material},
                    "properties": props})
    return out
