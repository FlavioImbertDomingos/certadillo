"""Crypto-agility drill: move the estate to a new issuing CA and time it.

A bank that may one day have to leave an algorithm (RSA and ECC for ML-DSA)
or a CA (after a key compromise) needs to know how long that takes, before it
has to do it for real. A drill answers that with the machinery a real move
would use:

1. Freeze the set of certificates to move: everything active that the source
   CAs issued.
2. Open an ARI renewal campaign for that set, so ACME clients,
   `certadillo cert renew-if-due` and push-provisioned installations renew on
   the server's schedule instead of at the usual point in their life.
3. Watch replacements arrive. A certificate counts as moved when its
   replacement was signed by the target CA; one replaced by some other CA
   points at a routing problem (a folder pinned to the old CA, an upstream
   issuer), and the status names the setting responsible.
4. Report progress and the time it took to reach 50, 90, 99 and 100 percent.

Nothing is revoked by a drill. Revoking the old certificates afterwards is a
separate, deliberate step through the campaign (`revoke-replaced`).
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from certadillo.audit.log import record
from certadillo.db import AgilityDrill, App, Certificate, CertificateAuthority, RenewalCampaign, Team, as_utc

MILESTONES = (50, 90, 99, 100)


def _issuing(p, name: str) -> CertificateAuthority:
    from certadillo.ca.authority import path_length

    ca = p.ca.get(name)
    if ca.is_root or path_length(ca) != 0:
        raise ValueError(f"{name} is not an issuing CA (it must be a non-root CA with pathlen 0)")
    return ca


def start(p, actor_name: str, name: str, target_ca: str, source_cas: list[str] | None = None,
          renew_within_hours: int = 72, immediate: bool = False) -> AgilityDrill:
    from certadillo.enrollment import ari

    target = _issuing(p, target_ca)
    if target.signer_type == "offline":
        raise ValueError(f"{target_ca} is offline and cannot sign certificates here")
    if source_cas:
        sources = [p.ca.get(n) for n in dict.fromkeys(source_cas)]
    else:
        sources = [ca for ca in p.s.query(CertificateAuthority).filter_by(is_root=False).all() if ca.id != target.id]
    if any(ca.id == target.id for ca in sources):
        raise ValueError("the target CA cannot also be a source")
    now = datetime.now(timezone.utc)
    certs = [c for c in p.s.query(Certificate).filter(
        Certificate.status == "active", Certificate.source == "issued",
        Certificate.ca_id.in_([ca.id for ca in sources])).order_by(Certificate.id).all()
        if as_utc(c.not_after) > now]
    if not certs:
        raise ValueError("no active certificates from the source CAs; there is nothing to move")
    camp = ari.create_campaign(
        p.s, actor_name, f"agility drill: {name}"[:120],
        f"Crypto-agility drill: move {len(certs)} certificate(s) to {target_ca}",
        {"cert_ids": [c.id for c in certs]}, renew_within_hours, immediate=immediate)
    drill = AgilityDrill(name=name, target_ca=target.name, source_cas=[ca.name for ca in sources],
                         certificate_ids=[c.id for c in certs], campaign_id=camp.id, started_at=now,
                         created_by=actor_name)
    p.s.add(drill)
    p.s.flush()
    record(p.s, actor_name, "agility_drill.start", f"drill:{drill.id}", {
        "name": name, "target_ca": target.name, "source_cas": drill.source_cas, "certificates": len(certs),
        "campaign": camp.id, "renew_within_hours": renew_within_hours, "immediate": immediate})
    return drill


def next_ca(p, app: App | None, profile: str | None) -> dict:
    """Where the next certificate for this app would be signed, and which
    setting decides it. Mirrors the routing in Platform._sign."""
    from certadillo.policy import folders

    eff = folders.effective(p.s, app.folder_id) if app is not None else {}
    prof = p.policies.get("profiles", {}).get(profile or (app.profile if app else ""), {})
    if "issuer" in eff and eff["issuer"]["value"] != "local":
        return {"kind": "upstream", "name": eff["issuer"]["value"], "set_by": f"folder {eff['issuer']['folder']}"}
    if "issuer" not in eff and prof.get("issuer", "local") != "local":
        return {"kind": "upstream", "name": prof["issuer"], "set_by": f"profile {profile}"}
    if "issuing_ca" in eff:
        return {"kind": "local", "name": eff["issuing_ca"]["value"],
                "set_by": f"folder {eff['issuing_ca']['folder']}"}
    try:
        return {"kind": "local", "name": p.ca.default_issuing().name, "set_by": "default (newest issuing CA)"}
    except LookupError:
        return {"kind": "none", "name": None, "set_by": "no issuing CA"}


def _latest(s, c: Certificate, since: datetime) -> Certificate | None:
    """The newest certificate in c's replacement chain (a certificate renewed
    twice during the drill counts by its latest successor)."""
    from certadillo.enrollment import ari

    new = ari.replacement_for(s, c, since)
    for _ in range(20):
        if new is None or not new.replaced_by:
            break
        nxt = s.get(Certificate, new.replaced_by)
        if nxt is None:
            break
        new = nxt
    return new


def progress(s, drill: AgilityDrill, now: datetime | None = None) -> float:
    """Share of the movable certificates now issued by the target CA (for the
    Prometheus gauge; status() has the full picture)."""
    now = now or datetime.now(timezone.utc)
    started = as_utc(drill.started_at)
    target = s.query(CertificateAuthority).filter_by(name=drill.target_ca).one_or_none()
    moved = gone = 0
    for cid in drill.certificate_ids:
        c = s.get(Certificate, cid)
        new = _latest(s, c, started) if c is not None else None
        if new is not None and target is not None and new.ca_id == target.id:
            moved += 1
        elif c is None or (new is None and (c.status == "revoked" or as_utc(c.not_after) <= now)):
            gone += 1
    denom = len(drill.certificate_ids) - gone
    return moved / denom if denom else 1.0


def status(p, drill: AgilityDrill, now: datetime | None = None) -> dict:
    s = p.s
    now = now or datetime.now(timezone.utc)
    started = as_utc(drill.started_at)
    target = s.query(CertificateAuthority).filter_by(name=drill.target_ca).one_or_none()
    apps = {a.id: a for a in s.query(App).all()}
    teams = {t.id: t for t in s.query(Team).all()}
    cas = {ca.id: ca.name for ca in s.query(CertificateAuthority).all()}
    counts = {"total": len(drill.certificate_ids), "moved": 0, "elsewhere": 0, "remaining": 0, "gone": 0}
    offsets: list[float] = []
    items, blocked = [], {}
    route_cache: dict[tuple, dict] = {}
    for cid in drill.certificate_ids:
        c = s.get(Certificate, cid)
        if c is None:
            counts["gone"] += 1
            continue
        new = _latest(s, c, started)
        moved_at = None
        if new is not None and target is not None and new.ca_id == target.id:
            state, moved_at = "moved", as_utc(new.created_at)
            offsets.append(max(0.0, (moved_at - started).total_seconds()))
        elif new is not None:
            state = "elsewhere"
        elif c.status == "revoked" or as_utc(c.not_after) <= now:
            state = "gone"  # out of the denominator: nothing left to move
        else:
            state = "remaining"
        counts[state] += 1
        app = apps.get(c.app_id) if c.app_id else None
        item = {"certificate_id": c.id, "common_name": c.common_name, "state": state, "protocol": c.protocol,
                "app": app.name if app else None, "team": teams[app.team_id].name if app else None,
                "from_ca": cas.get(c.ca_id), "replaced_by": new.id if new else None,
                "replaced_by_ca": (cas.get(new.ca_id) if new.ca_id else new.backend) if new else None,
                "moved_at": moved_at.isoformat() if moved_at else None}
        if state in ("remaining", "elsewhere"):
            key = (c.app_id, c.profile)
            if key not in route_cache:
                route_cache[key] = next_ca(p, app, c.profile)
            route = route_cache[key]
            item["next_ca"] = route["name"]
            if route["name"] != drill.target_ca:
                # renewing would not help: the next certificate would come from elsewhere
                name = app.name if app else f"certificate {c.id}"
                blocked.setdefault(name, {"app": app.name if app else None, "next_ca": route["name"],
                                          "kind": route["kind"], "set_by": route["set_by"], "certificates": 0})
                blocked[name]["certificates"] += 1
        items.append(item)

    denom = counts["total"] - counts["gone"]
    offsets.sort()
    milestones = {}
    for pct in MILESTONES:
        need = max(1, math.ceil(denom * pct / 100)) if denom else 0
        milestones[f"{pct}%"] = round(offsets[need - 1], 1) if need and len(offsets) >= need else None
    complete = denom == 0 or counts["moved"] >= denom
    camp = s.get(RenewalCampaign, drill.campaign_id) if drill.campaign_id else None
    if complete and milestones["100%"] is not None:
        elapsed_end = started + timedelta(seconds=milestones["100%"])  # the clock stops at 100%
    else:
        elapsed_end = as_utc(drill.closed_at) if drill.closed_at else now
    by_team: dict[str, int] = {}
    for i in items:
        if i["state"] in ("remaining", "elsewhere"):
            by_team[i["team"] or "(none)"] = by_team.get(i["team"] or "(none)", 0) + 1
    return {
        "id": drill.id, "name": drill.name, "status": drill.status, "target_ca": drill.target_ca,
        "target_exists": target is not None,
        "source_cas": drill.source_cas, "created_by": drill.created_by, "started_at": started.isoformat(),
        "closed_at": as_utc(drill.closed_at).isoformat() if drill.closed_at else None,
        "campaign_id": drill.campaign_id,
        "renew_by": as_utc(camp.window_end).isoformat() if camp else None,
        "overdue": bool(camp and now > as_utc(camp.window_end) and not complete),
        "counts": counts, "progress": round(counts["moved"] / denom, 4) if denom else 1.0,
        "complete": complete,
        "elapsed_seconds": round((elapsed_end - started).total_seconds(), 1),
        "time_to_seconds": milestones,
        "blocked": sorted(blocked.values(), key=lambda b: -b["certificates"]),
        "remaining_by_team": dict(sorted(by_team.items(), key=lambda kv: -kv[1])),
        "result": drill.result or None,
        "certificates": sorted(items, key=lambda i: (i["state"] != "elsewhere", i["state"] != "remaining",
                                                     i["common_name"] or "")),
    }


def close(p, actor_name: str, drill: AgilityDrill) -> dict:
    """Stop the drill, keep its final numbers, and close the campaign so ARI
    windows go back to normal for anything that did not move."""
    if drill.status == "closed":
        raise ValueError("the drill is already closed")
    st = status(p, drill)
    drill.status, drill.closed_at = "closed", datetime.now(timezone.utc)
    drill.result = {k: st[k] for k in ("counts", "progress", "complete", "elapsed_seconds", "time_to_seconds",
                                       "blocked", "remaining_by_team")}
    camp = p.s.get(RenewalCampaign, drill.campaign_id) if drill.campaign_id else None
    if camp is not None and camp.status == "active":
        camp.status = "closed"
    p.s.flush()
    record(p.s, actor_name, "agility_drill.close", f"drill:{drill.id}", {
        "name": drill.name, "target_ca": drill.target_ca, **{k: drill.result[k] for k in
                                                            ("counts", "progress", "complete", "time_to_seconds")}})
    return status(p, drill)
