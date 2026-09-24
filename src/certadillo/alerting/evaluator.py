"""Built-in alert evaluation.

Prometheus + Alertmanager (deploy/prometheus/rules) is the primary alerting
path in production. This evaluator runs inside the service as well, so a
small install with no Prometheus still gets expiry alerts, and so alerts can
be routed per team using onboarding data Prometheus does not have."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509

from certadillo.alerting.notifiers import Alert, SlackNotifier, WebhookNotifier, deliver
from certadillo.audit.log import verify_chain
from certadillo.db import (
    AdcsFinding,
    AdcsJob,
    AlertState,
    App,
    ApprovalRequest,
    Certificate,
    CertificateAuthority,
    RenewalCampaign,
    Team,
    as_utc,
)
from certadillo.policy.engine import grade_certificate

RUNBOOK = os.environ.get("CERTADILLO_RUNBOOK_URL", "https://github.com/FlavioImbertDomingos/certadillo/blob/main/docs/RUNBOOK.md#")
REPEAT = {"critical": timedelta(hours=4), "warning": timedelta(hours=24), "info": timedelta(days=7)}


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:32]


def expiry_state(not_before, not_after, settings, now=None) -> str | None:
    """expired | critical | warning | None. Thresholds scale with lifetime so a
    24h SVID or a 47-day certificate does not warn from the moment it is issued."""
    now = now or datetime.now(timezone.utc)
    left = as_utc(not_after) - now
    lifetime = as_utc(not_after) - as_utc(not_before)
    if left <= timedelta(0):
        return "expired"
    if left <= min(timedelta(days=settings.expiry_critical_days), lifetime / 10):
        return "critical"
    if left <= min(timedelta(days=settings.expiry_warning_days), lifetime / 3):
        return "warning"
    return None


def evaluate(session, settings, policies: dict) -> list[Alert]:
    now = datetime.now(timezone.utc)
    apps = {a.id: a for a in session.query(App).all()}
    teams = {t.id: t for t in session.query(Team).all()}
    out: list[Alert] = []

    def labels_for(c: Certificate) -> dict:
        app = apps.get(c.app_id) if c.app_id else None
        team = teams.get(app.team_id) if app else None
        return {
            "serial": c.serial_hex,
            "common_name": c.common_name,
            "not_after": as_utc(c.not_after).isoformat(),
            "app": app.name if app else "",
            "team": team.name if team else "",
            "environment": app.environment if app else "",
            "location": c.location or "",
            "source": c.source,
        }

    for c in session.query(Certificate).filter(Certificate.status == "active").all():
        left = as_utc(c.not_after) - now
        lab = labels_for(c)
        where = f" at {c.location}" if c.location else ""
        state = expiry_state(c.not_before, c.not_after, settings, now)
        if state == "expired":
            out.append(Alert(_fp("expired", c.fingerprint_sha256), "CertificateExpired", "critical",
                             f"{c.common_name}{where} expired {as_utc(c.not_after):%Y-%m-%d %H:%M} UTC", lab,
                             runbook=RUNBOOK + "certificateexpired"))
        elif state == "critical":
            out.append(Alert(_fp("expiring", c.fingerprint_sha256), "CertificateExpiringSoon", "critical",
                             f"{c.common_name}{where} expires in {left.days}d {left.seconds // 3600}h", lab,
                             runbook=RUNBOOK + "certificateexpiringsoon"))
        elif state == "warning":
            out.append(Alert(_fp("expiring", c.fingerprint_sha256), "CertificateExpiringSoon", "warning",
                             f"{c.common_name}{where} expires in {left.days} days", lab,
                             runbook=RUNBOOK + "certificateexpiringsoon"))
        if c.source in ("discovered", "imported"):
            cert = x509.load_pem_x509_certificate(c.pem.encode())
            weak = [f for f in grade_certificate(cert, policies) if f[0] in ("weak_key", "weak_signature")]
            if weak:
                out.append(Alert(_fp("weak", c.fingerprint_sha256), "WeakCryptography", "warning",
                                 f"{c.common_name}{where}: " + ", ".join(m for _, m in weak), lab,
                                 runbook=RUNBOOK + "weakcryptography"))
            if not c.app_id:
                out.append(Alert(_fp("unmanaged", c.fingerprint_sha256), "UnmanagedCertificate", "info",
                                 f"{c.common_name}{where} has no owner; assign it to an onboarded app", lab,
                                 runbook=RUNBOOK + "unmanagedcertificate"))

    for ca in session.query(CertificateAuthority).all():
        cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        left = cert.not_valid_after_utc - now
        if left < timedelta(days=365):
            sev = "critical" if left < timedelta(days=180) else "warning"
            out.append(Alert(_fp("ca", ca.name), "CAExpiring", sev, f"CA {ca.name} expires in {left.days} days",
                             {"ca": ca.name}, runbook=RUNBOOK + "caexpiring"))
        if not ca.is_root:
            last = as_utc(ca.crl_last_generated)
            if last is None or now - last > timedelta(hours=settings.crl_interval_hours * 2):
                out.append(Alert(_fp("crl", ca.name), "CRLStale", "critical",
                                 f"CRL for {ca.name} has not been published since {last or 'never'}",
                                 {"ca": ca.name}, runbook=RUNBOOK + "crlstale"))

    chain = verify_chain(session)
    if not chain["valid"]:
        out.append(Alert(_fp("audit"), "AuditChainBroken", "critical",
                         f"audit hash chain broken at event {chain['broken_at']}", {},
                         runbook=RUNBOOK + "auditchainbroken"))

    for camp in session.query(RenewalCampaign).filter_by(status="active").all():
        if now > as_utc(camp.window_end):
            from certadillo.enrollment.ari import campaign_status

            st = campaign_status(session, camp)
            left = st["counts"]["remaining"]
            if left:
                owners = sorted({c["team"] for c in st["certificates"] if c["state"] == "remaining" and c["team"]})
                out.append(Alert(_fp("campaign", camp.id), "RenewalCampaignOverdue", "critical",
                                 f"renewal campaign '{camp.name}' passed its deadline with {left} certificate(s) "
                                 f"not replaced" + (f" (teams: {', '.join(owners)})" if owners else ""),
                                 {"campaign": camp.id}, runbook=RUNBOOK + "renewalcampaignoverdue"))

    run_id, adcs_findings = _latest_adcs(session)
    for f in adcs_findings:
        if f.severity not in ("critical", "high"):
            continue
        sev = "critical" if f.severity == "critical" else "warning"
        out.append(Alert(_fp("adcs", f.object_type, f.object_name, f.esc), "AdcsTemplateVulnerable", sev,
                         f"{f.esc} on {f.object_type} '{f.object_name}': {f.title}",
                         {"esc": f.esc, "object": f.object_name, "object_type": f.object_type, "run": run_id},
                         runbook=RUNBOOK + "adcstemplatevulnerable"))

    for job in session.query(AdcsJob).filter(AdcsJob.status.in_(["pending", "claimed"])).all():
        if now - as_utc(job.created_at) > timedelta(hours=1):
            out.append(Alert(_fp("adcsjob", job.id), "AdcsGatewayJobStuck", "warning",
                             f"AD CS gateway {job.job_type} job #{job.id} still {job.status} after "
                             f"{(now - as_utc(job.created_at)).seconds // 3600 + 1}h; check the gateway worker",
                             {"job": job.id, "type": job.job_type}, runbook=RUNBOOK + "adcsgatewayjobstuck"))

    for req in session.query(ApprovalRequest).filter_by(status="pending").all():
        if now - as_utc(req.created_at) > timedelta(hours=24):
            out.append(Alert(_fp("approval", req.id), "ApprovalPending", "warning",
                             f"approval #{req.id} ({req.action}) waiting since {as_utc(req.created_at):%Y-%m-%d}",
                             {"approval": req.id}, runbook=RUNBOOK + "approvalpending"))
    return out


def _latest_adcs(session):
    """Findings from the most recent AD CS audit run only."""
    row = session.query(AdcsFinding).order_by(AdcsFinding.created_at.desc()).first()
    if row is None:
        return None, []
    return row.run_id, session.query(AdcsFinding).filter_by(run_id=row.run_id).all()


def reconcile(session, settings, policies: dict, notifiers: list, team_notifier_factory=None) -> dict:
    """Update alert state, send new/repeat/resolved notifications."""
    now = datetime.now(timezone.utc)
    firing = {a.fingerprint: a for a in evaluate(session, settings, policies)}
    to_send: list[Alert] = []
    known = {s.fingerprint: s for s in session.query(AlertState).all()}

    for fp, a in firing.items():
        st = known.get(fp)
        if st is None or st.resolved_at is not None:
            if st is None:
                st = AlertState(fingerprint=fp, rule=a.rule, severity=a.severity, summary=a.summary, labels=a.labels)
                session.add(st)
            st.resolved_at = None
            st.first_seen = now
            st.last_notified = now
            to_send.append(a)
        else:
            st.summary, st.labels = a.summary, a.labels
            if st.severity != a.severity or now - as_utc(st.last_notified or st.first_seen) >= REPEAT[a.severity]:
                st.severity = a.severity
                st.last_notified = now
                to_send.append(a)

    for fp, st in known.items():
        if fp not in firing and st.resolved_at is None:
            st.resolved_at = now
            to_send.append(Alert(fp, st.rule, st.severity, st.summary, st.labels, status="resolved"))
    session.flush()

    for n in notifiers:
        deliver(n, to_send)
    # Per-team routing from onboarding data.
    by_team: dict[str, list[Alert]] = {}
    for a in to_send:
        if a.labels.get("team"):
            by_team.setdefault(a.labels["team"], []).append(a)
    for team_name, alerts in by_team.items():
        team = session.query(Team).filter_by(name=team_name).one_or_none()
        if team and team.webhook_url:
            factory = team_notifier_factory or _team_notifier
            deliver(factory(team.webhook_url), alerts)
    return {"firing": len(firing), "notified": len(to_send)}


def _team_notifier(url: str):
    return SlackNotifier(url) if "hooks.slack.com" in url else WebhookNotifier(url)
