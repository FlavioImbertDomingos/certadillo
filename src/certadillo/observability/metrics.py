"""Prometheus metrics.

Counters and histograms are updated inline. Inventory gauges come from a
custom collector that reads the database at scrape time, so the numbers are
never stale and survive restarts."""
from __future__ import annotations

from datetime import datetime, timezone

from prometheus_client import REGISTRY, Counter, Histogram
from prometheus_client.core import GaugeMetricFamily

ISSUANCE_TOTAL = Counter(
    "certadillo_issuance_total", "Certificate issuance attempts", ["profile", "protocol", "result"]
)
POLICY_VIOLATIONS = Counter("certadillo_policy_violations_total", "Rejected requests by policy rule", ["rule"])
REVOCATIONS = Counter("certadillo_revocations_total", "Certificates revoked", ["reason"])
OCSP_REQUESTS = Counter("certadillo_ocsp_requests_total", "OCSP responses served", ["status"])
CRL_GENERATED = Counter("certadillo_crl_generated_total", "CRLs generated", ["ca"])
DISCOVERY_SCANS = Counter("certadillo_discovery_targets_total", "Discovery scan targets", ["result"])
NOTIFICATIONS = Counter("certadillo_notifications_total", "Alert notifications sent", ["channel", "result"])
SIGNING_SECONDS = Histogram(
    "certadillo_signing_duration_seconds",
    "Time spent in CA signing operations",
    ["signer"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
)
HTTP_SECONDS = Histogram(
    "certadillo_http_request_duration_seconds", "HTTP request latency", ["method", "route", "status"]
)


class InventoryCollector:
    """Exports per-certificate expiry and aggregate inventory state."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def collect(self):
        from certadillo.audit.log import verify_chain
        from certadillo.db import AlertState, App, CertificateAuthority, Certificate, Team, as_utc

        now = datetime.now(timezone.utc)
        expiry = GaugeMetricFamily(
            "certadillo_certificate_expiry_timestamp_seconds",
            "notAfter of each active certificate (unix seconds)",
            labels=["serial", "common_name", "app", "team", "environment", "source", "profile"],
        )
        lifetime = GaugeMetricFamily(
            "certadillo_certificate_lifetime_seconds",
            "notAfter minus notBefore of each active certificate",
            labels=["serial", "common_name", "app", "team", "environment", "source", "profile"],
        )
        counts = GaugeMetricFamily(
            "certadillo_certificates", "Certificates in inventory", labels=["status", "source"]
        )
        weak = GaugeMetricFamily(
            "certadillo_certificates_quantum_vulnerable",
            "Active certificates using RSA/ECC public keys (need PQC migration)",
            labels=["key_type"],
        )
        ca_exp = GaugeMetricFamily(
            "certadillo_ca_expiry_timestamp_seconds", "notAfter of each CA certificate", labels=["ca"]
        )
        crl_age = GaugeMetricFamily(
            "certadillo_crl_last_generated_timestamp_seconds", "Last CRL generation time", labels=["ca"]
        )
        alerts = GaugeMetricFamily("certadillo_alerts_active", "Open alerts", labels=["rule", "severity"])
        audit_ok = GaugeMetricFamily("certadillo_audit_chain_valid", "1 when the audit hash chain verifies")

        with self._session_factory() as s:
            apps = {a.id: a for a in s.query(App).all()}
            teams = {t.id: t for t in s.query(Team).all()}
            tally: dict[tuple[str, str], int] = {}
            qv: dict[str, int] = {}
            for c in s.query(Certificate).all():
                tally[(c.status, c.source)] = tally.get((c.status, c.source), 0) + 1
                if c.status != "active":
                    continue
                app = apps.get(c.app_id) if c.app_id else None
                team = teams.get(app.team_id) if app else None
                lv = [
                    c.serial_hex,
                    c.common_name,
                    app.name if app else "",
                    team.name if team else "",
                    app.environment if app else "",
                    c.source,
                    c.profile or "",
                ]
                expiry.add_metric(lv, as_utc(c.not_after).timestamp())
                lifetime.add_metric(lv, (as_utc(c.not_after) - as_utc(c.not_before)).total_seconds())
                if c.key_type in ("rsa", "ec") and as_utc(c.not_after) > now:
                    qv[c.key_type] = qv.get(c.key_type, 0) + 1
            for (status, source), n in tally.items():
                counts.add_metric([status, source], n)
            for kt, n in qv.items():
                weak.add_metric([kt], n)
            for ca in s.query(CertificateAuthority).all():
                from cryptography import x509

                cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
                ca_exp.add_metric([ca.name], cert.not_valid_after_utc.timestamp())
                if ca.crl_last_generated:
                    crl_age.add_metric([ca.name], as_utc(ca.crl_last_generated).timestamp())
            open_alerts: dict[tuple[str, str], int] = {}
            for a in s.query(AlertState).filter(AlertState.resolved_at.is_(None)).all():
                open_alerts[(a.rule, a.severity)] = open_alerts.get((a.rule, a.severity), 0) + 1
            for (rule, sev), n in open_alerts.items():
                alerts.add_metric([rule, sev], n)
            audit_ok.add_metric([], 1.0 if verify_chain(s)["valid"] else 0.0)

        yield from (expiry, lifetime, counts, weak, ca_exp, crl_age, alerts, audit_ok)


_registered: InventoryCollector | None = None


def register_inventory_collector(session_factory) -> None:
    global _registered
    if _registered is not None:
        try:
            REGISTRY.unregister(_registered)
        except KeyError:
            pass
    _registered = InventoryCollector(session_factory)
    REGISTRY.register(_registered)
