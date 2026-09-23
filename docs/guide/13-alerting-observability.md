# Alerting and observability

There are two alerting paths on purpose. The built-in evaluator knows which team owns each certificate and routes to them. Prometheus and Alertmanager keep working even if Certadillo itself is down, and can page on that.

## Built-in alerts

The evaluator runs every `CERTADILLO_ALERT_INTERVAL` seconds (300 by default), and on demand:

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -X POST $S/api/v1/alerts/evaluate
curl -s -H "X-API-Key: $OPERATOR_KEY" $S/api/v1/alerts
```

| Alert | Severity | Fires when |
| --- | --- | --- |
| `CertificateExpired` | critical | an active certificate is past notAfter |
| `CertificateExpiringSoon` | critical / warning | less than `min(7d, lifetime/10)` / `min(30d, lifetime/3)` is left |
| `WeakCryptography` | warning | a found certificate has RSA under 2048 or a SHA-1/MD5 signature |
| `UnmanagedCertificate` | info | a found certificate has no owning app |
| `CAExpiring` | warning / critical | a CA certificate has under 365 / 180 days |
| `CRLStale` | critical | an issuing CA's CRL was not re-signed for twice the CRL interval |
| `AuditChainBroken` | critical | the audit hash chain fails verification |
| `ApprovalPending` | warning | an approval has waited over 24 hours |

Each alert is sent when it starts, repeated every 4 hours (critical), 24 hours (warning) or 7 days (info) while it lasts, and sent once more as resolved. Every alert links to its [runbook](../RUNBOOK.md) section.

## Where alerts go

| Channel | Setting | Sends |
| --- | --- | --- |
| Log | always on | every alert as a JSON log line |
| Webhook | `CERTADILLO_WEBHOOK_URLS` (comma separated) | Alertmanager-compatible JSON |
| Slack | `CERTADILLO_SLACK_WEBHOOK_URLS` | a message with severity, summary and runbook link |
| Jira | `CERTADILLO_JIRA_URL`, `_USER`, `_TOKEN`, `_PROJECT` | one issue per new critical alert |
| ServiceNow | `CERTADILLO_SNOW_URL`, `_USER`, `_PASSWORD`, `_ASSIGNMENT_GROUP` | one incident per new critical alert, `correlation_id` = alert fingerprint |
| Team webhook | the team's `webhook_url` from onboarding | that team's alerts only |

## Metrics

`GET /metrics` in Prometheus format. The useful ones:

| Metric | Type | Labels |
| --- | --- | --- |
| `certadillo_certificate_expiry_timestamp_seconds` | gauge | serial, common_name, app, team, environment, source, profile |
| `certadillo_certificate_lifetime_seconds` | gauge | same |
| `certadillo_certificates` | gauge | status, source |
| `certadillo_certificates_quantum_vulnerable` | gauge | key_type |
| `certadillo_ca_expiry_timestamp_seconds` | gauge | ca |
| `certadillo_crl_last_generated_timestamp_seconds` | gauge | ca |
| `certadillo_alerts_active` | gauge | rule, severity |
| `certadillo_audit_chain_valid` | gauge | |
| `certadillo_issuance_total` | counter | profile, protocol, result |
| `certadillo_policy_violations_total` | counter | rule |
| `certadillo_revocations_total` | counter | reason |
| `certadillo_ocsp_requests_total` | counter | status |
| `certadillo_signing_duration_seconds` | histogram | signer (software, pkcs11) |
| `certadillo_http_request_duration_seconds` | histogram | method, route, status |

Inventory gauges are read from the database at scrape time, so they survive restarts and match the database exactly.

## Prometheus rules, Alertmanager, Grafana

`deploy/prometheus/rules/certadillo.rules.yml` has 11 rules (validated with `promtool` in CI), including `CertadilloDown`, `SigningLatencyHigh` (HSM saturation), `IssuanceErrorsHigh` and `NotificationFailures`. `deploy/alertmanager/alertmanager.yml` routes critical alerts to on-call and anything with a `team` label to the owning team; fill in the receivers.

The Grafana dashboard (`deploy/grafana/dashboards/certadillo.json`) shows active, expired and critical counts, quantum-vulnerable certificates, audit chain state, the 25 soonest expiries, inventory by source, CA expiry, issuance by protocol, policy rejections by rule, signing latency, OCSP traffic and API latency.

## Logs

One JSON object per line on stdout, ready for Splunk, Elastic or Loki:

```json
{"ts": "2026-09-23T22:28:17.825+00:00", "level": "info", "logger": "certadillo.audit", "msg": "audit",
 "request_id": "461e59da2ab34245",
 "audit": {"actor": "app:card-api:1", "action": "certificate.issue", "target": "7b4c29...", "protocol": "rest"}}
```

Every response carries `X-Request-ID`; send your own to trace a request across systems.
