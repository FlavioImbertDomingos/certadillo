# Runbook

Each alert links here by anchor. Every section says what the alert means, how to check it, and what to do.

## CertificateExpired

A certificate in inventory is past notAfter and has not been revoked or replaced. If it was discovered on the network (`source=discovered`, `location` set), clients connecting to that endpoint are failing now.

1. Open the certificate: `GET /api/v1/certificates?status=active&expiring_within_days=0`.
2. If `location` is set, confirm it is still served: `openssl s_client -connect <location> -servername <name> </dev/null | openssl x509 -noout -enddate`.
3. Owned certificate: renew through the app's automation (`certadillo cert renew-if-due --force`, the Ansible role, or ACME). Unowned certificate: find the owner (see UnmanagedCertificate) and issue a replacement.
4. Once replaced, the alert resolves: renewal marks the old certificate superseded, and a rescan that finds a new certificate at the same endpoint retires the old discovered one.
5. Open a problem ticket: an expired certificate in production means renewal automation failed or never existed.

## CertificateExpiringSoon

The certificate is inside its renewal window (warning) or close to expiry (critical). Thresholds scale with lifetime; see the architecture doc.

- Warning: automation should have renewed by now. Check the client's renewal job (systemd timer, cron, cert-manager `Certificate` status, certbot logs).
- Critical: renew by hand now, then fix automation. The alert resolves when the replacement is issued.

## WeakCryptography

A discovered or imported certificate uses RSA below 2048 bits or a SHA-1/MD5 signature. Replace it with a P-256/P-384 or RSA-3072 certificate from the platform and onboard its owner.

## UnmanagedCertificate

Discovery found a certificate with no owning app. Assign it: `POST /api/v1/certificates/{id}/assign {"app_id": N}`, or onboard the team first. Owned certificates route alerts to the team's webhook.

## CAExpiring

A CA certificate expires within a year (critical within 180 days). Leaf certificates cannot outlive their issuer, so issuance lengths start shrinking.

1. Create a new issuing CA through dual control: `POST /api/v1/cas {"name": "issuing-ca-2"}`, approved by a second person.
2. New issuance uses the newest issuing CA. Keep the old CA publishing CRLs until its last leaf expires.
3. For the root, follow the root key ceremony below.

## CRLStale

The CRL for an issuing CA has not been re-signed for too long (built-in evaluator: twice `CERTADILLO_CRL_INTERVAL_HOURS`; Prometheus rule: 24 hours). Relying parties that hard-fail on CRL expiry will start rejecting certificates when the published CRL's nextUpdate passes (24 hours by default).

1. Check the housekeeping loop in the logs (`housekeeping failed`).
2. Publish by hand: `certadillo alerts run`. (`GET /pki/crl/<ca>.crl` serves the cached CRL and only re-signs once it is past nextUpdate.)
3. If signing fails, check the HSM session and PIN (see SigningLatencyHigh).

## AuditChainBroken

`/api/v1/audit/verify` reports a hash mismatch: a row in `audit_events` was modified or deleted outside the application. Treat it as a security incident.

1. Do not fix the table. Snapshot the database and preserve logs.
2. Compare with the copy shipped to the SIEM to find the altered event (`broken_at` gives the first bad ID).
3. Rotate all API keys and database credentials; review database access logs.

## ApprovalPending

A maker-checker request has waited more than 24 hours. Ping the approver group; stale approvals block production onboarding and code signing.

## IssuanceErrorsHigh

More than a quarter of requests are rejected by policy over 15 minutes. Usually one client is misconfigured (wrong SAN, reused key, wrong profile). Break down `certadillo_policy_violations_total` by rule and check the `certificate.rejected` audit events for the app name.

## SigningLatencyHigh

p95 signing time is above 500 ms. For `signer="pkcs11"`, look at HSM partition load, network latency to the HSM, and session limits. Each signature opens a session today; session pooling is on the roadmap.

## CertadilloDown

Prometheus cannot scrape the service. OCSP, CRL downloads and enrollment are down. Relying parties with soft-fail OCSP keep working; hard-fail clients do not. Restart the container, check database connectivity and `readyz`.

## NotificationFailures

An alert channel is rejecting deliveries. Check the webhook URL, Jira token or ServiceNow credentials. Alerts are still visible in the console and in Alertmanager.

## Root key ceremony

Run with at least two custodians and an auditor, on an offline machine with the root HSM attached. Record the whole ceremony.

1. Initialise the HSM partition; custodians set their PED keys or smart cards (M of N).
2. Generate the root key on the HSM, non-extractable.
3. Create the self-signed root (P-384, 20 years, pathlen 1). Record its SHA-256 fingerprint in the ceremony log.
4. Import the issuing CA CSR produced on the online HSM, sign it (5 years, pathlen 0), export the certificate.
5. Sign an initial root CRL (30 days) and schedule the next CRL ceremony before it expires.
6. Store the root HSM and backups in separate safes.

## Mass revocation after a key compromise

1. Identify the scope: all certificates of an app (`GET /api/v1/certificates?app_id=N&status=active`) or of a CA.
2. Revoke with `reason=key_compromise` (no change ticket required for this reason). OCSP reflects it at once; a new CRL is published on every revoke.
3. Push new certificates through the app's automation, forcing a new key.
4. If an issuing CA key is compromised: stop issuance, revoke the CA at the root (ceremony), stand up a new issuing CA, reissue everything. Budget for this in advance; it is why leaf lifetimes are short.
