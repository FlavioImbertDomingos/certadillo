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

## RenewalCampaignOverdue

A renewal campaign passed its deadline with certificates that were not replaced. The alert names the teams.

1. `GET /api/v1/renewal-campaigns/{id}` lists the remaining certificates with app, team, protocol and expiry.
2. Ask each team why their client did not renew. Usual causes: the client does not check ARI (renew by hand or with `certadillo cert renew-if-due`), it has not checked yet (`Retry-After` up to 6 hours plus its own schedule), or its renewals fail policy (look for `certificate.rejected` in the audit trail).
3. Decide with the incident owner: extend by starting a new campaign for the remainder with a later deadline, or accept the outage risk and request the cutoff with `revoke-remaining` (a second person approves it).

## AdcsTemplateVulnerable

The last AD CS template audit found a critical or high misconfiguration (an ESC finding). This is a weakness in the Microsoft CA, not in Certadillo.

1. `GET /api/v1/adcs/findings` lists the current run: the object (template or CA), the ESC id, who can reach it and a remark. See [Windows and AD CS](guide/20-windows-adcs.md) for what each ESC means.
2. Take it to the AD CS owners. Typical fixes: remove enrollee-supplied-subject or restrict enrollment rights (ESC1/ESC15), remove the Any Purpose or enrollment-agent EKU or gate it behind approval (ESC2/ESC3), tighten the template ACL (ESC4), clear EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6), disable HTTP web enrollment or require channel binding (ESC8), stop the CA omitting the SID extension (ESC16).
3. Re-run the audit (`certadillo adcs audit` or the import endpoint). The alert clears when the finding is gone from the latest run.
4. If a finding is accepted as a known risk, record the decision; the alert re-fires each run until the template is changed.

## AdcsGatewayJobStuck

An AD CS gateway job has been pending or claimed for more than an hour, so a request, revocation or inventory is not reaching the Microsoft CA.

1. `GET /api/v1/adcs/gateway/jobs?status=pending` (and `?status=claimed`) shows the backlog and job types.
2. Check the gateway worker: the scheduled task on the domain-joined host, its network path to the CA, and that its account may still enroll the template (issue), has Certificate Manager rights (revoke) or database read (inventory).
3. A job stuck in `claimed` means a worker took it and did not report back; look for the error in the worker's log. Once fixed, the next run picks up pending work; a permanently failed job can be completed with an `error` so it stops alerting.

## Mass revocation after a key compromise

Revoking first takes every affected service down until someone installs a new certificate. When time allows, replace first and revoke second:

1. **Scope it.** All certificates of an app, a profile, a CA, a key type, or a list of serials. Try the criteria with a short campaign on a test app first if unsure.
2. **Start a renewal campaign** with those criteria (`POST /api/v1/renewal-campaigns`), a deadline, an `explanation_url` for the teams, and `revocation_reason: key_compromise`. For a confirmed compromise use `"immediate": true` so ACME clients renew on their next check. See [Renewal campaigns](guide/19-renewal-campaigns.md).
3. **Tell the owners.** The campaign status lists teams per certificate; non-ACME clients need their owners to renew (EST re-enroll, SCEP RenewalReq, CMP kur, REST renew, or the CLI/Ansible, which follow the ARI window).
4. **Revoke as replacements land.** `revoke-replaced` revokes every certificate that already has a successor; run it as often as you like. OCSP answers at once and the CRL is re-signed on every call.
5. **Cut off at the deadline.** `revoke-remaining` needs a second person. `RenewalCampaignOverdue` fires until the campaign is done or closed.
6. **If an issuing CA key is compromised:** stop issuance from it, stand up a new issuing CA (dual control), run the campaign with `"ca": "<old CA>"` so everything is reissued from the new one, then revoke the old CA at the root (ceremony). Budget for this in advance; it is why leaf lifetimes are short.

When there is no time at all (a key is being used by an attacker right now), revoke immediately with `reason=key_compromise` (no change ticket needed) and accept the outage; start the campaign in parallel so the owners have a clear list.
