# Troubleshooting and policy errors

## Policy rules

A rejected request returns every rule that failed (REST: `422`, EST: `400` with the text, ACME: `badCSR` or `rejectedIdentifier`, SCEP: a FAILURE CertRep plus an audit event, CMP: a rejection with the rules in the status text). Each rejection is also written to the audit trail as `certificate.rejected`.

| Rule | What it means | Fix |
| --- | --- | --- |
| `csr_format` | the CSR is not PEM PKCS#10 | send `-----BEGIN CERTIFICATE REQUEST-----` |
| `csr_signature` | the CSR signature does not verify | regenerate the CSR with the matching key |
| `unknown_profile` | the profile does not exist | check `GET /api/v1/profiles` |
| `profile_not_onboarded` | the request asks for a profile other than the app's | omit `profile`, or onboard another app |
| `key_strength` | RSA key below the profile minimum | use P-256/P-384, or RSA-3072 |
| `key_curve` | EC curve not allowed (for example P-521) | use P-256 or P-384 |
| `key_type` | Ed25519 or another type the profile does not allow | use EC or RSA for X.509 |
| `key_reuse` | a renewal reused the old key | generate a new key pair |
| `san_required` | no DNS name at all in a TLS server profile | add `subjectAltName=DNS:...` or a CN |
| `san_scope` | a DNS name outside the app's approved domains | fix the name, or ask for the app's scope to change |
| `cn_scope` | a host-name CN outside the scope (client profiles) | same |
| `wildcard` | `*.` name in a profile that forbids wildcards | list the real names |
| `ip_san` | IP address SAN | use DNS names |
| `uri_san` | URI SAN outside the `spiffe-svid` profile | remove it |
| `email_san` | email SAN outside the `smime` profile | remove it |
| `email_required` / `email_scope` | S/MIME without an email, or in another mail domain | add an address in an approved domain |
| `spiffe_id` | not exactly one `spiffe://` URI | one URI SAN per SVID |
| `spiffe_trust_domain` | the ID is in another trust domain | use `spiffe://bank.internal/...` |
| `spiffe_scope` | the ID is outside the app's pattern | fix the path |
| `validity` | longer than the profile maximum | ask for less, or leave it out for the default |
| `change_ref` | staff revoking a prod certificate without a ticket | pass `"change_ref": "CHG..."`, or use `key_compromise` |
| `ssh_type` / `ssh_principals` | bad SSH request | `cert_type` is `user` or `host`; give at least one principal |

## Common problems

**401 missing or invalid API key.** The key is wrong, deactivated, or belongs to an app that is still `pending_approval` or was `rejected`.

**403 on a read endpoint with an app key.** App keys can only see their own app and certificates. Use a staff key for inventory-wide views.

**403 when approving.** Only the `approver` role approves, never the requester, and never with a key the requester created.

**ACME `externalAccountRequired`.** Register with `--eab-kid` and `--eab-hmac-key` from `POST /api/v1/apps/{id}/acme-eab`. Each EAB works once.

**ACME http-01 stays `invalid`.** Certadillo fetches `http://<name>/.well-known/acme-challenge/<token>` from where it runs. Check DNS and firewalls from the Certadillo host, switch the client to dns-01, or use `CERTADILLO_ACME_CHALLENGE=ra-scope` for internal-only names.

**ACME dns-01 stays `invalid`.** The challenge error names the record and the DNS view that answered. `does not exist in the default view` usually means the zone is internal and has no entry in `CERTADILLO_ACME_DNS_VIEWS`. `no TXT record ... matches` means the record is missing, stale, or was written to a different view than the one Certadillo asks; query that view's resolver with `dig TXT _acme-challenge.<name>`.

**ACME `alreadyReplaced`.** The order's `replaces` names a certificate that was already renewed, or another open order is renewing it. Drop `replaces`, or finish the other order.

**A client does not renew during a campaign.** It checks ARI again only after `Retry-After` (up to 6 hours) and on its own schedule. See [how long clients take to notice](19-renewal-campaigns.md#how-long-clients-take-to-notice).

**EST 401 with a client certificate.** The header from the load balancer was ignored: the request lacked `X-Certadillo-Proxy-Auth` or did not come from `CERTADILLO_EST_TRUSTED_PROXIES`, or the certificate is revoked, superseded, expired, or from an issuer that is not registered. The log line `client certificate header ignored` means the first case.

**CMP `signerNotTrusted`.** For a MAC-protected message the reference is unknown, used or expired; mint a new secret. For a signed one, the certificate is not current (after `kur`, sign with the new one).

**SCEP FAILURE with `badRequest`.** Read the reason in the audit trail; the [SCEP page](07-scep.md#troubleshooting) lists the usual ones.

**`openssl verify` fails.** Pass the issuing CA as untrusted and the root as the trust anchor:
`openssl verify -CAfile root.pem -untrusted issuing.pem leaf.pem`.

**An expired certificate keeps alerting after it was replaced.** If it was discovered, rescan the endpoint; seeing the new certificate there retires the old one. If it was issued here, renew through the platform (that marks it `superseded`) or revoke it.

**`AuditChainBroken`.** Someone changed the database outside Certadillo. Follow the [runbook](../RUNBOOK.md#auditchainbroken); do not "fix" the table.

## Getting help

Collect the `X-Request-ID` from the failing response and search the JSON logs for it. It ties the HTTP request, the policy decision and the audit event together.
