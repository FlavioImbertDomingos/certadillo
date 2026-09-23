# Security model

## Assets

| Asset | Why it matters |
| --- | --- |
| Root and issuing CA private keys | Anyone holding them can mint trusted identities for the whole estate |
| SSH CA key | Same, for server access |
| API keys and EAB credentials | Let a caller obtain certificates inside an app's scope |
| Audit trail | Evidence for auditors and incident response |
| Inventory | Tells an attacker where the weak endpoints are |

## Threats and controls

| Threat | Control in this codebase |
| --- | --- |
| CA key theft | PKCS#11 signer: keys generated on the HSM as `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false` (asserted in tests). Software keys are PKCS#8 encrypted and meant for labs only. |
| Mis-issuance to the wrong name | Every DNS SAN, SPIFFE ID, email address and host-name CN is checked against the app's approved scope. URI and email SANs are only accepted by the profiles meant for them. ACME orders outside the scope are refused before any challenge. |
| A single insider issuing code-signing certs or new CAs | Maker-checker: only the approver role decides, the requester cannot approve, and an approver credential minted by the requester cannot approve that requester's requests. Approvals are audited. Production onboarding also needs a second person. |
| Stolen app credential | Scope-limited to one app's names and profile, and no read access to other apps or reports; short certificate lifetimes; `POST /api/v1/principals/{name}/deactivate`; renewal forces a new key pair. |
| Replay of ACME requests | Single-use nonces, committed as spent before the request is processed; JWS `url` must match the request path. |
| Weak keys submitted by clients | Minimum RSA size, allowed curves, CSR signature check (proof of possession). |
| Tampering with the audit log | SHA-256 hash chain, verify endpoint, `certadillo_audit_chain_valid` metric and a critical alert. Appends are serialized with a PostgreSQL advisory lock, and `prev_hash` is unique so a race fails instead of forking the chain. Ship events to a SIEM or WORM bucket as the durable copy. |
| Silent expiry | Lifetime-aware expiry alerts, per-team routing, Prometheus rules as an independent path. |
| Revocation not visible to relying parties | OCSP answers from live state; a new CRL is signed on every revocation and on a timer; CRLStale alert. |
| Rogue certificates on the network | Discovery scans and connectors; unowned and weak certificates raise alerts. |

## Known gaps in this MVP

These are listed so nobody deploys the MVP to production thinking they are handled.

1. Human authentication is by API key. Production should put OIDC (Entra ID, Okta) in front of the console and API and map groups to roles.
2. EST relies on HTTP Basic with the app key. RFC 7030 expects TLS client authentication for re-enrollment; terminate mTLS at the load balancer and forward the verified identity.
3. ACME `http-01` validation follows redirects and uses the platform's network position (it runs off the event loop, so a slow target only delays its own order). Restrict egress or use `ra-scope` mode for purely internal names.
4. EAB HMAC keys are stored in the database in clear (single use). Encrypt them at rest or keep only a hash plus a short validity window.
5. No rate limiting. Put the API behind a gateway with per-principal limits.
6. The SSH CA key is a software key. Move it to the HSM (OpenSSH supports PKCS#11 CA keys through `ssh-keygen -D`) or to Vault's SSH engine.
7. The housekeeping loop runs in every replica. Run it in one replica or as a CronJob until leader election lands.
8. Each HSM signature opens a new PKCS#11 session. Fine for hundreds of certificates a minute, not for bulk reissuance.
9. `certadillo init` creates the root online. Production roots come from an offline key ceremony (see the runbook).

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Please do not file public issues for vulnerabilities.
