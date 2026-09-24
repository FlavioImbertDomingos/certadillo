# Threat model

This document looks at Certadillo from the attacker's side: what they want,
how they would get it, and which controls stop them. It covers the code in this
repository and the reference deployment in `deploy/server` (the public demo at
certadillo.com). [SECURITY.md](SECURITY.md) lists controls per threat; this file
ranks the assets and walks the attack paths end to end.

## What an attacker wants

| Asset | Where it lives | Impact if taken | Recovery |
| --- | --- | --- | --- |
| Root CA private key | HSM (PKCS#11) or an encrypted file in the key volume | Mint any certificate, including new issuing CAs, trusted everywhere the root is | Replace the root and re-trust it everywhere; reissue the whole estate |
| Issuing CA private keys | Same as above | Mint any leaf certificate the root's trust allows. If the CA is in NTAuth (smart-card logon), mint a logon certificate for any account, a Domain Admin included | Revoke the CA at the root, stand up a new one, reissue everything it signed |
| RA keys (OCSP responder, SCEP RA, CMP RA) | Same as above | OCSP: say "good" for a revoked certificate. SCEP: decrypt enrollment envelopes. CMP: answer as the RA | Revoke and rotate; limited to what that role can sign |
| SSH CA key | Software key (known gap) | Log in to any host that trusts it, as any principal | Replace the CA in every `TrustedUserCAKeys` |
| Admin and approver credentials | API keys (SHA-256 hash in the DB), or tokens from the IdP | Onboard apps, approve dual-control requests, revoke anything | Deactivate and rotate |
| The database | PostgreSQL | Inventory (a map of the internal estate), approvals, revocation status, the audit trail, encrypted secrets | Restore from backup; integrity is the harder problem |
| The deploy path | GitHub `main`, the deploy SSH key, the server | Whatever runs in production | Rebuild the host |

The CA keys are the only assets whose loss cannot be undone by rotating a
secret. Everything else in this document is about keeping an attacker who gets
something smaller from turning it into a CA key, or into a forged decision.

## Attack paths

### Reading the database

SQL injection, a leaked dump, a stolen backup, a read replica left open.

They get: every certificate and its owner (a map of the estate), the audit
history, API key hashes (useless: keys are 256-bit random, so the hash cannot be
reversed), and the encrypted secret columns. They do not get CA keys, which are
never in the database.

Controls: secret columns (ACME EAB keys, CMP secrets, team webhook URLs) are
encrypted with a key that is not in the database, either derived from the key
passphrase or held in Vault Transit. Backups must be encrypted and stored off
the host.

### Writing to the database

A DB credential stolen from a config file, a rogue DBA, SQL injection with write
access.

Without controls, this is severe. Dual control, revocation status and the
principal list are all rows: an attacker could insert their own admin, mark
their own request approved, flip a revoked certificate back to active so OCSP
answers "good", then recompute the audit hash chain so the chain still
verifies.

Controls:

- Integrity seals. Principals, approval requests and certificate status carry
  an HMAC over their security-relevant fields, computed with a key that is not
  in the database. Every change the application makes reseals the row; a change
  made directly in SQL does not. A principal with a broken seal cannot log in.
  An approval with a broken seal is refused. A certificate with a broken seal is
  treated as revoked by OCSP and the CRL (fail closed), and
  `IntegritySealBroken` fires.
- Rollback check. A seal stops forgery but not rollback: an attacker holding an
  old copy of a row could restore its old, validly sealed state (a revoked
  certificate put back to "active"). Housekeeping cross-checks every active
  certificate against the audit trail's revocation events, and any mismatch
  fires the same alert.
- Append-only audit table. Triggers reject UPDATE and DELETE on
  `audit_events`. On PostgreSQL, `certadillo db harden` also moves ownership to
  a separate migration role and leaves the application role with SELECT and
  INSERT only, so the application's own credential cannot drop the trigger.
- Anchored audit chain. Once a day the chain head (last event id and hash) is
  sent off the host, to a webhook or an append-only file you ship to WORM
  storage. `certadillo audit verify --anchors` checks the current chain against
  every saved anchor, so a rewritten history no longer verifies.

### Running code inside the application

A deserialization bug, a malicious dependency, a compromised container image.

The process holds everything it needs to work: the key passphrase, the seal
key, the DB credential. With software CA keys, the attacker decrypts them and
walks away with them. That is the worst realistic outcome.

Controls: keep CA keys in an HSM, a cloud KMS or Vault Transit. The attacker can
then ask for signatures while they are inside, but cannot export the key, so the
compromise ends when access is cut, and every signature they obtain goes through
code paths that record it. Run the root offline: after it signs the issuing CA,
it should not be reachable by the application at all. Pin and hash dependencies,
run the container as non-root with a read-only filesystem.

### Root on the host

Everything in the previous section, plus `.env`, the key volume, database
backups and whatever else the server runs. On the reference deployment Traefik
also fronts other sites.

Controls: the same key custody as above (a host compromise cannot export an HSM
key), backups encrypted to a key that is not on the host, and a separate host for
Vault if Vault holds the CA or seal keys. Vault on the same host adds audit and
policy but little protection against host root.

### Changing the code

`deploy.sh` ships whatever is on `main`. A stolen GitHub token or a merged
malicious pull request becomes production.

Controls: branch protection on `main` with required review, required signed
commits (signed with your own key), and required CI. The deploy SSH key should
be used only for deploys, stored in a hardware token or a password manager, and
the server should accept it only from known addresses.

### Abusing identity

With OIDC enabled, a mis-set role map or an issuer that is too broad hands out
access. The Entra preset pins a single tenant's issuer rather than the
multi-tenant `common` endpoint for this reason. Tokens are checked for
signature, issuer, audience, expiry and algorithm; any failure is a 401.

### Windows logon raises the stakes

An issuing CA published to NTAuth can mint smart-card logon certificates for any
account. A stolen key for that CA is a stolen domain. Use a dedicated issuing CA
for the `windows-logon` profile and put only that CA in NTAuth, so a compromise
of the TLS issuing CA stays a TLS problem. Name constraints on each issuing CA
(`CERTADILLO_CA_PERMITTED_DNS`) limit what a stolen key can mint for DNS names.

## Encryption: what each layer covers

| Layer | Stops | Does not stop |
| --- | --- | --- |
| Volume or disk encryption | A stolen disk or snapshot | Anyone on the running host; SQL access |
| TLS and SCRAM to PostgreSQL | Sniffing between the application and the database | Anything else |
| Field encryption of secret columns (key outside the database) | DB read and backup theft for those columns | A DB writer; code running in the application |
| Encrypted, off-host backups | Backup theft | Nothing live |
| Integrity seals and the append-only, anchored audit trail | A DB writer forging admins, approvals, revocation status or history | Code running in the application (it holds the seal key) |

Community PostgreSQL has no built-in transparent data encryption, so the
practical combination is volume encryption, field encryption for secrets, and
integrity controls for the rows that decide access. Encryption alone never gives
integrity.

## Controls and status

| Priority | Control | Status |
| --- | --- | --- |
| P0 | CA keys in an HSM, cloud KMS or Vault Transit; root offline after signing the issuing CA | PKCS#11 supported; Vault Transit and offline-root ceremony on the roadmap |
| P0 | Dedicated issuing CA for Windows logon; only it in NTAuth | Documented; operator choice |
| P0 | Encrypted, off-host database backups | `deploy.sh` backups are local and unencrypted today; to do |
| P0 | Branch protection and signed commits on `main` | GitHub settings; to do |
| P0 | Application port reachable only through the TLS proxy | `deploy.sh` sets `CERTADILLO_BIND=127.0.0.1` for the Traefik and nginx setups; check with `curl -m5 http://<server-ip>:8080/healthz` from outside (it should not connect) |
| P1 | Append-only audit table (triggers; role split on PostgreSQL) | Done |
| P1 | Audit chain anchored off the host, verifiable against saved anchors | Done |
| P1 | Integrity seals on principals, approvals and certificate status, with rollback check | Done |
| P1 | Field encryption for EAB keys, CMP secrets and team webhooks (local key or Vault Transit) | Done |
| P1 | Name constraints on new issuing CAs | Done |
| P1 | Alerts: new privileged principal, broken seal or rollback, anchor mismatch | Done |
| P2 | Container hardening (non-root, read-only filesystem, dropped capabilities) | To do |
| P2 | Per-principal rate limits, egress restrictions | To do |

## For the public demo

The demo holds fake data, so the realistic losses are the server itself (and
anything else Traefik fronts on it) and the reputation attached to the domain.
There, host hardening, GitHub protection and keeping port 8080 off the internet
matter more than the PKI controls. The demo publishes a read-only auditor key on
purpose; it can read the fake inventory and the audit log, and nothing else.
