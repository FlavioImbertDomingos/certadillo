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
- Audit shipping. Every event leaves the host within seconds to a SIEM
  (syslog over TLS, Splunk HEC, HTTPS) and/or S3 with Object Lock in
  COMPLIANCE mode. Records carry their chain hashes and an Ed25519 signature;
  receivers hold only the public key, so they can verify but not forge. The
  shipper refuses to continue past a rewritten history and raises a critical
  `AuditShippingFailing`. Once shipped, an event can no longer be removed by
  anyone who controls only the Certadillo host.

### Running code inside the application

A deserialization bug, a malicious dependency, a compromised container image.

The process holds everything it needs to work: the key passphrase, the seal
key, the DB credential. With software CA keys, the attacker decrypts them and
walks away with them. That is the worst realistic outcome.

Controls: keep CA keys in an HSM (`CERTADILLO_SIGNER=pkcs11`) or Vault Transit (`vault-transit`). The attacker can
then ask for signatures while they are inside, but cannot export the key, so the
compromise ends when access is cut, and every signature they obtain goes through
code paths that record it. With Vault, the shipped application policy only allows
signing with issuing CA keys, so a compromised server cannot use the root to mint
a new intermediate. Run the root fully offline once it has signed the issuing CA. Pin and hash dependencies.
The shipped compose files run the container as uid 10001 with a read-only root
filesystem, no Linux capabilities, `no-new-privileges` and a process limit, so
code that gets in cannot install tools, persist outside the data volume or
escalate inside the container. Audit events shipped before the compromise stay
out of reach in the SIEM and the Object Lock bucket.

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

### Injecting script into the console

The console shows data that Certadillo did not write: the subject of a
certificate found by a discovery scan is whatever the scanned server chose, and
team names, locations and approval payloads come from API callers. If any of
that ran as script in an administrator's browser, it could read the API key the
console keeps in session storage and act as that administrator.

Three layers stop it. Every value is escaped: the console builds HTML only with
a tagged template that escapes each interpolation, and `render()` refuses
anything else. The page runs under a Content-Security-Policy with
`script-src 'self'` and no inline script, so markup that slipped through still
cannot run event handlers. And the policy turns on Trusted Types, so the browser
throws on any `innerHTML` assignment that does not go through the page's one
named policy. A browser test confirmed each layer on its own: with escaping
switched off the injected `<img onerror>` became markup but never ran, and a raw
`innerHTML` write threw. The knowledge base gets the same policy with its own
Trusted Types names; its page bodies are built from the repository's Markdown.
API responses carry `default-src 'none'`, so nothing served there can render as
a page.

### The build pipeline

A compromised GitHub Action runs with the workflow's token. Third-party actions
are pinned to commit SHAs (Dependabot keeps the pins current), checkout does not
leave the token in `.git/config`, the workflow token is read-only by default,
and only the job that uploads scan results gets `security-events: write`. The
Vault binary used in CI is checked against HashiCorp's published SHA-256 sums.

### Push provisioning widens the blast radius

A Certadillo that installs certificates also holds the means to log in to load
balancers, hosts and clusters. Someone who controls the Certadillo process can
use those credentials directly. That is why targets store only references:
Vault leases, mounted secret files or environment variables that the platform
team scopes and rotates on their own. Prefer `key_location: device` on hosts
that can generate keys, so the key never crosses the network, and keep the SSH
account to the minimum (writing the TLS directory and running one reload
command through sudo). Every run is audited without secrets.

### Windows logon raises the stakes

An issuing CA published to NTAuth can mint smart-card logon certificates for any
account. A stolen key for that CA is a stolen domain. Use a dedicated issuing CA
for the `windows-logon` profile and put only that CA in NTAuth, so a compromise
of the TLS issuing CA stays a TLS problem. Name constraints on each issuing CA
(`CERTADILLO_CA_PERMITTED_DNS`) limit what a stolen key can mint for DNS names.

## Would Go or Rust be safer?

Not by much, for this system. The class of bug a Go or Rust rewrite removes is
memory corruption (buffer overflows, use after free), and Python code does not
have it. The code that parses the most hostile input is pyca/cryptography:
its X.509, CSR and ASN.1 parsing is already written in Rust, and the rest
(PKCS#7, PKCS#12, the primitives) is OpenSSL, the same library a Go or Rust
service would most likely end up linking or reimplementing. A rewrite would trade a tested,
reviewed codebase for a new one, and the bugs that matter in a PKI
(an authorization check in the wrong place, a policy that can be widened, a
dual-control rule with a gap) are logic bugs that move with the rewrite.

What does reduce risk, in order:

1. Keep the CA keys where code cannot take them: an HSM or Vault Transit,
   root offline. A compromise then ends when access is cut.
2. Split signing into its own small process with its own credential, so the
   web-facing process can ask for signatures under policy but never holds key
   material. If any piece is worth writing in Go or Rust, it is this one: a few
   hundred lines, no parsing of client input, easy to review in full.
3. Supply chain: hash-pinned dependencies for the image build, `pip-audit` and
   an SBOM in CI, signed images, Dependabot (already on for Python, Docker and
   Actions).
4. Fuzz the parsers Certadillo owns: the CMP, SCEP and EST message handling
   and the AD CS security descriptor parser.
5. Keep the evidence out of reach: audit shipping to the SIEM and an Object
   Lock bucket, integrity seals, alerts on tampering (done).
6. Run it hardened: non-root, read-only filesystem, no capabilities (done),
   the port only behind the TLS proxy, egress limited to what the drivers need.

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
| P0 | CA keys in an HSM or Vault Transit, never in the application process | Done: `pkcs11` and `vault-transit` signers; the shipped Vault policy keeps the root key unusable by the application, and new CAs are created in a two-person ceremony with an exact-path token |
| P0 | Root fully offline after signing the issuing CA | Roadmap: import an issuing CA signed by an offline root |
| P0 | Dedicated issuing CA for Windows logon; only it in NTAuth | Documented; operator choice |
| P0 | Encrypted, off-host database backups | `deploy.sh` backups are local and unencrypted today; to do |
| P0 | Branch protection and signed commits on `main` | GitHub settings; to do |
| P0 | Application port reachable only through the TLS proxy | `deploy.sh` sets `CERTADILLO_BIND=127.0.0.1` for the Traefik and nginx setups; check with `curl -m5 http://<server-ip>:8080/healthz` from outside (it should not connect) |
| P1 | Append-only audit table (triggers; role split on PostgreSQL) | Done |
| P1 | Audit chain anchored off the host, verifiable against saved anchors | Done |
| P1 | Every audit event shipped off the host (SIEM, S3 Object Lock), signed, with chain-break detection | Done |
| P1 | Integrity seals on principals, approvals and certificate status, with rollback check | Done |
| P1 | Field encryption for EAB keys, CMP secrets and team webhooks (local key or Vault Transit) | Done |
| P1 | Name constraints on new issuing CAs | Done |
| P1 | Alerts: new privileged principal, broken seal or rollback, anchor mismatch | Done |
| P1 | Console and KB: escaping template, CSP without inline script, Trusted Types; deny-all CSP on the API | Done |
| P1 | CI: actions pinned to SHAs, read-only token by default, no persisted checkout credentials | Done |
| P1 | Onboarding approval decided by scope, not the environment label; scope shape checked | Done |
| P1 | LDAP to the directory over validated TLS only | Done |
| P1 | No built-in key passphrase; ceremony policy allowlists key parameters | Done |
| P2 | Container hardening (non-root, read-only filesystem, dropped capabilities) | Done: both compose files; `no-new-privileges` and a pids limit too |
| P2 | Per-principal rate limits, egress restrictions | To do |

## For the public demo

The demo holds fake data, so the realistic losses are the server itself (and
anything else Traefik fronts on it) and the reputation attached to the domain.
There, host hardening, GitHub protection and keeping port 8080 off the internet
matter more than the PKI controls. The demo publishes a read-only auditor key on
purpose; it can read the fake inventory and the audit log, and nothing else.
