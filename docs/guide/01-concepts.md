# Concepts

## The pieces

**Certificate authority (CA).** Certadillo runs a two-level hierarchy. The root CA signs only issuing CAs. The issuing CA (`issuing-ca-1`) signs everything else. In production the root lives on an offline HSM and the issuing CA key lives on an online HSM.

**Registration authority (RA).** The part that decides whether a request may be signed. It knows who owns what, which names each app may use, and which profile applies. Every protocol hands its request to the RA; no protocol signs on its own.

**Team.** A group of people who own applications and receive their alerts. A team has a contact email and, optionally, a chat channel, a webhook for alerts and a cost center.

**App.** Something that needs certificates: a service, a device fleet, a signing pipeline. An app belongs to one team and has:

- an environment: `dev`, `test` or `prod`;
- a profile, which decides what kind of certificate it gets;
- an approved scope: the names it may put in certificates;
- a data classification (`internal`, `confidential`, `pci`) that shows up in the PCI inventory.

**Scope.** The list of names an app may use, set at onboarding. Entries can be:

| Entry | Matches |
| --- | --- |
| `api.cards.bank.internal` | exactly that name |
| `*.cards.bank.internal` | any name under `cards.bank.internal`, at any depth, but not the apex |
| `spiffe://bank.internal/payments/*` | SPIFFE IDs under that path (for the `spiffe-svid` profile) |
| `bank.example` | a mail domain (for the `smime` profile) |

**Profile.** A certificate template with guard rails: extended key usage, allowed key types, default and maximum validity, whether wildcards are allowed, and whether issuance needs a second approver. Profiles live in `default_policies.yaml`.

| Profile | For | Default / max validity | Notes |
| --- | --- | --- | --- |
| `tls-server` | HTTPS and other TLS servers | 30 / 90 days | DNS SAN required, no wildcards |
| `tls-client` | clients doing mTLS, devices | 30 / 90 days | CN must be in scope |
| `mtls-service` | services that are both | 30 / 90 days | server and client EKU |
| `spiffe-svid` | workload identity | 24 / 72 hours | exactly one `spiffe://` URI |
| `code-signing` | release signing | 365 / 365 days | every issuance needs an approver |
| `smime` | email signing and encryption | 365 / 730 days | email SAN in an approved mail domain |

**Principal.** An API caller with a role:

| Role | Can |
| --- | --- |
| `admin` | onboard teams and apps, mint credentials, create principals, request new CAs |
| `approver` | approve or reject requests that need a second person |
| `operator` | onboard, mint credentials, scan, import, revoke |
| `auditor` | read the audit trail, reports and inventory |
| `app` | request, renew and revoke certificates for its own app only |

## Lifetimes and renewal

Certificates are short-lived by default. Short lifetimes limit the damage of a leaked key, keep revocation lists small, and get teams ready for the public TLS schedule (200 days since March 2026, 100 days from March 2027, 47 days from March 2029).

Clients renew when a third of the lifetime is left. Alerts use the same idea: a warning when less than `min(30 days, lifetime/3)` remains, critical under `min(7 days, lifetime/10)`. An alert therefore means the renewal automation did not run.

Renewal always needs a new key pair. Reusing the old key is rejected with `key_reuse`.

## What happens to a request

1. The client authenticates (API key, ACME account, EST Basic auth, SCEP challenge).
2. The RA checks the app is active and the profile matches the onboarding.
3. The policy engine checks the CSR: proof of possession, key strength, every name against the scope, validity.
4. If the profile needs dual control, the request waits for an approver.
5. The issuing CA signs, in the HSM when one is configured.
6. The certificate is stored in the inventory, an audit event is written, and metrics update.
