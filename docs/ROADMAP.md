# Roadmap

Ordered by what a bank PKI team would ask for next. Each item names the
interface it plugs into so contributors can pick one up.

## Status at a glance

| Area | Status | Done |
| --- | --- | --- |
| [Phase 2: enrollment coverage](#phase-2-enrollment-coverage) | Core done, extras open | 4 of 8 |
| [Phase 3: Windows and AD CS](#phase-3-windows-and-ad-cs) | Core done, auto-enrollment open | 3 of 4 |
| [Phase 3: more issuers and inventory connectors](#phase-3-more-issuers-and-inventory-connectors) | Mostly open | 4 of 10 |
| [Phase 3.5: zero-trust access](#phase-35-zero-trust-access) | Done (console SSO is in Phase 6) | 4 of 4 |
| [Security hardening](#security-hardening-from-the-threat-model) | P1 done, four items open | 6 of 10 |
| [Phase 7: enterprise CLM features](#phase-7-enterprise-clm-features) | Four done; console, three push targets, code signing, SSH keys and follow-ups open | 4 of 12 |
| [Phase 4: workload identity](#phase-4-workload-identity) | Not started | 0 of 3 |
| [Phase 5: post-quantum](#phase-5-post-quantum) | Not started | 0 of 4 |
| [Phase 6: production hardening](#phase-6-production-hardening) | Not started | 0 of 8 |
| Total | | 25 of 63 |

Below, every item is marked done (shipped and tested) or open (not built
yet). GitHub shows them as ticked and empty checkboxes, the knowledge base as
Done and Open tags. The full list of what works today, with the test that proves
each row, is the table in the [README](../README.md#what-works-today).

## Phase 2: enrollment coverage

Done:

- [x] ACME dns-01 with split-horizon resolver views and CNAME delegation, wildcards, ARI (RFC 9773) with renewal campaigns, key-change, and account and authorization deactivation.
- [x] SCEP RenewalReq, PENDING with CertPoll for dual-control profiles, per-app URLs and an Intune-style validation webhook.
- [x] EST client certificates forwarded by the load balancer, IDevID bootstrap, `csrattrs` and `serverkeygen`.
- [x] CMP following the RFC 9483 lightweight profile.

Open, in rough order of demand:

- [ ] A small Intune connector that turns the SCEP webhook calls into Microsoft's validation API.
- [ ] EST `fullcmc`, and serverkeygen keys encrypted to a key named in the request.
- [ ] CMP central key generation, PBMAC1, and the `certReqTemplate` and `rootCaCert` general messages.
- [ ] dns-01 checks from more than one resolver per view, for zones served by several providers.

## Phase 3: Windows and AD CS

Shipped September 2026 (commits 4f61eb0 to eb8869f, verified on PostgreSQL 16,
live on the demo). See [Windows and AD CS](guide/20-windows-adcs.md).

- [x] **AD CS template security audit.** Reads AD CS templates and CA
  configuration (over LDAP, or from an offline export) and flags the ESC
  misconfigurations from the SpecterOps "Certified Pre-Owned" catalogue:
  ESC1-4, ESC6, ESC8, ESC9, ESC11, ESC13, ESC15 and ESC16.
- [x] **Smart-card / PKINIT logon profiles.** `windows-logon` issues logon
  certificates with a UPN otherName and the SID security extension
  (szOID_NTDS_CA_SECURITY_EXT) for strong certificate mapping (KB5014754). The
  SID is resolved from the directory, never the request, disabled accounts are
  refused, and sensitive accounts force dual control. `windows-kdc` covers KDC
  authentication certificates.
- [x] **AD CS as an issuer backend and inventory source.** The `adcs` issuer
  queues jobs for a domain-joined gateway worker that submits to a Microsoft
  CA with certreq / certutil and posts the result back. Certadillo stays the
  registration authority; AD CS signs. The same gateway ingests the CA
  database as inventory.
- [ ] **Windows auto-enrollment through CEP/CES (MS-XCEP / MS-WSTEP).** Publish
  Certadillo as a policy and enrollment web service so Group Policy
  auto-enrollment points at it directly, without the gateway worker. The
  larger protocol effort (WS-Trust, the enrollment policy schema, Kerberos on
  IIS).

## Phase 3: more issuers and inventory connectors

Issuer backends (`CABackend`):

- [x] ACME CAs (Let's Encrypt and others), see Phase 7
- [x] DigiCert CertCentral, see Phase 7
- [x] AWS Private CA, see Phase 7
- [x] EJBCA, see Phase 7
- [ ] Google CAS: `projects.locations.caPools.certificates.create`

Inventory connectors (`InventoryConnector`):

- [ ] keycensus: import its `inventory.json` (certificates, owners and the applications linked to each key, from HSMs, KMS, Vault, Voltage and TLS scans)
- [ ] Venafi TLS Protect Datacenter: Web SDK `GET /vedsdk/Certificates/` with an OAuth token
- [ ] Keyfactor Command: `GET /KeyfactorAPI/Certificates`
- [ ] DigiCert CertCentral inventory: `GET /services/v2/order/certificate`
- [ ] F5 BIG-IP inventory: `GET /mgmt/tm/sys/crypto/cert`

## Phase 3.5: zero-trust access

Shipped September 2026. Certadillo validates short-lived OIDC/JWT tokens
minted by the organization's own identity provider, so access follows the same
controls (MFA, conditional access, device posture, session revocation) as
everything else the bank runs. See [Zero-trust access](guide/21-zero-trust-auth.md).

- [x] **OIDC / JWT bearer auth.** Every token is validated against the IdP's
  JWKS (signature, issuer, audience, exp/nbf/iat with clock skew, allowed
  algorithms, never `none`), then its role claim maps to a Certadillo role and,
  for an app token, to an onboarded app. Every check fails closed. Delegated to
  PyJWT rather than hand-rolled.
- [x] **Microsoft Entra ID.** A preset builds the issuer and JWKS from a tenant
  id; app-role or group claims map to admin / approver / operator / auditor /
  app. Workload identity federation covers CI jobs and pods.
- [x] **HashiCorp Vault.** A preset trusts Vault's OIDC provider, so a workload
  that already authenticates to Vault reuses that identity.
- [x] **Authenticator chain** (`auth/`). The OIDC token first, then the API key,
  so keys and tokens work side by side during a migration. The audit actor
  becomes the IdP subject; dual control, scope and the audit trail are
  unchanged.

Browser single sign-on for the console builds on this and is listed in Phase 6.

## Security hardening from the threat model

[THREAT_MODEL.md](THREAT_MODEL.md) ranks what an attacker wants and how they
would get it. Each shipped control has a test that fails when the control is
removed.

- [x] **P1 database and audit controls** (September 2026). Integrity seals on
  principals, approvals and certificate status with an audit-trail rollback
  check; an append-only audit table with the PostgreSQL role split
  (`certadillo db harden`); off-host anchoring of the audit chain; encryption of
  secret columns (local key or Vault Transit); name constraints on new issuing
  CAs; alerts for a broken seal, an anchor mismatch and a new privileged
  credential.
- [x] **CA keys in an HSM** (PKCS#11, tested on SoftHSM2). See [key custody](HSM.md).
- [x] **CA keys in Vault Transit** (September 2026). Non-exportable keys with
  pinned versions, every signature verified before use, the shipped policy
  keeps the root unusable by the application, new CAs from a two-person
  ceremony with an exact-path token. Tested against a real Vault in CI.
- [x] **Container hardening** (November 2026). Non-root user, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`, a pids limit,
  Dependabot on the base image.
- [x] **Audit shipping** (November 2026). Every event to syslog over TLS,
  Splunk HEC, HTTPS or S3 Object Lock, signed with Ed25519, with chain-break
  detection and `audit verify-export`. See [audit shipping](guide/25-audit-shipping.md).
- [x] **Console and API browser hardening.** Escaping template, CSP without
  inline script, Trusted Types; deny-all CSP on the API.
- [x] **Offline root ceremony** (November 2026). The root key lives on an
  air-gapped machine (`certadillo offline-root`); the server generates the
  issuing key in the HSM or Vault, sends a CSR, and imports the signed
  certificate only if it carries that key, chains to the root and keeps the
  required name constraints. The root CRL is signed offline and imported, with
  replay refused. See [offline root ceremony](guide/26-offline-root.md).
- [ ] **Encrypted, off-host backups** in `deploy.sh` (age or gpg to a key that
  is not on the server).
- [ ] **Separate signing service.** Move CA signing into a small process with
  its own credential (or keep it entirely in the HSM or Vault), so the
  web-facing process can ask for signatures under policy but never holds key
  material.
- [ ] **Supply chain.** Hash-pinned lock file for the image build, `pip-audit`
  and an SBOM in CI, signed images (cosign), and fuzzing of the DER, CMS and
  CMP parsers.

## Phase 7: enterprise CLM features

Commercial machine-identity platforms (CyberArk Certificate Manager, formerly
Venafi TLS Protect, is the one most banks run) combine things Certadillo did
not have together. This phase builds those capabilities in Certadillo's own
design. Nothing of those products' code, names or interfaces is copied.

Done (November 2026), in the API, the CLI and the knowledge base:

- [x] **Push provisioning.** Targets, installations and runs; SSH (nginx,
  Apache, HAProxy), Kubernetes TLS secrets, F5 BIG-IP and AWS ACM; key
  generated in memory or on the host; endpoint validation before the old
  certificate is retired; renewal, retries with backoff and a
  `ProvisioningFailed` alert. See [Push provisioning](guide/22-push-provisioning.md).
- [x] **Policy folder tree.** Folders with inherited and locked settings
  (zones, key sizes and curves, validity, issuing CA, approvals), apps placed
  in folders, the effective policy shown for every app, every change through a
  second person. Apps and folders are sealed. See [The policy tree](guide/23-policy-tree.md).
- [x] **Public and enterprise CA drivers.** ACME CAs (dns-01 through RFC 2136
  or an HTTP hook, EAB), DigiCert CertCentral, AWS Private CA and EJBCA,
  routed per profile or per policy folder. See [Upstream issuers](guide/24-upstream-issuers.md).
- [x] **Wider discovery.** A host agent for PEM, DER, PKCS#12, JKS and the
  Windows store that flags world-readable private keys; AWS ACM, Azure Key
  Vault and GCP Certificate Manager on a schedule; Certificate Transparency
  monitoring for public certificates Certadillo did not issue. See
  [Discovery and inventory](guide/12-discovery-inventory.md).

Still missing compared with Venafi:

- [ ] **Console screens for all of the above.** Targets, installations and run
  history with each step; the policy tree with own and effective settings and
  the lock on each one; upstream issuers and their health; discovery sources,
  agent hosts and the findings queue with acknowledge; audit shipping status.
  Same escaping template and CSP as the current console, and every change
  still goes through the approval flow.
- [ ] **Pushing to IIS, NetScaler and Azure Key Vault.** IIS bindings and the
  Windows certificate store over WinRM, or through the domain-joined AD CS
  gateway worker so no new inbound access is needed; Citrix NetScaler through
  NITRO (key, certificate and chain objects, then the vserver binding, old
  objects kept for rollback); Azure Key Vault certificate import with a
  managed identity. Each with endpoint validation like the existing drivers.
- [ ] **A code-signing service.** Signing keys that never leave the HSM or
  Vault, with Certadillo signing hashes on request: per-project keys and
  signers, dual control on release signing, timestamping (RFC 3161), signed
  artifacts recorded in the audit trail, and clients for signtool, jarsigner,
  cosign and GPG. Today code-signing certificates can be issued under dual
  control, but the requester holds the key.
- [ ] **SSH key management.** Certadillo already issues short-lived SSH user
  and host certificates. Missing: discovery of static `authorized_keys` and
  host keys across servers (through the host agent), ownership and age of each
  key, alerts for orphaned, shared or weak keys, and rotation of keys that
  cannot move to certificates yet.

Smaller follow-ups to the four shipped features:

- [ ] More push targets: Java keystores over SSH, Palo Alto, Fortinet.
- [ ] Per-folder notification contacts.
- [ ] More issuers: Sectigo, Entrust; DNS provider APIs (Route 53, Azure DNS, Cloudflare) for ACME.
- [ ] A signed agent package with a systemd unit and a Windows service.

## Phase 4: workload identity

- [ ] SPIRE integration: issue SPIRE's intermediate through dual control (`spire-intermediate` profile), then either the SPIRE `disk` UpstreamAuthority or a small Go UpstreamAuthority plugin that calls Certadillo.
- [ ] cert-manager: the ACME ClusterIssuer in the console snippet works in principle; add it to CI with kind, then ship an external issuer for EST-style flows.
- [ ] Service mesh (Istio) CA integration via istio-csr.

## Phase 5: post-quantum

- [ ] ML-DSA-65 / ML-DSA-87 issuance once pyca/cryptography exposes ML-DSA; the signer layer and DER re-signing are already algorithm-agnostic.
- [ ] Composite ML-DSA + ECDSA certificates (IETF LAMPS drafts) for a transition root.
- [ ] Hybrid key exchange tracking: collect TLS group support (X25519MLKEM768) during discovery scans and add it to the CBOM.
- [ ] A crypto-agility drill: rotate the whole estate to a new issuing CA and measure time to 100%.

## Phase 6: production hardening

- [ ] Console single sign-on on top of the zero-trust access work in Phase 3.5.
- [ ] Leader election for housekeeping (PostgreSQL advisory lock) and HSM session pooling.
- [ ] Per-principal rate limits and egress restrictions.
- [ ] OpenTelemetry traces across enrollment, policy and signing.
- [ ] Helm chart and a Terraform module (EKS or ECS, RDS PostgreSQL, CloudHSM).
- [ ] Alembic migrations.
- [ ] Oracle Database support, for banks that standardize on it. A compile of
  the schema against SQLAlchemy's Oracle dialect shows the work: a portable
  JSON column type, `TIMESTAMP WITH TIME ZONE` instead of the `DATE` that
  `DateTime(timezone=True)` becomes (DATE drops the microseconds the audit hash
  covers), identity columns for primary keys, no empty strings in NOT NULL
  columns (Oracle stores '' as NULL), and Oracle versions of the audit lock,
  the append-only triggers, `add_missing_columns` and `db harden`. Plus a CI
  job against Oracle Database Free.
- [ ] ServiceNow catalog item for self-service onboarding, with the approval recorded in both systems.
