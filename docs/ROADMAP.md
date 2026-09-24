# Roadmap

Ordered by what a bank PKI team would ask for next. Each item names the interface it plugs into so contributors can pick one up.

## Phase 2: enrollment coverage (done)

- ACME dns-01 with split-horizon resolver views and CNAME delegation, wildcards, ARI (RFC 9773) with renewal campaigns, key-change, and account and authorization deactivation.
- SCEP RenewalReq, PENDING with CertPoll for dual-control profiles, per-app URLs and an Intune-style validation webhook.
- EST client certificates forwarded by the load balancer, IDevID bootstrap, `csrattrs` and `serverkeygen`.
- CMP following the RFC 9483 lightweight profile.

Left over from Phase 2, in rough order of demand:

- A small Intune connector that turns the SCEP webhook calls into Microsoft's validation API.
- EST `fullcmc`, and serverkeygen keys encrypted to a key named in the request.
- CMP central key generation, PBMAC1, and the `certReqTemplate` and `rootCaCert` general messages.
- dns-01 checks from more than one resolver per view, for zones served by several providers.

## Phase 3: connectors to the platforms banks already run

### Windows and AD CS (done, September 2026)

The first tranche of Phase 3 is the Microsoft PKI work banks ask for first. It
shipped in commits 4f61eb0 to eb8869f: 40 new tests (111 passing), ruff clean,
verified on PostgreSQL 16, and live on the demo at certadillo.com.

- **AD CS template security audit.** Certadillo reads AD CS templates and CA
  configuration (over LDAP, or from an offline export) and flags the ESC
  misconfigurations from the SpecterOps "Certified Pre-Owned" catalogue:
  ESC1-4, ESC6, ESC8, ESC9, ESC11, ESC13, ESC15 and ESC16. See the guide,
  [Windows and AD CS](guide/20-windows-adcs.md).
- **Smart-card / PKINIT logon profiles.** The `windows-logon` profile issues
  logon certificates with a UPN otherName and the SID security extension
  (szOID_NTDS_CA_SECURITY_EXT) for strong certificate mapping (KB5014754). The
  SID is resolved from the directory, never the request, disabled accounts are
  refused, and sensitive accounts force dual control. `windows-kdc` covers KDC
  authentication certificates.
- **AD CS as an issuer backend and inventory source.** The `adcs` issuer
  enqueues jobs for a domain-joined gateway worker that submits to a Microsoft
  CA with certreq / certutil and posts the result back. Certadillo stays the
  registration authority; AD CS signs. The same gateway ingests the CA
  database as inventory.

Item 4, deferred:

- **Windows auto-enrollment through CEP/CES (MS-XCEP / MS-WSTEP).** Publish
  Certadillo as a policy and enrollment web service so Windows Group Policy
  auto-enrollment points at it directly, without the gateway worker. This is
  the larger protocol effort (WS-Trust, the enrollment policy schema, Kerberos
  on IIS) and is left for a later phase.

### Remaining issuer backends (`CABackend`):

| Target | API it would call |
| --- | --- |
| Public ACME CAs (Let's Encrypt and others) | an ACME client inside the backend, dns-01 through the DNS provider's API; ARI decides renewal |
| DigiCert CertCentral | `POST /services/v2/order/certificate/{product}`; `PUT /services/v2/certificate/{id}/revoke` |
| AWS Private CA | `IssueCertificate`, `GetCertificate`, `RevokeCertificate` |
| Google CAS | `projects.locations.caPools.certificates.create` |
| EJBCA | REST `/v1/certificate/pkcs10enroll` |

Inventory connectors (`InventoryConnector`):

| Target | API |
| --- | --- |
| keycensus | import its `inventory.json`: certificates, owners and the applications linked to each key, from HSMs, KMS, Vault, Voltage and TLS scans |
| Venafi TLS Protect Datacenter | Web SDK `GET /vedsdk/Certificates/` with OAuth token |
| Keyfactor Command | `GET /KeyfactorAPI/Certificates` |
| DigiCert CertCentral | `GET /services/v2/order/certificate` |
| F5 BIG-IP | `GET /mgmt/tm/sys/crypto/cert` |
| AWS ACM, Azure Key Vault, GCP Certificate Manager | list certificates per account/subscription |

## Phase 3.5: zero-trust access (identity from an external IdP) (done, September 2026)

Certadillo no longer has to be an identity store. It validates short-lived
OIDC/JWT tokens minted by the organization's own identity provider, so access
follows the same controls (MFA, conditional access, device posture, session
revocation) as everything else the bank runs. See the guide,
[Zero-trust access](guide/21-zero-trust-auth.md).

- **OIDC / JWT bearer auth.** Every request's token is validated against the
  IdP's JWKS (signature, issuer, audience, exp/nbf/iat with clock skew,
  allowed algorithms, never `none`), then its role claim maps to a Certadillo
  role and, for an app token, to an onboarded app. Every check fails closed.
  Delegated to PyJWT rather than hand-rolled.
- **Microsoft Entra ID.** A preset builds the issuer and JWKS from a tenant id;
  Entra app-role or group claims map to admin / approver / operator / auditor /
  app. Workload identity federation covers CI jobs and pods.
- **HashiCorp Vault.** A preset trusts Vault's OIDC provider, so a workload that
  already authenticates to Vault reuses that identity, with Vault policy
  deciding what it may do.
- **The seam.** A pluggable `Authenticator` chain (`auth/`) runs the OIDC token
  first, then the API key, so keys and tokens work side by side during a
  migration and a machine that cannot get a token still uses a key. The audit
  actor becomes the IdP subject; dual control, scope and the audit trail are
  unchanged. 19 tests, including the fail-closed paths.

Still to build on top of this: a browser single-sign-on flow for the console
(the token validation and role mapping already live here), listed in Phase 6.

## Security hardening from the threat model

[THREAT_MODEL.md](THREAT_MODEL.md) ranks what an attacker wants and how they
would get it. The P1 controls are done (September 2026): integrity seals on
principals, approvals and certificate status with an audit-trail rollback
check, an append-only audit table with the PostgreSQL role split
(`certadillo db harden`), off-host anchoring of the audit chain, encryption of
secret columns (local key or Vault Transit), name constraints on new issuing
CAs, and alerts for a broken seal, an anchor mismatch and a new privileged
credential. Each control has a test that fails when the control is removed.

Next:

- ~~CA keys in Vault Transit~~ **Done (September 2026).** `CERTADILLO_SIGNER=vault-transit`:
  CA keys are non-exportable Transit keys with pinned versions, every signature
  is verified before use, the shipped policy keeps the root unusable by the
  application, and new CAs come from a two-person ceremony with an exact-path
  token (`certadillo ca ceremony-policy`, `ca create-issuing`). Tested against a
  real Vault in CI, including the shipped policies and Vault Agent config. See
  [key custody](HSM.md).
- **Offline root ceremony.** `certadillo init` creates the root online today.
  Add a mode that takes an issuing CA certificate signed by an offline root,
  so the root key never touches the server.
- **Encrypted, off-host backups** in `deploy.sh` (age or gpg to a key that is
  not on the server).
- **Container hardening:** non-root user, read-only root filesystem, dropped
  capabilities.

## Phase 4: workload identity

- SPIRE integration: issue SPIRE's intermediate through dual control (`spire-intermediate` profile), then either the SPIRE `disk` UpstreamAuthority or a small Go UpstreamAuthority plugin that calls Certadillo.
- cert-manager: the ACME ClusterIssuer in the console snippet works in principle; add it to CI with kind, then ship an external issuer for EST-style flows.
- Service mesh (Istio) CA integration via istio-csr.

## Phase 5: post-quantum

- ML-DSA-65 / ML-DSA-87 issuance once pyca/cryptography exposes ML-DSA; the signer layer and DER re-signing are already algorithm-agnostic.
- Composite ML-DSA + ECDSA certificates (IETF LAMPS drafts) for a transition root.
- Hybrid key exchange tracking: collect TLS group support (X25519MLKEM768) during discovery scans and add it to the CBOM.
- A crypto-agility drill: rotate the whole estate to a new issuing CA and measure time to 100%.

## Phase 6: production hardening

- Console single sign-on on top of the zero-trust access work in Phase 3.5 (the token validation and role mapping live there).
- Leader election for housekeeping (PostgreSQL advisory lock), HSM session pooling, per-principal rate limits.
- OpenTelemetry traces across enrollment, policy and signing.
- Audit shipping to Splunk HEC / S3 Object Lock, with the chain head anchored daily.
- Helm chart and a Terraform module (EKS or ECS, RDS PostgreSQL, CloudHSM).
- Alembic migrations.
- Oracle Database support, for banks that standardize on it. A compile of the
  schema against SQLAlchemy's Oracle dialect shows the work: a portable JSON
  column type (the generic JSON type has no Oracle rendering in SQLAlchemy
  2.0), `TIMESTAMP WITH TIME ZONE` instead of the `DATE` that
  `DateTime(timezone=True)` becomes (DATE drops the microseconds the audit hash
  covers), identity columns for primary keys, no empty strings in NOT NULL
  columns (Oracle stores '' as NULL), and Oracle versions of the audit lock,
  the append-only triggers, `add_missing_columns` and `db harden`. Plus a CI
  job against Oracle Database Free.
- ServiceNow catalog item for self-service onboarding, with the approval recorded in both systems.
