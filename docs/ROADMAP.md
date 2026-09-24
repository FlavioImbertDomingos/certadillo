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

### Windows and AD CS (done)

The first tranche of Phase 3 is the Microsoft PKI work banks ask for first:

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

## Phase 3.5: zero-trust access (identity from an external IdP)

Today the console and API authenticate with API keys that Certadillo hashes and
stores in its own database. The next step is to stop being an identity store and
instead trust short-lived tokens minted by the organization's own identity
provider, so access follows the same zero-trust controls (conditional access,
MFA, device posture, session revocation) as everything else the bank runs. No
long-lived secret in Certadillo's database is a credential to steal.

- **OIDC / JWT bearer auth.** Accept a signed access token on every request,
  validate it against the IdP's JWKS (issuer, audience, expiry, signature), and
  map its claims to a Certadillo role and, for app credentials, to an app. Keys
  become a fallback for machines that cannot get a token, not the default.
- **Microsoft Entra ID.** Validate Entra-issued tokens; map Entra group or app-
  role claims to admin / approver / operator / auditor and to onboarded apps.
  Workload identity federation lets a CI job or a pod present a federated token
  instead of a stored key.
- **HashiCorp Vault.** Trust Vault-issued identity tokens (or JWTs from Vault's
  OIDC provider), so a workload that already authenticates to Vault reuses that
  identity to call Certadillo, with Vault policy deciding what it may do.
- **Enforcement details.** Per-claim scoping (an app token limited to its own
  app), token replay and clock-skew handling, and honouring the IdP's session
  revocation so a disabled user loses access at once rather than at key
  rotation. Dual control and the audit trail stay; the actor on each audit
  event becomes the IdP subject.

The pluggable seam is an `Authenticator` in front of `Platform.authenticate`,
so the local key store, Entra and Vault are interchangeable and can run side by
side during migration. This supersedes the single "OIDC login" bullet in Phase
6 and is pulled forward because it is a control banks ask for early.

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
- ServiceNow catalog item for self-service onboarding, with the approval recorded in both systems.
