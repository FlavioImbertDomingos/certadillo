# Roadmap

Ordered by what a bank PKI team would ask for next. Each item names the interface it plugs into so contributors can pick one up.

## Phase 2: enrollment coverage

- ACME dns-01 (dnspython lookups, split-horizon aware) and ACME Renewal Information (RFC 9773) so clients renew on the server's schedule, which is how a mass revocation gets absorbed without an outage.
- ACME key-change and account deactivation cleanup.
- SCEP (RFC 8894) with a dynamic-challenge hook for Microsoft Intune and MDM tools. Either native, or by fronting micromdm/scep and calling `Platform.request_certificate()`.
- EST with TLS client authentication forwarded from the load balancer; `csrattrs` and `serverkeygen` for constrained devices.
- CMP (RFC 9483 lightweight profile) for telecom and industrial gear.

## Phase 3: connectors to the platforms banks already run

Issuer backends (`CABackend`):

| Target | API it would call |
| --- | --- |
| Microsoft AD CS | certreq / ICertRequest via a Windows worker, or CES/CEP web services; revocation via ICertAdmin |
| DigiCert CertCentral | `POST /services/v2/order/certificate/{product}`; `PUT /services/v2/certificate/{id}/revoke` |
| AWS Private CA | `IssueCertificate`, `GetCertificate`, `RevokeCertificate` |
| Google CAS | `projects.locations.caPools.certificates.create` |
| EJBCA | REST `/v1/certificate/pkcs10enroll` |

Inventory connectors (`InventoryConnector`):

| Target | API |
| --- | --- |
| Venafi TLS Protect Datacenter | Web SDK `GET /vedsdk/Certificates/` with OAuth token |
| Keyfactor Command | `GET /KeyfactorAPI/Certificates` |
| DigiCert CertCentral | `GET /services/v2/order/certificate` |
| AD CS database | `certutil -view` export or PSPKI `Get-IssuedRequest` (the PowerShell module already pushes Windows stores) |
| F5 BIG-IP | `GET /mgmt/tm/sys/crypto/cert` |
| AWS ACM, Azure Key Vault, GCP Certificate Manager | list certificates per account/subscription |

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

- OIDC login and group-to-role mapping for the console and API.
- Leader election for housekeeping (PostgreSQL advisory lock), HSM session pooling, per-principal rate limits.
- OpenTelemetry traces across enrollment, policy and signing.
- Audit shipping to Splunk HEC / S3 Object Lock, with the chain head anchored daily.
- Helm chart and a Terraform module (EKS or ECS, RDS PostgreSQL, CloudHSM).
- Alembic migrations.
- ServiceNow catalog item for self-service onboarding, with the approval recorded in both systems.
