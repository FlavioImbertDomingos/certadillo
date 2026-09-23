# Standards map

Which requirement each part of Certadillo covers. "Partial" means the platform supplies the evidence or mechanism but the organization still owns part of the control.

## Protocols and formats

| Standard | Where | Status |
| --- | --- | --- |
| RFC 5280 X.509 profile | `ca/authority.py` (BasicConstraints, KeyUsage, EKU, SKI/AKI, CDP, AIA; critical SAN when the subject is empty) | Done |
| RFC 6960 OCSP | `revocation/ocsp.py` (delegated responder, nonce echo, GET and POST) | Done, verified with `openssl ocsp` |
| RFC 7030 EST | `enrollment/est.py` (cacerts, simpleenroll, simplereenroll) | Done; serverkeygen and csrattrs not implemented |
| RFC 8555 ACME | `enrollment/acme.py` (EAB, http-01, revoke) | Done, verified with certbot; dns-01, key-change planned |
| RFC 9773 ACME Renewal Information | | Planned |
| RFC 8894 SCEP | | Planned (Intune, MDM, legacy network gear) |
| RFC 9525 service identity in TLS | Policy puts every name in SAN; CN is folded into SAN | Done |
| SPIFFE X.509-SVID and trust bundle | `spiffe-svid` profile, `/pki/spiffe/bundle` | Done; SPIRE UpstreamAuthority planned |
| OpenSSH certificate format (PROTOCOL.certkeys) | `ca/ssh.py` | Done |
| CycloneDX 1.6 cryptography BOM | `/api/v1/reports/cbom` | Done |
| PKCS#11 v2.40 | `crypto/signers.py` | Done, tested on SoftHSM2 |

## Industry and regulatory

| Requirement | How Certadillo supports it | Status |
| --- | --- | --- |
| CA/Browser Forum SC-081v3: public TLS max validity 200 days (15 Mar 2026), 100 days (15 Mar 2027), 47 days (15 Mar 2029) | Schedule in `default_policies.yaml`; discovered certificates that carry embedded CT SCTs (the mark of public trust) are graded against it; internal default is 30 days so automation is already exercised | Done |
| PCI DSS v4.0 3.6 / 3.7 key management procedures | HSM custody, dual control on CA creation, key rotation enforced on renewal, audit trail | Partial |
| PCI DSS v4.0 4.2.1 certificates for PAN in transit are valid, not expired or revoked | Expiry alerts, OCSP/CRL, discovery | Done |
| PCI DSS v4.0 4.2.1.1 inventory of trusted keys and certificates | `/api/v1/reports/pci-inventory` (JSON/CSV) with owner and classification | Done |
| PCI DSS v4.0 10.2 / 10.3 audit logs and their protection | Audit events for every privileged action, hash chain, JSON logs for SIEM | Partial (ship to WORM storage) |
| PCI DSS v4.0 12.3.3 cryptographic cipher suites and protocols inventory reviewed yearly | CBOM and crypto report | Partial |

## NIST

| Publication | Relevance | Status |
| --- | --- | --- |
| SP 800-57 Part 1 Rev 5 (key management, cryptoperiods) | Profile validity caps, CA lifetimes, forced key rotation | Done |
| SP 800-52 Rev 2 (TLS) | Allowed key types and curves in profiles | Partial (server config is the owner's) |
| SP 800-53 Rev 5 AC-5 separation of duties | Maker-checker approvals | Done |
| SP 800-53 Rev 5 AU-9 / AU-10 protection of audit information, non-repudiation | Hash-chained audit | Partial |
| SP 800-53 Rev 5 CM-8 system component inventory | Certificate inventory, discovery | Done |
| SP 800-53 Rev 5 SC-12 / SC-17 key management, PKI certificates | CA hierarchy, HSM custody, policy engine | Done |
| SP 800-53 Rev 5 SI-4 system monitoring | Metrics, alerts, Prometheus rules | Done |
| SP 800-207 zero trust | Workload identity (SPIFFE), short-lived mTLS certificates | Partial |
| FIPS 140-3 | Delegated to the HSM (Level 3 appliances) | Depends on HSM |
| FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA) | ML-DSA and SLH-DSA OIDs recognised in inventory; issuance waits for pyca/cryptography support | Partial |
| NIST IR 8547 (draft) PQC transition: RSA/ECC deprecated after 2030, disallowed after 2035 | Crypto report flags CAs and certificates that cross those dates | Done |
