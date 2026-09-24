# Standards map

Which requirement each part of Certadillo covers. "Partial" means the platform supplies the evidence or mechanism but the organization still owns part of the control.

## Protocols and formats

| Standard | Where | Status |
| --- | --- | --- |
| RFC 5280 X.509 profile | `ca/authority.py` (BasicConstraints, KeyUsage, EKU, SKI/AKI, CDP, AIA; critical SAN when the subject is empty) | Done |
| RFC 6960 OCSP | `revocation/ocsp.py` (delegated responder, nonce echo, GET and POST) | Done, verified with `openssl ocsp` |
| RFC 7030 EST | `enrollment/est.py` (cacerts, csrattrs, simpleenroll, simplereenroll with the 4.2.2 subject check, serverkeygen; client certificates forwarded by the TLS terminator) | Done, verified with the GlobalSign estclient behind nginx; fullcmc not implemented |
| IEEE 802.1AR device identity (IDevID) | EST bootstrap with manufacturer CAs registered per app | Done (direct issuance by the registered CA) |
| RFC 8555 ACME | `enrollment/acme.py` (EAB, http-01, dns-01 with split-horizon views, wildcards, key-change, account and authz deactivation, revocation by account or certificate key) | Done, verified with certbot (http-01, dns-01 wildcard, unregister) |
| RFC 9773 ACME Renewal Information (ARI) | `enrollment/ari.py` (renewalInfo, `replaces`, alreadyReplaced), renewal campaigns | Done, verified with certbot 5.8 (`certbot renew` follows the window) |
| RFC 8894 SCEP | `enrollment/scep.py` (GetCACaps, GetCACert, PKCSReq, RenewalReq, CertPoll; RA certificate; one-time challenges; validation webhook) | Done, verified with micromdm scepclient including PENDING and polling |
| RFC 4210 / RFC 9480 CMP, RFC 4211 CRMF, RFC 6712 CMP over HTTP | `enrollment/cmp.py` | Done for the RFC 9483 lightweight profile, verified with `openssl cmp` |
| RFC 9483 Lightweight CMP profile | ir/cr/kur/p10cr, certConf/pkiConf, implicitConfirm, pollReq/pollRep, rr, genm caCerts; PasswordBasedMac and signature protection; RA certificate with id-kp-cmcRA | Done; central key generation, PBMAC1 and some general messages not implemented |
| RFC 9525 service identity in TLS | Policy puts every name in SAN; CN is folded into SAN | Done |
| SPIFFE X.509-SVID and trust bundle | `spiffe-svid` profile, `/pki/spiffe/bundle` | Done; SPIRE UpstreamAuthority planned |
| OpenSSH certificate format (PROTOCOL.certkeys) | `ca/ssh.py` | Done |
| Microsoft AD CS templates (MS-CRTD) and enrollment (MS-WCCE / certreq) | `adcs/` audit reads msPKI-* flags, EKUs and nTSecurityDescriptor; the gateway submits via certreq | Audit and gateway done; CEP/CES (MS-XCEP/MS-WSTEP) auto-enrollment planned |
| Microsoft SID security extension (szOID_NTDS_CA_SECURITY_EXT) and strong certificate mapping (KB5014754) | `adcs/windows.py` emits the SID extension and UPN otherName for `windows-logon`; SID resolved from the directory | Done |
| Smart-card logon / PKINIT (RFC 4556) client EKUs and UPN SAN | `windows-logon` and `windows-kdc` profiles | Done (issuance; KDC-side config is the domain's) |
| AD CS privilege-escalation catalogue (SpecterOps "Certified Pre-Owned"; ESC1-16) | `adcs/analyzer.py` detects ESC1-4, 6, 8, 9, 11, 13, 15, 16 | Done; SD parser cross-checked against impacket |
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
