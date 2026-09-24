# Windows and AD CS

Most banks already run Microsoft AD CS. Certadillo works with it three ways: it
audits AD CS templates for the misconfigurations that lead to privilege
escalation, it issues Windows smart-card logon certificates that pass strong
mapping, and it can put AD CS behind its own registration authority as an
issuing backend.

## Template security audit

AD CS templates are easy to misconfigure into a domain-compromise path. The
ESC family (SpecterOps, "Certified Pre-Owned"; detected by tools such as
Certipy) is the catalogue. Certadillo reads the templates and CA settings and
reports the same findings, so a PKI team can fix them before anyone abuses
them. It is read-only: it enumerates and grades, it never enrolls or edits.

What it checks:

| ESC | What it flags |
| --- | --- |
| ESC1 | A client-auth template that lets the enrollee choose the subject |
| ESC2 | An Any Purpose template |
| ESC3 | An enrollment-agent template a low-privileged user can enroll |
| ESC4 | A template a low-privileged user can edit (WriteDacl/Owner, GenericAll, full-property write, or non-admin owner) |
| ESC6 | A CA with EDITF_ATTRIBUTESUBJECTALTNAME2 (honours a SAN from the request) |
| ESC8 | HTTP web enrollment without channel binding (an NTLM relay target) |
| ESC9 | A client-auth template with CT_FLAG_NO_SECURITY_EXTENSION (0x80000) |
| ESC11 | A CA that does not enforce encryption on ICertRequest RPC |
| ESC13 | A client-auth template whose issuance policy is linked to a group (msDS-OIDToGroupLink) |
| ESC15 | A schema v1 enrollee-supplies-subject template (CVE-2024-49019) |
| ESC16 | A CA that omits the SID security extension for every certificate |

Enrollment-based findings (ESC1, 2, 3, 9, 13, 15) are reported only when a
low-privileged principal (Domain Users, Authenticated Users, Domain Computers
and the like) can actually enroll and the template does not require manager
approval or an authorized signature, the same gate Certipy applies. Several
findings are hardened on a domain that fully enforces KB5014754 (see below);
the audit says so in the finding's remark rather than dropping it.

### Two ways to feed it

The live collector reads the Configuration naming context over LDAP or LDAPS.
A read-only bind account with ordinary domain read access is enough:

```bash
export CERTADILLO_ADCS_LDAP_URL=ldaps://dc1.corp.bank.internal
export CERTADILLO_ADCS_LDAP_USER='CORP\pki-audit'
export CERTADILLO_ADCS_LDAP_PASSWORD=...
export CERTADILLO_ADCS_LDAP_BASE='DC=corp,DC=bank,DC=internal'

certadillo adcs audit           # or: POST /api/v1/adcs/audit/ldap
```

LDAP does not expose the CA registry, so ESC6, ESC8, ESC11 and ESC16 (which
depend on CA flags) need the offline export. The
`Export-CertadilloAdcsTemplates.ps1` script (under `automation/powershell`)
runs on any domain-joined host, reads the templates, the issuance-policy group
links, the enrollment services and, with `certutil -getreg`, the CA policy
flags, and writes a JSON document:

```powershell
.\Export-CertadilloAdcsTemplates.ps1 -Path adcs-export.json
```

```bash
certadillo adcs audit --json adcs-export.json
# or
curl -s "${A[@]}" -X POST $S/api/v1/adcs/audit/import -d @<(jq '{document: .}' adcs-export.json)
```

`certadillo adcs audit` exits non-zero when it finds anything critical or high,
so it drops into a pipeline. Findings are stored, and a critical or high
finding raises the `AdcsTemplateVulnerable` alert, routed like any other. Read
the latest run at `GET /api/v1/adcs/findings`.

The security descriptor parser is checked byte-for-byte against impacket's
`ldaptypes` (the library Certipy uses) in the tests, so a template's ACL is
read the same way AD does.

## Smart-card and PKINIT logon

The `windows-logon` profile issues certificates for Windows logon (smart card,
or PKINIT for a virtual smart card or a certificate on disk). It carries the
three logon EKUs (client auth, smart card logon, PKINIT client), a UPN in an
otherName SAN, and the SID security extension.

Since KB5014754 reached full enforcement (February 2025, with the
`StrongCertificateBindingEnforcement` registry escape removed in the September
2025 update), a domain controller maps a logon certificate to an account by a
strong identifier. The SID security extension (`szOID_NTDS_CA_SECURITY_EXT`,
1.3.6.1.4.1.311.25.2) is how the CA states that identifier, and Certadillo
emits it so its certificates keep working under full enforcement.

The rules that make this safe:

- The identity is a UPN otherName, and its suffix must be inside the app's
  approved domains. A logon certificate carries no DNS, email, URI or IP SAN.
- The account SID is resolved from the directory by the platform, never taken
  from the request, so an enroller cannot claim another account's SID. The
  lookup fails closed: if the UPN matches zero or more than one account, no
  certificate is issued.
- A disabled account is refused.
- A sensitive account (adminCount=1: protected groups such as Domain Admins)
  forces dual control, so a second approver signs off before issuance.

```bash
# onboard an app scoped to a UPN suffix, then request with a UPN otherName CSR
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 3, "name": "vpn-logon",
  "environment": "prod", "profile": "windows-logon", "allowed_domains": ["corp.bank.internal"]}'
```

For the certificate to be accepted for logon, the issuing CA chain must be
published to the NTAuth store:

```powershell
certutil -dspublish -f issuing-ca.crt NTAuthCA
```

`windows-kdc` is the companion profile for domain-controller / KDC
authentication certificates (KDC Authentication EKU 1.3.6.1.5.2.3.5 plus client
and server auth), named by DNS SAN like any TLS profile.

## AD CS as an issuing backend

A profile with `issuer: adcs` does not sign locally. Certadillo applies its
scope, policy, dual control and audit as usual, then hands the approved request
to a gateway: a domain-joined worker that submits to a Microsoft CA and posts
the certificate back. Certadillo stays the registration authority; AD CS is the
CA.

```yaml
adcs-user:
  issuer: adcs
  adcs_ca: "CA01.corp.bank.internal\\Corp Issuing CA"
  adcs_template: CertadilloUser
  extended_key_usage: [client_auth]
```

How a request flows:

1. A client requests a certificate as usual. Because the profile's issuer is
   `adcs`, Certadillo enqueues a job and answers `202` with a `job_id` and a
   poll URL instead of a certificate.
2. The gateway worker (`Invoke-CertadilloAdcsGateway.ps1`, run from Task
   Scheduler as an account that may enroll the template) claims pending jobs,
   runs `certreq -submit -config "<CA>" -attrib "CertificateTemplate:<template>"`,
   and posts the issued certificate back.
3. The client polls `GET /api/v1/adcs/gateway/jobs/{id}` and gets the
   certificate once the gateway completes it. It lands in inventory with
   backend `adcs` and location `adcs:<CA>`, owned by the requesting app.

Identical CSRs are de-duplicated, so a client that retries does not double
submit. Revoking an AD CS certificate enqueues a revoke job that the gateway
carries out with `certutil -revoke`. An inventory job (`POST
/api/v1/adcs/inventory`) has the gateway export the CA database; certificates
whose template maps to an onboarded app are assigned to it. A job that no
gateway completes within an hour raises the `AdcsGatewayJobStuck` alert.

The gateway needs a principal with the `gateway` role:

```bash
certadillo principal gw-dc1 --role gateway
```

Auto-enrollment through Group Policy (CEP/CES, MS-XCEP/MS-WSTEP) is on the
roadmap; until then the gateway covers request, renewal, revocation and
inventory against an existing CA.

## Coming from AD CS

If you are consolidating on Certadillo, the usual order is: run the template
audit and fix or retire the risky templates; stand up the gateway so existing
Windows enrollment keeps working through Certadillo's RA; move logon issuance
to the `windows-logon` profile; and use the inventory job to pull the AD CS
database into one place with the rest of the estate.
