# Automation: CLI, Ansible, PowerShell, CI

## CLI

Installed with the package (`pip install git+https://github.com/FlavioImbertDomingos/certadillo`). Server-side commands run on the Certadillo host; `cert` commands are an API client for app teams.

| Command | Does |
| --- | --- |
| `certadillo serve [--port 8080]` | run the API, console, knowledge base, ACME, EST and SCEP |
| `certadillo init` | create the database and CA hierarchy if missing; print CA fingerprints |
| `certadillo principal NAME --role ROLE` | create a human principal and print its key once |
| `certadillo scan TARGET...` | discover TLS certificates into the inventory |
| `certadillo audit verify` | verify the audit chain; exit code 1 if broken |
| `certadillo alerts run` | publish due CRLs and evaluate alerts once (cron, Kubernetes CronJob) |
| `certadillo cert request --cn --san --spiffe-id --key-type --days --out DIR` | new key and certificate |
| `certadillo cert renew-if-due --dir DIR [--fraction 0.33] [--force]` | renew with a new key once due |

`cert` commands read `CERTADILLO_SERVER` and `CERTADILLO_API_KEY`.

## Ansible

`automation/ansible/roles/certadillo_cert` enrolls a host the first time and renews it once a third of the lifetime is left. The private key is generated on the host and never leaves it. It needs the `community.crypto` collection.

```yaml
- hosts: web
  become: true
  roles:
    - role: certadillo_cert
      vars:
        certadillo_server: https://pki.bank.internal
        certadillo_api_key: "{{ lookup('env', 'CERTADILLO_API_KEY') }}"
        certadillo_sans: ["{{ inventory_hostname }}", "www.{{ inventory_hostname }}"]
        certadillo_reload_services: [nginx]
```

| Variable | Default |
| --- | --- |
| `certadillo_server` | `https://pki.bank.internal` |
| `certadillo_api_key` | `$CERTADILLO_API_KEY` |
| `certadillo_ca_bundle` | system trust store |
| `certadillo_common_name` / `certadillo_sans` | `inventory_hostname` |
| `certadillo_key_type` | `ECC` (P-256); `RSA` gives 3072 bits |
| `certadillo_validity_days` | 30 |
| `certadillo_cert_dir` | `/etc/pki/certadillo` |
| `certadillo_renew_fraction` | 0.33 |
| `certadillo_reload_services` | `[]` |

Checked against a live server: the first run enrolls (6 changes), the second run changes nothing, and a forced renewal supersedes the old certificate.

## PowerShell

`automation/powershell/Certadillo.psm1`, for Windows servers, IIS and AD CS migrations. Tested with PowerShell 7.

```powershell
Import-Module ./Certadillo.psm1
Connect-Certadillo -Server https://pki.bank.internal -ApiKey $env:CERTADILLO_API_KEY

New-CertadilloCertificate -CsrPath .\iis01.csr -ValidityDays 30
Get-CertadilloCertificate -Status active | Where-Object days_left -lt 14
Invoke-CertadilloRenew -Id 42 -CsrPath .\iis01-new.csr
Invoke-CertadilloRevoke -Id 42 -Reason superseded -ChangeRef CHG0012345
Import-CertadilloInventory -StorePath Cert:\LocalMachine\My      # push a Windows store into the inventory
Get-CertadilloAlert
```

## CI pipelines

Any pipeline can call the REST API. A GitHub Actions step that issues a short-lived client certificate for an integration test:

```yaml
- name: Get a test client certificate
  env:
    CERTADILLO_SERVER: https://pki.bank.internal
    CERTADILLO_API_KEY: ${{ secrets.CERTADILLO_API_KEY }}
  run: |
    pip install git+https://github.com/FlavioImbertDomingos/certadillo
    certadillo cert request --cn ci-${{ github.run_id }}.ci.bank.internal --days 1 --out ./tls
```

## Certadillo's own CI

`.github/workflows/ci.yml` runs ruff, the test suite on Python 3.11 and 3.12 with SoftHSM2, `promtool` and `amtool` checks, the certbot interop test, the SCEP interop test with micromdm `scepclient`, an image build, a CycloneDX SBOM and a Trivy scan.
