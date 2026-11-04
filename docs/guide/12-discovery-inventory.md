# Discovery and inventory

The inventory holds every certificate Certadillo issued plus every certificate it has found elsewhere. Found certificates are what cause outages: nobody owns them, so nobody renews them.

Each row records its `source`:

| Source | How it got there |
| --- | --- |
| `issued` | signed by Certadillo (or a configured backend such as Vault) |
| `discovered` | seen on a TLS endpoint by a scan |
| `imported` | pushed as PEM (by a connector, the PowerShell module, or by hand) |

## Scan the network

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -H "Content-Type: application/json" -X POST $S/api/v1/discovery/scan \
  -d '{"targets": ["10.20.0.0/28:443", "payments.bank.internal:8443", "[fd00::10]:443"], "timeout": 4}'
```

Targets are `host:port`, `IP:port`, `CIDR:port` (up to 1024 addresses per range) or a bare host (port 443). The scanner connects with SNI, collects the leaf certificate without trusting it, and grades it:

| Finding | Meaning |
| --- | --- |
| `weak_key` | RSA under 2048 bits |
| `weak_signature` | SHA-1 or MD5 signature |
| `public_validity` | a publicly trusted certificate (it carries CT SCTs) whose lifetime exceeds the CA/Browser Forum limit that applied when it was issued |
| `quantum_vulnerable` | RSA or ECC key; informational, feeds the PQC report |

From the command line on the Certadillo host:

```bash
certadillo scan 10.20.0.0/28:443 payments.bank.internal:8443
```

Scanning the same endpoint again updates `last_seen`. If the endpoint now serves a different certificate, the old one is marked `superseded`, so an expired certificate that someone already replaced stops alerting.

## Import

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -H "Content-Type: application/json" -X POST $S/api/v1/inventory/import \
  -d "$(python3 -c 'import json;print(json.dumps({"pem": open("bundle.pem").read(), "location": "f5-dmz-01"}))')"
```

From Windows, the PowerShell module pushes a certificate store: `Import-CertadilloInventory -StorePath Cert:\LocalMachine\My`.

## Connectors

In code (`discovery/connectors.py`), each yielding `(certificate, location)`:

| Connector | Reads |
| --- | --- |
| `VaultPKIInventory` | every certificate in a Vault or OpenBao PKI mount |
| `KubernetesTLSSecrets` | every `kubernetes.io/tls` Secret the service account can list |

The AD CS CA database is read through the AD CS gateway (see [Windows and AD CS](20-windows-adcs.md)). Venafi, DigiCert, Keyfactor and F5 inventory connectors are designed in the [roadmap](../ROADMAP.md).

## The host agent

Network scans see what a server serves. The agent sees what is on its disks:
PEM and DER certificates, PKCS#12 files (with the passwords it is given, and an
empty one), Java keystores through `keytool` (the password goes through the
environment, not the command line), and on Windows the personal and web hosting
certificate stores. It reports the public certificates, plus the path, owner
and permission bits of every private key file it finds. Key material is never
read into the report.

```bash
# once, on the server: a key that can only post agent reports
certadillo principal agent-web1 --role agent > /etc/certadillo/agent.key

# on each host, from cron or a systemd timer
CERTADILLO_SERVER=https://pki.bank.internal \
  certadillo agent scan --api-key-file /etc/certadillo/agent.key --password-file /etc/certadillo/keystore-passwords
certadillo agent scan --dry-run --path /etc/nginx       # see what it would report
```

Without `--path` it scans the usual places (`/etc/ssl`, `/etc/pki`, `/etc/nginx`,
`/etc/httpd`, `/etc/haproxy`, `/etc/letsencrypt/live`, `/opt`, `/srv`) and skips
the system trust stores. Certificates land in the inventory with
`source: agent` and the location `host:/path`. A private key that every user on
the host can read opens a `PrivateKeyExposed` finding and a critical alert; the
next report after the permissions are fixed closes it.

An agent key can post reports and read nothing else: not the inventory, not
approvals, not configuration.

The agent also reports static SSH keys (authorized_keys and host keys). See
[static SSH keys](08-ssh.md#static-ssh-keys).

## Cloud certificate stores

Configured in the policy file, run on their own schedule by the server, and
run on demand with `POST /api/v1/discovery/sources/{name}/run`:

```yaml
discovery:
  sources:
    acm:
      type: aws-acm
      regions: [us-east-1, us-west-2]          # standard AWS credential chain
      interval_hours: 24
    kv-payments:
      type: azure-keyvault
      vault_url: https://kv-payments.vault.azure.net
      token_ref: file:/run/secrets/azure-kv-token   # Entra ID token for https://vault.azure.net
    gcp-edge:
      type: gcp-certmanager
      project: bank-edge
      location: global
      token_ref: vault:secret/data/certadillo/gcp#token
```

Every certificate found goes into the inventory with `source: cloud` and its
ARN, Key Vault id or resource name as the location, and is de-duplicated by
fingerprint. `GET /api/v1/discovery/sources` shows the last run of each; a
failing source raises `DiscoverySourceFailing`.

## Certificate Transparency monitoring

Every publicly trusted TLS certificate is logged in CT. Certadillo watches the
logs for your zones through SSLMate's Cert Spotter API and opens an
`UnknownPublicCertificate` finding for each unexpired certificate it did not
issue and does not already have in its inventory: shadow IT at best, a
certificate for your name in someone else's hands at worst.

```yaml
discovery:
  sources:
    ct:
      type: ct
      provider: certspotter
      zones: [bank.example, bank-online.example]
      token_ref: env:CERTSPOTTER_TOKEN
      interval_hours: 6
```

Matching is by serial number, because a CT entry can be the precertificate
rather than the final certificate. Final certificates are added to the
inventory (`source: ct`) so their expiry is tracked too; precertificates are
recorded only as findings. A finding that is expected (a marketing site run by
an agency) is acknowledged with a reason:
`POST /api/v1/discovery/findings/{id}/acknowledge` with `{"comment": "..."}`.

## Give found certificates an owner

Unowned certificates raise an `UnmanagedCertificate` alert (info). Assign one to an onboarded app and its alerts start going to that team:

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -H "Content-Type: application/json" \
  -X POST $S/api/v1/certificates/42/assign -d '{"app_id": 3}'
```

## Reports

| Report | Endpoint |
| --- | --- |
| PCI DSS v4.0 4.2.1.1 inventory of trusted keys and certificates | `GET /api/v1/reports/pci-inventory` (`?format=csv` for a spreadsheet) |
| CycloneDX 1.6 cryptography bill of materials | `GET /api/v1/reports/cbom` |
| Crypto agility and PQC readiness | `GET /api/v1/reports/crypto` |
| Dashboard summary | `GET /api/v1/reports/summary` |

The crypto report counts RSA/ECC certificates, flags CA certificates that outlive the 2035 cutoff in NIST IR 8547, shows how much issuance is automated, and lists recommendations.

## Keys and applications from keycensus

[keycensus](https://github.com/FlavioImbertDomingos/keycensus) inventories the
keys Certadillo never sees (HSM objects over PKCS#11, AWS KMS, Vault, Voltage)
and links every key and certificate to the applications that use it, from
their SBOMs. Import its `inventory.json` to answer "which applications depend
on this certificate or key" in one place:

```bash
keycensus scan -c sources.yaml -o out -f json
certadillo import-keycensus out/inventory.json
# or
curl -s -H "X-API-Key: $OPERATOR_KEY" -X POST $S/api/v1/inventory/keycensus --data-binary @out/inventory.json
```

| What | Where it goes |
| --- | --- |
| A certificate keycensus saw that Certadillo knows (same SHA-256 fingerprint) | linked to it: `GET /api/v1/inventory/external?certificate_id=<id>` shows the applications |
| A certificate Certadillo does not know | an `untracked_certificate` finding with the applications that use it: issued outside the platform |
| HSM, KMS and Vault keys | `GET /api/v1/inventory/external?kind=key`, and in the CycloneDX CBOM (`/api/v1/reports/cbom`) with their applications |
| An asset missing from a later export | marked `removed`; its finding closes |

`GET /api/v1/inventory/external?application=card-api` lists everything one
application depends on. Run the import after each keycensus scan (it is
idempotent); the import is in the audit trail.
