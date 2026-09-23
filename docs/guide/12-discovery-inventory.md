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

Venafi, DigiCert, Keyfactor, AD CS, F5, ACM and Key Vault connectors are designed in the [roadmap](../ROADMAP.md) with the API each would call.

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
