# Push provisioning

Pull enrollment (ACME, EST, SCEP, CMP) works when the thing that needs a
certificate can run a client. Load balancers, appliances, Kubernetes secrets
and cloud certificate stores often cannot. For those, Certadillo pushes: it
issues the certificate under the app's policy, installs it on the target,
connects to the endpoint to check the new certificate is really served, and
renews it before it expires.

## The pieces

| Object | Who creates it | What it is |
| --- | --- | --- |
| Target | admin | A place Certadillo can write to: a host over SSH, a Kubernetes cluster, an F5 BIG-IP, an AWS account's ACM. Belongs to one team. |
| Installation | operator, admin, or the app's own credential | One certificate kept in one place on a target: the names, key type, where the key is generated, the placement on the target, and the endpoint to check. |
| Run | the scheduler, or a person | One attempt: issue, install, check, retire the old certificate. Every run is in the audit trail. |

A target can only be used by apps of the team that owns it, so one team's
installation cannot overwrite another team's load balancer.

## Supported targets

| kind | Installs | Key generated | Notes |
| --- | --- | --- | --- |
| `ssh` | PEM files on Linux or Unix hosts (nginx, Apache, HAProxy, Postfix) | in Certadillo, or on the host | Host key pinned; paths limited to `allowed_dirs`; reload command set by the admin |
| `kubernetes` | a `kubernetes.io/tls` secret | in Certadillo | Namespaces limited to the target's list; never overwrites a secret it did not create unless `adopt: true` |
| `f5` | key, certificate and chain objects, then the client-SSL profile | in Certadillo | New serial-named objects first, profile switch last; old objects kept for rollback |
| `aws-acm` | an ACM certificate | in Certadillo | Re-imports into the same ARN, so ELB and CloudFront pick it up unchanged |

IIS and Windows certificate stores, Citrix NetScaler and Azure Key Vault are
planned next (see the roadmap).

## Keys

With `key_location: central`, the run generates the key in memory, builds the
CSR, has it issued, pushes key and certificate, and drops the key. It is never
written to the database, a log or the audit trail. If the push fails after
issuance, the new certificate is revoked straight away, because nobody holds
its key any more.

With `key_location: device` (SSH targets), the host generates the key with
openssl and returns only a CSR. The key never leaves the host. The new key is
written next to the live one and swapped in only when the certificate is
installed.

## Credentials

Targets hold a reference to their credential, never the credential:

| Reference | Resolved from |
| --- | --- |
| `env:F5_PASSWORD` | an environment variable of the Certadillo process |
| `file:/run/secrets/k8s-token` | a mounted secret file |
| `vault:secret/data/certadillo/f5#password` | a HashiCorp Vault KV v2 field, read with Certadillo's Vault token |

A target config that contains a key such as `password`, `token` or `secret` is
refused. ACM uses the standard AWS credential chain (instance role, IRSA).

Targets and installations carry the same integrity seals as principals and
approvals. A database write that changes a target's host, allowed paths or
reload command, or an installation's placement, breaks the seal; the run then
stops before it connects and `IntegritySealBroken` fires.

## Example: nginx over SSH

```bash
S=https://pki.bank.internal
A=(-H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json")

# the host key comes from the server, not from a first connection
HOSTKEY=$(ssh-keyscan -t ed25519 web1.pay.bank.internal 2>/dev/null | cut -d' ' -f2-)

curl -s "${A[@]}" -X POST $S/api/v1/targets -d @- <<EOF
{"name": "web1", "kind": "ssh", "team_id": 1,
 "config": {"host": "web1.pay.bank.internal", "username": "certadillo",
            "host_key": "$HOSTKEY", "allowed_dirs": ["/etc/nginx/tls"],
            "reload_command": "sudo systemctl reload nginx"},
 "credential_ref": "vault:secret/data/certadillo/web1#ssh_key"}
EOF

curl -s "${A[@]}" -X POST $S/api/v1/installations -d '{
  "app_id": 1, "target_id": 1, "common_name": "www.pay.bank.internal",
  "key_location": "device",
  "params": {"cert_path": "/etc/nginx/tls/www.crt", "key_path": "/etc/nginx/tls/www.key"},
  "validate_endpoint": "web1.pay.bank.internal:443"}'

curl -s "${A[@]}" -X POST $S/api/v1/installations/1/provision
```

The response lists every step of the run: key generated where, serial issued,
files written, reload, and whether `web1:443` serves the new certificate.

## Kubernetes, F5 and ACM

```json
{"name": "aks-prod", "kind": "kubernetes", "team_id": 1,
 "config": {"api_server": "https://aks-prod.bank.internal:443", "namespaces": ["payments"],
            "ca_cert": "-----BEGIN CERTIFICATE-----..."},
 "credential_ref": "file:/run/secrets/aks-prod-token"}

{"name": "bigip-dc1", "kind": "f5", "team_id": 1,
 "config": {"host": "https://bigip-dc1.bank.internal", "username": "certadillo", "partition": "Payments"},
 "credential_ref": "vault:secret/data/certadillo/bigip-dc1#password"}

{"name": "acm-us-east-1", "kind": "aws-acm", "team_id": 1, "config": {"region": "us-east-1"}}
```

Installation `params` per kind: `{"namespace": "payments", "secret_name": "api-tls"}`
for Kubernetes, `{"profile": "www_clientssl"}` for F5, and nothing for ACM (the
ARN is recorded after the first import).

## Checking the endpoint

`validate_endpoint` is optional but recommended. After the install the run
opens TLS connections to it with the certificate's name as SNI and requires
three in a row to present the new certificate. One is not enough: during a
graceful reload old workers keep serving for a moment, and behind a load
balancer each connection may reach a different node. A server that took the
new files but was not reloaded is reported as failed, with the fingerprint it
still serves.

## Renewal and retries

The server's housekeeping timer runs installations that are due: never
provisioned, in their renewal window (the same lifetime-scaled thresholds as
the expiry alerts), covered by a [renewal campaign](19-renewal-campaigns.md),
or failed and past their backoff (5 minutes doubling, at most 24 hours). Up to
20 run per cycle. `certadillo provision due` does the same from cron, and
`certadillo provision run <id>` runs one now.

A failed installation raises `ProvisioningFailed`, routed to the app's team,
and becomes critical after three failures in a row.

## What it does not do

Profiles that need a second approver or the AD CS gateway for every issuance
(code signing, for example) cannot be pushed, because the run must hold the
certificate within one transaction. Use the REST API with approvals for those.
