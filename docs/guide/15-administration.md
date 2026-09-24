# Administration

## People and keys

Bootstrap keys come from the environment on first start (`CERTADILLO_BOOTSTRAP_ADMIN_KEY`, `CERTADILLO_BOOTSTRAP_APPROVER_KEY`). After that, create one principal per person:

```bash
certadillo principal jdoe --role operator            # on the server, prints the key once
curl -s "${A[@]}" -X POST $S/api/v1/principals -d '{"name": "asmith", "role": "approver"}'
curl -s "${A[@]}" -X POST $S/api/v1/principals/asmith/deactivate
```

Keys are stored as SHA-256 hashes. A lost key cannot be recovered; deactivate it and mint another.

In production, put OIDC (Entra ID, Okta) in front of the console and API and map groups to roles; API keys then remain for apps only. That integration is on the roadmap.

## Dual control

| Action | Needs a second person | Set by |
| --- | --- | --- |
| Onboarding a `prod` app | yes | `CERTADILLO_DUAL_CONTROL` (default `onboard_prod_app`) |
| Issuing or renewing a certificate in a profile with `dual_control: true` (code signing) | yes | the profile |
| Creating a subordinate CA | always | fixed |

Rules the approver check enforces:

- only principals with the `approver` role decide; admins request, approvers approve;
- the requester can never approve their own request;
- an approver key minted by the requester cannot approve that requester's requests.

Every request and decision is in the audit trail with the approver's comment.

## Certificate authorities

```bash
curl -s "${A[@]}" $S/api/v1/cas
```

Add an issuing CA (for rollover, or to separate a business line):

```bash
curl -s "${A[@]}" -X POST $S/api/v1/cas -d '{"name": "issuing-ca-2", "parent": "root-ca", "years": 5}'
# 202 pending_approval -> an approver approves it
```

The parent must allow subordinates (a pathlen 0 CA is refused). New issuance goes to the newest CA with pathlen 0; older CAs keep publishing CRLs for their certificates.

The root key ceremony, CA rollover and compromise procedures are in the [runbook](../RUNBOOK.md#root-key-ceremony).

## HSM

Set `CERTADILLO_SIGNER=pkcs11` with `CERTADILLO_PKCS11_LIB`, `CERTADILLO_PKCS11_TOKEN` and `CERTADILLO_PKCS11_PIN`. CA keys are generated on the token as sensitive, non-extractable and sign-only. Details and vendor library paths: [HSM guide](../HSM.md).

## Profiles and policy

Profiles live in `src/certadillo/default_policies.yaml`. To change them without touching the package, copy the file and point `CERTADILLO_POLICY_FILE` at the copy.

```yaml
profiles:
  tls-server:
    extended_key_usage: [server_auth]
    default_validity_days: 30
    max_validity_days: 90
    require_dns_san: true
    allow_wildcard: false
    allowed_keys: {rsa_min_bits: 2048, ec_curves: [secp256r1, secp384r1]}
    require_new_key_on_renewal: true
    # issuer: vault        # sign with a registered backend instead of the local CA
    # dual_control: true   # every issuance needs an approver
```

`spiffe_trust_domain` sets the SPIFFE trust domain. `ssh.user` and `ssh.host` set SSH certificate lifetimes. `public_tls_schedule` holds the CA/Browser Forum validity steps used to grade public certificates.

## Configuration reference

All settings are environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTADILLO_DATA_DIR` | `./.certadillo` | SQLite file, software keys |
| `CERTADILLO_DB_URL` | SQLite in the data dir | e.g. `postgresql+psycopg://user:pass@host/certadillo` |
| `CERTADILLO_BASE_URL` | `http://localhost:8080` | written into AIA and CDP URLs; set to the public HTTPS name |
| `CERTADILLO_ORG_NAME` | `Example Bank` | O= in CA and leaf subjects |
| `CERTADILLO_POLICY_FILE` | built-in | profile file |
| `CERTADILLO_SIGNER` | `software` | `software` or `pkcs11` |
| `CERTADILLO_KEY_PASSPHRASE` | dev value | encrypts software keys; set a real secret |
| `CERTADILLO_PKCS11_LIB` / `_TOKEN` / `_PIN` | | HSM access |
| `CERTADILLO_BOOTSTRAP_ADMIN_KEY` / `_APPROVER_KEY` | | first principals |
| `CERTADILLO_AUTO_INIT_CA` | `true` | create the hierarchy on first start |
| `CERTADILLO_DUAL_CONTROL` | `onboard_prod_app` | settings-driven maker-checker actions |
| `CERTADILLO_ACME_CHALLENGE` | `http-01` | `http-01` offers http-01 and dns-01; `ra-scope` skips the network check |
| `CERTADILLO_ACME_DNS_VIEWS` | | split-horizon resolvers per zone, `zone=ip[:port],...;zone=...` |
| `CERTADILLO_ACME_DNS_RESOLVERS` | host resolv.conf | resolvers for names in no view |
| `CERTADILLO_ACME_DNS_TIMEOUT` | `8` | seconds per dns-01 lookup |
| `CERTADILLO_ARI_RETRY_AFTER` | `21600` | seconds ACME clients wait between ARI checks |
| `CERTADILLO_SCEP_ALLOW_DES` | `false` | accept single-DES SCEP envelopes |
| `CERTADILLO_SCEP_VALIDATION_URL` / `_TOKEN` | | validation webhook for apps with `scep_validation: webhook` |
| `CERTADILLO_EST_CLIENT_CERT_HEADER` | | header carrying the client certificate from the load balancer |
| `CERTADILLO_EST_PROXY_SECRET` | | shared secret the load balancer sends as `X-Certadillo-Proxy-Auth` |
| `CERTADILLO_EST_TRUSTED_PROXIES` | | or: CIDRs the load balancer connects from |
| `CERTADILLO_OIDC_PROVIDER` | | `entra`, `vault` or `generic`; enables IdP token auth ([zero-trust access](21-zero-trust-auth.md)) |
| `CERTADILLO_OIDC_ENTRA_TENANT` | | Entra tenant id or domain (builds issuer + JWKS) |
| `CERTADILLO_OIDC_VAULT_ISSUER` | | Vault OIDC provider issuer (builds JWKS at `/.well-known/keys`) |
| `CERTADILLO_OIDC_ISSUER` / `_JWKS_URI` | | issuer and JWKS URL for a generic provider |
| `CERTADILLO_OIDC_AUDIENCE` | | the audience the IdP mints tokens for |
| `CERTADILLO_OIDC_ALGORITHMS` | `RS256,ES256` | allowed signature algorithms (never `none`) |
| `CERTADILLO_OIDC_ROLE_CLAIM` | `roles` | claim holding the role or group |
| `CERTADILLO_OIDC_ROLE_MAP` | | `claim=role;...`, e.g. `PKI.Admin=admin;App-Cards=app` |
| `CERTADILLO_OIDC_APP_CLAIM` | `app` | claim naming the app for an `app`-role token |
| `CERTADILLO_OIDC_USERNAME_CLAIM` | `sub` | claim recorded as the audit actor (`idp:<value>`) |
| `CERTADILLO_OIDC_CLOCK_SKEW` | `60` | seconds of leeway on token times |
| `CERTADILLO_CRL_INTERVAL_HOURS` | `12` | CRL re-signing interval |
| `CERTADILLO_ALERT_INTERVAL` | `300` | seconds between housekeeping runs |
| `CERTADILLO_EXPIRY_WARNING_DAYS` / `_CRITICAL_DAYS` | `30` / `7` | caps for the lifetime-scaled thresholds |
| `CERTADILLO_WEBHOOK_URLS` / `_SLACK_WEBHOOK_URLS` | | global alert channels |
| `CERTADILLO_JIRA_URL` / `_USER` / `_TOKEN` / `_PROJECT` | project `PKI` | Jira issues for critical alerts |
| `CERTADILLO_SNOW_URL` / `_USER` / `_PASSWORD` / `_ASSIGNMENT_GROUP` | group `PKI Operations` | ServiceNow incidents |
| `CERTADILLO_RUNBOOK_URL` | GitHub runbook | base URL for alert runbook links |

## Per-app protocol settings

Some protocol behaviour is set per app, not globally:

| Setting | How | Page |
| --- | --- | --- |
| SCEP challenges from an MDM | `PUT /api/v1/apps/{id}/options` with `{"scep_validation": "webhook"}` | [SCEP](07-scep.md) |
| Manufacturer (IDevID) CAs for EST | `POST /api/v1/apps/{id}/est-trust-anchors` (approval for prod apps) | [EST](06-est.md) |
| One-time CMP secrets | `POST /api/v1/apps/{id}/cmp-secret` | [CMP](18-cmp.md) |
| One-time SCEP challenges | `POST /api/v1/apps/{id}/scep-challenge` | [SCEP](07-scep.md) |
| ACME account credentials | `POST /api/v1/apps/{id}/acme-eab` | [ACME](05-acme.md) |

## Database upgrades

On start, Certadillo creates missing tables and adds missing nullable columns to existing ones, so moving to a newer version needs no manual migration for additive changes. Anything else will come with a migration and a note in the release.

## Audit

```bash
curl -s -H "X-API-Key: $AUDITOR_KEY" "$S/api/v1/audit?limit=100"
curl -s -H "X-API-Key: $AUDITOR_KEY" $S/api/v1/audit/verify
certadillo audit verify        # exit code 1 if the chain is broken
```

Ship the JSON logs to your SIEM as the long-term copy; the hash chain proves the database copy was not edited.

## Backups

Back up the database and, for software keys, the data directory (`keys/`, `ocsp-keys/`, `ssh-ca/`). HSM keys are backed up with the HSM vendor's tooling, never exported.
