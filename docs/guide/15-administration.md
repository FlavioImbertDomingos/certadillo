# Administration

## People and keys

Bootstrap keys come from the environment on first start (`CERTADILLO_BOOTSTRAP_ADMIN_KEY`, `CERTADILLO_BOOTSTRAP_APPROVER_KEY`). After that, create one principal per person:

```bash
certadillo principal jdoe --role operator            # on the server, prints the key once
curl -s "${A[@]}" -X POST $S/api/v1/principals -d '{"name": "asmith", "role": "approver"}'
curl -s "${A[@]}" -X POST $S/api/v1/principals/asmith/deactivate
```

Keys are stored as SHA-256 hashes. A lost key cannot be recovered; deactivate it and mint another.

Two roles are for machines, not people: `gateway` (the AD CS gateway worker claims and completes its jobs) and `agent` (a host agent posts discovery reports). Neither can read the inventory, approvals or configuration, so a key left on a server exposes as little as possible.

In production, put OIDC (Entra ID, Okta) in front of the console and API and map groups to roles; API keys then remain for apps only. That integration is on the roadmap.

## Dual control

| Action | Needs a second person | Set by |
| --- | --- | --- |
| Onboarding an app, unless it is non-prod and its whole scope is inside `CERTADILLO_DEV_DOMAINS` | yes | `CERTADILLO_DUAL_CONTROL` (`onboard_prod_app`) and `CERTADILLO_DEV_DOMAINS` |
| Creating or changing a policy folder, moving an app between folders | yes | `CERTADILLO_DUAL_CONTROL` (`policy_change`) |
| Issuing in a folder with `dual_control: true` | yes | the [policy tree](23-policy-tree.md) |
| Issuing or renewing a certificate in a profile with `dual_control: true` (code signing) | yes | the profile |
| Creating a subordinate CA | always | fixed |

Rules the approver check enforces:

- only principals with the `approver` role decide; admins request, approvers approve;
- the requester can never approve their own request;
- an approver key minted by the requester cannot approve that requester's requests;
- a request is re-checked when it is approved: if the app is no longer in the state the request assumed, or the requester's credential has been deactivated, it cannot be approved.

The environment an app declares is a label the requester chooses, so on its own it
never skips the second person. Only an app whose names all sit inside the zones
in `CERTADILLO_DEV_DOMAINS` (for example `dev.bank.internal`) is activated
straight away; with the variable unset, every onboarding needs an approver.

Scopes are checked when an app is onboarded. An entry is an exact DNS name, a
`*.suffix` with at least two labels after the star, or a SPIFFE prefix such as
`spiffe://bank.internal/payments/*`. Broader patterns (`*`, `*.com`,
`a*b.bank.internal`) are refused, and SPIFFE IDs with `.`, `..` or empty path
segments are never issued.

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
| `CERTADILLO_DB_URL` | SQLite in the data dir | `postgresql+psycopg://user:pass@host/certadillo`, or `oracle+oracledb://user:pass@host:1521/?service_name=PDB1` |
| `CERTADILLO_DB_SCHEMA` | | the schema that owns the tables, when the app connects as a separate restricted user (Oracle `CURRENT_SCHEMA`, PostgreSQL `search_path`) |
| `CERTADILLO_DB_AUTO_MIGRATE` | `true` | upgrade the schema at start-up; `false` refuses to start on an out-of-date schema, for deployments that run `certadillo db migrate` as their own step |
| `CERTADILLO_BASE_URL` | `http://localhost:8080` | written into AIA and CDP URLs; set to the public HTTPS name |
| `CERTADILLO_ORG_NAME` | `Example Bank` | O= in CA and leaf subjects |
| `CERTADILLO_POLICY_FILE` | built-in | profile file |
| `CERTADILLO_SIGNER` | `software` | where new CA keys are created: `software`, `pkcs11` or `vault-transit` ([key custody](../HSM.md)); existing keys load from where their `key_ref` points |
| `CERTADILLO_KEY_PASSPHRASE` | generated | encrypts software keys and derives the seal and field keys. Unset: a random one is created on first start in `<data dir>/key-passphrase` (mode 0600). Known placeholders and values under 16 characters are refused |
| `CERTADILLO_PKCS11_LIB` / `_TOKEN` / `_PIN` | | HSM access |
| `CERTADILLO_BOOTSTRAP_ADMIN_KEY` / `_APPROVER_KEY` | | first principals |
| `CERTADILLO_AUTO_INIT_CA` | `true` | create the hierarchy on first start |
| `CERTADILLO_DUAL_CONTROL` | `onboard_prod_app,policy_change` | settings-driven maker-checker actions |
| `CERTADILLO_DEV_DOMAINS` | | comma-separated zones for non-production names; see [Dual control](#dual-control) |
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
| `CERTADILLO_SEAL_KEY` | derived from `KEY_PASSPHRASE` | HMAC key for integrity seals (hex or base64); keep it out of the database host's reach if you can |
| `CERTADILLO_SEAL_KEY_PREVIOUS` | | the old key while rotating; then run `certadillo integrity reseal` |
| `CERTADILLO_AUDIT_ANCHOR_FILE` / `_URL` | | where the daily audit chain head goes (a JSONL file you ship to WORM storage, and/or a webhook) |
| `CERTADILLO_AUDIT_ANCHOR_HOURS` | `24` | how often to anchor |
| `CERTADILLO_SSH_RSA_MIN_BITS` | `2048` | RSA SSH keys below this raise `SshKeyWeak` |
| `CERTADILLO_SSH_KEY_MAX_AGE_DAYS` | `365` | authorized keys unchanged this long raise `SshKeyRotationDue` |
| `CERTADILLO_AUDIT_SHIP` | | sinks every audit event is shipped to: `file:`, `syslog+tls://`, `syslog+tcp://`, `splunk+https://`, `https://`, `s3://` ([audit shipping](25-audit-shipping.md)) |
| `CERTADILLO_AUDIT_SHIP_INTERVAL` | `15` | seconds between shipping passes |
| `CERTADILLO_AUDIT_SHIP_TOKEN_REF` | | `env:`, `file:` or `vault:` reference to the HEC or bearer token |
| `CERTADILLO_AUDIT_SHIP_CACERT` | | CA bundle for the syslog TLS, Splunk and HTTPS sinks |
| `CERTADILLO_AUDIT_SHIP_SPLUNK_INDEX` | | Splunk index |
| `CERTADILLO_AUDIT_SHIP_S3_RETENTION_DAYS` | `2555` | Object Lock (COMPLIANCE) retention for the S3 sink |
| `CERTADILLO_FIELD_CIPHER` | `local` | `local` or `vault`: where the key for encrypted secret columns lives |
| `CERTADILLO_VAULT_ADDR` / `_NAMESPACE` | | Vault, for `SIGNER=vault-transit` and `FIELD_CIPHER=vault` |
| `CERTADILLO_VAULT_TOKEN_FILE` / `_TOKEN` | | the token: a file Vault Agent keeps fresh (re-read on every call; wins over `_TOKEN`), or a static token |
| `CERTADILLO_VAULT_CACERT` | | CA bundle for Vault's TLS certificate |
| `CERTADILLO_VAULT_SIGNER_MOUNT` / `_KEY_PREFIX` | `transit` / `certadillo-` | where CA keys live in Vault; key name is prefix + CA name |
| `CERTADILLO_VAULT_TRANSIT_MOUNT` / `_KEY` | `transit` / `certadillo-fields` | the Transit key used for field encryption |
| `CERTADILLO_CA_PERMITTED_DNS` / `_EXCLUDED_DNS` / `_PERMITTED_EMAIL` | | name constraints written into new issuing CAs |
| `CERTADILLO_CRL_INTERVAL_HOURS` | `12` | CRL re-signing interval |
| `CERTADILLO_ALERT_INTERVAL` | `300` | seconds between housekeeping runs |
| `CERTADILLO_EXPIRY_WARNING_DAYS` / `_CRITICAL_DAYS` | `30` / `7` | caps for the lifetime-scaled thresholds |
| `CERTADILLO_WEBHOOK_URLS` / `_SLACK_WEBHOOK_URLS` | | global alert channels |
| `CERTADILLO_JIRA_URL` / `_USER` / `_TOKEN` / `_PROJECT` | project `PKI` | Jira issues for critical alerts |
| `CERTADILLO_SNOW_URL` / `_USER` / `_PASSWORD` / `_ASSIGNMENT_GROUP` | group `PKI Operations` | ServiceNow incidents |
| `CERTADILLO_RUNBOOK_URL` | GitHub runbook | base URL for alert runbook links |

## Schema upgrades

The schema is versioned with Alembic. Each release that changes it ships a migration under `src/certadillo/migrations/versions/`, and CI checks on SQLite, PostgreSQL 16 and Oracle Database 23 that running every migration gives exactly the tables the code expects.

By default the server upgrades its own schema at start-up. With several replicas on PostgreSQL, one takes an advisory lock and migrates while the others wait; on Oracle, run `db migrate` as its own step instead. For a production rollout, migrate as a separate step with the owner credential and start the new version with `CERTADILLO_DB_AUTO_MIGRATE=false`, so a replica never runs DDL:

```bash
certadillo db status    # {"current": "0001", "head": "0001", "up_to_date": true}; exits 1 when behind
certadillo db migrate   # {"action": "upgraded", "from": "0001", "to": "0002", "audit_guards": "..."}
```

A database created before migrations existed (Certadillo 0.1 from before November 2026) is adopted on the first `db migrate` or start: the tables and nullable columns it is missing are added, it is stamped at the baseline revision `0001`, and later migrations run from there. Nothing is dropped or rewritten.

To write a migration after changing the model, bring a scratch PostgreSQL database to head and let Alembic compare (`alembic.ini` at the repository root points at it):

```bash
alembic upgrade head
alembic revision --autogenerate -m "add foo to bar"
```

Read the generated file before committing it: autogenerate misses renames and data changes.

## Oracle Database

Certadillo runs on Oracle Database 19c and later (CI uses Oracle Database 23ai Free) through python-oracledb in thin mode, so no Instant Client is needed; the container image includes the driver. The differences from PostgreSQL are handled in the model and do not need configuration:

| Topic | On Oracle |
| --- | --- |
| Timestamps | `TIMESTAMP WITH TIME ZONE`, never `DATE`, which would drop the microseconds the audit hash covers |
| JSON columns | stored as text, so numbers come back exactly as written and seals and the audit hash stay stable |
| Primary keys | identity columns |
| Empty strings | never written to NOT NULL columns (Oracle stores `''` as NULL) |
| Audit appends | serialized with `LOCK TABLE audit_events IN EXCLUSIVE MODE` (readers are not blocked) |
| Append-only guard | a row trigger refuses UPDATE and DELETE, and a schema DDL trigger refuses TRUNCATE |

Use one schema owner for the tables and a separate application user:

```bash
# once, as a DBA
CREATE USER certadillo_owner IDENTIFIED BY "..." QUOTA UNLIMITED ON users;
GRANT CREATE SESSION, CREATE TABLE, CREATE TRIGGER, CREATE SEQUENCE TO certadillo_owner;
CREATE USER certadillo_app IDENTIFIED BY "...";
GRANT CREATE SESSION TO certadillo_app;

# as the owner: create or upgrade the schema, then grant the app user what it needs
export CERTADILLO_DB_URL='oracle+oracledb://certadillo_owner:...@db:1521/?service_name=PKIPDB'
certadillo db migrate
certadillo db harden --app-role certadillo_app

# the application connects as the app user and works in the owner's schema
CERTADILLO_DB_URL='oracle+oracledb://certadillo_app:...@db:1521/?service_name=PKIPDB'
CERTADILLO_DB_SCHEMA=CERTADILLO_OWNER
CERTADILLO_DB_AUTO_MIGRATE=false
```

Oracle has no default privileges for future tables, so run `db harden` again after a `db migrate` that adds tables.

## Database hardening

See [the threat model](../THREAT_MODEL.md) for why these exist.

Integrity seals. Principals, approvals and certificate status carry an HMAC over their security-relevant fields, keyed with `CERTADILLO_SEAL_KEY` (or a key derived from the passphrase). Every change the application makes reseals the row. A change made directly in SQL does not, and the row is treated as tampered. The first start after an upgrade seals existing rows once and writes `integrity.epoch` into the data directory; from then on a missing seal counts as tampering. `certadillo integrity check` lists problems. Rotate the key by setting the old one as `CERTADILLO_SEAL_KEY_PREVIOUS`, running `certadillo integrity reseal`, then removing it.

Append-only audit table. Triggers refuse UPDATE, DELETE and TRUNCATE on `audit_events` (SQLite, PostgreSQL and Oracle). On PostgreSQL (and on Oracle, as shown above), split the roles so the application's credential cannot drop them:

```bash
# once, as a superuser: an owner role for schema changes and a restricted role for the app
psql -c "CREATE ROLE certadillo_owner LOGIN PASSWORD '...'; CREATE ROLE certadillo_app LOGIN PASSWORD '...'"
psql -c "ALTER DATABASE certadillo OWNER TO certadillo_owner"

# as the owner: create or upgrade the schema, then restrict the app role
CERTADILLO_DB_URL=postgresql+psycopg://certadillo_owner:...@db/certadillo certadillo db migrate
CERTADILLO_DB_URL=postgresql+psycopg://certadillo_owner:...@db/certadillo certadillo db harden --app-role certadillo_app

# the application itself connects as the restricted role
CERTADILLO_DB_URL=postgresql+psycopg://certadillo_app:...@db/certadillo
```

The app role then has SELECT and INSERT on `audit_events` and no way to change or drop its triggers. Run `db migrate` with the owner credential before starting each new version, and start the app with `CERTADILLO_DB_AUTO_MIGRATE=false`: the restricted role cannot run DDL.

Audit anchoring. Set `CERTADILLO_AUDIT_ANCHOR_FILE` and/or `_URL`. Once a day (and on `certadillo audit anchor` or `POST /api/v1/audit/anchor`) the verified chain head, with a MAC under the seal key, goes there. Ship the file to storage with object lock. `certadillo audit verify --anchors <file>` fails if the history was rewritten after any saved anchor, even when the rewritten chain re-hashes cleanly.

Audit shipping. Set `CERTADILLO_AUDIT_SHIP` so every event leaves the host within seconds, signed with an Ed25519 key whose public half receivers use to verify. See [audit shipping](25-audit-shipping.md).

Field encryption. EAB HMAC keys, CMP secrets and team webhook URLs are encrypted at rest. The default key is derived from the passphrase; with `CERTADILLO_FIELD_CIPHER=vault`, Vault Transit holds it and every decrypt is a Vault call you can audit and revoke. Existing plaintext values are encrypted at the next start.

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
