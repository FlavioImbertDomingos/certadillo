# API reference

Generated from the OpenAPI schema by `scripts/gen_api_reference.py`. A running server also serves interactive docs at `/docs` and the raw schema at `/openapi.json`.

Authenticate with `X-API-Key: <key>` or `Authorization: Bearer <key>`. Errors are JSON: `401` bad key, `403` wrong role or another app's resource, `404` not found, `422` policy violation (with a `violations` list), `400` bad input.

| Method | Path | Who may call | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/me` | any authenticated | who the key belongs to |
| `POST` | `/api/v1/principals` | admin | create a principal; returns its key once |
| `POST` | `/api/v1/principals/{name}/deactivate` | admin | disable a principal's key |
| `GET` | `/api/v1/profiles` | any authenticated | certificate profiles and their limits |
| `GET` | `/api/v1/teams` | admin, operator, approver, auditor | list teams |
| `POST` | `/api/v1/teams` | admin, operator | create a team |
| `GET` | `/api/v1/apps` | admin, operator, approver, auditor | list apps |
| `POST` | `/api/v1/apps` | admin, operator | onboard an app; prod apps return an approval_id |
| `GET` | `/api/v1/apps/{app_id}` | admin, operator, approver, auditor; app (own) | one app |
| `POST` | `/api/v1/apps/{app_id}/credentials` | admin, operator | mint an app API key (REST, EST) |
| `POST` | `/api/v1/apps/{app_id}/acme-eab` | admin, operator | mint a single-use ACME EAB credential |
| `POST` | `/api/v1/apps/{app_id}/scep-challenge` | admin, operator | mint a one-time SCEP challenge (`ttl_minutes`) |
| `GET` | `/api/v1/approvals` | admin, operator, approver, auditor; app (own) | list approvals (`status=pending`) |
| `POST` | `/api/v1/approvals/{approval_id}/approve` | approver | approve; runs the action |
| `POST` | `/api/v1/approvals/{approval_id}/reject` | approver | reject |
| `POST` | `/api/v1/certificates` | app; admin, operator with app_id | request a certificate from a CSR |
| `GET` | `/api/v1/certificates` | any authenticated (apps see their own) | list: `status`, `source`, `app_id`, `expiring_within_days`, `renewal_due`, `limit` |
| `GET` | `/api/v1/certificates/{cert_id}` | any authenticated (apps see their own) | one certificate with PEM |
| `POST` | `/api/v1/certificates/{cert_id}/renew` | app (own); admin, operator | renew with a new CSR |
| `POST` | `/api/v1/certificates/{cert_id}/revoke` | app (own); admin, operator | revoke (`reason`, `change_ref`) |
| `POST` | `/api/v1/certificates/{cert_id}/assign` | admin, operator | give a found certificate an owning app |
| `GET` | `/api/v1/ssh/ca` | public | SSH CA public key for TrustedUserCAKeys |
| `POST` | `/api/v1/ssh/certificates` | app, admin, operator | issue an SSH user or host certificate |
| `POST` | `/api/v1/discovery/scan` | admin, operator | scan TLS endpoints into the inventory |
| `POST` | `/api/v1/inventory/import` | admin, operator | import PEM certificates |
| `GET` | `/api/v1/cas` | admin, operator, approver, auditor | list CAs |
| `POST` | `/api/v1/cas` | admin | request a subordinate CA (dual control) |
| `GET` | `/api/v1/alerts` | admin, operator, approver, auditor | open alerts (`include_resolved`) |
| `POST` | `/api/v1/alerts/evaluate` | admin, operator | publish due CRLs and evaluate alerts now |
| `GET` | `/api/v1/audit` | admin, operator, approver, auditor | audit events, newest first (`limit`) |
| `GET` | `/api/v1/audit/verify` | admin, operator, approver, auditor | verify the audit hash chain |
| `GET` | `/api/v1/reports/summary` | admin, operator, approver, auditor | dashboard summary |
| `GET` | `/api/v1/reports/crypto` | admin, operator, approver, auditor | crypto agility and PQC readiness |
| `GET` | `/api/v1/reports/cbom` | admin, operator, approver, auditor | CycloneDX 1.6 cryptography BOM |
| `GET` | `/api/v1/reports/pci-inventory` | admin, operator, approver, auditor | PCI DSS v4.0 4.2.1.1 inventory (`format=csv`) |
| `GET` | `/pki/ca/{name}.crt` | public | CA certificate, DER |
| `GET` | `/pki/ca/{name}.pem` | public | CA certificate, PEM |
| `GET` | `/pki/crl/{name}.crl` | public | current CRL, DER |
| `POST` | `/pki/ocsp` | public | OCSP (RFC 6960), body is the DER request |
| `GET` | `/pki/ocsp/{encoded}` | public | OCSP GET form |
| `GET` | `/pki/spiffe/bundle` | public | SPIFFE trust bundle (JWKS) |
| `GET` | `/.well-known/est/cacerts` | public | EST CA certificates |
| `POST` | `/.well-known/est/simpleenroll` | app key as Basic password | EST enrollment |
| `POST` | `/.well-known/est/simplereenroll` | app key as Basic password | EST re-enrollment |
| `GET` | `/acme/directory` | public | ACME directory |
| `GET` | `/acme/new-nonce` | public | ACME nonce |
| `HEAD` | `/acme/new-nonce` | public | ACME nonce |
| `POST` | `/acme/new-account` | JWS + EAB | register an ACME account |
| `POST` | `/acme/acct/{acct_id}` | JWS (kid) | account (deactivate) |
| `POST` | `/acme/new-order` | JWS (kid) | new order |
| `POST` | `/acme/order/{order_id}` | JWS (kid) | order status |
| `POST` | `/acme/authz/{authz_id}` | JWS (kid) | authorization |
| `POST` | `/acme/chall/{authz_id}` | JWS (kid) | trigger http-01 validation |
| `POST` | `/acme/order/{order_id}/finalize` | JWS (kid) | submit the CSR |
| `POST` | `/acme/cert/{cert_id}` | JWS (kid) | download the chain |
| `POST` | `/acme/revoke-cert` | JWS (kid) | revoke |
| `POST` | `/acme/key-change` | JWS (kid) | not implemented (501) |
| `GET` | `/scep` | challenge in the CSR | SCEP GetCACaps, GetCACert, PKIOperation (GET form) |
| `POST` | `/scep` | challenge in the CSR | SCEP PKIOperation |
