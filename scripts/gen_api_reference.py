"""Regenerate docs/guide/16-api-reference.md from the live OpenAPI schema.

Fails if an endpoint has no entry in DESCRIBE, so the reference cannot drift."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ANY = "any authenticated"
STAFF = "admin, operator, approver, auditor"
DESCRIBE = {
    ("GET", "/api/v1/me"): (ANY, "who the key belongs to"),
    ("POST", "/api/v1/principals"): ("admin", "create a principal; returns its key once"),
    ("POST", "/api/v1/principals/{name}/deactivate"): ("admin", "disable a principal's key"),
    ("GET", "/api/v1/profiles"): (ANY, "certificate profiles and their limits"),
    ("GET", "/api/v1/teams"): (STAFF, "list teams"),
    ("POST", "/api/v1/teams"): ("admin, operator", "create a team"),
    ("GET", "/api/v1/apps"): (STAFF, "list apps"),
    ("POST", "/api/v1/apps"): ("admin, operator", "onboard an app; prod apps return an approval_id"),
    ("GET", "/api/v1/apps/{app_id}"): (STAFF + "; app (own)", "one app"),
    ("POST", "/api/v1/apps/{app_id}/credentials"): ("admin, operator", "mint an app API key (REST, EST)"),
    ("POST", "/api/v1/apps/{app_id}/acme-eab"): ("admin, operator", "mint a single-use ACME EAB credential"),
    ("POST", "/api/v1/apps/{app_id}/scep-challenge"): ("admin, operator", "mint a one-time SCEP challenge (`ttl_minutes`)"),
    ("POST", "/api/v1/apps/{app_id}/cmp-secret"): ("admin, operator", "mint a one-time CMP reference and secret (`ttl_minutes`)"),
    ("PUT", "/api/v1/apps/{app_id}/options"): ("admin, operator", "per-app protocol settings (`scep_validation`)"),
    ("POST", "/api/v1/apps/{app_id}/est-trust-anchors"): ("admin, operator", "register a manufacturer (IDevID) CA; prod apps return an approval_id"),
    ("GET", "/api/v1/apps/{app_id}/est-trust-anchors"): (STAFF, "list the app's manufacturer CAs"),
    ("GET", "/api/v1/approvals"): (STAFF + "; app (own)", "list approvals (`status=pending`)"),
    ("POST", "/api/v1/approvals/{approval_id}/approve"): ("approver", "approve; runs the action"),
    ("POST", "/api/v1/approvals/{approval_id}/reject"): ("approver", "reject"),
    ("POST", "/api/v1/certificates"): ("app; admin, operator with app_id", "request a certificate from a CSR"),
    ("GET", "/api/v1/certificates"): (ANY + " (apps see their own)", "list: `status`, `source`, `app_id`, `expiring_within_days`, `renewal_due`, `limit`"),
    ("GET", "/api/v1/certificates/{cert_id}"): (ANY + " (apps see their own)", "one certificate with PEM"),
    ("POST", "/api/v1/certificates/{cert_id}/renew"): ("app (own); admin, operator", "renew with a new CSR"),
    ("POST", "/api/v1/certificates/{cert_id}/revoke"): ("app (own); admin, operator", "revoke (`reason`, `change_ref`)"),
    ("POST", "/api/v1/certificates/{cert_id}/assign"): ("admin, operator", "give a found certificate an owning app"),
    ("GET", "/api/v1/certificates/{cert_id}/renewal-info"): (ANY + " (apps see their own)", "ARI window and CertID; `renew_now`"),
    ("POST", "/api/v1/renewal-campaigns"): ("admin, operator", "start a renewal campaign (`criteria`, `renew_within_hours`, `immediate`)"),
    ("GET", "/api/v1/renewal-campaigns"): (STAFF, "list campaigns with counts"),
    ("GET", "/api/v1/renewal-campaigns/{campaign_id}"): (STAFF, "campaign status by certificate and team"),
    ("POST", "/api/v1/renewal-campaigns/{campaign_id}/revoke-replaced"): ("admin, operator", "revoke certificates that have a successor"),
    ("POST", "/api/v1/renewal-campaigns/{campaign_id}/revoke-remaining"): ("admin, operator", "request the cutoff for the rest (dual control)"),
    ("POST", "/api/v1/renewal-campaigns/{campaign_id}/close"): ("admin, operator", "close a campaign; its windows stop applying"),
    ("POST", "/api/v1/adcs/audit/import"): ("admin, operator", "audit an Export-CertadilloAdcsTemplates document"),
    ("POST", "/api/v1/adcs/audit/ldap"): ("admin, operator", "audit the live directory over LDAP (CERTADILLO_ADCS_LDAP_*)"),
    ("GET", "/api/v1/adcs/findings"): (STAFF, "findings of the most recent AD CS audit run"),
    ("POST", "/api/v1/adcs/gateway/jobs/claim"): ("admin, gateway", "a gateway worker claims pending jobs"),
    ("POST", "/api/v1/adcs/gateway/jobs/{job_id}/complete"): ("admin, gateway", "report a job's result (certificate, revoke, inventory, or error)"),
    ("GET", "/api/v1/adcs/gateway/jobs/{job_id}"): (STAFF + "; app (own)", "poll one gateway job"),
    ("GET", "/api/v1/adcs/gateway/jobs"): ("admin, operator, gateway, auditor", "list gateway jobs (`status`)"),
    ("POST", "/api/v1/adcs/inventory"): ("admin, operator", "queue an AD CS CA database inventory job"),
    ("GET", "/api/v1/audit/head"): ("admin, auditor", "the current chain head as a signed anchor, for an external monitor"),
    ("POST", "/api/v1/audit/anchor"): ("admin", "send the chain head to the configured anchor file or URL now"),
    ("GET", "/api/v1/integrity"): ("admin, operator, auditor", "rows whose integrity seal fails, and certificates whose revocation was rolled back"),
    ("GET", "/api/v1/ssh/ca"): ("public", "SSH CA public key for TrustedUserCAKeys"),
    ("POST", "/api/v1/ssh/certificates"): ("app, admin, operator", "issue an SSH user or host certificate"),
    ("POST", "/api/v1/discovery/scan"): ("admin, operator", "scan TLS endpoints into the inventory"),
    ("POST", "/api/v1/inventory/import"): ("admin, operator", "import PEM certificates"),
    ("GET", "/api/v1/cas"): (STAFF, "list CAs"),
    ("GET", "/api/v1/cas/keys"): ("admin, operator, auditor", "where each CA key lives and whether it is reachable and intact (live check for Vault keys)"),
    ("POST", "/api/v1/cas"): ("admin", "request a subordinate CA (dual control)"),
    ("GET", "/api/v1/alerts"): (STAFF, "open alerts (`include_resolved`)"),
    ("POST", "/api/v1/alerts/evaluate"): ("admin, operator", "publish due CRLs and evaluate alerts now"),
    ("GET", "/api/v1/audit"): (STAFF, "audit events, newest first (`limit`)"),
    ("GET", "/api/v1/audit/verify"): (STAFF, "verify the audit hash chain"),
    ("GET", "/api/v1/reports/summary"): (STAFF, "dashboard summary"),
    ("GET", "/api/v1/reports/crypto"): (STAFF, "crypto agility and PQC readiness"),
    ("GET", "/api/v1/reports/cbom"): (STAFF, "CycloneDX 1.6 cryptography BOM"),
    ("GET", "/api/v1/reports/pci-inventory"): (STAFF, "PCI DSS v4.0 4.2.1.1 inventory (`format=csv`)"),
    ("GET", "/pki/ca/{name}.crt"): ("public", "CA certificate, DER"),
    ("GET", "/pki/ca/{name}.pem"): ("public", "CA certificate, PEM"),
    ("GET", "/pki/crl/{name}.crl"): ("public", "current CRL, DER"),
    ("POST", "/pki/ocsp"): ("public", "OCSP (RFC 6960), body is the DER request"),
    ("GET", "/pki/ocsp/{encoded}"): ("public", "OCSP GET form"),
    ("GET", "/pki/spiffe/bundle"): ("public", "SPIFFE trust bundle (JWKS)"),
    ("GET", "/.well-known/est/cacerts"): ("public", "EST CA certificates"),
    ("GET", "/.well-known/est/csrattrs"): ("public; per profile with credentials", "EST CSR attributes"),
    ("POST", "/.well-known/est/simpleenroll"): ("Basic (app key), IDevID or client certificate", "EST enrollment"),
    ("POST", "/.well-known/est/simplereenroll"): ("client certificate or Basic", "EST re-enrollment"),
    ("POST", "/.well-known/est/serverkeygen"): ("Basic or client certificate", "EST enrollment with a server-generated key"),
    ("GET", "/acme/directory"): ("public", "ACME directory"),
    ("GET", "/acme/new-nonce"): ("public", "ACME nonce"),
    ("HEAD", "/acme/new-nonce"): ("public", "ACME nonce"),
    ("POST", "/acme/new-account"): ("JWS + EAB", "register an ACME account"),
    ("POST", "/acme/acct/{acct_id}"): ("JWS (kid)", "account: update contact, deactivate"),
    ("POST", "/acme/new-order"): ("JWS (kid)", "new order"),
    ("POST", "/acme/order/{order_id}"): ("JWS (kid)", "order status"),
    ("POST", "/acme/authz/{authz_id}"): ("JWS (kid)", "authorization"),
    ("POST", "/acme/chall/{authz_id}"): ("JWS (kid)", "trigger http-01 validation (older URL form)"),
    ("POST", "/acme/chall/{authz_id}/{ctype}"): ("JWS (kid)", "trigger http-01 or dns-01 validation"),
    ("POST", "/acme/order/{order_id}/finalize"): ("JWS (kid)", "submit the CSR"),
    ("POST", "/acme/cert/{cert_id}"): ("JWS (kid)", "download the chain"),
    ("POST", "/acme/revoke-cert"): ("JWS (kid, or jwk of the certificate key)", "revoke"),
    ("POST", "/acme/key-change"): ("JWS (kid) wrapping a JWS by the new key", "account key rollover"),
    ("GET", "/acme/renewal-info/{cert_id}"): ("public", "ARI suggested renewal window (RFC 9773)"),
    ("GET", "/scep"): ("challenge in the CSR", "SCEP GetCACaps, GetCACert, PKIOperation (GET form)"),
    ("POST", "/scep"): ("challenge in the CSR, or the current certificate", "SCEP PKIOperation"),
    ("GET", "/scep/{app_name}"): ("as /scep, or a webhook-validated challenge", "per-app SCEP URL"),
    ("POST", "/scep/{app_name}"): ("as /scep, or a webhook-validated challenge", "per-app SCEP PKIOperation"),
    ("POST", "/.well-known/cmp"): ("CMP MAC (one-time secret) or signature", "CMP (RFC 9483 lightweight profile)"),
    ("POST", "/.well-known/cmp/p/{label}"): ("as /.well-known/cmp, for one app", "CMP for a named app"),
}

os.environ.setdefault("CERTADILLO_DATA_DIR", tempfile.mkdtemp())
from certadillo.api.app import create_app  # noqa: E402

spec = create_app(background=False).openapi()
rows, missing = [], []
for path, ops in spec["paths"].items():
    for method in ops:
        key = (method.upper(), path)
        if key not in DESCRIBE:
            missing.append(key)
            continue
        who, what = DESCRIBE[key]
        rows.append(f"| `{key[0]}` | `{path}` | {who} | {what} |")
if missing:
    sys.exit(f"undocumented endpoints: {missing}")

out = Path(__file__).resolve().parent.parent / "docs/guide/16-api-reference.md"
out.write_text(
    "# API reference\n\n"
    "Generated from the OpenAPI schema by `scripts/gen_api_reference.py`. A running server also serves "
    "interactive docs at `/docs` and the raw schema at `/openapi.json`.\n\n"
    "Authenticate with `X-API-Key: <key>` or `Authorization: Bearer <key>`. Errors are JSON: "
    "`401` bad key, `403` wrong role or another app's resource, `404` not found, `422` policy violation "
    "(with a `violations` list), `400` bad input.\n\n"
    "| Method | Path | Who may call | Purpose |\n| --- | --- | --- | --- |\n" + "\n".join(rows) + "\n"
)
print(f"wrote {len(rows)} endpoints to {out}")
