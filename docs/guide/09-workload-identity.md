# Workload identity (SPIFFE)

SPIFFE gives each workload an identity like `spiffe://bank.internal/payments/card-auth`, carried in an X.509 certificate called an X.509-SVID. Services then authenticate each other with mTLS based on those IDs rather than hostnames or IPs.

Certadillo issues SVIDs through the `spiffe-svid` profile and publishes the trust bundle.

## Onboard a workload group

The scope is a SPIFFE ID pattern under the trust domain (`bank.internal`, set by `spiffe_trust_domain` in the policy file):

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 1, "name": "payments-mesh",
  "environment": "prod", "profile": "spiffe-svid",
  "allowed_domains": ["spiffe://bank.internal/payments/*"]}'
```

## Request an SVID

The CSR carries exactly one URI SAN and no CN:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout svid.key \
  -subj "/" -addext "subjectAltName=URI:spiffe://bank.internal/payments/card-auth" -out svid.csr

certadillo cert request --spiffe-id spiffe://bank.internal/payments/card-auth --out ./svid    # or use the CLI
```

With REST, send the CSR to `POST /api/v1/certificates`; `validity_hours` defaults to 24 and is capped at 72.

The SVID has an empty subject, a critical SAN with the SPIFFE ID, and both server and client authentication EKUs. Requests are refused when the ID is in another trust domain (`spiffe_trust_domain`), outside the app's pattern (`spiffe_scope`), or when there is more than one URI (`spiffe_id`).

## Trust bundle

```bash
curl -s $S/pki/spiffe/bundle
```

```json
{"keys": [{"use": "x509-svid", "kty": "EC", "crv": "P-384", "x": "...", "y": "...", "x5c": ["MIIC..."]}],
 "spiffe_sequence": 1, "spiffe_refresh_hint": 300, "trust_domain": "bank.internal"}
```

This is the JWKS form from the SPIFFE Trust Domain and Bundle specification, usable for SPIRE federation or for Envoy's SDS validation context.

## With SPIRE

SPIRE is a common way to hand SVIDs to workloads automatically after attesting them. Two integration paths, both on the roadmap:

1. Certadillo issues SPIRE server an intermediate CA through dual control, and SPIRE's `disk` UpstreamAuthority plugin uses it. SPIRE then mints SVIDs itself, chained to the bank root.
2. A small UpstreamAuthority plugin calls Certadillo for each SPIRE CA rotation.

Today you can issue SVIDs directly as shown above, which suits batch jobs and services outside Kubernetes.
