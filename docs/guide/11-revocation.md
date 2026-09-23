# Revocation: OCSP and CRL

Revoking a certificate is only useful if relying parties find out. Certadillo publishes revocation two ways, and every certificate it issues points at both (the AIA and CDP extensions).

| | OCSP | CRL |
| --- | --- | --- |
| What | ask about one certificate, get a signed "good", "revoked" or "unknown" | download the signed list of every revoked serial |
| URL | `POST /pki/ocsp` (or `GET /pki/ocsp/<base64 request>`) | `GET /pki/crl/<ca>.crl` |
| Freshness | live: reflects a revocation the moment it is committed | re-signed on every revocation and every `CERTADILLO_CRL_INTERVAL_HOURS` (12); valid 24 hours |
| Signed by | a delegated OCSP responder certificate (30 days, rotated automatically) | the issuing CA key (in the HSM) |

The knowledge base at `/kb` animates both paths.

## Revoke

```bash
curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -X POST $S/api/v1/certificates/7/revoke -d '{"reason": "key_compromise"}'
```

Production revocations by staff need `"change_ref"` unless the reason is `key_compromise`. ACME clients revoke with their own protocol (`certbot revoke`), and the same CRL publishing happens.

## Check with openssl

```bash
curl -s $S/pki/ca/root-ca.pem -o root.pem
curl -s $S/pki/ca/issuing-ca-1.pem -o issuing.pem

openssl ocsp -issuer issuing.pem -cert server.crt -url $S/pki/ocsp -CAfile root.pem
# Response verify OK
# server.crt: good            (or: revoked, with the reason and time)

curl -s $S/pki/crl/issuing-ca-1.crl | openssl crl -inform DER -noout -text | head -20
```

## How the responder works

The issuing CA signs a short-lived responder certificate with `id-kp-OCSPSigning` and the `ocsp-nocheck` extension (RFC 6960 section 4.2.2.2). The responder signs OCSP answers with that certificate's key, so the CA key in the HSM is only used for certificates and CRLs. Answers are valid for 4 hours and echo the client's nonce when one is sent.

`GET /pki/crl/<ca>.crl` serves the stored CRL. It is only re-signed when a revocation happens, when the timer runs, or when the stored one has passed its nextUpdate. Anonymous downloads never trigger signing.

## For large deployments

- Put CRLs behind a CDN or static host; they hold no secrets.
- Run OCSP on several replicas in the DMZ against a read-only database replica.
- Watch `CRLStale` and `certadillo_ocsp_requests_total` (see [Alerting](13-alerting-observability.md)).

## Superseded is not revoked

Renewal marks the old certificate `superseded`; it stays valid until it expires and OCSP keeps answering "good". Revoke it explicitly if the old key must stop working now.
