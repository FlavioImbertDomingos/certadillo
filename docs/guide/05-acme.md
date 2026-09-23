# ACME

ACME (RFC 8555) is the protocol Let's Encrypt made common. Most web servers, reverse proxies and Kubernetes already have a client for it, so it is the easiest way to get fully automatic renewal.

Directory URL: `https://<your-certadillo>/acme/directory`

## How it works in Certadillo

```
certbot                                   Certadillo
  │  GET  /acme/directory ───────────────▶  endpoints + "externalAccountRequired": true
  │  HEAD /acme/new-nonce ───────────────▶  Replay-Nonce
  │  POST /acme/new-account  (JWS + EAB) ─▶  account bound to the onboarded app
  │  POST /acme/new-order    (names) ────▶  names checked against the app's scope up front
  │  POST /acme/authz/{id} ──────────────▶  http-01 token
  │     (client serves token.thumbprint at http://<name>/.well-known/acme-challenge/<token>)
  │  POST /acme/chall/{id} ──────────────▶  Certadillo fetches it and compares
  │  POST /acme/order/{id}/finalize (CSR) ▶  same RA + policy engine as every protocol
  │  POST /acme/cert/{id} ───────────────▶  leaf + issuing CA (PEM chain)
```

Three things differ from a public ACME CA:

1. **External Account Binding is mandatory.** An ACME account is always tied to one onboarded app, so orders are limited to that app's scope, profile and environment.
2. **Scope is checked at `new-order`.** A name outside the app's approved domains is refused with `rejectedIdentifier` before any challenge runs.
3. **Challenge mode is configurable.** `CERTADILLO_ACME_CHALLENGE=http-01` (default) validates by fetching the token. `ra-scope` skips the network check for names already inside the app's scope, because ownership was proven at onboarding. Use it for internal names that the platform cannot reach over HTTP.

The knowledge base at `/kb` has a 3D, step-by-step walkthrough of this flow.

## Get an EAB credential

```bash
curl -s -H "X-API-Key: $ADMIN_KEY" -X POST $S/api/v1/apps/1/acme-eab
```

```json
{"kid": "eab_ea1ae05c6517f939",
 "hmac_key": "oh7sIaV_ZUzExOL24qDutXJfRwAHF4OL1X-ZjiXUWO8",
 "example": "certbot certonly --server https://pki.bank.internal/acme/directory --eab-kid eab_ea1ae05c6517f939 --eab-hmac-key oh7s... -d <name>"}
```

The credential works once: the first account registered with it keeps it.

## certbot

Tested in CI with `scripts/interop-certbot.sh` (issue, OCSP check, revoke, CRL check).

```bash
certbot certonly --standalone \
  --server https://pki.bank.internal/acme/directory \
  --eab-kid eab_ea1ae05c6517f939 --eab-hmac-key oh7sIaV_ZUzExOL24qDutXJfRwAHF4OL1X-ZjiXUWO8 \
  -m web-team@bank.example --agree-tos --key-type ecdsa \
  -d www.portal.bank.internal -d api.portal.bank.internal
```

With nginx already on port 80, use `--webroot -w /var/www/html` instead of `--standalone`. Renewal is certbot's own timer (`certbot renew`), which uses the stored account; no new EAB is needed.

If the host trusts the enterprise root only in a custom bundle, point certbot at it with `REQUESTS_CA_BUNDLE=/etc/pki/bank-root.pem`.

Revoke:

```bash
certbot revoke --server https://pki.bank.internal/acme/directory \
  --cert-name www.portal.bank.internal --reason keycompromise
```

## cert-manager (Kubernetes)

Not yet part of the automated tests; the configuration follows cert-manager's standard ACME issuer.

```yaml
apiVersion: v1
kind: Secret
metadata: {name: certadillo-eab, namespace: cert-manager}
stringData: {secret: oh7sIaV_ZUzExOL24qDutXJfRwAHF4OL1X-ZjiXUWO8}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: certadillo}
spec:
  acme:
    server: https://pki.bank.internal/acme/directory
    caBundle: <base64 of bank-root.pem>
    externalAccountBinding:
      keyID: eab_ea1ae05c6517f939
      keySecretRef: {name: certadillo-eab, key: secret}
    privateKeySecretRef: {name: certadillo-acme-account}
    solvers:
      - http01: {ingress: {ingressClassName: nginx}}
```

Then annotate an Ingress with `cert-manager.io/cluster-issuer: certadillo`, or create a `Certificate` resource.

## Other clients

Any RFC 8555 client with EAB support should work; only certbot is tested today.

| Client | EAB flags |
| --- | --- |
| lego | `--eab --kid <kid> --hmac <hmac_key> --server <directory>` |
| acme.sh | `--register-account --server <directory> --eab-kid <kid> --eab-hmac-key <hmac_key>` |
| win-acme | `--baseuri <directory> --eab-key-identifier <kid> --eab-key <hmac_key>` |

## Limits today

- Only `http-01` (or `ra-scope`). `dns-01`, key rollover (`key-change`) and ACME Renewal Information are on the roadmap.
- Profiles with dual control (code signing) cannot be issued over ACME; use REST.
- Orders expire after 8 hours.
