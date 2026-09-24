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
  │  POST /acme/authz/{id} ──────────────▶  http-01 and dns-01 challenges (dns-01 only for wildcards)
  │     http-01: serve token.thumbprint at http://<name>/.well-known/acme-challenge/<token>
  │     dns-01:  publish a TXT record at _acme-challenge.<name>
  │  POST /acme/chall/{id}/{type} ───────▶  Certadillo checks it
  │  POST /acme/order/{id}/finalize (CSR) ▶  same RA + policy engine as every protocol
  │  POST /acme/cert/{id} ───────────────▶  leaf + issuing CA (PEM chain)
  │  GET  /acme/renewal-info/{CertID} ───▶  when to renew (ARI, RFC 9773)
```

Four things differ from a public ACME CA:

1. **External Account Binding is mandatory.** An ACME account is always tied to one onboarded app, so orders are limited to that app's scope, profile and environment.
2. **Scope is checked at `new-order`.** A name outside the app's approved domains, or a wildcard on a profile that does not allow wildcards, is refused with `rejectedIdentifier` before any challenge runs.
3. **DNS lookups follow your views.** dns-01 asks the resolvers you configure per zone, so internal zones are checked against internal DNS (see [Split-horizon DNS](#split-horizon-dns)).
4. **The server can ask for early renewal.** ARI lets an operator pull renewal forward for chosen certificates, ahead of a revocation. See [Renewal campaigns](19-renewal-campaigns.md).

`CERTADILLO_ACME_CHALLENGE=ra-scope` skips the network check for names already inside the app's scope, because ownership was proven at onboarding. Use it only where the platform can reach neither the web servers nor the DNS.

The knowledge base at `/kb` has 3D, step-by-step walkthroughs of the http-01 flow and of dns-01 with a renewal campaign.

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

## certbot with http-01

Tested with `scripts/interop-certbot.sh` (issue, OCSP check, revoke, CRL check).

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

A certificate can also be revoked with a request signed by its own private key instead of the account key, for example after the account key is lost (RFC 8555 section 7.6).

## dns-01 and wildcards

dns-01 proves control of a name by publishing a TXT record: `_acme-challenge.<name>` must contain `base64url(SHA-256(token "." account thumbprint))`. It is the only way to prove a wildcard, and the usual choice when the web servers are not reachable from the PKI or when there is no web server at all (a database, a message broker, a load balancer VIP).

Wildcards need an app onboarded with the `tls-wildcard` profile. For the name `*.edge.portal.bank.internal` the authorization is for `edge.portal.bank.internal` with `"wildcard": true`, and it offers dns-01 only.

certbot with manual hooks, as run by `scripts/interop-acme-dns.sh`:

```bash
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /usr/local/bin/dns-add.sh --manual-cleanup-hook /usr/local/bin/dns-del.sh \
  --server https://pki.bank.internal/acme/directory --eab-kid <kid> --eab-hmac-key <hmac_key> \
  -d '*.edge.portal.bank.internal' -d edge.portal.bank.internal
```

The hooks receive `CERTBOT_DOMAIN` and `CERTBOT_VALIDATION` and write the record through your DNS provider's API. certbot plugins exist for most providers (`certbot-dns-rfc2136` for BIND and anything that accepts dynamic updates, `certbot-dns-route53`, `certbot-dns-cloudflare`, and so on).

### Split-horizon DNS

Banks usually run different DNS views inside and outside. Certadillo picks the resolvers for each lookup by zone, longest suffix first:

```bash
# internal zones go to the internal resolvers; the rest to the defaults
CERTADILLO_ACME_DNS_VIEWS="bank.internal=10.1.0.53,10.2.0.53;pay.bank.internal=10.9.0.53"
CERTADILLO_ACME_DNS_RESOLVERS="10.1.0.53,10.2.0.53"   # names in no view (default: the host's resolv.conf)
CERTADILLO_ACME_DNS_TIMEOUT=8                          # seconds per lookup
```

Servers can carry a port (`10.9.0.53:5353`, `[fd00::53]:53`). Answers are never cached, so a record the client just wrote is seen at once.

### CNAME delegation

When the main zone belongs to another team, point `_acme-challenge` at a zone the app's automation may write:

```
_acme-challenge.api.portal.bank.internal.  CNAME  api.acme-delegate.portal.bank.internal.
```

Certadillo follows the CNAME. The target is resolved in the same view as the original name.

When dns-01 fails, the challenge error says what was found and where, for example `no TXT record at _acme-challenge.db.portal.bank.internal matches the key authorization (1 found in the portal.bank.internal view)`.

## ARI: renewal information

The directory advertises `renewalInfo`. A client asks `GET /acme/renewal-info/<CertID>`, where CertID is `base64url(authority key identifier) "." base64url(serial)`, and gets a window:

```json
{"suggestedWindow": {"start": "2026-10-09T04:10:13Z", "end": "2026-10-12T04:10:13Z"}}
```

- By default the window covers 50 to 60 percent of the certificate's lifetime. That is before the platform's own expiry warning (at `min(30 days, lifetime/3)` left), so a client that follows ARI renews before anyone is paged.
- A revoked certificate gets a window in the past, which means renew now.
- During a [renewal campaign](19-renewal-campaigns.md) the window moves forward and the response adds an `explanationURL`.
- `Retry-After` is 6 hours (`CERTADILLO_ARI_RETRY_AFTER`, seconds), 1 hour for certificates in a campaign.

When renewing, a client sends `"replaces": "<CertID>"` in `new-order`. Certadillo then requires a new key and marks the old certificate superseded. A second order for the same certificate gets `alreadyReplaced`.

certbot 5.x checks ARI during `certbot renew` but does not send `replaces`; Certadillo recognises such renewals by app and names instead (a newer certificate for the same app with the same names counts as the replacement). Check your client's release notes for its ARI support.

For clients that do not speak ACME, the same window is at `GET /api/v1/certificates/{id}/renewal-info`.

## Accounts

| Action | How |
| --- | --- |
| Change contact | `POST /acme/acct/{id}` with `{"contact": [...]}` |
| Roll the account key | `POST /acme/key-change`: outer JWS signed with the old key, payload an inner JWS signed with the new key carrying `{"account", "oldKey"}` (RFC 8555 7.3.5). A key already used by another account returns 409 with that account's URL. |
| Deactivate | `POST /acme/acct/{id}` with `{"status": "deactivated"}`, or `certbot unregister`. Open orders are closed, their authorizations deactivated, and the key cannot register again. |
| Give up an authorization | `POST /acme/authz/{id}` with `{"status": "deactivated"}` |

Housekeeping runs every `CERTADILLO_ALERT_INTERVAL` seconds: orders past their 8-hour expiry are closed, orders expired for 30 days are deleted, and unused nonces older than an hour are dropped.

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
      - selector: {dnsNames: ["*.edge.portal.bank.internal"]}
        dns01: {rfc2136: {nameserver: 10.9.0.53, tsigKeyName: acme, tsigAlgorithm: HMACSHA256,
                          tsigSecretSecretRef: {name: tsig, key: secret}}}
```

Then annotate an Ingress with `cert-manager.io/cluster-issuer: certadillo`, or create a `Certificate` resource.

## Other clients

Any RFC 8555 client with EAB support should work; certbot is the one in the automated tests.

| Client | EAB flags |
| --- | --- |
| lego | `--eab --kid <kid> --hmac <hmac_key> --server <directory>` |
| acme.sh | `--register-account --server <directory> --eab-kid <kid> --eab-hmac-key <hmac_key>` |
| win-acme | `--baseuri <directory> --eab-key-identifier <kid> --eab-key <hmac_key>` |

## Limits today

- Profiles with dual control (code signing) cannot be issued over ACME; use REST, SCEP or CMP, which can wait for an approver.
- Orders expire after 8 hours.
- dns-01 checks from one vantage point (the Certadillo host). Public CAs check from several; for internal names that adds little.
