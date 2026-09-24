# SCEP

SCEP (RFC 8894) is old, but it is what Microsoft Intune, Jamf, most MDMs, Cisco and Juniper routers, VPN concentrators and many appliances speak. Certadillo implements it the way Microsoft NDES does with Intune: a one-time challenge password per device, bound to an onboarded app, or a challenge from the MDM that a validation webhook checks.

Server URL: `https://<your-certadillo>/scep`, or `https://<your-certadillo>/scep/<app name>` for a per-app URL (`/pkiclient.exe` may be appended to either).

## How it works

```
device / MDM                                  Certadillo
  GET  /scep?operation=GetCACaps ───────────▶  POSTPKIOperation, Renewal, SHA-256, SHA-512, AES, SCEPStandard
  GET  /scep?operation=GetCACert ───────────▶  RA certificate (RSA) + issuing CA
  device builds: CSR (+ challengePassword)
                 └─ encrypted to the RA cert (EnvelopedData)
                    └─ signed with a throwaway self-signed cert (SignedData)
  POST /scep?operation=PKIOperation ────────▶  verify signature, decrypt, check the challenge,
                                               RA + policy engine, sign
       ◀──── CertRep: SignedData by the RA ──  EnvelopedData(new certificate) for the device
```

The RA certificate is RSA-3072 even when the CA is ECDSA, because SCEP's envelope needs RSA key transport. It is issued by the issuing CA, lasts a year and rotates automatically 30 days before expiry.

| messageType | What Certadillo does |
| --- | --- |
| 19 PKCSReq | enrollment with a challenge |
| 17 RenewalReq | renewal signed with the current certificate, no challenge |
| 20 CertPoll (GetCertInitial) | answers a pending request |

The knowledge base at `/kb` has a 3D walkthrough of EST and SCEP side by side, including renewal and a pending request.

## 1. Onboard the device fleet

Devices usually get client certificates:

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 2, "name": "branch-routers",
  "environment": "prod", "profile": "tls-client", "allowed_domains": ["*.routers.bank.internal"]}'
```

## 2. Mint a challenge per device

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -X POST "$S/api/v1/apps/7/scep-challenge?ttl_minutes=60"
```

```json
{"challenge": "90b0eb873c1e68e462ea7aeca645b992",
 "expires": "2026-09-24T00:19:27+00:00",
 "server_url": "https://pki.bank.internal/scep"}
```

A challenge works once and expires (5 minutes to 24 hours, default 60). A failed request still uses it up, which stops guessing. On `/scep` the challenge itself says which app the device belongs to; on `/scep/<app name>` it must also belong to that app.

## 3. Enroll

With micromdm's `scepclient` (run by `scripts/interop-scep.sh`):

```bash
scepclient -server-url https://pki.bank.internal/scep \
  -challenge 90b0eb873c1e68e462ea7aeca645b992 \
  -cn rtr-0042.routers.bank.internal -dnsname rtr-0042.routers.bank.internal \
  -private-key rtr.key -certificate rtr.crt -key-encipherment-selector
```

`-key-encipherment-selector` tells the client to encrypt to the RA certificate rather than the CA; many device firmwares do this on their own by checking key usage.

On a Cisco IOS router the equivalent is a trustpoint with `enrollment url https://pki.bank.internal/scep` and the challenge as the enrollment password. The CN must be inside the app's scope.

## Renewal

A device renews with `RenewalReq`: the same kind of message, but signed with its current certificate and key instead of a throwaway certificate. No challenge is needed; the signature is the authentication. Certadillo checks that:

- the signing certificate was issued here, is active and not expired,
- the CSR keeps the subject and names of that certificate,
- the key is new (for profiles with `require_new_key_on_renewal`).

The old certificate is then `superseded` and cannot renew again. A `PKCSReq` signed by a current certificate and carrying no challenge is treated the same way, because some clients renew like that.

## Pending requests and polling

For a profile under dual control (such as `code-signing`), the first answer is `PENDING` and an approval request is created. The device polls, either with `CertPoll` (messageType 20) or, like micromdm `scepclient`, by sending the same request again (every 30 seconds for scepclient). Once an approver decides:

- approved: the next poll returns `SUCCESS` with the certificate,
- rejected: the next poll returns `FAILURE` with `badRequest`.

Only the key that sent the original request can collect the answer; a poll signed by another key fails with `badMessageCheck`. `scripts/interop-scep.sh` runs this with scepclient and an approver.

## Intune and other MDMs: the validation webhook

With Intune, the MDM issues the challenge, not Certadillo. Microsoft's pattern for third-party SCEP servers is to ask the MDM whether a challenge is valid for this exact request, then report back what happened. Certadillo does this through a webhook, so a small connector next to your MDM can translate to its API:

```bash
CERTADILLO_SCEP_VALIDATION_URL=https://scep-connector.bank.internal/validate
CERTADILLO_SCEP_VALIDATION_TOKEN=<bearer token the connector checks>

# the app's devices enroll at /scep/corp-laptops
curl -s "${A[@]}" -X PUT $S/api/v1/apps/9/options -d '{"scep_validation": "webhook"}'
```

For each request to `/scep/corp-laptops` Certadillo POSTs JSON to the URL:

```json
{"event": "validate", "transactionId": "tx-77", "app": "corp-laptops",
 "challenge": "<from the CSR>", "csr": "<base64 DER>",
 "subject": "CN=laptop-77.corp.bank.internal", "sans": ["laptop-77.corp.bank.internal"]}
```

and signs only if the answer is `{"valid": true}`. Anything else, including a timeout or an error, fails the request with the reason in the audit trail. Afterwards it sends `{"event": "success", "transactionId", "serial", "thumbprint", "notAfter", "issuer"}` or `{"event": "failure", "transactionId", "reason"}`. Those three calls line up with the validate, success-notification and failure-notification calls of Microsoft's SCEP validation library, which the connector would call. The connector itself is not part of Certadillo.

## Legacy DES clients

Some clients still encrypt the request with single DES (micromdm `scepclient` 2.3 does, even when the server advertises AES). Certadillo refuses single DES unless you set `CERTADILLO_SCEP_ALLOW_DES=true`. AES-CBC and 3DES are always accepted. Keep SCEP behind HTTPS in either case. Responses to the device are always encrypted with AES.

## Troubleshooting

Every rejected SCEP request writes a `certificate.rejected` audit event with the reason:

```bash
curl -s -H "X-API-Key: $ADMIN_KEY" "$S/api/v1/audit?limit=20" | grep -A3 scep
```

| Reason | Fix |
| --- | --- |
| `SCEP challenge password is unknown, used or expired` | mint a new challenge, or use the app's own URL |
| `validation webhook refused the request` / `unavailable` | check the connector and the MDM; the request was not signed |
| `RenewalReq must be signed by a current certificate issued here` | the device's certificate is revoked, superseded or expired; enroll again with a challenge |
| `renewal must keep the subject and names` | renew with the same CN and SANs |
| `CertPoll must be signed by the key that sent the request` | the device lost its temporary key; send a new request |
| `content encryption des not accepted` | update the client, or set `CERTADILLO_SCEP_ALLOW_DES=true` |
| `san_scope` / `cn_scope` | the device name is outside the app's `allowed_domains` |
| `envelope is not addressed to the SCEP RA certificate` | the client encrypted to the CA; use the key-encipherment selector |

## Limits today

- `GetCRL` and `GetCert` are not implemented; use the CRL distribution point and OCSP.
- The webhook contract is Certadillo's own; talking to Intune needs a connector that calls Microsoft's validation API.
