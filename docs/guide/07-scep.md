# SCEP

SCEP (RFC 8894) is old, but it is what Microsoft Intune, Jamf, most MDMs, Cisco and Juniper routers, VPN concentrators and many appliances speak. Certadillo implements it the way Microsoft NDES does with Intune: a one-time challenge password per device, bound to an onboarded app.

Server URL: `https://<your-certadillo>/scep` (`/scep/pkiclient.exe` also works for clients that append it).

## How it works

```
device / MDM                                  Certadillo
  GET  /scep?operation=GetCACaps ───────────▶  POSTPKIOperation, SHA-256, SHA-512, AES, SCEPStandard
  GET  /scep?operation=GetCACert ───────────▶  RA certificate (RSA) + issuing CA
  device builds: CSR (+ challengePassword)
                 └─ encrypted to the RA cert (EnvelopedData)
                    └─ signed with a throwaway self-signed cert (SignedData)
  POST /scep?operation=PKIOperation ────────▶  verify signature, decrypt, redeem challenge,
                                               RA + policy engine, sign
       ◀──── CertRep: SignedData by the RA ──  EnvelopedData(new certificate) for the device
```

The RA certificate is RSA-3072 even when the CA is ECDSA, because SCEP's envelope needs RSA key transport. It is issued by the issuing CA, lasts a year and rotates automatically 30 days before expiry.

The knowledge base at `/kb` has a 3D walkthrough of EST and SCEP side by side.

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

A challenge works once and expires (5 minutes to 24 hours, default 60). A failed request still uses it up, which stops guessing. An MDM would call this endpoint for each device it enrolls; that is the same pattern as the Intune certificate connector asking NDES for a dynamic challenge.

## 3. Enroll

With micromdm's `scepclient` (tested in CI with `scripts/interop-scep.sh`):

```bash
scepclient -server-url https://pki.bank.internal/scep \
  -challenge 90b0eb873c1e68e462ea7aeca645b992 \
  -cn rtr-0042.routers.bank.internal -dnsname rtr-0042.routers.bank.internal \
  -private-key rtr.key -certificate rtr.crt -key-encipherment-selector
```

`-key-encipherment-selector` tells the client to encrypt to the RA certificate rather than the CA; many device firmwares do this on their own by checking key usage.

On a Cisco IOS router the equivalent is a trustpoint with `enrollment url https://pki.bank.internal/scep` and the challenge as the enrollment password. The CN must be inside the app's scope.

## Legacy DES clients

Some clients still encrypt the request with single DES (micromdm `scepclient` 2.3 does, even when the server advertises AES). Certadillo refuses single DES unless you set `CERTADILLO_SCEP_ALLOW_DES=true`. AES-CBC and 3DES are always accepted. Keep SCEP behind HTTPS in either case. Responses to the device are always encrypted with AES.

## Troubleshooting

Every rejected SCEP request writes a `certificate.rejected` audit event with the reason:

```bash
curl -s -H "X-API-Key: $ADMIN_KEY" "$S/api/v1/audit?limit=20" | grep -A3 scep
```

| Reason | Fix |
| --- | --- |
| `SCEP challenge password is unknown, used or expired` | mint a new challenge |
| `content encryption des not accepted` | update the client, or set `CERTADILLO_SCEP_ALLOW_DES=true` |
| `san_scope` / `cn_scope` | the device name is outside the app's `allowed_domains` |
| `envelope is not addressed to the SCEP RA certificate` | the client encrypted to the CA; use the key-encipherment selector |

## Limits today

- Only `PKCSReq` (initial enrollment). `RenewalReq` and `GetCertInitial` polling are on the roadmap, so dual-control profiles cannot be issued over SCEP.
- Re-enrollment is a new `PKCSReq` with a new challenge.
