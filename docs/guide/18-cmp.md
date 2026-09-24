# CMP

CMP (Certificate Management Protocol, RFC 4210, updated by RFC 9480) is what much telecom and industrial equipment speaks: 3GPP base stations, Siemens and other OT gear, some routers. Certadillo follows the lightweight CMP profile (RFC 9483), the subset those devices implement, over HTTP (RFC 6712).

Endpoint: `POST https://<your-certadillo>/.well-known/cmp`, content type `application/pkixcmp`. `/.well-known/cmp/p/<app name>` works too and refuses credentials of other apps.

The knowledge base at `/kb` has a 3D walkthrough of a device's life over CMP: first enrollment with a secret, confirmation, key update, a request that waits for an approver, and revocation.

## What is supported

| Request | Reply | Use |
| --- | --- | --- |
| `ir` | `ip` | first enrollment |
| `cr` | `cp` | another certificate for an enrolled device |
| `kur` | `kup` | key update: new key, same subject |
| `p10cr` | `cp` | enrollment with a PKCS#10 CSR |
| `certConf` | `pkiConf` | the device confirms the certificate it received |
| `pollReq` | `pollRep`, then `ip`/`cp`/`kup` | waiting for a second person |
| `rr` | `rp` | the device revokes one of its certificates |
| `genm` (id-it-caCerts) | `genp` | fetch the CA certificates |

One certificate request per message, as the lightweight profile requires. Central key generation (the server making the key) is not offered over CMP; use EST serverkeygen for that.

## How a device is authenticated

**First enrollment: a shared secret.** A device with no certificate proves itself with a one-time reference and secret (RFC 9483 section 4.1.1). The message is protected with PasswordBasedMac: the secret, a salt and an iteration count derive an HMAC key over the message. Mint one per device:

```bash
curl -s -H "X-API-Key: $OPERATOR_KEY" -X POST "$S/api/v1/apps/5/cmp-secret?ttl_minutes=60"
```

```json
{"reference": "cmp-37614dc792fc", "secret": "q7Cq3oT0y1F2l8i9WmXbRk2v",
 "expires": "2026-09-24T05:27:21+00:00", "server": "pki.bank.internal/.well-known/cmp",
 "example": "openssl cmp -cmd ir -server pki.bank.internal -path .well-known/cmp -ref cmp-37614dc792fc -secret pass:q7Cq... ..."}
```

The reference goes in `senderKID`. The secret works for one enrollment (the certificate request plus its confirmation or polling) and is stored encrypted, because the MAC needs the plaintext.

**After that: the device's certificate.** `cr`, `kur`, `p10cr`, `rr` and `genm` can be signed with a current certificate from this CA, carried first in `extraCerts`. It identifies the app. After a `kur` the old certificate is superseded, but the device may still sign that transaction's `certConf` with it, as RFC 9483 section 4.1.3 describes.

**Replies** use the same kind of protection as the request: the same shared secret, or a signature from the CMP RA certificate. That certificate is EC P-256, issued by the issuing CA with the extended key usage `id-kp-cmcRA`, and signed replies carry it plus the issuing CA in `extraCerts`. A device that enrolled with a secret has no trust anchor yet, so its `ip` also carries the root in `caPubs`.

## With the OpenSSL CMP client

OpenSSL 3.0 and later include `openssl cmp`. `tests/test_cmp.py` runs these against a live server.

```bash
S=pki.bank.internal
# first enrollment with the secret; saves the root it receives
openssl ecparam -name prime256v1 -genkey -noout -out dev.key
openssl cmp -cmd ir -server $S -path .well-known/cmp \
  -ref cmp-37614dc792fc -secret pass:q7Cq3oT0y1F2l8i9WmXbRk2v \
  -newkey dev.key -subject "/CN=s1.plant.bank.internal" -sans s1.plant.bank.internal \
  -certout dev.crt -cacertsout root.pem -extracertsout chain.pem

# key update, signed with the current certificate; the subject is carried over
openssl ecparam -name prime256v1 -genkey -noout -out dev2.key
openssl cmp -cmd kur -server $S -path .well-known/cmp -trusted root.pem \
  -cert dev.crt -key dev.key -extracerts chain.pem -newkey dev2.key -certout dev2.crt

# CA certificates
openssl cmp -cmd genm -server $S -path .well-known/cmp -trusted root.pem \
  -cert dev2.crt -key dev2.key -infotype caCerts

# a PKCS#10 request, without the certConf round trip
openssl cmp -cmd p10cr -server $S -path .well-known/cmp -trusted root.pem \
  -cert dev2.crt -key dev2.key -csr other.csr -certout other.crt -implicit_confirm

# revoke it (reason 4 = superseded)
openssl cmp -cmd rr -server $S -path .well-known/cmp -trusted root.pem \
  -cert dev2.crt -key dev2.key -oldcert other.crt -revreason 4
```

## Confirmation

After an `ip`, `cp` or `kup` the device sends `certConf` with the hash of the certificate it received, and Certadillo answers `pkiConf`. A device that asks for `implicitConfirm` in the request header gets it: the reply says so and no `certConf` is expected.

If the device rejects the certificate in `certConf`, Certadillo revokes it. If it never confirms, the transaction is marked `cmp.unconfirmed` in the audit trail after 15 minutes; the certificate stays valid, because some devices never send `certConf`.

## Waiting for an approver

For a profile under dual control (such as `code-signing`) the reply's status is `waiting` and an approval request is created. The device sends `pollReq`; each `pollRep` says to ask again in 30 seconds. Once an approver decides, the next `pollReq` gets the final `ip` with the certificate, or a rejection naming who rejected it. OpenSSL does this on its own; give it enough time with `-total_timeout`.

## Revocation

`rr` names the certificate by serial number (and issuer) and may carry a CRLReason. It must be signed with a certificate of the same app, and the certificate being revoked must belong to that app. The CRL is re-signed right away. Supported reasons: unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation.

## Errors

Every failure is answered with a CMP `error` message (never an HTTP error), with a `PKIFailureInfo` bit and a text, and written to the audit trail as `cmp.error`:

| Text | failInfo | Fix |
| --- | --- | --- |
| `unknown senderKID` | signerNotTrusted | wrong reference |
| `the shared secret was already used or has expired` | signerNotTrusted | mint a new one |
| `MAC does not verify` | wrongIntegrity | wrong secret |
| `the signing certificate was not issued here or is no longer current` | signerNotTrusted | the certificate is revoked, superseded or expired |
| `proof of possession signature does not verify` | badPOP | the request was not signed with the new key |
| `san_scope` / `cn_scope` in the status text | badCertTemplate | the name is outside the app's `allowed_domains` |
| `send exactly one certificate request per message` | badRequest | one request per message |

An error to a request whose protection could not be verified is signed by the CMP RA; with OpenSSL, `-unprotected_errors` shows its text even without a trust anchor.

## Limits today

- Only PasswordBasedMac for MAC protection (not PBMAC1 or DH-based MAC).
- No central key generation, no `ccr` (cross-certification), no nested messages, and no announcement messages.
- The lightweight profile's `certReqTemplate` and `rootCaCert` general messages are not answered.
