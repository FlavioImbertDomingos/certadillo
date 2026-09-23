# EST

EST (Enrollment over Secure Transport, RFC 7030) is the device-friendly protocol: plain HTTPS, base64 PKCS#10 in, base64 PKCS#7 out. ATMs, IoT gateways and newer network gear often support it natively.

Base path: `https://<your-certadillo>/.well-known/est/`

| Operation | Method and path | Auth |
| --- | --- | --- |
| Get CA certificates | `GET /.well-known/est/cacerts` | none |
| First enrollment | `POST /.well-known/est/simpleenroll` | HTTP Basic, password = app API key |
| Renewal with a new key | `POST /.well-known/est/simplereenroll` | same |

The Basic username is free text (a device ID is a good choice; it shows up in logs). The password is an API key minted with `POST /api/v1/apps/{id}/credentials`. Run EST behind HTTPS; RFC 7030 requires TLS.

## With curl and openssl

```bash
# 1. trust anchors (root + issuing CA), base64 PKCS#7
curl -s $S/.well-known/est/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs -out est-ca.pem

# 2. key and CSR on the device; EST wants base64 DER
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout atm.key \
  -subj "/CN=atm-0042.atm.bank.internal" -outform DER | base64 > atm.csr.b64

# 3. enroll
curl -s -u "atm-0042:$KEY" -H "Content-Type: application/pkcs10" --data-binary @atm.csr.b64 \
  $S/.well-known/est/simpleenroll | base64 -d | openssl pkcs7 -inform DER -print_certs -out atm.crt

openssl x509 -in atm.crt -noout -subject -enddate
```

For an EST client the CN is enough; Certadillo copies it into the SAN, as RFC 9525 expects.

## Re-enrollment

Send a CSR with the same subject and a new key to `simplereenroll`. Certadillo finds the device's current certificate by app and CN, issues the new one and marks the old one `superseded`.

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout atm-new.key \
  -subj "/CN=atm-0042.atm.bank.internal" -outform DER | base64 > atm-new.csr.b64
curl -s -u "atm-0042:$KEY" -H "Content-Type: application/pkcs10" --data-binary @atm-new.csr.b64 \
  $S/.well-known/est/simplereenroll | base64 -d | openssl pkcs7 -inform DER -print_certs -out atm.crt
```

## Responses

| Status | Meaning |
| --- | --- |
| 200 | base64 PKCS#7 certs-only with the new certificate |
| 202 + `Retry-After` | the profile needs dual control; ask again after approval |
| 400 | policy rejection or malformed CSR; the body names the rule |
| 401 | missing or wrong Basic credentials |

## Limits today

- Authentication is by API key over Basic auth. For TLS client-certificate authentication on re-enrollment (as RFC 7030 describes), terminate mTLS at your load balancer; native support is on the roadmap.
- `csrattrs`, `serverkeygen` and `fullcmc` are not implemented.
