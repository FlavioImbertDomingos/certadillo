# EST

EST (Enrollment over Secure Transport, RFC 7030) is the device-friendly protocol: plain HTTPS, base64 PKCS#10 in, base64 PKCS#7 out. ATMs, IoT gateways and newer network gear often support it natively.

Base path: `https://<your-certadillo>/.well-known/est/`

| Operation | Method and path | Auth |
| --- | --- | --- |
| Get CA certificates | `GET /cacerts` | none |
| What to put in the CSR | `GET /csrattrs` | optional; with credentials the answer follows the app's profile |
| First enrollment | `POST /simpleenroll` | HTTP Basic, or a manufacturer (IDevID) certificate |
| Renewal with a new key | `POST /simplereenroll` | the current certificate, or HTTP Basic |
| Key made by the server | `POST /serverkeygen` | HTTP Basic or a certificate; only for some profiles |

The knowledge base at `/kb` has a 3D walkthrough of EST behind a load balancer, from a factory certificate to re-enrollment.

## Authentication

Three ways, checked in this order:

1. **A certificate issued here**, presented as the TLS client certificate. It identifies the app it was issued to. This is how RFC 7030 expects re-enrollment to work.
2. **A manufacturer certificate (IDevID)** from a CA registered for the app. Devices bootstrap without any shared secret.
3. **HTTP Basic**: the username is free text (a device ID shows up in logs), the password an API key minted with `POST /api/v1/apps/{id}/credentials`.

Certadillo runs behind a TLS terminator, so the client certificate reaches it from the load balancer in a header (next section). Without that set up, only HTTP Basic works.

## Behind a load balancer

The load balancer terminates TLS, asks for a client certificate, and forwards it in a header. Certadillo believes that header only when the request proves it came through the load balancer:

- with a shared secret the load balancer adds as `X-Certadillo-Proxy-Auth` (`CERTADILLO_EST_PROXY_SECRET`), or
- from a proxy address listed in `CERTADILLO_EST_TRUSTED_PROXIES` (CIDRs). This works only when Certadillo sees the load balancer's own address, that is, when the load balancer is not in uvicorn's `FORWARDED_ALLOW_IPS`. Behind uvicorn's proxy-header handling, use the secret.

Otherwise the header is ignored and logged. The load balancer must also overwrite any copy of the header a client sends, which `proxy_set_header` does.

```bash
CERTADILLO_EST_CLIENT_CERT_HEADER=X-SSL-Client-Cert
CERTADILLO_EST_PROXY_SECRET=<long random value, also in the nginx config>
```

nginx, as used by `scripts/interop-est.sh`:

```nginx
server {
    listen 443 ssl;
    server_name est.bank.internal;
    ssl_certificate     /etc/nginx/est.crt;
    ssl_certificate_key /etc/nginx/est.key;
    # ask for a client certificate. The handshake proves the client holds its key;
    # Certadillo decides whether the issuer is trusted, which covers manufacturer CAs too.
    ssl_verify_client optional_no_ca;
    location /.well-known/est/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-SSL-Client-Cert       $ssl_client_escaped_cert;
        proxy_set_header X-Certadillo-Proxy-Auth <same secret>;
    }
}
```

If you prefer the load balancer to check issuers too, use `ssl_verify_client optional` with `ssl_client_certificate` pointing at a bundle of the Certadillo root and the manufacturer CAs.

Header formats Certadillo reads:

| Source | Header and format |
| --- | --- |
| nginx | `$ssl_client_escaped_cert` (URL-encoded PEM) |
| AWS ALB (mutual TLS, passthrough) | `X-Amzn-Mtls-Clientcert` (URL-encoded PEM) |
| Envoy / Istio | `x-forwarded-client-cert`, the `Cert="..."` field |
| Traefik `passTLSClientCert` | `X-Forwarded-Tls-Client-Cert` (URL-encoded base64 DER) |
| anything else | a PEM, possibly folded onto one line, or base64 DER |

RFC 7030's `tls-unique` channel binding cannot survive TLS termination at a load balancer, so it is not used; the shared secret and network placement take its place.

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

## With the GlobalSign estclient

`scripts/interop-est.sh` runs these through nginx:

```bash
E="-server est.bank.internal:443 -explicit root.pem"
estclient cacerts  $E -out cacerts.pem
estclient csrattrs $E -user atm -pass $KEY
estclient enroll   $E -user atm -pass $KEY -key k1.pem -cn atm-7.atm.bank.internal -out c1.pem
# re-enroll: TLS with the current certificate, CSR with a new key, no password
estclient csr      -key k2.pem -cn atm-7.atm.bank.internal -out c2.csr
estclient reenroll $E -certs c1.pem -key k1.pem -csr c2.csr -out c2.pem
estclient serverkeygen $E -user atm -pass $KEY -cn sensor-3.atm.bank.internal -key k2.pem -out s.pem -keyout s.key
```

## Re-enrollment

Send a CSR with a new key to `simplereenroll`.

- **With the current certificate as the TLS client certificate**, RFC 7030 section 4.2.2 applies: the CSR must keep the subject and names of that certificate. The new certificate replaces it and the old one is marked `superseded`, after which it no longer authenticates.
- **With HTTP Basic**, Certadillo finds the device's current certificate by app and CN.

A manufacturer certificate can enroll but not re-enroll: after bootstrap the device uses its operational certificate.

## Manufacturer certificates (IDevID)

Many devices leave the factory with a certificate from the manufacturer's CA (IEEE 802.1AR calls it an IDevID). Register that CA for the app the devices belong to:

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps/7/est-trust-anchors \
  -d "{\"name\": \"acme-devices\", \"cert_pem\": $(jq -Rs . < acme-idevid-ca.pem)}"
```

For a production app this creates an approval, since it lets every device from that factory enroll into the app. `GET /api/v1/apps/7/est-trust-anchors` lists them. A device with a certificate that chains directly to the anchor can then call `simpleenroll`; its CSR still has to fit the app's scope and profile, and the audit event records `"auth": "idevid"`.

## csrattrs

`GET /csrattrs` returns the CSR attributes the profile wants (RFC 7030 section 4.5): the key type as an attribute (`id-ecPublicKey` with the curve, or `rsaEncryption` with the minimum size), the signature algorithm, and for profiles that need a DNS name, `extensionRequest` with `subjectAltName` as a hint. Without credentials it answers EC P-256 with ECDSA-SHA256, which every built-in profile accepts.

## serverkeygen

For devices that cannot generate a good key, `POST /serverkeygen` makes the key on the server and returns it with the certificate (RFC 7030 section 4.4):

```
200 multipart/mixed; boundary=est-4f1c...
--est-4f1c...
Content-Type: application/pkcs8
Content-Transfer-Encoding: base64
<private key>
--est-4f1c...
Content-Type: application/pkcs7-mime; smime-type=certs-only
Content-Transfer-Encoding: base64
<certificate>
--est-4f1c...--
```

The CSR only supplies the subject and names. Only profiles with `allow_server_keygen: true` accept it (`tls-client` in the default policy); others get 403. The key travels inside TLS only (no CMS encryption of the key) and is not stored; the audit event `est.serverkeygen` records `"stored": false`. Anything that can make its own key should.

## Responses

| Status | Meaning |
| --- | --- |
| 200 | base64 PKCS#7 certs-only with the new certificate (multipart for serverkeygen) |
| 202 + `Retry-After` | the profile needs dual control; ask again after approval |
| 400 | policy rejection, malformed CSR, or a re-enrollment that changes the subject |
| 401 | no usable client certificate and no valid Basic credentials |
| 403 | the profile does not allow serverkeygen, or a manufacturer certificate tried to re-enroll |

## Limits today

- `fullcmc` is not implemented.
- serverkeygen returns the key unencrypted inside TLS; encrypting it to a key named in the request (RFC 7030 `DecryptKeyIdentifier`) is not supported.
- An IDevID must be issued directly by the registered CA (no intermediate).
