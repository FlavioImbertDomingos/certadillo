# Code signing and S/MIME

## Code signing

A code-signing certificate lets its holder make software that every machine in the bank will trust, so each one needs a second person's approval. The `code-signing` profile sets `dual_control: true`, allows only RSA-3072+ or P-384 keys, and lasts up to a year.

Onboard the signing pipeline:

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 3, "name": "release-signing",
  "environment": "prod", "profile": "code-signing", "allowed_domains": ["release.bank.internal"]}'
```

Request (the key should be generated in an HSM or a cloud KMS that the signing service uses):

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout sign.key \
  -subj "/CN=Release Signing 2026" -out sign.csr
curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" -X POST $S/api/v1/certificates \
  -d "$(python3 -c 'import json;print(json.dumps({"csr_pem": open("sign.csr").read()}))')"
# 202 {"status": "pending_approval", "approval_id": 12}
```

An approver reviews and decides:

```bash
curl -s -H "X-API-Key: $APPROVER_KEY" $S/api/v1/approvals?status=pending
curl -s -H "X-API-Key: $APPROVER_KEY" -H "Content-Type: application/json" \
  -X POST $S/api/v1/approvals/12/approve -d '{"comment": "release 4.2, ticket REL-881"}'
```

The approval response carries `payload.certificate_id`; fetch it with `GET /api/v1/certificates/{id}`. Renewals go through approval as well, and the old certificate is marked `superseded` when the new one is approved.

The CN of a code-signing certificate is a display name ("Release Signing 2026"), so it is not checked against the scope.

## The signing service: keys that never leave the HSM

A code-signing certificate handed to a pipeline means the private key sits on
a build agent, where anyone who can change the pipeline can sign with it. The
signing service keeps the key where CA keys live (a PKCS#11 HSM, Vault
Transit, or the software store in a lab). The pipeline sends only the digest
of what it built and gets a signature back.

```
build agent                                   Certadillo
-----------                                   ----------
sha256(artifact) --- digest, key, name ---->  owning app?  release key -> approver decides
                                              HSM signs the CMS signed attributes
                 <--- CMS detached signature   + code-signing certificate + RFC 3161 timestamp
```

### Keys

```bash
curl -s "${A[@]}" -X POST $S/api/v1/signing/keys \
  -d '{"name": "payments-release", "app_id": 7, "purpose": "release", "alg": "ec-p384"}'
# 202 {"status": "pending_approval", "approval_id": 41}
curl -s -H "X-API-Key: $APPROVER_KEY" -X POST $S/api/v1/approvals/41/approve
```

Creating a key is always a second-person decision. On approval the key is
generated in the keystore (`CERTADILLO_SIGNER`) and gets a certificate from
the `code-signing` profile, which lands in the inventory like any other
certificate, so its expiry is alerted on.

| Purpose | Every signature |
| --- | --- |
| `release` | waits for an approver (`code_sign`); the requester can never approve their own |
| `test` | is made straight away, for CI snapshots and internal builds |

Only the owning app's credentials (and admins or operators acting for it)
can ask a key for a signature.

### Signing

```bash
CERTADILLO_SERVER=https://pki.bank.internal CERTADILLO_API_KEY_FILE=/run/secrets/release-bot \
  certadillo sign dist/payments-api-3.0.0.tar.gz --key payments-release --version 3.0.0 --commit $GIT_SHA --wait 900
# {"signature": "dist/payments-api-3.0.0.tar.gz.p7s", ...}
```

The CLI hashes the file locally and sends only the digest with the artifact
name, version and commit, which go into the audit trail. With a release key
it waits (up to `--wait` seconds) for the approver. The API underneath:

```bash
curl -s -H "X-API-Key: $APP_KEY" -X POST $S/api/v1/signing/sign -H "Content-Type: application/json" \
  -d '{"key": "payments-release", "digest_alg": "sha384", "digest": "<hex>",
       "artifact": {"name": "payments-api-3.0.0.tar.gz", "version": "3.0.0"}}'
# 202 {"id": 18, "status": "pending", "approval_id": 52}  then  GET /api/v1/signing/requests/18
```

The result is a CMS (RFC 5652) detached SignedData: the signed attributes
carry the artifact's digest, the code-signing certificate and its chain are
included, and an RFC 3161 timestamp over the signature value is attached
(RFC 3161 appendix A), so the signature stays verifiable after the certificate
expires. Anyone can check it with standard tooling:

```bash
curl -s -H "X-API-Key: $AUDITOR_KEY" $S/api/v1/signing/keys/payments-release/chain > chain.pem
openssl cms -verify -binary -inform DER -in payments-api-3.0.0.tar.gz.p7s \
  -content payments-api-3.0.0.tar.gz -CAfile chain.pem -purpose any -out /dev/null
```

### Time stamping (RFC 3161)

`POST /tsa` is a standard time-stamping unit (`application/timestamp-query`
in, `application/timestamp-reply` out), so other signing tools can use it:
`signtool sign /tr https://pki.bank.internal/tsa /td sha256`, `jarsigner -tsa`,
`osslsigncode -ts`, or `openssl ts -query`. The TSA certificate is issued by the
issuing CA with the critical timeStamping EKU and nothing else, its key is
generated where CA keys live, and each token carries the ESS
signing-certificate-v2 attribute. Tokens are issued under policy
`2.25.<uuid>` (shown in each token). The endpoint needs no credential, like a
public TSA; put it behind the same network controls as OCSP.

```bash
openssl ts -query -data contract.pdf -sha256 -cert -out q.tsq
curl -s -H "Content-Type: application/timestamp-query" --data-binary @q.tsq $S/tsa -o r.tsr
openssl ts -verify -in r.tsr -queryfile q.tsq -CAfile chain.pem      # Verification: OK
```

### Not yet

Native signing formats are not produced yet: Authenticode (signtool) and JAR
signatures need the signing tool to call out to a remote key, which means a
PKCS#11 or KSP plugin; cosign and GPG need their own key-provider plugins. Those
are on the roadmap. Until then, sign with a CMS detached signature, or use
the TSA from the native tools with a locally held key.

## S/MIME

The `smime` profile issues email-protection certificates. The app's scope lists mail domains, and every email SAN must be in one of them.

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 4, "name": "mail-gateway",
  "environment": "prod", "profile": "smime", "allowed_domains": ["bank.example"]}'

openssl req -new -newkey rsa:3072 -nodes -keyout jane.key -subj "/CN=Jane Doe" \
  -addext "subjectAltName=email:jane.doe@bank.example" -out jane.csr
```

Email SANs are accepted only by this profile, and URI SANs only by `spiffe-svid`, so a TLS app cannot slip an email identity or a workload identity into its certificate.
