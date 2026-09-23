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

## S/MIME

The `smime` profile issues email-protection certificates. The app's scope lists mail domains, and every email SAN must be in one of them.

```bash
curl -s "${A[@]}" -X POST $S/api/v1/apps -d '{"team_id": 4, "name": "mail-gateway",
  "environment": "prod", "profile": "smime", "allowed_domains": ["bank.example"]}'

openssl req -new -newkey rsa:3072 -nodes -keyout jane.key -subj "/CN=Jane Doe" \
  -addext "subjectAltName=email:jane.doe@bank.example" -out jane.csr
```

Email SANs are accepted only by this profile, and URI SANs only by `spiffe-svid`, so a TLS app cannot slip an email identity or a workload identity into its certificate.
