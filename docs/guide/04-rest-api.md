# REST API and CLI

The REST API is the most direct way in. Every other protocol ends up in the same code path.

Authenticate with the app's API key in either header:

```
X-API-Key: cdl_...
Authorization: Bearer cdl_...
```

## Request a certificate

Generate the key where it will be used, then send only the CSR.

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout auth.key -subj "/CN=auth.cards.bank.internal" \
  -addext "subjectAltName=DNS:auth.cards.bank.internal" -out auth.csr

curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" -X POST $S/api/v1/certificates \
  -d "$(python3 -c 'import json;print(json.dumps({"csr_pem": open("auth.csr").read(), "validity_days": 30}))')"
```

The response (201) holds the certificate and its chain:

```json
{
  "id": 7,
  "serial": "7b4c294dac830d452407acffe8492c99a84d2bd6",
  "common_name": "auth.cards.bank.internal",
  "sans": ["auth.cards.bank.internal"],
  "not_after": "2026-10-23T22:28:17+00:00",
  "profile": "tls-server",
  "protocol": "rest",
  "pem": "-----BEGIN CERTIFICATE-----...",
  "chain_pem": "-----BEGIN CERTIFICATE-----..."
}
```

Body fields:

| Field | Required | Notes |
| --- | --- | --- |
| `csr_pem` | yes | PKCS#10 in PEM |
| `app_id` | admins and operators only | app keys always act for their own app |
| `validity_days` / `validity_hours` | no | capped by the profile; hours apply to `spiffe-svid` |
| `profile` | no | must equal the app's onboarded profile |

If the profile needs dual control (code signing) the answer is `202 {"status": "pending_approval", "approval_id": N}`. Once approved, the certificate shows up in `GET /api/v1/certificates`, and `GET /api/v1/approvals` (an app key sees only its own requests) carries its `certificate_id`.

A policy rejection is `422` with every rule that failed:

```json
{"error": "policy_violation",
 "violations": [{"rule": "san_scope", "message": "evil.example.com is outside the app's approved domains"}]}
```

[Troubleshooting](17-troubleshooting.md) lists every rule.

## Renew

Always with a new key:

```bash
curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -X POST $S/api/v1/certificates/7/renew -d '{"csr_pem": "..."}'
```

The old certificate becomes `superseded` and points at its replacement (`replaced_by`). It is not revoked; it simply ages out.

## Revoke

```bash
curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -X POST $S/api/v1/certificates/7/revoke -d '{"reason": "key_compromise"}'
```

Reasons: `unspecified`, `key_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`, `certificate_hold`, `privilege_withdrawn`, `ca_compromise`.

When an operator or admin revokes a production certificate for any reason except `key_compromise`, they must pass `"change_ref": "CHG0012345"`. OCSP answers "revoked" immediately and a new CRL is published in the same request.

## List and inspect

```bash
curl -s -H "X-API-Key: $KEY" "$S/api/v1/certificates?status=active&expiring_within_days=14"
curl -s -H "X-API-Key: $KEY" "$S/api/v1/certificates?renewal_due=true"
curl -s -H "X-API-Key: $KEY" $S/api/v1/certificates/7
```

App keys see only their own certificates.

## The CLI does all of this for you

```bash
export CERTADILLO_SERVER=https://pki.bank.internal CERTADILLO_API_KEY=cdl_...

certadillo cert request --cn auth.cards.bank.internal --san auth.cards.bank.internal --out /etc/pki/auth
certadillo cert renew-if-due --dir /etc/pki/auth           # no-op until a third of the lifetime is left
certadillo cert renew-if-due --dir /etc/pki/auth --force
```

Run `renew-if-due` from a systemd timer or cron every few hours:

```ini
# /etc/systemd/system/certadillo-renew.service
[Service]
Type=oneshot
EnvironmentFile=/etc/certadillo/env
ExecStart=/usr/local/bin/certadillo cert renew-if-due --dir /etc/pki/auth
ExecStartPost=/bin/systemctl reload nginx

# /etc/systemd/system/certadillo-renew.timer
[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=30m
[Install]
WantedBy=timers.target
```
