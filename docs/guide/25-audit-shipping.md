# Audit shipping

The audit trail in the database is hash-chained and append-only, and the
daily anchor catches a history rewritten after the fact. All of that still
lives on the Certadillo host. Someone with root on that host, or the database
owner credential, could drop the triggers and rewrite events before anyone
looked. Audit shipping removes that window: every event leaves the host within
seconds, in order, to systems the Certadillo operators do not control.

## What a shipped record proves

Each audit event is sent as one JSON record:

```json
{"id": 412, "ts": "2026-11-04T02:51:07.118204+00:00", "actor": "key:ops-admin",
 "action": "cert.issue", "target": "cert:7f3a...", "details": {"profile": "tls-server"},
 "prev_hash": "9c1e...", "hash": "b04d...", "instance": "https://pki.bank.internal",
 "kid": "5e0b9a2c4d1f8e37", "sig": "MEUCIQ...", "mac": "d2a1..."}
```

A receiver can check, without trusting Certadillo's database:

| Check | How | Catches |
| --- | --- | --- |
| Nothing edited | `hash` recomputes from the fields and `prev_hash` | a record changed in transit or at rest |
| Nothing dropped, inserted or reordered | each `prev_hash` is the previous record's `hash` | a gap, a deleted event, an injected one |
| It came from this Certadillo | `sig` is an Ed25519 signature over the record | records forged by anyone without the signing key, even with a recomputed chain |
| Second origin check | `mac` is an HMAC under the seal key | the same, for a verifier that runs with Certadillo's own key material |

The signature is the check to rely on. The receiver holds only the public key,
so the SIEM team, the storage team or an external auditor can verify records
but cannot produce one that verifies. The HMAC is symmetric: anyone who can
check it can also forge it, so it is only useful to a verifier that already
holds the seal key.

## Sinks

Set `CERTADILLO_AUDIT_SHIP` to one or more sinks, comma-separated. Each sink
has its own cursor, so a slow or broken sink does not hold the others back.

| Sink | Example | Notes |
| --- | --- | --- |
| File | `file:/var/log/certadillo/audit.jsonl` | Append-only JSONL for a log forwarder (Fluent Bit, Filebeat, the Splunk UF) to tail |
| Syslog over TLS | `syslog+tls://siem.bank.internal:6514` | RFC 5424 messages, RFC 5425 octet-counted framing, facility 13 (log audit). The server certificate is verified; set `CERTADILLO_AUDIT_SHIP_CACERT` for a private CA |
| Syslog over TCP | `syslog+tcp://127.0.0.1:514` | The same without TLS, for a relay on the same host only |
| Splunk HEC | `splunk+https://splunk.bank.internal:8088` | HTTP Event Collector, sourcetype `certadillo:audit`. Token from `CERTADILLO_AUDIT_SHIP_TOKEN_REF`; index from `CERTADILLO_AUDIT_SHIP_SPLUNK_INDEX` |
| HTTPS | `https://collector.bank.internal/audit` | `POST {"records": [...]}` with an optional bearer token from the token ref. Any status of 300 or more is a failure |
| S3 with Object Lock | `s3://pki-audit/certadillo/prod` | One object per batch, written in COMPLIANCE mode for `CERTADILLO_AUDIT_SHIP_S3_RETENTION_DAYS` (default 2555, seven years). Nobody, including the bucket owner and AWS root, can delete or overwrite it before then |

The shipped containers have a read-only root filesystem, so a file sink there must point into the data volume (`file:/var/lib/certadillo/audit.jsonl`) or a volume you mount for the forwarder.

A sink that does not parse stops startup, so a typo never means silently
shipping nowhere.

The token ref takes the same forms as provisioning credentials: `env:NAME`,
`file:/run/secrets/hec-token` or `vault:secret/data/certadillo#hec`. The token
is never written to the database, the logs or the status endpoint.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTADILLO_AUDIT_SHIP` | (none) | Sinks, comma-separated |
| `CERTADILLO_AUDIT_SHIP_INTERVAL` | `15` | Seconds between shipping passes |
| `CERTADILLO_AUDIT_SHIP_TOKEN_REF` | (none) | Bearer token for HTTPS, HEC token for Splunk |
| `CERTADILLO_AUDIT_SHIP_CACERT` | (system store) | CA bundle for syslog+tls, Splunk and HTTPS sinks |
| `CERTADILLO_AUDIT_SHIP_SPLUNK_INDEX` | (HEC default) | Splunk index |
| `CERTADILLO_AUDIT_SHIP_S3_RETENTION_DAYS` | `2555` | Object Lock retention for the S3 sink |

S3 credentials come from the usual AWS chain (instance role, IRSA, or the
`AWS_*` variables). The role needs `s3:PutObject` and
`s3:PutObjectRetention` on the prefix and nothing else. The bucket must have
been created with Object Lock enabled.

## The signing key

The first start with `CERTADILLO_AUDIT_SHIP` set creates
`audit-signing.key.pem` in the data directory: an Ed25519 key, encrypted under
`CERTADILLO_KEY_PASSPHRASE`, mode 0600. Give the public half to whoever
receives the records:

```bash
certadillo audit signing-key > certadillo-audit.pub
# or
curl -s -H "X-API-Key: $AUDITOR_KEY" $S/api/v1/audit/signing-key
```

Each record carries `kid`, the first 16 hex characters of the SHA-256 of the
raw public key, so a receiver can tell which key to use after a rotation.
Back the key up with the CA keys. If it is lost, records shipped before the
loss still verify with the old public key; new records are signed with a new
key and a new `kid`.

## Verifying an export

`certadillo audit verify-export` checks a JSONL copy, which is what the file
sink, an S3 download or a SIEM search export gives you:

```bash
certadillo audit verify-export audit-2026-11.jsonl --public-key certadillo-audit.pub --no-mac
```

```json
{"valid": true, "records": 18342, "problems": [], "first_id": 1, "last_id": 18342,
 "from_genesis": true, "signatures_checked": true, "macs_checked": false}
```

The exit code is 1 when any record was changed, a record is missing, a
signature or MAC does not verify, or neither the signatures nor the MACs could
be checked at all. An export may start anywhere in the chain (a month's
slice, say); `from_genesis` says whether it starts at the first event.

Delivery is at least once. If Certadillo stops between sending a batch and
moving the cursor, the batch is sent again. The verifier skips records it has
already seen, and receivers should de-duplicate on `hash`.

## When the history changes after shipping

Before each batch the shipper checks that the next event in the database
continues the chain it already shipped. If someone rewrote shipped history in
the database, it stops, sends nothing further to that sink, and records the
error:

```
chain break after event 412: the history was changed after it was shipped
```

Housekeeping then raises the critical `AuditShippingFailing` alert. The
shipped copy is the reference: compare it with the database to see what was
changed. See the [runbook](../RUNBOOK.md#auditshippingfailing).

## Status

```bash
curl -s -H "X-API-Key: $AUDITOR_KEY" $S/api/v1/audit/shipping
```

```json
[{"sink": "syslog+tls://siem.bank.internal", "behind": 0, "oldest_unsent": null,
  "failures": 0, "last_error": null}]
```

`AuditShippingFailing` fires as a warning when a pass to a sink has failed or
the oldest unsent event is more than 15 minutes old. It becomes critical after
five failed passes in a row, and straight away on a chain break.
`certadillo audit ship` runs one pass by hand.

## Recommended setup for a regulated environment

Ship to two places owned by different teams: syslog over TLS or Splunk HEC to
the SOC's SIEM for search and correlation, and S3 with Object Lock in a
separate AWS account for retention. Keep the public key with both teams and
with internal audit. Run `verify-export` against the S3 copy on a schedule
owned by audit, not by the PKI team.
