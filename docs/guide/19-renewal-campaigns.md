# Renewal campaigns

A renewal campaign replaces a chosen set of certificates early, on the platform's schedule, before they are revoked. It is how a mass revocation (a suspected key exposure, a mis-issued batch, an issuing CA that must be retired) happens without taking services down.

The pieces:

1. **Pick the certificates.** Certadillo gives each of them an early renewal window.
2. **Clients renew.** ACME clients see the new window through ARI (RFC 9773) and renew inside it. Other clients are told through their owners, who can read the same window from the API.
3. **Watch progress.** The campaign shows which certificates were replaced and which were not, by team.
4. **Revoke the replaced ones.** They have successors, so nothing breaks.
5. **Cut off the rest at the deadline.** This can cause an outage, so it needs a second person.

The knowledge base at `/kb` has a 3D walkthrough of a campaign, from the wildcard order to the overdue alert.

## Start a campaign

```bash
curl -s "${A[@]}" -X POST $S/api/v1/renewal-campaigns -d '{
  "name": "rotate portal-edge",
  "reason": "suspected key exposure on build host bh-12",
  "criteria": {"app_ids": [4]},
  "renew_within_hours": 24,
  "explanation_url": "https://status.bank.example/pki/2026-09",
  "revocation_reason": "key_compromise"
}'
```

Only active certificates issued here are selected. Criteria, all optional but at least one required (a campaign never selects everything by accident):

| Criterion | Example |
| --- | --- |
| `cert_ids` | `[12, 13]` |
| `serials` | `["5a1f..."]` (hex, colons allowed) |
| `app_ids` | `[4]` |
| `profiles` | `["tls-server"]` |
| `protocols` | `["acme", "est"]` |
| `ca` | `"issuing-ca-1"` |
| `issued_before`, `issued_after` | ISO 8601 times |
| `key_types` | `["rsa"]` |

The response lists every selected certificate with its app and team, and `warnings` when the deadline is shorter than clients may take to notice (see below).

`"immediate": true` puts the window in the past, so every ACME client renews on its next ARI check. Without it, clients spread their renewals over the window, which is kinder to the CA and to the services. Keep `immediate` for emergencies.

## How long clients take to notice

A client learns about the new window the next time it asks. ARI responses carry `Retry-After`: 6 hours by default (`CERTADILLO_ARI_RETRY_AFTER`, seconds), 1 hour for certificates already in a campaign. certbot's timer runs twice a day. So a certificate may be renewed up to about 18 hours after the campaign starts, even with `immediate`. Lower `CERTADILLO_ARI_RETRY_AFTER` a day ahead of a planned campaign if you need it faster.

## Track it

```bash
curl -s -H "X-API-Key: $KEY" $S/api/v1/renewal-campaigns/3
```

```json
{"id": 3, "name": "rotate portal-edge", "status": "active", "overdue": false,
 "window_end": "2026-09-25T04:15:00+00:00",
 "counts": {"total": 14, "replaced": 11, "revoked": 0, "remaining": 3},
 "certificates": [{"certificate_id": 41, "common_name": "www.edge.portal.bank.internal",
                   "state": "remaining", "app": "portal-edge", "team": "web", ...}, ...]}
```

A certificate counts as replaced when it has an explicit successor (ACME `replaces`, REST renew, EST or SCEP re-enrollment, CMP kur) or when a newer active certificate was issued to the same app with the same names after the campaign started. The second rule covers clients such as certbot that check ARI but do not send `replaces`.

Past the deadline with certificates remaining, the `RenewalCampaignOverdue` alert fires as critical and names the teams that still have to act.

## Revoke

```bash
# certificates that have a successor: safe, no second person
curl -s "${A[@]}" -X POST $S/api/v1/renewal-campaigns/3/revoke-replaced -d '{"change_ref": "CHG0042117"}'
# {"revoked": 11}

# the rest: the hard cutoff, which needs an approver
curl -s "${A[@]}" -X POST $S/api/v1/renewal-campaigns/3/revoke-remaining -d '{"change_ref": "CHG0042117"}'
# 202 {"status": "pending_approval", "approval_id": 61}
```

Both use the campaign's `revocation_reason` and re-sign the CRL at once. Production certificates need a `change_ref` unless the reason is `key_compromise`, the same rule as single revocations. Close a campaign with `POST /api/v1/renewal-campaigns/3/close`; its windows stop applying.

## Without ACME

ARI is an ACME feature, but the window is available for any certificate at `GET /api/v1/certificates/{id}/renewal-info`:

```json
{"cert_id": "kBXWiC6ES11xBWj1ZleSver1klM.WhBfketKLIVSfmI5ps5e1Ht5sE4",
 "suggested_window": {"start": "2026-09-24T04:15:00+00:00", "end": "2026-09-25T04:15:00+00:00"},
 "explanation_url": "https://status.bank.example/pki/2026-09", "renew_now": true}
```

`certadillo cert renew-if-due` and the Ansible role check it on every run and renew when `renew_now` is true, so hosts that renew from cron or Ansible follow campaigns too. The PowerShell module has `Get-CertadilloRenewalInfo`. For other clients, point their owners at the campaign status.

The [runbook](../RUNBOOK.md) has the full mass-revocation procedure.
