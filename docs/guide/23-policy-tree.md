# The policy tree

Profiles say what kind of certificate an app gets (TLS server, mTLS, code
signing). The policy tree says what the bank allows, by business line. Folders
hold settings, apps sit in folders, and every issuance is checked against the
profile and then narrowed by the folder an app sits in and every folder above
it.

## Inheritance and locks

A setting on a folder applies to everything under it. A subfolder can set its
own value for the same setting, unless an ancestor marked it locked; then the
subfolder cannot set it at all, and an attempt is refused with the folder that
holds the lock:

```
\Bank                    allowed_zones bank.internal (locked), rsa_min_bits 3072 (locked), max_validity_days 200
\Bank\Payments           max_validity_days 30, allowed_profiles tls-server, tls-client
\Bank\Payments\Cards     issuing_ca cards-ca (locked)
```

An app in `\Bank\Payments\Cards` gets names only under `bank.internal`, RSA keys
of at least 3072 bits, at most 30 days, only the two TLS profiles, and its
certificates are signed by `cards-ca`. Nobody below `\Bank` can loosen the zone
or the key size.

## Settings

| Setting | Value | Effect |
| --- | --- | --- |
| `allowed_profiles` | list of profile names | apps here can only be onboarded (or moved here) with these profiles |
| `allowed_zones` | list of DNS zones | every app scope entry, and every name at issuance, must fall under one of them |
| `rsa_min_bits` | integer | smaller RSA keys are refused |
| `ec_curves` | `secp256r1`, `secp384r1`, `secp521r1` | other curves are refused |
| `max_validity_days` | integer | an explicit request for longer is refused; a profile default that is longer is shortened |
| `issuing_ca` | CA name | the issuing CA that signs for apps here (it must exist and not be a root) |
| `dual_control` | `true` / `false` | every issuance needs a second approver |

The folder rules only ever narrow the profile: a folder cannot allow an RSA
size, a validity or a name the profile itself refuses.

## Changes go through a second person

Creating a folder, changing its settings and moving an app between folders
change what apps may get, so they are approval requests by default
(`policy_change` in `CERTADILLO_DUAL_CONTROL`). An admin asks; an approver who
is not that admin decides. Each applied change is in the audit trail with the
settings before and after.

```bash
# ask for a folder; the response is 202 with an approval id
curl -s "${A[@]}" -X POST $S/api/v1/folders -d '{
  "name": "Bank",
  "settings": {"allowed_zones": {"value": ["bank.internal"], "locked": true},
               "rsa_min_bits": {"value": 3072, "locked": true}}}'

# a second person approves
curl -s -H "X-API-Key: $APPROVER_KEY" -X POST $S/api/v1/approvals/<id>/approve

# place an app (also a policy change), then look at what applies to it
curl -s "${A[@]}" -X POST $S/api/v1/apps/7/move -d '{"folder_id": 1}'
curl -s "${A[@]}" $S/api/v1/apps/7/policy
```

`GET /api/v1/apps/{id}/policy` shows the profile's rules and each folder rule
with the folder it came from and whether it is locked. `GET /api/v1/folders`
lists the tree with each folder's own and effective settings.

Onboarding takes a `folder_id`. An app whose profile or scope does not fit the
folder is refused at onboarding, and so is a move into a folder it does not fit.
A setting tightened later (a zone removed, a larger minimum key) applies to the
next issuance of every app below it.

## Tamper resistance

Apps and folders carry integrity seals like principals and approvals. An app
moved out of its folder, or given a wider scope, by a direct database write can
no longer get certificates, and `IntegritySealBroken` fires. A deployment that
predates app seals has its apps sealed once at the first start of this version.
