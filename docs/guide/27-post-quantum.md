# Post-quantum: ML-DSA and the agility drill

Certadillo issues ML-DSA (FIPS 204) certificates and can measure how long
your estate takes to move to a new issuing CA. The two go together: a
post-quantum CA is only useful once the certificates that matter have moved
to it, and the time that takes is the number a migration plan needs.

ML-DSA support needs pyca/cryptography 50 or later, which the container image
already pins.

## What is supported

| Where | ML-DSA-65 | ML-DSA-87 | Notes |
| --- | --- | --- | --- |
| Issuing CA key (software store) | yes | yes | `ca create-issuing --alg`, or `alg` on `POST /api/v1/cas` |
| Issuing CA key (PKCS#11 HSM) | no | no | refused with an error; python-pkcs11 does not expose the PKCS#11 3.2 ML-DSA mechanisms yet |
| Issuing CA key (Vault Transit) | no | no | refused; Certadillo creates only EC and RSA keys in Vault |
| Offline root | yes | yes | `offline-root init --alg ml-dsa-87` |
| End-entity keys | yes | yes | only in profiles that list them, such as `tls-server-pq` |
| CRLs and OCSP | yes | yes | CRLs are ML-DSA signed; the OCSP responder certificate is ML-DSA signed and its own key stays P-256 |
| CSR proof of possession | yes | yes | ML-DSA-44 is also recognised in requests and inventory |

Any mix works: an EC root can certify an ML-DSA issuing CA, and an ML-DSA CA
can sign EC leaf certificates. That lets you move CA by CA instead of all at
once.

## Create an ML-DSA issuing CA

From the admin workstation, with a ceremony operator and a witness:

```bash
certadillo ca create-issuing --name issuing-pq-1 --alg ml-dsa-87 \
  --operator alice --witness bob
```

or through the API, which goes to a second person for approval:

```bash
curl -s "${A[@]}" -X POST $S/api/v1/cas -d '{"name": "issuing-pq-1", "alg": "ml-dsa-87"}'
```

The newest issuing CA becomes the default for new certificates, the same as
for any other new CA. Pin a folder to the old CA with the `issuing_ca`
setting if some applications must stay on it for now (see
[the policy tree](23-policy-tree.md)).

Use ML-DSA-87 where CNSA 2.0 applies. ML-DSA-65 has smaller signatures and is
NIST security category 3.

## ML-DSA leaf certificates

ML-DSA keys are opt-in per profile, because a client that cannot verify
ML-DSA rejects the whole chain. The shipped `tls-server-pq` profile takes
ML-DSA-65 and ML-DSA-87 keys and nothing else:

```yaml
tls-server-pq:
  extended_key_usage: [server_auth]
  allowed_keys: {ml_dsa: [ml-dsa-65, ml-dsa-87]}
```

Add `ml_dsa` to any other profile's `allowed_keys` to accept ML-DSA there as
well. A policy folder can narrow it further, for example to ML-DSA-87 only:

```json
{"ml_dsa": {"value": ["ml-dsa-87"], "locked": true}}
```

The CLI makes the key and the CSR:

```bash
certadillo cert request --cn web.pq.bank.internal --san web.pq.bank.internal \
  --key-type ml-dsa-65 --out ./web
```

`cert renew-if-due` keeps the same parameter set when it renews.

## The crypto-agility drill

A drill moves every active certificate of one or more CAs to a target CA and
times it. It uses the same machinery a real move would:

1. The set of certificates is frozen when the drill starts, so the percentage
   means the same thing from start to finish.
2. A [renewal campaign](19-renewal-campaigns.md) gives each of them an early
   renewal window. ACME clients see it through ARI, `cert renew-if-due` reads
   it from the API, and push-provisioned installations renew on the next
   housekeeping cycle.
3. A certificate counts as moved when its replacement was signed by the
   target CA. If it was renewed twice, its latest successor counts.
4. The drill reports progress and the time to 50, 90, 99 and 100 percent,
   measured from the start. The clock stops at 100 percent.

Nothing is revoked. When you are ready, revoke the old certificates through
the campaign's `revoke-replaced` action.

Start one from the console (Reports tab), the CLI or the API:

```bash
certadillo drill start --name "move to ML-DSA" --target issuing-pq-1 \
  --hours 72 --operator alice

curl -s "${A[@]}" -X POST $S/api/v1/agility-drills -d '{
  "name": "move to ML-DSA",
  "target_ca": "issuing-pq-1",
  "source_cas": ["issuing-ca-1"],
  "renew_within_hours": 72
}'
```

`source_cas` defaults to every other issuing CA. Then watch it:

```text
$ certadillo drill status 1
drill 1 'move to ML-DSA' -> issuing-pq-1 (running)
  moved 9 of 12 (75%); remaining 2, replaced by another CA 1, gone 0
  time to 50% 3h12m, 90% -, 99% -, 100% -
  blocked: legacy-api would renew from issuing-ca-1 (folder \Bank\Legacy), 3 certificate(s)
```

The status separates four states:

| State | Meaning |
| --- | --- |
| moved | replaced by a certificate from the target CA |
| elsewhere | replaced, but by a different CA or an upstream issuer |
| remaining | not replaced yet |
| gone | revoked or expired without a successor; left out of the percentage |

The `blocked` list is the useful part of a drill. It names each application
whose next certificate would not come from the target CA, and the setting
responsible: a folder's `issuing_ca` or `issuer`, or a profile routed to an
upstream issuer. Renewing alone does not fix those; the setting has to
change first.

`GET /api/v1/agility-drills/{id}` returns the same data with a row per
certificate. `certadillo_agility_drill_progress_ratio{drill,target_ca}` in
Prometheus tracks running drills.

Close the drill when you are done. That keeps its final numbers and closes
the campaign, so the ARI windows go back to normal for anything that did not
move:

```bash
certadillo drill close 1 --operator alice
```

## Reports

The crypto report marks ML-DSA CAs as post-quantum, and they are not flagged
for the 2035 cutoff. In the CycloneDX CBOM, ML-DSA-44, -65 and -87 signatures
carry NIST security levels 2, 3 and 5.

## Not done yet

Composite ML-DSA + ECDSA certificates, ML-DSA keys in an HSM or Vault, ML-DSA
for the code-signing service, and tracking of hybrid TLS key exchange
(X25519MLKEM768) in discovery scans are on the [roadmap](../ROADMAP.md#phase-5-post-quantum).
