# Offline root ceremony

By default `certadillo init` creates the root and the issuing CA on the server,
which is fine for a lab. In production the root key should never be on a
machine that is on a network. With the offline ceremony the server only ever
holds the issuing CA's key (in the HSM or Vault), and the root lives on an
air-gapped machine and removable media in a safe.

```
 admin workstation (server config)          offline machine (air-gapped)
 ---------------------------------          ----------------------------
                                            offline-root init   -> root.key.pem (encrypted), root.pem
 ca offline-csr   -> issuing.csr  ------->  offline-root sign   -> issuing.pem
 ca import-issuing <- issuing.pem, root.pem <-----
                                            offline-root crl    -> root.crl  (every few months)
 ca import-crl    <- root.crl      <-----
```

Every step needs an operator and a different witness, and the server side is
in the audit trail with both names.

## Before you start

Set `CERTADILLO_AUTO_INIT_CA=false` so the server does not create its own root
at first start. Until the issuing CA is imported, `/readyz` fails and nothing
can be issued, which is what you want.

Install Certadillo on the offline machine from a wheel carried over on media
(`pip install certadillo-*.whl`). The offline commands need no database, no
server configuration and no network.

## 1. Create the root (offline)

```bash
certadillo offline-root init --dir /media/root-ca --org "Example Bank" --years 20
# prompts twice for the passphrase (16 characters or more)
```

This writes `root.key.pem` (encrypted with the passphrase, mode 0600),
`root.pem`, and `signed.jsonl`, an append-only record of everything the root
signs. The output includes the root's SHA-256 fingerprint. Write it on the
ceremony form; every later step is checked against it. Use `--alg rsa-4096`
if relying parties need an RSA root.

## 2. Ask for the issuing CA (server side)

```bash
certadillo ca offline-csr --name issuing-ca-1 --operator alice --witness bob --out issuing.csr
```

The issuing key is generated wherever CA keys live: in the HSM with
`CERTADILLO_SIGNER=pkcs11`, in Vault Transit with `vault-transit`. It never
leaves it. The CSR asks for a CA with pathlen 0 and, if
`CERTADILLO_CA_PERMITTED_DNS` (or the other name constraint settings) is set,
carries those name constraints.

## 3. Sign it (offline)

```bash
certadillo offline-root sign --dir /media/root-ca --csr issuing.csr --out issuing.pem \
  --years 5 --crl-url https://pki.bank.internal/pki/crl/root-ca.crl
```

Only the subject, the public key and the name constraints come from the CSR.
Everything else (CA with pathlen 0, keyCertSign and cRLSign, validity capped
at the root's, the CRL location) is set by the tool. Read the printed subject
and fingerprint aloud for the witness.

## 4. Import it (server side)

```bash
certadillo ca import-issuing --name issuing-ca-1 --cert issuing.pem --root root.pem \
  --operator alice --witness bob
```

The import refuses anything that is not exactly what was asked for:

| Check | Refused when |
| --- | --- |
| The key | the certificate carries any key other than the one generated in step 2 |
| The signature | it does not verify with the root's key, even if the issuer name matches |
| The root | it is not self-signed, not a CA, lacks keyCertSign, or is outside its validity |
| The CA flags | not a CA, pathlen other than 0, or no keyCertSign and cRLSign |
| Validity | the issuing CA outlives the root |
| Name constraints | the server requires name constraints and the certificate does not carry exactly those |

On success the root is stored with `key_ref` `offline:<fingerprint>` and no
key, the issuing CA starts issuing, and its OCSP responder and first CRL are
created. Compare the printed `root_sha256` with the fingerprint from step 1.
Anything that would sign with the root on the server (`ca create-issuing
--parent root-ca`, a CRL re-sign) is refused with a pointer back to the
ceremony.

## 5. The root CRL

The root's CRL can only be signed offline. Sign one at the ceremony and
publish it:

```bash
certadillo offline-root crl --dir /media/root-ca --out root.crl --days 180      # offline
certadillo ca import-crl --ca root-ca root.crl                                   # server
# or: POST /api/v1/cas/root-ca/crl {"crl_pem": "..."}  (admin)
```

It is served at `/pki/crl/root-ca.crl`. The import checks the signature and
the issuer, and refuses a CRL whose number is not higher than the current one,
so an old CRL cannot be replayed to take a revocation back.

`CRLStale` warns 30 days before the root CRL's nextUpdate and goes critical 7
days before (and while none has been imported), which leaves time to book the
next ceremony.

## Retiring or revoking an issuing CA

```bash
certadillo offline-root revoke --dir /media/root-ca --serial <hex serial> --reason key_compromise
certadillo offline-root crl --dir /media/root-ca --out root.crl
certadillo ca import-crl --ca root-ca root.crl
```

For a planned change, bring up the new issuing CA with steps 2 to 4 first and
move certificates across with a [renewal campaign](19-renewal-campaigns.md)
before revoking the old one.

## Using other offline tooling

The server only checks what it is given, so the offline side can be anything
that produces a valid certificate and CRL: an offline HSM with its own
ceremony software, `openssl ca`, or a commercial tool. `certadillo
offline-root` is there so a bank without one can run the whole ceremony from a
single, reviewable package.
