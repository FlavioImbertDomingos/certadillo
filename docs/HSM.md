# Key custody: HSMs and Vault

CA keys can live in three places, chosen with `CERTADILLO_SIGNER`:

| Signer | Where the key lives | Use it for |
| --- | --- | --- |
| `software` | encrypted PEM files in the data directory | labs and demos only |
| `pkcs11` | an HSM, through PKCS#11 (`python-pkcs11`); SoftHSM2 in the lab | production, where the bank has HSMs |
| `vault-transit` | HashiCorp Vault's Transit engine, non-exportable | production without a dedicated HSM, or with Vault Enterprise managed keys in front of one |

`CERTADILLO_SIGNER` decides where new CA keys are created. Existing keys keep loading from wherever their `key_ref` says they live, so a deployment can move to an HSM or to Vault without a flag day (see [Moving an existing deployment](HSM.md#moving-an-existing-deployment)). `certadillo ca keys` (or `GET /api/v1/cas/keys`) shows where each CA key is and whether it is reachable and intact (for Vault: the pinned version exists, the key matches the CA certificate, and it is still non-exportable). It does not make test signatures, so a root key the application is not allowed to sign with still shows as healthy.

## Lab: SoftHSM2

```bash
# Debian/Ubuntu: apt install softhsm2   macOS: brew install softhsm
mkdir -p ~/.softhsm/tokens
echo "directories.tokendir = $HOME/.softhsm/tokens" > ~/.softhsm/softhsm2.conf
export SOFTHSM2_CONF=~/.softhsm/softhsm2.conf
softhsm2-util --init-token --free --label certadillo --pin 1234 --so-pin 5678

export CERTADILLO_SIGNER=pkcs11
export CERTADILLO_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so   # brew: /opt/homebrew/lib/softhsm/libsofthsm2.so
export CERTADILLO_PKCS11_TOKEN=certadillo
export CERTADILLO_PKCS11_PIN=1234
certadillo init      # root and issuing CA keys are generated on the token, sign-only
certadillo serve
```

Check the keys are on the token and cannot be exported:

```bash
pkcs11-tool --module $CERTADILLO_PKCS11_LIB --token-label certadillo --login --pin 1234 --list-objects --type privkey
# Private Key Object; EC
#   label:      root-ca
#   Usage:      sign
#   Access:     sensitive, always sensitive, never extractable, local
```

`tests/test_keys_and_backends.py::test_ca_keys_in_pkcs11_hsm` does all of this automatically and also checks that no CA key file is written to disk.

## Production HSMs

| HSM | PKCS#11 library (typical path) | Notes |
| --- | --- | --- |
| Thales Luna Network HSM 7 | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | Use an HA group as the token label; FIPS 140-3 Level 3 mode |
| Entrust nShield Connect | `/opt/nfast/toolkits/pkcs11/libcknfast.so` | Module or OCS protection per your Security World policy |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | PIN format is `user:password` |

Set `CERTADILLO_PKCS11_LIB`, `CERTADILLO_PKCS11_TOKEN` and `CERTADILLO_PKCS11_PIN` (from your secrets manager, never from a file in the image). The container image ships `softhsm2` and `opensc` only; mount the vendor client and its config into the container.

## How signing works with a key that never leaves the HSM

pyca/cryptography only signs with in-process keys. For HSM keys Certadillo:

1. builds the certificate or CRL and signs it with a throwaway key of the same algorithm, which fixes the `signatureAlgorithm` in the TBS structure;
2. takes the TBS bytes, hashes them, and asks the HSM to sign (`CKM_ECDSA` on the digest, or `CKM_SHA384_RSA_PKCS`);
3. rebuilds the outer DER `SEQUENCE { tbs, algorithm, BIT STRING signature }` (`crypto/der.py`).

The throwaway key's signature is discarded. Tests verify the rebuilt certificates and CRLs with the real public key for EC P-384 and RSA-3072.

OCSP responses are signed by a delegated responder key (software, 30-day certificate, rotated automatically), so the HSM is only on the path for certificates and CRLs.

## HashiCorp Vault Transit

With `CERTADILLO_SIGNER=vault-transit` the CA private keys are generated inside Vault as non-exportable Transit keys and never enter the Certadillo process. Certadillo sends the to-be-signed bytes of each certificate or CRL to Vault and gets a signature back, through the same external-signing path the HSM uses. Someone who takes over the application server can ask for signatures while they are inside, and each request lands in Vault's audit log, but they cannot copy the key. Revoking the application's Vault token ends their access.

### Setup

```bash
vault secrets enable transit
vault write -f transit/keys/certadillo-fields type=aes256-gcm96        # only if you also use FIELD_CIPHER=vault
vault policy write certadillo-app deploy/vault/certadillo-app.hcl
```

```bash
CERTADILLO_SIGNER=vault-transit
CERTADILLO_VAULT_ADDR=https://vault.bank.internal:8200
CERTADILLO_VAULT_CACERT=/etc/certadillo/vault-ca.pem          # if Vault's certificate is from an internal CA
CERTADILLO_VAULT_TOKEN_FILE=/run/certadillo/vault-token        # written by Vault Agent (deploy/vault/agent.hcl)
CERTADILLO_VAULT_KEY_PREFIX=certadillo-                        # key name = prefix + CA name
```

Use Vault Agent with AppRole (or Kubernetes or cloud auth) rather than a static `CERTADILLO_VAULT_TOKEN`: the agent renews the token and rewrites the file, and Certadillo re-reads the file on every call.

### Least privilege, and keeping the root out of reach

`deploy/vault/certadillo-app.hcl` lets the application sign with issuing CA keys, read public keys and use the field-encryption key. It cannot sign with the root key, and cannot create, rotate, reconfigure, export or delete any key. So a compromised application server cannot mint a new intermediate CA.

Creating CA keys is a key ceremony, run from an admin workstation with a short-lived token, two people present:

```bash
# first hierarchy (root-ca and issuing-ca-1)
certadillo ca ceremony-policy --init > ceremony.hcl
vault policy write certadillo-ceremony ceremony.hcl
T=$(vault token create -policy=certadillo-ceremony -ttl=1h -field=token)
CERTADILLO_VAULT_TOKEN=$T certadillo init
vault token revoke "$T"

# a later issuing CA
certadillo ca ceremony-policy --name issuing-ca-2 --parent root-ca > ceremony.hcl
vault policy write certadillo-ceremony ceremony.hcl
T=$(vault token create -policy=certadillo-ceremony -ttl=1h -field=token)
CERTADILLO_VAULT_TOKEN=$T certadillo ca create-issuing --name issuing-ca-2 --operator alice --witness bob
vault token revoke "$T"
```

The ceremony policy grants write access on the exact keys being created, never on a glob. Creating a Transit key needs `update`, and `update` on `transit/keys/certadillo-*` would also allow `rotate`, `config` (which can make a key exportable) and `trim` on every CA key. Vault ranks that glob above deny rules such as `transit/keys/+/rotate`, so a deny cannot patch it. The tests check all of this against a real Vault.

`create-issuing` records both people in the audit trail. The new CA becomes the default for new certificates.

### What Certadillo checks

- The key version is pinned (`key_ref` is `vault-transit:<key>:<version>`), so rotating the Transit key never changes which key signs for an existing CA.
- RSA is signed as PKCS#1 v1.5 (Transit's default is PSS), and ECDSA signatures come back DER-encoded.
- Every signature is verified against the pinned public key before it is used, and the key's public key must match the CA certificate. A replaced key, a wrong version or a misbehaving proxy produces an error, never a certificate.
- A key name that already exists in Vault is refused rather than adopted.
- `CAKeyUnhealthy` fires when a Vault-held key cannot sign (Vault unreachable, token revoked or expired, version trimmed) or has been weakened (made exportable, deletion allowed).

### Limits

Vault open source stores Transit keys encrypted inside its own storage, not in an HSM, so Vault's own security (unseal keys, policies, who holds root tokens, audit devices) becomes part of the CA's trust boundary. For keys held in an HSM behind Vault, use Vault Enterprise managed keys, or the `pkcs11` signer directly. The root should still end up offline; see the roadmap.

## Moving an existing deployment

Keys cannot move between backends, and should not: a key that was once a file has a history an HSM cannot vouch for. Move by rotation instead:

1. Set `CERTADILLO_SIGNER=vault-transit` (or `pkcs11`) and restart. Existing CAs keep signing from their current keys.
2. Create a new issuing CA in the new backend (`certadillo ca create-issuing`, or `POST /api/v1/cas` with dual control). It becomes the default for new certificates.
3. Start a renewal campaign on the old CA (`"criteria": {"ca": "issuing-ca-1"}`) so every certificate is replaced from the new one, then revoke the rest at the deadline.
4. Retire the old issuing CA once nothing it issued is still valid.
