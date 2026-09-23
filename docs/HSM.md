# HSM guide

Certadillo talks to HSMs through PKCS#11 (`python-pkcs11`). The same code path is used for SoftHSM2 in the lab and for network HSMs in production.

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
