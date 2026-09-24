# Vault policy for the Certadillo application's own token.
#
# It can sign with issuing CA keys, read public keys, and encrypt or decrypt
# secret columns. It cannot sign with the root key, and cannot create, rotate,
# reconfigure, export or delete any key. A compromised application server can
# therefore not mint a new intermediate CA, and loses all access when its token
# is revoked. New issuing CAs are created in a key ceremony with
# certadillo-ceremony.hcl (see docs/HSM.md).
#
# Adjust "transit" and the "certadillo-" prefix if you changed
# CERTADILLO_VAULT_SIGNER_MOUNT or CERTADILLO_VAULT_KEY_PREFIX.

path "transit/keys/certadillo-*" {
  capabilities = ["read"]
}

path "transit/sign/certadillo-issuing-*" {
  capabilities = ["update"]
}

# field encryption (CERTADILLO_FIELD_CIPHER=vault)
path "transit/encrypt/certadillo-fields" {
  capabilities = ["update"]
}

path "transit/decrypt/certadillo-fields" {
  capabilities = ["update"]
}
