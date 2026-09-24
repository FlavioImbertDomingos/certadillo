# Example key ceremony policy: creating issuing-ca-2 under root-ca.
#
# Do not edit this by hand for a real ceremony. Generate the exact policy:
#
#   certadillo ca ceremony-policy --name issuing-ca-2 --parent root-ca > ceremony.hcl
#   certadillo ca ceremony-policy --init > ceremony.hcl      # first hierarchy
#
# Write access is on the exact key being created, never a glob. Creating a
# Transit key needs "update", and "update" on transit/keys/certadillo-* would
# also allow rotate, config (making a key exportable) and trim on every CA key.
# Vault ranks that glob above deny rules such as transit/keys/+/rotate, so
# denies cannot fix it. tests/test_vault_signer.py checks this against Vault.
#
# Signing with the root key cannot be narrowed to one message in a policy, so
# the ceremony token must be short-lived and single-purpose:
#   vault token create -policy=<ceremony> -ttl=15m -use-limit=10 -orphan
#

path "transit/keys/certadillo-issuing-ca-2" {
  capabilities = ["create", "update", "read"]
  # Only a non-exportable key without plaintext backup can be created. This is an
  # allowlist on purpose: a deny on exportable=true is bypassed by the string "true".
  allowed_parameters = {
    "type" = ["ecdsa-p256", "ecdsa-p384", "rsa-3072", "rsa-4096"]
    "exportable" = [false]
    "allow_plaintext_backup" = [false]
  }
}

path "transit/keys/certadillo-*" {
  capabilities = ["read"]
}

path "transit/sign/certadillo-root-ca" {
  capabilities = ["update"]
}

path "transit/sign/certadillo-issuing-ca-2" {
  capabilities = ["update"]
}

