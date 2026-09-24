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

path "transit/keys/certadillo-issuing-ca-2" {
  capabilities = ["create", "update", "read"]
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

