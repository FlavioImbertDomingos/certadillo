# Vault Agent for the Certadillo host: logs in with AppRole, keeps the token
# renewed, and writes it where CERTADILLO_VAULT_TOKEN_FILE points. Certadillo
# re-reads the file on every Vault call, so renewals need no restart.
#
#   vault agent -config=agent.hcl
#
# role_id and secret_id come from your provisioning (the secret_id response-
# wrapped and delivered once). The AppRole's token_policies should be
# certadillo-app only.

vault {
  address = "https://vault.bank.internal:8200"
  # ca_cert = "/etc/certadillo/vault-ca.pem"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/etc/certadillo/vault-role-id"
      secret_id_file_path                 = "/etc/certadillo/vault-secret-id"
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/run/certadillo/vault-token"
      mode = 0400
    }
  }
}
