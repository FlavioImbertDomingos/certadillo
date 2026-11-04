# SSH certificates

OpenSSH has its own certificate format, separate from X.509. Instead of copying public keys into `authorized_keys` on every server, servers trust one CA key, and people get certificates that expire in hours. Hosts get certificates too, so clients stop seeing "unknown host key" prompts.

Certadillo runs an Ed25519 SSH CA next to the X.509 hierarchy.

## Set up servers once

```bash
curl -s $S/api/v1/ssh/ca | sudo tee /etc/ssh/certadillo_user_ca.pub
```

`/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/certadillo_user_ca.pub
# optional: only certificates, no authorized_keys files
AuthorizedKeysFile none
```

Reload sshd. A user can now log in as any account listed in their certificate's principals.

## Get a user certificate

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C alice

curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" -X POST $S/api/v1/ssh/certificates -d "{
  \"public_key\": \"$(cat ~/.ssh/id_ed25519.pub)\",
  \"cert_type\": \"user\",
  \"principals\": [\"alice\"],
  \"key_id\": \"alice@bank.example\",
  \"validity_hours\": 8,
  \"source_address\": \"10.0.0.0/8\"
}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["certificate"])' > ~/.ssh/id_ed25519-cert.pub

ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
ssh alice@server01     # OpenSSH picks up id_ed25519-cert.pub automatically
```

This was checked against a real `sshd`: the certificate logs in as `alice`, and the same certificate is refused for `root` because `root` is not a principal.

| Field | Notes |
| --- | --- |
| `principals` | the Unix accounts the certificate may log in as |
| `key_id` | shows up in the server's auth log; use the person's identity |
| `validity_hours` | user certificates: 8 by default, 24 maximum |
| `source_address` | optional CIDR list; the certificate only works from there |

User certificates carry `permit-pty`, `permit-port-forwarding` and `permit-agent-forwarding`.

## Host certificates

```bash
curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" -X POST $S/api/v1/ssh/certificates -d "{
  \"public_key\": \"$(cat /etc/ssh/ssh_host_ed25519_key.pub)\",
  \"cert_type\": \"host\",
  \"principals\": [\"server01.ops.bank.internal\"],
  \"key_id\": \"server01\",
  \"validity_days\": 30
}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["certificate"])' | sudo tee /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Add `HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub` to `sshd_config`. On clients:

```
# ~/.ssh/known_hosts
@cert-authority *.ops.bank.internal ssh-ed25519 AAAA... certadillo-ssh-ca
```

Host certificates: 30 days by default, 90 maximum.

## Static SSH keys

Certificates are where SSH access should end up, but most estates still run
on `authorized_keys` files: keys that never expire, copied between accounts,
and owned by nobody in particular. The host agent finds them so they can be
cleaned up and moved to certificates.

`certadillo agent scan` (see [discovery](12-discovery-inventory.md#the-host-agent))
reports, for every account with a home directory, the keys in
`~/.ssh/authorized_keys` and `authorized_keys2`, the files under
`/etc/ssh/authorized_keys/` (for `AuthorizedKeysFile /etc/ssh/authorized_keys/%u`),
and the host public keys. For each key: the SHA-256 fingerprint exactly as
`ssh-keygen -l` prints it, the type and size, the comment, the account, the
restrictions on the line, and when the file last changed. The `from=`,
`permitopen=` and `principals=` values are kept; a `command=` is reported only
as present, because forced commands often carry credentials. Public keys only.
Use `--no-ssh` to leave SSH out.

```bash
curl -s -H "X-API-Key: $AUDITOR_KEY" "$S/api/v1/ssh-keys?host=web1"
curl -s -H "X-API-Key: $AUDITOR_KEY" "$S/api/v1/ssh-keys?owner=none"      # keys nobody has claimed
curl -s -H "X-API-Key: $OPERATOR_KEY" -X PUT "$S/api/v1/ssh-keys/12/owner" \
  -H "Content-Type: application/json" -d '{"owner": "team-payments", "note": "CHG0042"}'
```

Claiming a key records the owner on every place the same key appears. A key
that disappears from a host is kept as `removed` so the history stays.

| Finding | Alert | Raised when |
| --- | --- | --- |
| `ssh_weak_key` | `SshKeyWeak` | DSA, or RSA under `CERTADILLO_SSH_RSA_MIN_BITS` (2048) |
| `ssh_shared_key` | `SshKeyShared` | the same key is authorized for more than one account or host |
| `ssh_root_unrestricted` | `SshRootKeyUnrestricted` | a key logs in as root with no `from=` restriction |
| `ssh_orphaned_key` | `SshKeyOrphaned` | a key in `/etc/ssh/authorized_keys/` for an account that does not exist |
| `ssh_rotation_due` | `SshKeyRotationDue` (info) | the authorized_keys file has not changed for `CERTADILLO_SSH_KEY_MAX_AGE_DAYS` (365) |

Findings close by themselves once a report no longer shows the problem, and
can be acknowledged with a reason like any other discovery finding. Rotating
static keys from Certadillo is not built yet; the way out for most of them is a
short-lived certificate from this page.

## Limits today

- The SSH CA key is a software key; the HSM covers the X.509 CAs only. See [SECURITY.md](../SECURITY.md).
- SSH certificates cannot be revoked through the API yet. Keep them short; for emergencies use sshd's `RevokedKeys`.
