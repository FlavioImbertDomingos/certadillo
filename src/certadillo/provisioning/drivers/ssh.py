"""Linux and Unix hosts over SSH: nginx, Apache, HAProxy, Postfix, anything
that reads PEM files.

The host key is pinned in the target config and anything else is refused (no
trust on first use). Files are written next to their final path and renamed
into place, the key with mode 0600 before any byte of it is written. The reload
command is set by the admin on the target, never by an installation, and paths
must sit inside the target's allowed_dirs.

With key_location "device" the key is generated on the host with openssl and
never leaves it; Certadillo only sees the CSR.
"""
from __future__ import annotations

import io
import posixpath
import shlex

from certadillo.provisioning.drivers import register
from certadillo.provisioning.drivers.base import Driver, InstallBundle, ProvisioningError

KEYGEN = {
    "ec-p256": "-newkey ec -pkeyopt ec_paramgen_curve:P-256",
    "ec-p384": "-newkey ec -pkeyopt ec_paramgen_curve:P-384",
    "rsa-2048": "-newkey rsa:2048",
    "rsa-3072": "-newkey rsa:3072",
}


@register
class SshDriver(Driver):
    kind = "ssh"
    key_locations = ("central", "device")

    @classmethod
    def check_config(cls, config: dict) -> dict:
        cls.require(config, "host", "username", "host_key", "allowed_dirs")
        parts = str(config["host_key"]).split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
            raise ValueError("host_key must be the server's public host key, e.g. 'ssh-ed25519 AAAA...'")
        dirs = config["allowed_dirs"]
        if not isinstance(dirs, list) or not all(isinstance(d, str) and d.startswith("/") and ".." not in d
                                                 for d in dirs):
            raise ValueError("allowed_dirs must be a list of absolute directories")
        if config.get("auth", "key") not in ("key", "password"):
            raise ValueError("auth must be 'key' or 'password'")
        return config

    def _path(self, value: str | None, what: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.startswith("/"):
            raise ValueError(f"{what} must be an absolute path")
        norm = posixpath.normpath(value)
        if norm != value or any(c in value for c in "\n\r\x00"):
            raise ValueError(f"{what} {value!r} is not a clean path")
        if not any(norm.startswith(d.rstrip("/") + "/") for d in self.config["allowed_dirs"]):
            raise ValueError(f"{what} {value!r} is outside the target's allowed_dirs")
        return norm

    def check_params(self, params: dict) -> dict:
        out = {"cert_path": self._path(params.get("cert_path"), "cert_path"),
               "key_path": self._path(params.get("key_path"), "key_path"),
               "chain_path": self._path(params.get("chain_path"), "chain_path"),
               "fullchain": bool(params.get("fullchain", True))}
        if not out["cert_path"] or not out["key_path"]:
            raise ValueError("an ssh installation needs cert_path and key_path")
        return out

    # ------------------------------------------------------------------ connection
    def _connect(self):
        import paramiko

        c = self.config
        port = int(c.get("port", 22))
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        ktype, kdata = str(c["host_key"]).split()[:2]
        entry = c["host"] if port == 22 else f"[{c['host']}]:{port}"
        key = paramiko.PKey.from_type_string(ktype, __import__("base64").b64decode(kdata))
        client.get_host_keys().add(entry, ktype, key)
        kwargs = {"hostname": c["host"], "port": port, "username": c["username"], "timeout": 15,
                  "allow_agent": False, "look_for_keys": False}
        if c.get("auth", "key") == "password":
            kwargs["password"] = self.secret
        else:
            if not self.secret:
                raise ProvisioningError("no SSH private key: set the target's credential_ref")
            kwargs["pkey"] = _load_private_key(self.secret)
        try:
            client.connect(**kwargs)
        except paramiko.BadHostKeyException:
            raise ProvisioningError("the host presented a different host key than the pinned one") from None
        except (paramiko.SSHException, OSError) as exc:
            raise ProvisioningError(f"SSH connection failed: {exc}") from None
        return client

    @staticmethod
    def _run(client, command: str) -> str:
        _, stdout, stderr = client.exec_command(command, timeout=60)
        out = stdout.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        if code != 0:
            raise ProvisioningError(f"remote command failed ({code}): {stderr.read().decode(errors='replace')[:300]}")
        return out

    # ------------------------------------------------------------------ operations
    def device_csr(self, params: dict, common_name: str, sans: list[str], key_type: str) -> str:
        if key_type not in KEYGEN:
            raise ValueError(f"key_type {key_type} not supported for on-device generation")
        nxt = params["key_path"] + ".next"
        san = ",".join(f"DNS:{s}" for s in [common_name, *sans] if s)
        cmd = (f"umask 077 && openssl req -new -nodes {KEYGEN[key_type]} -keyout {shlex.quote(nxt)} "
               f"-subj {shlex.quote('/CN=' + common_name)} -addext {shlex.quote('subjectAltName=' + san)}")
        client = self._connect()
        try:
            csr = self._run(client, cmd)
        finally:
            client.close()
        if "BEGIN CERTIFICATE REQUEST" not in csr:
            raise ProvisioningError("openssl on the host did not return a CSR")
        return csr[csr.index("-----BEGIN"):]

    def install(self, params: dict, bundle: InstallBundle) -> None:
        client = self._connect()
        try:
            sftp = client.open_sftp()
            cert_body = bundle.cert_pem + (bundle.chain_pem if params["fullchain"] else "")
            if bundle.key_pem is not None:
                _put(sftp, params["key_path"], bundle.key_pem, 0o600)
                bundle.steps.append(f"wrote {params['key_path']} (0600)")
            else:
                sftp.posix_rename(params["key_path"] + ".next", params["key_path"])
                bundle.steps.append(f"activated device key {params['key_path']}")
            if params.get("chain_path"):
                _put(sftp, params["chain_path"], bundle.chain_pem.encode(), 0o644)
            _put(sftp, params["cert_path"], cert_body.encode(), 0o644)
            bundle.steps.append(f"wrote {params['cert_path']}")
            sftp.close()
            reload_cmd = self.config.get("reload_command")
            if reload_cmd:
                self._run(client, reload_cmd)
                bundle.steps.append("ran the target's reload command")
        finally:
            client.close()


def _put(sftp, path: str, data: bytes, mode: int) -> None:
    tmp = path + ".certadillo-tmp"
    f = sftp.open(tmp, "wb")
    try:
        sftp.chmod(tmp, mode)  # before any content is written
        f.write(data)
    finally:
        f.close()
    sftp.posix_rename(tmp, path)


def _load_private_key(text: str):
    import paramiko

    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError):
            continue
    raise ProvisioningError("the SSH credential is not a private key paramiko can read")
