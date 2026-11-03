"""Credentials for targets are references, resolved only at the moment of use.

  env:NAME                    an environment variable of the Certadillo process
  file:/run/secrets/f5        a file (Docker/Kubernetes secret mounts)
  vault:secret/data/f5#pass   a field of a HashiCorp Vault KV v2 secret

The database holds the reference, never the value, so a database copy does not
hand out the keys to the load balancers. Values are never logged or audited.
"""
from __future__ import annotations

import os
from pathlib import Path


class CredentialError(Exception):
    pass


SCHEMES = ("env:", "file:", "vault:")


def check_ref(ref: str | None) -> None:
    if ref is None:
        return
    if not ref.startswith(SCHEMES):
        raise ValueError("credential_ref must be env:NAME, file:/path or vault:mount/data/path#field; "
                         "Certadillo does not store target secrets")
    if ref.startswith("vault:") and "#" not in ref:
        raise ValueError("a vault: credential_ref needs #field")


def resolve(ref: str | None, settings=None) -> str | None:
    if ref is None:
        return None
    if ref.startswith("env:"):
        value = os.environ.get(ref[4:])
        if value is None:
            raise CredentialError(f"environment variable {ref[4:]} is not set")
        return value
    if ref.startswith("file:"):
        try:
            return Path(ref[5:]).read_text().strip()
        except OSError as exc:
            raise CredentialError(f"cannot read {ref[5:]}: {exc.strerror}") from None
    if ref.startswith("vault:"):
        from certadillo.crypto.vault import VaultClient, VaultError

        path, _, field = ref[6:].partition("#")
        try:
            data = VaultClient.from_settings(settings).request("GET", path)
        except VaultError as exc:
            raise CredentialError(f"Vault read of {path} failed: {exc}") from None
        inner = (data.get("data") or {}).get("data") or data.get("data") or {}
        if field not in inner:
            raise CredentialError(f"field {field} not found at {path}")
        return str(inner[field])
    raise CredentialError("unsupported credential reference")
