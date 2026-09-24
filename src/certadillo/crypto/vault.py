"""A small HashiCorp Vault HTTP client shared by the Transit signer and field
encryption.

Authentication is a token. In production that token should come from Vault
Agent, which logs in (AppRole, Kubernetes, AWS IAM...), renews the token and
writes it to a file: set CERTADILLO_VAULT_TOKEN_FILE and the file is re-read on
every call, so a renewed or re-issued token is picked up without a restart.
CERTADILLO_VAULT_CACERT points at the CA bundle for Vault's own TLS certificate.
"""
from __future__ import annotations

from pathlib import Path

import httpx


class VaultError(Exception):
    """Vault refused or could not be reached. Callers fail closed."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class VaultClient:
    def __init__(self, addr: str, token: str | None = None, token_file: str | None = None,
                 namespace: str | None = None, cacert: str | None = None, timeout: float = 10.0,
                 http: httpx.Client | None = None):
        if not addr:
            raise VaultError("CERTADILLO_VAULT_ADDR is not set")
        if not (token or token_file):
            raise VaultError("set CERTADILLO_VAULT_TOKEN_FILE (Vault Agent sink) or CERTADILLO_VAULT_TOKEN")
        self.addr = addr.rstrip("/")
        self._token = token
        self._token_file = token_file
        self.namespace = namespace
        self._http = http or httpx.Client(timeout=timeout, verify=cacert if cacert else True)

    @classmethod
    def from_settings(cls, settings, http: httpx.Client | None = None) -> "VaultClient":
        return cls(settings.vault_addr, settings.vault_token, settings.vault_token_file,
                   settings.vault_namespace, settings.vault_cacert, http=http)

    def token(self) -> str:
        if self._token_file:
            try:
                return Path(self._token_file).read_text().strip()
            except OSError as exc:
                raise VaultError(f"cannot read Vault token file {self._token_file}: {exc}") from exc
        return self._token

    def request(self, method: str, path: str, json: dict | None = None) -> dict:
        headers = {"X-Vault-Token": self.token()}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        try:
            r = self._http.request(method, f"{self.addr}/v1/{path.lstrip('/')}", json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise VaultError(f"Vault unreachable at {self.addr}: {exc}") from exc
        if r.status_code >= 400:
            try:
                errors = "; ".join(r.json().get("errors") or []) or r.text[:200]
            except ValueError:
                errors = r.text[:200]
            raise VaultError(f"Vault {method} {path} returned {r.status_code}: {errors}", status=r.status_code)
        if r.status_code == 204 or not r.content:
            return {}
        try:
            return r.json()
        except ValueError as exc:
            raise VaultError(f"Vault {method} {path} returned invalid JSON") from exc
