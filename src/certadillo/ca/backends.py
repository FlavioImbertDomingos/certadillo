"""Issuer backends. The policy engine, RA workflow, inventory and alerting
stay the same whichever CA signs. Add a backend by implementing
CABackend and registering it under a name referenced from a profile's
`issuer:` key.

Shipped: `local` (built-in CA, software or PKCS#11 keys) and `vault`
(HashiCorp Vault / OpenBao PKI secrets engine). Planned adapters are listed
in docs/ROADMAP.md with the vendor API each one calls."""
from __future__ import annotations

from typing import Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certadillo.policy.engine import Decision


class CABackend(Protocol):
    name: str

    def sign(self, csr: x509.CertificateSigningRequest, decision: Decision) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Return (leaf, chain)."""

    def revoke(self, serial_hex: str, reason: str) -> None: ...


class VaultPKIBackend:
    """Vault / OpenBao `pki` engine via `sign/:role` (the role keeps its own
    guard rails; ours run first)."""

    name = "vault"

    def __init__(self, addr: str, token: str, mount: str = "pki", role: str = "certadillo", namespace: str | None = None,
                 client: httpx.Client | None = None):
        self.addr = addr.rstrip("/")
        self.mount = mount
        self.role = role
        headers = {"X-Vault-Token": token}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        self.http = client or httpx.Client(timeout=15)
        self.headers = headers

    def sign(self, csr, decision):
        body = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "common_name": decision.common_name or "",
            "alt_names": ",".join(decision.dns_names),
            "uri_sans": ",".join(decision.uris),
            "ttl": f"{int(decision.validity.total_seconds())}s",
            "format": "pem",
        }
        r = self.http.post(f"{self.addr}/v1/{self.mount}/sign/{self.role}", json=body, headers=self.headers)
        r.raise_for_status()
        data = r.json()["data"]
        leaf = x509.load_pem_x509_certificate(data["certificate"].encode())
        chain = [x509.load_pem_x509_certificate(c.encode()) for c in data.get("ca_chain", [])]
        return leaf, chain

    def revoke(self, serial_hex: str, reason: str) -> None:
        s = serial_hex.rjust(len(serial_hex) + len(serial_hex) % 2, "0")
        colon = ":".join(s[i : i + 2] for i in range(0, len(s), 2))
        r = self.http.post(f"{self.addr}/v1/{self.mount}/revoke", json={"serial_number": colon}, headers=self.headers)
        r.raise_for_status()


_registry: dict[str, CABackend] = {}


def register_backend(backend: CABackend) -> None:
    _registry[backend.name] = backend


def get_backend(name: str) -> CABackend | None:
    return _registry.get(name)


def clear_backends() -> None:
    _registry.clear()
