"""Inventory connectors: pull certificates from systems that already hold them.

Each connector yields (certificate, location). The platform de-duplicates by
SHA-256 fingerprint, so running several connectors over the same estate is
safe. Planned connectors (Venafi TLS Protect, DigiCert CertCentral, Keyfactor
Command, Microsoft AD CS, F5 BIG-IP, AWS ACM, Azure Key Vault) are in
docs/ROADMAP.md with the API each would call."""
from __future__ import annotations

import base64
from typing import Iterator, Protocol

import httpx
from cryptography import x509


class InventoryConnector(Protocol):
    name: str

    def collect(self) -> Iterator[tuple[x509.Certificate, str]]: ...


class VaultPKIInventory:
    name = "vault-pki"

    def __init__(self, addr: str, token: str, mount: str = "pki", client: httpx.Client | None = None):
        self.addr, self.mount = addr.rstrip("/"), mount
        self.http = client or httpx.Client(timeout=15)
        self.headers = {"X-Vault-Token": token}

    def collect(self):
        r = self.http.request("LIST", f"{self.addr}/v1/{self.mount}/certs", headers=self.headers)
        r.raise_for_status()
        for serial in r.json()["data"]["keys"]:
            c = self.http.get(f"{self.addr}/v1/{self.mount}/cert/{serial}", headers=self.headers)
            c.raise_for_status()
            yield x509.load_pem_x509_certificate(c.json()["data"]["certificate"].encode()), f"vault:{self.mount}/{serial}"


class KubernetesTLSSecrets:
    """Reads every `kubernetes.io/tls` Secret the service account can list."""

    name = "kubernetes"

    def __init__(self, api_server: str, token: str, ca_bundle: str | bool = True, client: httpx.Client | None = None):
        self.api = api_server.rstrip("/")
        self.http = client or httpx.Client(timeout=15, verify=ca_bundle)
        self.headers = {"Authorization": f"Bearer {token}"}

    def collect(self):
        r = self.http.get(
            f"{self.api}/api/v1/secrets", params={"fieldSelector": "type=kubernetes.io/tls"}, headers=self.headers
        )
        r.raise_for_status()
        for item in r.json().get("items", []):
            crt = item.get("data", {}).get("tls.crt")
            if not crt:
                continue
            meta = item["metadata"]
            for cert in x509.load_pem_x509_certificates(base64.b64decode(crt)):
                yield cert, f"k8s:{meta.get('namespace')}/{meta.get('name')}"
                break  # leaf only; the chain is not inventory


def parse_pem_bundle(text: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(text.encode())
