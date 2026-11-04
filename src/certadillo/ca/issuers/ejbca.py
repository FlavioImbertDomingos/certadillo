"""Keyfactor EJBCA through its REST API (pkcs10enroll and revoke), with
client-certificate authentication as EJBCA requires. The end entity is named
after the certificate's first name; the enrollment code is a one-time random
value, since Certadillo has already authorized the request."""
from __future__ import annotations

import base64
import secrets
import ssl
from urllib.parse import quote

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certadillo.provisioning import credentials

EJBCA_REASONS = {"key_compromise": "KEY_COMPROMISE", "superseded": "SUPERSEDED", "affiliation_changed":
                 "AFFILIATION_CHANGED", "cessation_of_operation": "CESSATION_OF_OPERATION"}


class EjbcaError(Exception):
    pass


class EjbcaIssuer:
    def __init__(self, name: str, cfg: dict, settings=None, transport=None):
        for k in ("url", "ca_name", "certificate_profile", "end_entity_profile"):
            if not cfg.get(k):
                raise ValueError(f"issuer {name}: ejbca needs {k}")
        if not str(cfg["url"]).startswith("https://"):
            raise ValueError(f"issuer {name}: url must be https://")
        for k in ("client_cert_ref", "client_key_ref"):
            credentials.check_ref(cfg.get(k))
        self.name, self.cfg, self.settings, self.transport = name, cfg, settings, transport

    def _http(self) -> httpx.Client:
        ctx = ssl.create_default_context(cadata=self.cfg["ca_bundle"]) if self.cfg.get("ca_bundle") \
            else ssl.create_default_context()
        if self.cfg.get("client_cert_ref"):
            import os
            import tempfile

            cert = credentials.resolve(self.cfg["client_cert_ref"], self.settings)
            key = credentials.resolve(self.cfg["client_key_ref"], self.settings)
            with tempfile.TemporaryDirectory() as d:  # ssl only loads client keys from files
                cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
                fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(key)
                with open(cp, "w") as fh:
                    fh.write(cert)
                ctx.load_cert_chain(cp, kp)
        return httpx.Client(base_url=self.cfg["url"].rstrip("/"), verify=ctx, timeout=30, transport=self.transport)

    def sign(self, csr, decision):
        username = f"certadillo-{(decision.common_name or decision.dns_names[0])}"[:250]
        body = {"certificate_request": csr.public_bytes(serialization.Encoding.PEM).decode(),
                "certificate_profile_name": self.cfg["certificate_profile"],
                "end_entity_profile_name": self.cfg["end_entity_profile"],
                "certificate_authority_name": self.cfg["ca_name"], "username": username,
                "password": secrets.token_urlsafe(24), "include_chain": True}
        with self._http() as c:
            r = c.post("/v1/certificate/pkcs10enroll", json=body)
            if r.status_code >= 300:
                raise EjbcaError(f"enrollment failed ({r.status_code}): {r.text[:200]}")
            data = r.json()
        leaf = x509.load_der_x509_certificate(base64.b64decode(data["certificate"]))
        chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in data.get("certificate_chain") or []]
        return leaf, chain, leaf.issuer.rfc4514_string()

    def revoke(self, serial_hex: str, reason: str, ref: str | None = None, cert_pem: str | None = None) -> None:
        issuer_dn = ref or x509.load_pem_x509_certificate(cert_pem.encode()).issuer.rfc4514_string()
        with self._http() as c:
            r = c.put(f"/v1/certificate/{quote(issuer_dn, safe='')}/{serial_hex}/revoke",
                      params={"reason": EJBCA_REASONS.get(reason, "UNSPECIFIED")})
            if r.status_code >= 300:
                raise EjbcaError(f"revocation failed ({r.status_code}): {r.text[:200]}")
