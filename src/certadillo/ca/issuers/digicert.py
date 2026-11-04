"""DigiCert CertCentral (Services API v2).

Orders go to /order/certificate/{product}. With a pre-validated organization
and domains, CertCentral issues immediately and returns the chain in the order
response; otherwise the order is polled until issued. skip_approval keeps the
order out of CertCentral's own approval queue, because Certadillo already ran
policy and dual control. Revocation calls /certificate/{id}/revoke with the
CertCentral certificate id recorded at issuance.
"""
from __future__ import annotations

import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from certadillo.provisioning import credentials

API = "https://www.digicert.com/services/v2"
REASONS = {"key_compromise": "key_compromise", "superseded": "superseded",
           "cessation_of_operation": "cessation_of_operation", "affiliation_changed": "affiliation_changed"}


class DigiCertError(Exception):
    pass


class DigiCertIssuer:
    def __init__(self, name: str, cfg: dict, settings=None, transport=None):
        for k in ("product", "organization_id", "api_key_ref"):
            if not cfg.get(k):
                raise ValueError(f"issuer {name}: digicert needs {k}")
        credentials.check_ref(cfg["api_key_ref"])
        self.name, self.cfg, self.settings, self.transport = name, cfg, settings, transport

    def _http(self) -> httpx.Client:
        key = credentials.resolve(self.cfg["api_key_ref"], self.settings)
        return httpx.Client(base_url=self.cfg.get("api_url", API), timeout=30, transport=self.transport,
                            headers={"X-DC-DEVKEY": key, "Content-Type": "application/json"})

    @staticmethod
    def _check(r: httpx.Response, what: str) -> dict:
        if r.status_code >= 300:
            errors = r.json().get("errors", []) if "json" in r.headers.get("content-type", "") else []
            raise DigiCertError(f"{what} failed ({r.status_code}): {errors or r.text[:200]}")
        return r.json() if r.content else {}

    def sign(self, csr, decision):
        names = list(dict.fromkeys(decision.dns_names))
        days = max(1, decision.validity.days)
        body = {
            "certificate": {"common_name": decision.common_name or names[0], "dns_names": names,
                            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
                            "signature_hash": "sha256", "server_platform": {"id": -1}},
            "organization": {"id": int(self.cfg["organization_id"])},
            "order_validity": {"days": days},
            "skip_approval": True,
            "payment_method": self.cfg.get("payment_method", "balance"),
        }
        with self._http() as c:
            order = self._check(c.post(f"/order/certificate/{self.cfg['product']}", json=body), "order")
            cert_id = order.get("certificate_id")
            chain = order.get("certificate_chain")
            deadline = time.monotonic() + float(self.cfg.get("timeout", 120))
            while not chain:
                info = self._check(c.get(f"/order/certificate/{order['id']}"), "order status")
                status = info.get("status")
                cert_id = (info.get("certificate") or {}).get("id", cert_id)
                if status == "issued":
                    pem = c.get(f"/certificate/{cert_id}/download/format/pem_all")
                    if pem.status_code >= 300:
                        raise DigiCertError(f"download failed ({pem.status_code})")
                    chain = [{"pem": p} for p in _split(pem.text)]
                    break
                if status in ("rejected", "canceled", "revoked"):
                    raise DigiCertError(f"order {order['id']} is {status}")
                if time.monotonic() > deadline:
                    raise DigiCertError(f"order {order['id']} still {status}; it may need validation in CertCentral")
                time.sleep(float(self.cfg.get("poll_interval", 5)))
        certs = [x509.load_pem_x509_certificate(e["pem"].encode()) for e in chain]
        return certs[0], certs[1:], str(cert_id)

    def revoke(self, serial_hex: str, reason: str, ref: str | None = None, cert_pem: str | None = None) -> None:
        if not ref:
            raise DigiCertError("no CertCentral certificate id recorded for this certificate")
        with self._http() as c:
            self._check(c.put(f"/certificate/{ref}/revoke",
                              json={"reason": REASONS.get(reason, "unspecified"), "skip_approval": True,
                                    "comments": f"revoked through Certadillo ({reason})"}), "revocation")


def _split(text: str) -> list[str]:
    out, cur = [], []
    for line in text.splitlines():
        cur.append(line)
        if line.startswith("-----END CERTIFICATE"):
            out.append("\n".join(cur) + "\n")
            cur = []
    return out
