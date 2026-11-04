"""Certadillo as an ACME client (RFC 8555), so a public or third-party ACME CA
(Let's Encrypt, Google Trust Services, ZeroSSL, Sectigo, DigiCert ACME, an
internal step-ca or Boulder) can be the issuer behind Certadillo's policy.

Only dns-01 is used: Certadillo is not the web server, so it proves control by
writing the TXT record through the configured DNS provider and removing it
afterwards. The account key is generated once and kept in the data directory,
encrypted with the key passphrase. External account binding (RFC 8555 7.3.4)
is supported for CAs that require it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import ssl
import time
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from certadillo.ca.issuers import REASON_CODES, dns_providers
from certadillo.provisioning import credentials

log = logging.getLogger("certadillo.issuers.acme")


class AcmeError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AcmeIssuer:
    def __init__(self, name: str, cfg: dict, settings=None, transport=None):
        if not str(cfg.get("directory", "")).startswith("https://"):
            raise ValueError(f"issuer {name}: directory must be an https:// ACME directory URL")
        if not cfg.get("dns"):
            raise ValueError(f"issuer {name}: dns-01 needs a dns provider")
        if cfg.get("eab"):
            credentials.check_ref(cfg["eab"].get("hmac_ref"))
        self.name = name
        self.cfg = cfg
        self.settings = settings
        self.dns = dns_providers.build(cfg["dns"], settings)
        self.transport = transport
        self.timeout = float(cfg.get("timeout", 120))
        self._key = None
        self._kid = None
        self._dir = None
        self._nonce = None

    # ------------------------------------------------------------------ plumbing
    def _http(self) -> httpx.Client:
        # a private ACME CA's root (step-ca, Pebble) as a file path
        verify = ssl.create_default_context(cafile=self.cfg["ca_bundle"]) if self.cfg.get("ca_bundle") else True
        return httpx.Client(timeout=30, verify=verify, transport=self.transport,
                            headers={"User-Agent": "certadillo-acme-client"})

    def _account_key(self):
        if self._key is not None:
            return self._key
        path = Path(self.settings.data_dir) / "acme-accounts" / f"{self.name}.pem"
        pw = self.settings.key_passphrase.encode()
        if path.exists():
            self._key = serialization.load_pem_private_key(path.read_bytes(), pw)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._key = ec.generate_private_key(ec.SECP256R1())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.BestAvailableEncryption(pw)))
        return self._key

    def _jwk(self) -> dict:
        n = self._account_key().public_key().public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}

    def thumbprint(self) -> str:
        jwk = self._jwk()
        return b64u(hashlib.sha256(json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")},
                                              separators=(",", ":")).encode()).digest())

    def _sign(self, protected: dict, payload) -> dict:
        p64 = b64u(json.dumps(protected).encode())
        body = "" if payload is None else b64u(json.dumps(payload).encode())
        der = self._account_key().sign(f"{p64}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return {"protected": p64, "payload": body, "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}

    def _directory(self, c: httpx.Client) -> dict:
        if self._dir is None:
            r = c.get(self.cfg["directory"])
            if r.status_code != 200:
                raise AcmeError(f"ACME directory returned {r.status_code}")
            self._dir = r.json()
        return self._dir

    def _new_nonce(self, c: httpx.Client) -> str:
        r = c.head(self._directory(c)["newNonce"])
        return r.headers["Replay-Nonce"]

    def _post(self, c: httpx.Client, url: str, payload, use_jwk: bool = False) -> httpx.Response:
        for _ in range(3):
            nonce = self._nonce or self._new_nonce(c)
            self._nonce = None
            protected = {"alg": "ES256", "nonce": nonce, "url": url}
            if use_jwk:
                protected["jwk"] = self._jwk()
            else:
                protected["kid"] = self._kid
            r = c.post(url, content=json.dumps(self._sign(protected, payload)),
                       headers={"Content-Type": "application/jose+json"})
            self._nonce = r.headers.get("Replay-Nonce")
            if r.status_code == 400 and "badNonce" in r.text:
                continue
            return r
        raise AcmeError("the ACME server kept rejecting nonces")

    def _ok(self, r: httpx.Response, what: str) -> httpx.Response:
        if r.status_code >= 300:
            detail = r.json().get("detail", r.text[:200]) if r.headers.get("content-type", "").endswith("json") else r.text[:200]
            raise AcmeError(f"{what} failed ({r.status_code}): {detail}")
        return r

    def _account(self, c: httpx.Client) -> None:
        if self._kid:
            return
        payload: dict = {"termsOfServiceAgreed": True}
        if self.cfg.get("contact"):
            payload["contact"] = [self.cfg["contact"]]
        eab = self.cfg.get("eab")
        if eab:
            url = self._directory(c)["newAccount"]
            protected = {"alg": "HS256", "kid": eab["kid"], "url": url}
            p64 = b64u(json.dumps(protected).encode())
            pl = b64u(json.dumps(self._jwk()).encode())
            key = base64.urlsafe_b64decode(credentials.resolve(eab["hmac_ref"], self.settings) + "==")
            payload["externalAccountBinding"] = {"protected": p64, "payload": pl,
                                                 "signature": b64u(hmac.new(key, f"{p64}.{pl}".encode(),
                                                                            hashlib.sha256).digest())}
        r = self._ok(self._post(c, self._directory(c)["newAccount"], payload, use_jwk=True), "account registration")
        self._kid = r.headers["Location"]

    def _poll(self, c: httpx.Client, url: str, done: set[str], failed: set[str], what: str) -> dict:
        deadline = time.monotonic() + self.timeout
        while True:
            obj = self._ok(self._post(c, url, None), what).json()
            if obj.get("status") in done:
                return obj
            if obj.get("status") in failed:
                raise AcmeError(f"{what} is {obj.get('status')}: {json.dumps(obj.get('error') or obj)[:300]}")
            if time.monotonic() > deadline:
                raise AcmeError(f"{what} still {obj.get('status')} after {int(self.timeout)}s")
            time.sleep(float(self.cfg.get("poll_interval", 1.0)))

    # ------------------------------------------------------------------ CABackend
    def sign(self, csr, decision):
        names = list(dict.fromkeys(decision.dns_names))
        if not names or decision.uris or decision.emails or decision.upns:
            raise AcmeError("an ACME issuer can only issue DNS-name certificates")
        published: list[tuple[str, str]] = []
        with self._http() as c:
            self._account(c)
            r = self._ok(self._post(c, self._directory(c)["newOrder"],
                                    {"identifiers": [{"type": "dns", "value": n} for n in names]}), "new order")
            order_url, order = r.headers["Location"], r.json()
            try:
                challenges = []
                for authz_url in order["authorizations"]:
                    authz = self._ok(self._post(c, authz_url, None), "authorization").json()
                    if authz.get("status") == "valid":
                        continue
                    ch = next((x for x in authz["challenges"] if x["type"] == "dns-01"), None)
                    if ch is None:
                        raise AcmeError(f"no dns-01 challenge offered for {authz['identifier']['value']}")
                    fqdn = "_acme-challenge." + authz["identifier"]["value"].removeprefix("*.") + "."
                    value = b64u(hashlib.sha256(f"{ch['token']}.{self.thumbprint()}".encode()).digest())
                    self.dns.set_txt(fqdn, value)
                    published.append((fqdn, value))
                    challenges.append((authz_url, ch["url"]))
                time.sleep(float(self.cfg.get("propagation_seconds", 0)))
                for _authz_url, ch_url in challenges:
                    self._ok(self._post(c, ch_url, {}), "challenge response")
                for authz_url, _ in challenges:
                    self._poll(c, authz_url, {"valid"}, {"invalid", "revoked", "expired", "deactivated"},
                               "authorization")
                der = csr.public_bytes(serialization.Encoding.DER)
                self._ok(self._post(c, order["finalize"], {"csr": b64u(der)}), "finalize")
                order = self._poll(c, order_url, {"valid"}, {"invalid"}, "order")
                pem = self._ok(self._post(c, order["certificate"], None), "certificate download").text
            finally:
                for fqdn, value in published:
                    try:
                        self.dns.clear_txt(fqdn, value)
                    except Exception:  # noqa: BLE001 - a stale TXT record is harmless; the result stands
                        log.warning("could not remove %s", fqdn)
        certs = x509.load_pem_x509_certificates(pem.encode())
        return certs[0], certs[1:], order["certificate"]

    def revoke(self, serial_hex: str, reason: str, ref: str | None = None, cert_pem: str | None = None) -> None:
        if cert_pem is None:
            raise AcmeError("ACME revocation needs the certificate")
        der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(serialization.Encoding.DER)
        with self._http() as c:
            self._account(c)
            self._ok(self._post(c, self._directory(c)["revokeCert"],
                                {"certificate": b64u(der), "reason": REASON_CODES.get(reason, 0)}), "revocation")
