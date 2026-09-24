"""CA keys held in HashiCorp Vault's Transit engine.

The private key is generated inside Vault as non-exportable and never enters
the Certadillo process. To sign a certificate or a CRL, Certadillo sends the
to-be-signed bytes to Vault and gets a signature back, through the same
external-signing path the PKCS#11 signer uses. Someone who takes over the
application can ask for signatures while they are inside, and every request
lands in Vault's audit log, but they cannot copy the key and leave. Cutting the
application's Vault token ends it.

Details that matter:

- Pinned key version. A Transit key can be rotated, and signing without a
  version uses the newest one, which would not match the CA certificate. The
  key_ref records the version ("vault-transit:<key>:<version>") and every sign
  request names it.
- PKCS#1 v1.5 for RSA. Transit signs RSA with PSS by default; X.509
  sha*WithRSAEncryption needs PKCS#1 v1.5, so it is requested explicitly.
  ECDSA signatures come back DER-encoded (marshaling_algorithm=asn1), which is
  what X.509 expects.
- Every signature is verified locally against the pinned public key before it
  is used, so a wrong key, a wrong version or a misbehaving Vault produces an
  error instead of a broken certificate.
- A key name that already exists is refused rather than reused, so a key
  planted in Vault ahead of time cannot become a CA key.

Vault open source keeps Transit keys encrypted inside its own storage; for keys
held in an HSM behind Vault, use Vault Enterprise managed keys. Either way,
Vault's policy and audit log become part of the CA's trust boundary.
"""
from __future__ import annotations

import base64
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from certadillo.crypto.vault import VaultClient, VaultError

VAULT_TYPES = {"ec-p256": "ecdsa-p256", "ec-p384": "ecdsa-p384", "rsa-3072": "rsa-3072", "rsa-4096": "rsa-4096"}
HASHES = {"sha256": "sha2-256", "sha384": "sha2-384", "sha512": "sha2-512"}
PREFIX = "vault-transit:"


class VaultTransitSigner:
    kind = "vault-transit"

    def __init__(self, store: "VaultTransitKeyStore", key_name: str, version: int, public_key):
        self._store = store
        self.key_name = key_name
        self.version = version
        self._pub = public_key
        self.key_ref = f"{PREFIX}{key_name}:{version}"

    def public_key(self):
        return self._pub

    @property
    def private_key(self):
        return None  # never leaves Vault

    def sign(self, data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes:
        if hash_alg.name not in HASHES:
            raise VaultError(f"hash {hash_alg.name} is not supported by the Vault signer")
        body = {"input": base64.b64encode(data).decode(), "hash_algorithm": HASHES[hash_alg.name],
                "key_version": self.version}
        if isinstance(self._pub, rsa.RSAPublicKey):
            body["signature_algorithm"] = "pkcs1v15"
        else:
            body["marshaling_algorithm"] = "asn1"
        resp = self._store.client.request("POST", f"{self._store.mount}/sign/{self.key_name}", body)
        try:
            prefix, version, b64 = resp["data"]["signature"].split(":", 2)
        except (KeyError, ValueError) as exc:
            raise VaultError("Vault returned no signature") from exc
        if prefix != "vault" or version != f"v{self.version}":
            raise VaultError(f"Vault signed with key version {version}, expected v{self.version}")
        sig = base64.b64decode(b64)
        try:
            if isinstance(self._pub, rsa.RSAPublicKey):
                self._pub.verify(sig, data, padding.PKCS1v15(), hash_alg)
            else:
                self._pub.verify(sig, data, ec.ECDSA(hash_alg))
        except InvalidSignature as exc:
            raise VaultError(f"signature from Vault key {self.key_name} v{self.version} does not verify "
                             "against the pinned public key") from exc
        return sig


class VaultTransitKeyStore:
    kind = "vault-transit"

    def __init__(self, client: VaultClient, mount: str = "transit", prefix: str = "certadillo-"):
        self.client = client
        self.mount = mount.strip("/")
        self.prefix = prefix
        self._pubs: dict[tuple[str, int], object] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings, http=None) -> "VaultTransitKeyStore":
        return cls(VaultClient.from_settings(settings, http=http), settings.vault_signer_mount,
                   settings.vault_key_prefix)

    def _key_info(self, key_name: str) -> dict:
        return self.client.request("GET", f"{self.mount}/keys/{key_name}")["data"]

    def generate(self, name: str, alg: str = "ec-p384") -> VaultTransitSigner:
        if alg not in VAULT_TYPES:
            raise VaultError(f"algorithm {alg} is not supported for Vault-held CA keys "
                             f"(use one of {', '.join(sorted(VAULT_TYPES))})")
        key_name = f"{self.prefix}{name}"
        try:
            self._key_info(key_name)
        except VaultError as exc:
            if exc.status != 404:
                raise
        else:
            raise VaultError(f"Vault key {key_name} already exists; refusing to adopt a key Certadillo did not create")
        self.client.request("POST", f"{self.mount}/keys/{key_name}",
                            {"type": VAULT_TYPES[alg], "exportable": False, "allow_plaintext_backup": False})
        info = self._key_info(key_name)
        if info.get("exportable") or info.get("allow_plaintext_backup"):
            raise VaultError(f"Vault key {key_name} was created exportable; refusing to use it")
        return self._signer(key_name, int(info["latest_version"]), info)

    def load(self, key_ref: str) -> VaultTransitSigner:
        if not key_ref.startswith(PREFIX):
            raise VaultError(f"not a Vault Transit key reference: {key_ref}")
        key_name, _, version = key_ref[len(PREFIX):].rpartition(":")
        return self._signer(key_name, int(version))

    def _signer(self, key_name: str, version: int, info: dict | None = None) -> VaultTransitSigner:
        with self._lock:
            pub = self._pubs.get((key_name, version))
        if pub is None:
            info = info or self._key_info(key_name)
            entry = (info.get("keys") or {}).get(str(version))
            if not entry or not entry.get("public_key"):
                raise VaultError(f"Vault key {key_name} has no version {version} (trimmed or never existed)")
            pub = serialization.load_pem_public_key(entry["public_key"].encode())
            with self._lock:
                self._pubs[(key_name, version)] = pub
        return VaultTransitSigner(self, key_name, version, pub)

    def health(self, key_ref: str) -> dict:
        """What an operator needs to know about one CA key: reachable, the pinned
        version still present, and not exportable."""
        key_name, _, version = key_ref[len(PREFIX):].rpartition(":")
        info = self._key_info(key_name)
        return {"key": key_name, "version": int(version), "latest_version": info.get("latest_version"),
                "exportable": bool(info.get("exportable")), "deletion_allowed": bool(info.get("deletion_allowed")),
                "version_present": str(version) in (info.get("keys") or {})}
