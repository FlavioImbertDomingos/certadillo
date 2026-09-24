"""Encryption for secret columns.

Some secrets must be stored in a form the application can read back: an ACME
EAB HMAC key is needed to verify the client's MAC, a CMP shared secret to
compute one, a team's webhook URL (which is itself a bearer credential for Slack
and similar) to deliver alerts. They are encrypted with a key that is not in
the database, so a database dump or a stolen backup does not reveal them.

Two key sources:

- local: a key derived from CERTADILLO_KEY_PASSPHRASE with HKDF. Protects the
  database and its backups; does not protect against someone who also has the
  passphrase.
- vault: HashiCorp Vault's Transit engine. The key never leaves Vault; each
  encrypt and decrypt is an API call that Vault authorizes and audits, and
  access can be cut centrally.

Stored values carry their scheme, so the key source can change without a
flag day: "enc:v1:local:<fernet token>" or "enc:v1:vault:<key>:<vault:v1:...>".
Values without the prefix are legacy plaintext and are encrypted by
backfill_encrypted_fields() at startup.
"""
from __future__ import annotations

import base64
import logging

import httpx

log = logging.getLogger("certadillo.fieldcipher")

PREFIX = "enc:v1:"


class CipherError(Exception):
    pass


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)


class FieldCipher:
    def __init__(self, settings, http: httpx.Client | None = None):
        self.mode = (settings.field_cipher or "local").lower()
        self._settings = settings
        self._http = http
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"certadillo-fields",
                   info=b"v1").derive(settings.key_passphrase.encode())
        self._local = Fernet(base64.urlsafe_b64encode(key))
        self._vault_client = None
        if self.mode == "vault":
            from certadillo.crypto.vault import VaultClient, VaultError

            try:
                self._vault_client = VaultClient.from_settings(settings, http=http)
            except VaultError as exc:
                raise CipherError(f"CERTADILLO_FIELD_CIPHER=vault: {exc}") from exc

    # ------------------------------------------------------------------ vault transit
    def _vault(self, op: str, key: str, body: dict) -> dict:
        from certadillo.crypto.vault import VaultError

        try:
            return self._vault_client.request("POST", f"{self._settings.vault_transit_mount}/{op}/{key}", body)["data"]
        except (VaultError, KeyError) as exc:
            raise CipherError(f"Vault Transit {op} failed: {exc}") from exc

    # ------------------------------------------------------------------ api
    def encrypt(self, plaintext: str | bytes) -> str:
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        if self.mode == "vault":
            key = self._settings.vault_transit_key
            ct = self._vault("encrypt", key, {"plaintext": base64.b64encode(data).decode()})["ciphertext"]
            return f"{PREFIX}vault:{key}:{ct}"
        return f"{PREFIX}local:{self._local.encrypt(data).decode()}"

    def decrypt(self, value: str) -> bytes:
        if not is_encrypted(value):
            raise CipherError("value is not encrypted")
        scheme, _, rest = value[len(PREFIX):].partition(":")
        if scheme == "local":
            from cryptography.fernet import InvalidToken

            try:
                return self._local.decrypt(rest.encode())
            except InvalidToken as exc:
                raise CipherError("local field key does not decrypt this value") from exc
        if scheme == "vault":
            key, _, ct = rest.partition(":")
            return base64.b64decode(self._vault("decrypt", key, {"ciphertext": ct})["plaintext"])
        raise CipherError(f"unknown field cipher scheme {scheme!r}")

    def decrypt_str(self, value: str) -> str:
        return self.decrypt(value).decode()


_cache: dict[int, FieldCipher] = {}


def get_cipher(settings) -> FieldCipher:
    c = _cache.get(id(settings))
    if c is None:
        c = _cache[id(settings)] = FieldCipher(settings)
    return c


def set_cipher(settings, cipher: FieldCipher) -> None:
    """Tests: inject a cipher (for example one backed by a mocked Vault)."""
    _cache[id(settings)] = cipher


def backfill_encrypted_fields(platform) -> dict:
    """Encrypt legacy plaintext secrets written before field encryption existed.
    Idempotent; a failure (for example Vault unreachable) is logged, not fatal."""
    from certadillo.db import AcmeEab, CmpSecret, Team

    done = {"eab": 0, "cmp": 0, "webhook": 0}
    try:
        cipher = platform.cipher
        s = platform.s
        for e in s.query(AcmeEab).filter(AcmeEab.hmac_key_enc.is_(None)):
            if e.hmac_key_b64:
                e.hmac_key_enc, e.hmac_key_b64 = cipher.encrypt(e.hmac_key_b64), ""
                done["eab"] += 1
        for t in s.query(Team).filter(Team.webhook_enc.is_(None), Team.webhook_url.isnot(None)):
            t.webhook_enc, t.webhook_url = cipher.encrypt(t.webhook_url), None
            done["webhook"] += 1
        for c in s.query(CmpSecret):
            if not is_encrypted(c.secret_enc):
                c.secret_enc = cipher.encrypt(platform._legacy_cmp_box().decrypt(c.secret_enc.encode()))
                done["cmp"] += 1
        s.flush()
    except Exception as exc:  # noqa: BLE001 - never block startup on this; the error is logged
        log.error("could not encrypt legacy secret columns: %s", exc)
    if any(done.values()):
        log.info("encrypted legacy secret columns", extra=done)
    return done
