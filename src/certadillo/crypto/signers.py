"""Key custody. Every CA key sits behind a Signer so the rest of the code never
touches private key material directly. Swap SoftwareKeyStore for
Pkcs11KeyStore (Thales Luna, Entrust nShield, AWS CloudHSM, SoftHSM2) with a
config change."""
from __future__ import annotations

import functools
import hashlib
import threading
import time
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from certadillo.crypto.der import replace_signature
from certadillo.observability.metrics import SIGNING_SECONDS

SUPPORTED_ALGS = {"ec-p256", "ec-p384", "rsa-3072", "rsa-4096", "ed25519"}


class Signer(Protocol):
    key_ref: str
    kind: str  # software | pkcs11

    def public_key(self): ...

    def sign(self, data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes: ...

    @property
    def private_key(self): ...


class SoftwareSigner:
    kind = "software"

    def __init__(self, key_ref: str, key):
        self.key_ref = key_ref
        self._key = key

    def public_key(self):
        return self._key.public_key()

    @property
    def private_key(self):
        return self._key

    def sign(self, data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes:
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            return self._key.sign(data, ec.ECDSA(hash_alg))
        return self._key.sign(data, padding.PKCS1v15(), hash_alg)


class ExternalOnlySigner(SoftwareSigner):
    """Test double: software key that refuses to expose itself, forcing the
    HSM code path (tbs extraction + DER reassembly)."""

    kind = "external-test"

    @property
    def private_key(self):
        return None


def _generate(alg: str):
    if alg == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if alg == "ec-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if alg == "rsa-3072":
        return rsa.generate_private_key(65537, 3072)
    if alg == "rsa-4096":
        return rsa.generate_private_key(65537, 4096)
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported algorithm {alg}")


class SoftwareKeyStore:
    """Encrypted PEM files on disk. Dev and lab use only."""

    def __init__(self, directory: Path, passphrase: str):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._pw = passphrase.encode()

    def generate(self, name: str, alg: str = "ec-p384") -> SoftwareSigner:
        key = _generate(alg)
        path = self.dir / f"{name}.key.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self._pw),
            )
        )
        path.chmod(0o600)
        return SoftwareSigner(f"file:{name}", key)

    def load(self, key_ref: str) -> SoftwareSigner:
        name = key_ref.split(":", 1)[1]
        key = serialization.load_pem_private_key((self.dir / f"{name}.key.pem").read_bytes(), self._pw)
        return SoftwareSigner(key_ref, key)


class Pkcs11Signer:
    kind = "pkcs11"

    def __init__(self, store: "Pkcs11KeyStore", label: str, pub):
        self.key_ref = f"pkcs11:{label}"
        self._store = store
        self._label = label
        self._pub = pub

    def public_key(self):
        return self._pub

    @property
    def private_key(self):
        return None  # never leaves the HSM

    def sign(self, data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes:
        from pkcs11 import KeyType, Mechanism, ObjectClass
        from pkcs11.util.ec import encode_ecdsa_signature

        digest = hashes.Hash(hash_alg)
        digest.update(data)
        dgst = digest.finalize()
        with self._store.session() as s:
            if isinstance(self._pub, ec.EllipticCurvePublicKey):
                key = s.get_key(label=self._label, key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY)
                raw = key.sign(dgst, mechanism=Mechanism.ECDSA)
                return encode_ecdsa_signature(raw)
            key = s.get_key(label=self._label, key_type=KeyType.RSA, object_class=ObjectClass.PRIVATE_KEY)
            mech = {
                "sha256": Mechanism.SHA256_RSA_PKCS,
                "sha384": Mechanism.SHA384_RSA_PKCS,
                "sha512": Mechanism.SHA512_RSA_PKCS,
            }[hash_alg.name]
            return key.sign(data, mechanism=mech)


class Pkcs11KeyStore:
    """Keys generated on the token as sensitive and non-extractable."""

    _lock = threading.Lock()

    def __init__(self, lib_path: str, token_label: str, pin: str):
        import pkcs11

        self._lib = pkcs11.lib(lib_path)
        self._token = self._lib.get_token(token_label=token_label)
        self._pin = pin

    def session(self):
        return self._token.open(user_pin=self._pin, rw=True)

    def generate(self, name: str, alg: str = "ec-p384") -> Pkcs11Signer:
        from pkcs11 import Attribute, KeyType
        from pkcs11.util.ec import encode_named_curve_parameters

        priv_tmpl = {Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False, Attribute.SIGN: True,
                     Attribute.DERIVE: False, Attribute.SIGN_RECOVER: False, Attribute.DECRYPT: False,
                     Attribute.UNWRAP: False}
        with self._lock, self.session() as s:
            if alg.startswith("ec-"):
                curve = {"ec-p256": "secp256r1", "ec-p384": "secp384r1"}[alg]
                params = s.create_domain_parameters(
                    KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters(curve)}, local=True
                )
                params.generate_keypair(store=True, label=name, private_template=priv_tmpl)
            else:
                bits = int(alg.split("-")[1])
                s.generate_keypair(KeyType.RSA, bits, store=True, label=name, private_template=priv_tmpl)
        return self.load(f"pkcs11:{name}")

    def load(self, key_ref: str) -> Pkcs11Signer:
        from pkcs11 import KeyType, ObjectClass
        from pkcs11.util.ec import encode_ec_public_key
        from pkcs11.util.rsa import encode_rsa_public_key

        label = key_ref.split(":", 1)[1]
        with self.session() as s:
            try:
                pub = s.get_key(label=label, key_type=KeyType.EC, object_class=ObjectClass.PUBLIC_KEY)
                der = encode_ec_public_key(pub)
            except Exception:
                pub = s.get_key(label=label, key_type=KeyType.RSA, object_class=ObjectClass.PUBLIC_KEY)
                der = encode_rsa_public_key(pub)
                return Pkcs11Signer(self, label, serialization.load_der_public_key(_rsa_spki(der)))
        return Pkcs11Signer(self, label, serialization.load_der_public_key(der))


def _rsa_spki(pkcs1_der: bytes) -> bytes:
    """Wrap a PKCS#1 RSAPublicKey in SubjectPublicKeyInfo."""
    from certadillo.crypto.der import tlv

    alg = bytes.fromhex("300d06092a864886f70d0101010500")
    return tlv(0x30, alg + tlv(0x03, b"\x00" + pkcs1_der))


@functools.lru_cache(maxsize=8)
def _dummy_key(kind: str):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP384R1())
    return rsa.generate_private_key(65537, 2048)


def sign_x509(builder, signer: Signer, hash_alg: hashes.HashAlgorithm | None = None):
    """Sign a CertificateBuilder or CertificateRevocationListBuilder."""
    hash_alg = hash_alg or hashes.SHA384()
    start = time.perf_counter()
    try:
        if signer.private_key is not None:
            return builder.sign(signer.private_key, hash_alg)
        kind = "ec" if isinstance(signer.public_key(), ec.EllipticCurvePublicKey) else "rsa"
        tmp = builder.sign(_dummy_key(kind), hash_alg)
        is_cert = isinstance(tmp, x509.Certificate)
        tbs = tmp.tbs_certificate_bytes if is_cert else tmp.tbs_certlist_bytes
        sig = signer.sign(tbs, hash_alg)
        der = replace_signature(tmp.public_bytes(serialization.Encoding.DER), tbs, sig)
        return x509.load_der_x509_certificate(der) if is_cert else x509.load_der_x509_crl(der)
    finally:
        SIGNING_SECONDS.labels(signer=signer.kind).observe(time.perf_counter() - start)


def key_fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


class RoutingKeyStore:
    """New CA keys are generated in the configured backend (CERTADILLO_SIGNER);
    existing keys load from wherever their key_ref says they live. That lets a
    software-backed issuing CA keep working while a new one is created in an HSM
    or in Vault, so a deployment can move its CA keys without a flag day."""

    def __init__(self, settings):
        self.settings = settings
        self._stores: dict[str, object] = {}
        self._lock = threading.Lock()
        self.generator = self._store(settings.signer if settings.signer in ("pkcs11", "vault-transit") else "file")

    @property
    def kind(self) -> str:
        return getattr(self.generator, "kind", "software")

    def _store(self, scheme: str):
        with self._lock:
            if scheme not in self._stores:
                s = self.settings
                if scheme == "file":
                    self._stores[scheme] = SoftwareKeyStore(s.data_dir / "keys", s.key_passphrase)
                elif scheme == "pkcs11":
                    if not (s.pkcs11_lib and s.pkcs11_pin):
                        raise RuntimeError("CERTADILLO_PKCS11_LIB and CERTADILLO_PKCS11_PIN are required for pkcs11 keys")
                    self._stores[scheme] = Pkcs11KeyStore(s.pkcs11_lib, s.pkcs11_token, s.pkcs11_pin)
                elif scheme == "vault-transit":
                    from certadillo.crypto.vault_signer import VaultTransitKeyStore

                    self._stores[scheme] = VaultTransitKeyStore.from_settings(s)
                else:
                    raise RuntimeError(f"unknown key scheme {scheme!r}")
            return self._stores[scheme]

    def generate(self, name: str, alg: str = "ec-p384"):
        return self.generator.generate(name, alg)

    def load(self, key_ref: str):
        scheme = key_ref.split(":", 1)[0]
        return self._store(scheme).load(key_ref)

    def store_for(self, key_ref: str):
        return self._store(key_ref.split(":", 1)[0])


def build_keystore(settings):
    if settings.signer not in ("software", "pkcs11", "vault-transit"):
        raise RuntimeError(f"CERTADILLO_SIGNER must be software, pkcs11 or vault-transit, not {settings.signer!r}")
    return RoutingKeyStore(settings)
