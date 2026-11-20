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

from certadillo.crypto.der import replace_signature, split_sequence, tlv
from certadillo.observability.metrics import SIGNING_SECONDS

try:  # ML-DSA (FIPS 204) arrived in pyca/cryptography 50
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:  # pragma: no cover - older cryptography
    mldsa = None

# Parameter sets Certadillo issues with: ML-DSA-65 (NIST category 3) and
# ML-DSA-87 (category 5, the one CNSA 2.0 asks for). ML-DSA-44 is recognised in
# requests and inventory but not offered for CA keys.
ML_DSA_CA_ALGS = ("ml-dsa-65", "ml-dsa-87")
_ML_DSA = {} if mldsa is None else {
    "ml-dsa-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    "ml-dsa-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
    "ml-dsa-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
}

SUPPORTED_ALGS = {"ec-p256", "ec-p384", "rsa-3072", "rsa-4096", "ed25519"} | (set(ML_DSA_CA_ALGS) if mldsa else set())


def ml_dsa_params(key) -> str | None:
    """'ml-dsa-65' for an ML-DSA-65 public or private key, None for anything else."""
    for name, classes in _ML_DSA.items():
        if isinstance(key, classes):
            return name
    return None


def signs_whole_message(key) -> bool:
    """Ed25519 and ML-DSA sign the message itself, with no separate hash
    algorithm: X.509 builders take None for the hash and the AlgorithmIdentifier
    has no parameters (RFC 8410, RFC 9881)."""
    return isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)) or ml_dsa_params(key) is not None


def hash_for(key, default: hashes.HashAlgorithm | None = None) -> hashes.HashAlgorithm | None:
    """The hash argument for builder.sign(key, ...) with this key."""
    return None if signs_whole_message(key) else (default or hashes.SHA384())


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

    def sign(self, data: bytes, hash_alg: hashes.HashAlgorithm | None) -> bytes:
        if signs_whole_message(self._key):
            return self._key.sign(data)
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
    if alg in _ML_DSA:
        return _ML_DSA[alg][0].generate()
    if alg.startswith("ml-dsa"):
        raise ValueError(f"{alg} needs pyca/cryptography 50 or later for ML-DSA")
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
        return self._store.retrying(lambda: self._sign(data, hash_alg))

    def _sign(self, data: bytes, hash_alg: hashes.HashAlgorithm) -> bytes:
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


class SessionPool:
    """Logged-in PKCS#11 sessions kept open and reused.

    Opening a session and logging in costs more than the signature itself on
    most network HSMs, and PKCS#11 login state belongs to the whole process:
    closing one session can log out the others. So sessions are opened once,
    lent to one thread at a time, and closed only when the HSM reports one as
    broken (a failover, a restarted appliance, an expired login). At most
    `size` sessions exist; a caller waits for a free one."""

    BROKEN = ("SessionHandleInvalid", "SessionClosed", "DeviceRemoved", "DeviceError", "TokenNotPresent",
              "UserNotLoggedIn")

    def __init__(self, opener, size: int = 4, wait_seconds: float = 30.0):
        import queue

        self._open = opener
        self.size = max(1, size)
        self._wait = wait_seconds
        self._idle: queue.LifoQueue = queue.LifoQueue()
        self._lock = threading.Lock()
        self.created = 0
        self.discarded = 0

    @classmethod
    def is_broken(cls, exc: BaseException) -> bool:
        return type(exc).__name__ in cls.BROKEN

    def _borrow(self):
        import queue

        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self.created < self.size:
                self.created += 1
                try:
                    return self._open()
                except BaseException:
                    self.created -= 1
                    raise
        try:
            return self._idle.get(timeout=self._wait)
        except queue.Empty:
            raise RuntimeError(f"no free HSM session after {self._wait:g}s (pool size {self.size})") from None

    def _discard(self, session) -> None:
        with self._lock:
            self.created -= 1
            self.discarded += 1
        try:
            session.close()
        except Exception:  # noqa: BLE001, S110 - it is already broken
            pass

    def session(self):
        import contextlib

        @contextlib.contextmanager
        def lend():
            s = self._borrow()
            try:
                yield s
            except BaseException as exc:
                if self.is_broken(exc):
                    self._discard(s)
                else:
                    self._idle.put(s)
                raise
            else:
                self._idle.put(s)

        return lend()

    def close(self) -> None:
        import queue

        while True:
            try:
                self._discard(self._idle.get_nowait())
            except queue.Empty:
                return


_LIBRARY_LOCKS: dict[str, threading.RLock] = {}


class Pkcs11KeyStore:
    """Keys generated on the token as sensitive and non-extractable.

    The logged-in session is kept open and reused (see SessionPool) instead of
    opening and logging in for every signature. Calls into the PKCS#11 library
    are serialized: python-pkcs11 initializes it with C_Initialize(NULL), and
    the PKCS#11 standard says the application must then not call it from
    several threads at once (doing so crashes SoftHSM2)."""

    _lock = threading.Lock()

    def __init__(self, lib_path: str, token_label: str, pin: str):
        import pkcs11

        self._lib = pkcs11.lib(lib_path)
        self._token = self._lib.get_token(token_label=token_label)
        self._pin = pin
        self._calls = _LIBRARY_LOCKS.setdefault(lib_path, threading.RLock())
        self.pool = SessionPool(self._open_session, size=1)

    def _open_session(self):
        """The first session logs in; PKCS#11 login covers the whole process,
        so later sessions open already logged in."""
        from pkcs11.exceptions import UserAlreadyLoggedIn

        try:
            return self._token.open(user_pin=self._pin, rw=True)
        except UserAlreadyLoggedIn:
            return self._token.open(rw=True)

    def session(self):
        import contextlib

        @contextlib.contextmanager
        def serialized():
            with self._calls, self.pool.session() as s:
                yield s

        return serialized()

    def retrying(self, fn):
        """Run fn; if the HSM dropped its session (failover, appliance restart),
        try once more on a fresh one."""
        try:
            return fn()
        except Exception as exc:
            if not SessionPool.is_broken(exc):
                raise
            return fn()

    def generate(self, name: str, alg: str = "ec-p384") -> Pkcs11Signer:
        if alg.startswith("ml-dsa"):
            # PKCS#11 3.2 defines CKM_ML_DSA, but python-pkcs11 and most HSM
            # firmware do not expose it yet. Refuse rather than fall back to software.
            raise ValueError(f"{alg} keys cannot be generated on a PKCS#11 token yet; create ML-DSA CAs "
                             "with CERTADILLO_SIGNER=software until the HSM supports PKCS#11 3.2 ML-DSA")
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
        return self.retrying(lambda: self._load(key_ref))

    def _load(self, key_ref: str) -> Pkcs11Signer:
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
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if kind in _ML_DSA:
        return _ML_DSA[kind][0].generate()
    return rsa.generate_private_key(65537, 2048)


def _dummy_kind(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ec"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519"
    return ml_dsa_params(pub) or "rsa"


def sign_x509(builder, signer: Signer, hash_alg: hashes.HashAlgorithm | None = None):
    """Sign a CertificateBuilder, CertificateSigningRequestBuilder or CertificateRevocationListBuilder."""
    from certadillo.observability import tracing

    what = type(builder).__name__.replace("Builder", "")
    with tracing.span("certadillo.sign", signer=signer.kind, object=what, key_ref=signer.key_ref):
        return _sign_x509(builder, signer, hash_alg)


def _sign_x509(builder, signer: Signer, hash_alg: hashes.HashAlgorithm | None):
    hash_alg = hash_for(signer.public_key(), hash_alg)
    start = time.perf_counter()
    try:
        if signer.private_key is not None:
            return builder.sign(signer.private_key, hash_alg)
        # The throwaway key has the same algorithm (and ML-DSA parameter set),
        # so the AlgorithmIdentifier in the to-be-signed bytes is the right one.
        tmp = builder.sign(_dummy_key(_dummy_kind(signer.public_key())), hash_alg)
        if isinstance(tmp, x509.Certificate):
            tbs, load = tmp.tbs_certificate_bytes, x509.load_der_x509_certificate
        elif isinstance(tmp, x509.CertificateSigningRequest):
            # A CSR builder takes its public key from the signing key, so the
            # throwaway key's SubjectPublicKeyInfo is in the request; put the
            # real one in before signing (RFC 2986: version, subject, spki, attrs).
            spki = signer.public_key().public_bytes(serialization.Encoding.DER,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
            info = split_sequence(tmp.tbs_certrequest_bytes)
            tbs = tlv(0x30, info[0] + info[1] + spki + b"".join(info[3:]))
            outer = split_sequence(tmp.public_bytes(serialization.Encoding.DER))
            sig = signer.sign(tbs, hash_alg)
            return x509.load_der_x509_csr(tlv(0x30, tbs + outer[1] + tlv(0x03, b"\x00" + sig)))
        else:
            tbs, load = tmp.tbs_certlist_bytes, x509.load_der_x509_crl
        sig = signer.sign(tbs, hash_alg)
        return load(replace_signature(tmp.public_bytes(serialization.Encoding.DER), tbs, sig))
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
