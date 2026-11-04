"""Offline root ceremony.

The root key never touches the Certadillo server. The ceremony has two sides:

On the server (an admin workstation with the server's configuration):

    certadillo ca offline-csr --name issuing-ca-1 ...       key in the HSM / Vault, CSR out
    certadillo ca import-issuing --name issuing-ca-1 ...    signed certificate and root in
    certadillo ca import-crl --ca root-ca root.crl          the root's CRL, twice a year

On the offline machine (air-gapped, no database, no network):

    certadillo offline-root init --dir /media/root-ca ...   root key and self-signed certificate
    certadillo offline-root sign --dir ... --csr ...        signs the issuing CA
    certadillo offline-root crl  --dir ...                  signs the root CRL

Any other offline tooling (an offline HSM, openssl ca, a commercial ceremony
tool) works too: the server only checks what it is given. The checks are the
point: the issuing certificate must carry the key the server generated, be
signed by the root it came with, be a CA that can sign certificates, and keep
the name constraints the server is configured to require.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

OFFLINE = "offline"
_NAME = re.compile(r"[a-z0-9-]{3,60}")


class CeremonyError(ValueError):
    pass


def _fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _pending_dir(settings) -> Path:
    d = Path(settings.data_dir) / "ceremony"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


# ------------------------------------------------------------------ server side
def prepare_issuing(p, name: str, alg: str = "ec-p384", operator: str = "", witness: str = "") -> str:
    """Generate the issuing CA key where CA keys live (HSM, Vault, or the
    software store) and return a CSR for the offline root to sign."""
    from certadillo.audit.log import record
    from certadillo.crypto.signers import sign_x509
    from certadillo.db import CertificateAuthority

    _check_people(operator, witness)
    if not _NAME.fullmatch(name):
        raise CeremonyError("CA names are 3-60 lowercase letters, digits and hyphens")
    if p.s.query(CertificateAuthority).filter_by(name=name).first():
        raise CeremonyError(f"a CA named {name} already exists")
    pending = _pending_dir(p.settings) / f"{name}.json"
    if pending.exists():
        raise CeremonyError(f"a ceremony for {name} is already open ({pending}); import its certificate first")
    signer = p.ca.keystore.generate(name, alg)
    b = (x509.CertificateSigningRequestBuilder()
         .subject_name(p.ca._name(f"{p.settings.org_name} Issuing CA {name}"))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True))
    nc = p.ca._name_constraints()
    if nc is not None:
        b = b.add_extension(nc, critical=True)
    csr = sign_x509(b, signer)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    state = {"name": name, "key_ref": signer.key_ref, "signer": signer.kind, "alg": alg, "csr_pem": csr_pem,
             "spki_sha256": hashlib.sha256(_spki(signer.public_key())).hexdigest(),
             "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "operator": operator, "witness": witness}
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=2)
    record(p.s, f"ceremony:{operator}", "ca.offline.csr", name,
           {"key_ref": signer.key_ref, "signer": signer.kind, "operator": operator, "witness": witness,
            "spki_sha256": state["spki_sha256"]})
    return csr_pem


def import_issuing(p, name: str, cert_pem: str, root_pem: str, operator: str = "", witness: str = "",
                   root_name: str = "root-ca") -> dict:
    """Check the certificate the offline root signed and make it a working
    issuing CA under a root whose key Certadillo does not hold."""
    from certadillo.audit.log import record
    from certadillo.db import CertificateAuthority

    _check_people(operator, witness)
    pending = _pending_dir(p.settings) / f"{name}.json"
    if not pending.exists():
        raise CeremonyError(f"no open ceremony for {name}; start with `certadillo ca offline-csr`")
    state = json.loads(pending.read_text())
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        root = x509.load_pem_x509_certificate(root_pem.encode())
    except ValueError as exc:
        raise CeremonyError(f"not a PEM certificate: {exc}") from None
    now = datetime.now(timezone.utc)

    # the root: self-signed, a CA, able to sign certificates, in its validity period
    if root.subject != root.issuer:
        raise CeremonyError("the root certificate is not self-signed")
    try:
        root.verify_directly_issued_by(root)
    except Exception:  # noqa: BLE001 - InvalidSignature, ValueError, TypeError all mean the same here
        raise CeremonyError("the root certificate's self-signature does not verify") from None
    _check_ca(root, "root", now)

    # the issuing CA: carries our key, signed by that root, a CA with pathlen 0
    signer = p.ca.keystore.load(state["key_ref"])
    if _spki(cert.public_key()) != _spki(signer.public_key()):
        raise CeremonyError("the certificate does not carry the key generated for this ceremony")
    if cert.issuer != root.subject:
        raise CeremonyError("the certificate was not issued by this root (issuer name differs)")
    try:
        cert.verify_directly_issued_by(root)
    except Exception:  # noqa: BLE001
        raise CeremonyError("the certificate's signature does not verify with the root's key") from None
    _check_ca(cert, "issuing CA", now)
    bc = _ext(cert, x509.BasicConstraints)
    if bc.path_length != 0:
        raise CeremonyError("an issuing CA must have pathLenConstraint 0, so it cannot create further CAs")
    if cert.not_valid_after_utc > root.not_valid_after_utc:
        raise CeremonyError("the issuing CA outlives its root")
    wanted = p.ca._name_constraints()
    if wanted is not None:
        got = _ext(cert, x509.NameConstraints)
        if got != wanted:
            raise CeremonyError("the certificate does not carry the name constraints this server requires "
                                "(CERTADILLO_CA_PERMITTED_DNS / _EXCLUDED_DNS / _PERMITTED_EMAIL)")
    if p.s.query(CertificateAuthority).filter_by(name=name).first():
        raise CeremonyError(f"a CA named {name} already exists")

    # the root row: known by fingerprint, never with a key
    root_fp = _fp(root)
    root_row = p.s.query(CertificateAuthority).filter_by(name=root_name).one_or_none()
    if root_row is not None:
        if _fp(x509.load_pem_x509_certificate(root_row.cert_pem.encode())) != root_fp:
            raise CeremonyError(f"a different CA named {root_name} already exists")
    else:
        root_row = CertificateAuthority(name=root_name, subject=root.subject.rfc4514_string(),
                                        cert_pem=root.public_bytes(serialization.Encoding.PEM).decode(),
                                        key_ref=f"{OFFLINE}:{root_fp}", signer_type=OFFLINE, is_root=True)
        p.s.add(root_row)
        p.s.flush()
    ca = CertificateAuthority(name=name, parent_id=root_row.id, subject=cert.subject.rfc4514_string(),
                              cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
                              key_ref=state["key_ref"], signer_type=state["signer"], is_root=False)
    p.s.add(ca)
    p.s.flush()
    p.ca.signer_for(ca)  # key and certificate match through the real signer path
    p.ca.rotate_ocsp_signer(ca)
    p.ca.generate_crl(ca)
    record(p.s, f"ceremony:{operator}", "ca.offline.import", name,
           {"root": root_name, "root_sha256": root_fp, "sha256": _fp(cert), "key_ref": state["key_ref"],
            "operator": operator, "witness": witness, "prepared_by": state.get("operator")})
    pending.rename(pending.with_suffix(".imported"))
    return {"issuing": name, "sha256": _fp(cert), "root": root_name, "root_sha256": root_fp,
            "not_after": cert.not_valid_after_utc.isoformat(), "signer": state["signer"]}


def import_crl(p, ca_name: str, data: bytes, actor: str = "system") -> dict:
    """Accept a CRL signed offline for an offline CA. It must verify with the
    CA's key, name the CA as issuer, move the CRL number forward and still be
    current, so an old CRL cannot be replayed to un-revoke something."""
    from certadillo.audit.log import record

    ca = p.ca.get(ca_name)
    if ca.signer_type != OFFLINE:
        raise CeremonyError(f"{ca_name} signs its own CRLs; only offline CAs take an imported CRL")
    try:
        crl = x509.load_pem_x509_crl(data) if b"-----BEGIN" in data else x509.load_der_x509_crl(data)
    except ValueError as exc:
        raise CeremonyError(f"not a CRL: {exc}") from None
    cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    if crl.issuer != cert.subject or not crl.is_signature_valid(cert.public_key()):
        raise CeremonyError(f"the CRL is not signed by {ca_name}")
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        raise CeremonyError("the CRL has no CRL number") from None
    if number <= (ca.crl_number or 0):
        raise CeremonyError(f"CRL number {number} is not newer than the current {ca.crl_number}")
    now = datetime.now(timezone.utc)
    if crl.next_update_utc is None or crl.next_update_utc <= now:
        raise CeremonyError("the CRL is already past its nextUpdate")
    ca.crl_number = number
    ca.crl_der = crl.public_bytes(serialization.Encoding.DER)
    ca.crl_last_generated = crl.last_update_utc
    p.s.flush()
    revoked = [format(r.serial_number, "x") for r in crl]
    record(p.s, actor, "ca.crl.import", ca_name,
           {"crl_number": number, "next_update": crl.next_update_utc.isoformat(), "revoked": revoked})
    return {"ca": ca_name, "crl_number": number, "next_update": crl.next_update_utc.isoformat(),
            "revoked": len(revoked)}


def _check_ca(cert: x509.Certificate, what: str, now: datetime) -> None:
    bc = _ext(cert, x509.BasicConstraints)
    if bc is None or not bc.ca:
        raise CeremonyError(f"the {what} certificate is not a CA (BasicConstraints cA is not set)")
    ku = _ext(cert, x509.KeyUsage)
    if ku is None or not ku.key_cert_sign or not ku.crl_sign:
        raise CeremonyError(f"the {what} certificate lacks keyCertSign and cRLSign")
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise CeremonyError(f"the {what} certificate is not in its validity period")


def _check_people(operator: str, witness: str) -> None:
    if not operator.strip() or not witness.strip():
        raise CeremonyError("a ceremony needs an operator and a witness")
    if operator.strip().lower() == witness.strip().lower():
        raise CeremonyError("the witness must be a different person")


# ------------------------------------------------------------------ offline side
# Runs on an air-gapped machine with nothing but this package installed. State
# is a directory (removable media): the encrypted root key, its certificate, and
# two append-only logs of what was signed and revoked.
def _key_pw(passphrase: str) -> bytes:
    if len(passphrase) < 16:
        raise CeremonyError("the root key passphrase must be at least 16 characters")
    return passphrase.encode()


def offline_init(directory: Path, org: str, passphrase: str, years: int = 20, alg: str = "ec-p384",
                 country: str = "US") -> dict:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "root.key.pem").exists():
        raise CeremonyError(f"{directory} already holds a root key")
    key = {"ec-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
           "rsa-4096": lambda: rsa.generate_private_key(65537, 4096)}.get(alg)
    if key is None:
        raise CeremonyError("root key algorithm must be ec-p384 or rsa-4096")
    key = key()
    pw = _key_pw(passphrase)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Digital Certificate Services"),
                         x509.NameAttribute(NameOID.COMMON_NAME, f"{org} Root CA")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365 * years))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ku(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA384()))
    fd = os.open(directory / "root.key.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.BestAvailableEncryption(pw)))
    (directory / "root.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "crlnumber").write_text("0\n")
    _log(directory / "signed.jsonl", {"event": "root", "serial": format(cert.serial_number, "x"),
                                      "sha256": _fp(cert), "subject": cert.subject.rfc4514_string()})
    return {"root": str(directory / "root.pem"), "sha256": _fp(cert),
            "not_after": cert.not_valid_after_utc.isoformat()}


def offline_sign(directory: Path, csr_pem: str, passphrase: str, years: int = 5, crl_url: str | None = None) -> str:
    directory = Path(directory)
    key, root = _load_root(directory, passphrase)
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise CeremonyError("the CSR's signature does not verify (it was changed or corrupted)")
    now = datetime.now(timezone.utc)
    not_after = min(now + timedelta(days=365 * years), root.not_valid_after_utc)
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(root.subject)
         .public_key(csr.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(minutes=5)).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(_ku(), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False))
    if crl_url:
        b = b.add_extension(x509.CRLDistributionPoints(
            [x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]), critical=False)
    # carry the name constraints the server asked for; nothing else from the CSR
    for ext in csr.extensions:
        if ext.oid == ExtensionOID.NAME_CONSTRAINTS:
            b = b.add_extension(ext.value, critical=True)
    cert = b.sign(key, hashes.SHA384())
    _log(directory / "signed.jsonl", {"event": "sign", "serial": format(cert.serial_number, "x"),
                                      "sha256": _fp(cert), "subject": cert.subject.rfc4514_string(),
                                      "not_after": not_after.isoformat()})
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def offline_revoke(directory: Path, serial_hex: str, reason: str = "superseded") -> None:
    directory = Path(directory)
    signed = {e["serial"] for e in _read_log(directory / "signed.jsonl") if e["event"] == "sign"}
    serial = serial_hex.lower().lstrip("0") or "0"
    if serial not in {s.lstrip("0") for s in signed}:
        raise CeremonyError(f"serial {serial_hex} was not signed by this root")
    if reason not in _REASONS:
        raise CeremonyError(f"reason must be one of {', '.join(_REASONS)}")
    _log(directory / "revoked.jsonl", {"serial": serial, "reason": reason})


def offline_crl(directory: Path, passphrase: str, days: int = 180) -> bytes:
    directory = Path(directory)
    key, root = _load_root(directory, passphrase)
    number = int((directory / "crlnumber").read_text().strip() or 0) + 1
    now = datetime.now(timezone.utc)
    b = (x509.CertificateRevocationListBuilder().issuer_name(root.subject).last_update(now)
         .next_update(now + timedelta(days=days))
         .add_extension(x509.CRLNumber(number), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False))
    for e in _read_log(directory / "revoked.jsonl"):
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(int(e["serial"], 16))
            .revocation_date(datetime.fromisoformat(e["at"]))
            .add_extension(x509.CRLReason(_REASONS[e["reason"]]), critical=False).build())
    crl = b.sign(key, hashes.SHA384())
    (directory / "crlnumber").write_text(f"{number}\n")
    return crl.public_bytes(serialization.Encoding.PEM)


_REASONS = {"unspecified": x509.ReasonFlags.unspecified, "key_compromise": x509.ReasonFlags.key_compromise,
            "ca_compromise": x509.ReasonFlags.ca_compromise, "superseded": x509.ReasonFlags.superseded,
            "cessation_of_operation": x509.ReasonFlags.cessation_of_operation}


def _ku() -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                         encipher_only=False, decipher_only=False)


def _load_root(directory: Path, passphrase: str):
    try:
        key = serialization.load_pem_private_key((directory / "root.key.pem").read_bytes(), _key_pw(passphrase))
    except FileNotFoundError:
        raise CeremonyError(f"no root key in {directory}; run `certadillo offline-root init` first") from None
    except (ValueError, TypeError):
        raise CeremonyError("wrong passphrase for the root key") from None
    return key, x509.load_pem_x509_certificate((directory / "root.pem").read_bytes())


def _log(path: Path, entry: dict) -> None:
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
