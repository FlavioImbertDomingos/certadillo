"""The host agent: find certificates and keystores on a server's disks and
report the public certificates to Certadillo.

It looks for PEM and DER certificates, PKCS#12 files (with the passwords it is
given, and an empty one), Java keystores (through keytool, with the passwords
it is given), and on Windows the system certificate stores. Private key files
are reported only as a path, owner and permission bits, so Certadillo can flag
keys other users can read; key material never leaves the host.

    certadillo agent scan --server https://pki.bank.internal --api-key-file /etc/certadillo/agent.key
"""
from __future__ import annotations

import os
import shutil
import ssl
import stat
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

DEFAULT_PATHS = ["/etc/ssl", "/etc/pki", "/etc/nginx", "/etc/httpd", "/etc/apache2", "/etc/haproxy",
                 "/etc/letsencrypt/live", "/opt", "/usr/local/etc", "/srv"]
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/usr/share/ca-certificates",
             "/etc/ssl/certs", "/etc/pki/ca-trust", "/etc/pki/tls/certs/ca-bundle.crt"}
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".cert"}
P12_EXT = {".p12", ".pfx"}
JKS_EXT = {".jks", ".keystore", ".truststore"}
MAX_BYTES = 1_000_000


def _pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def _key_entry(path: Path) -> dict:
    st = path.stat()
    try:
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
    except (ImportError, KeyError):
        owner = str(st.st_uid)
    mode = stat.S_IMODE(st.st_mode)
    return {"path": str(path), "mode": oct(mode), "owner": owner, "world_readable": bool(mode & 0o004)}


def scan_file(path: Path, passwords: list[str]) -> tuple[list[dict], list[dict]]:
    """(certificates, key files) found in one file."""
    certs: list[dict] = []
    keys: list[dict] = []
    ext = path.suffix.lower()
    try:
        if path.stat().st_size > MAX_BYTES:
            return certs, keys
        data = path.read_bytes()
    except OSError:
        return certs, keys
    if b"-----BEGIN" in data:
        if b"PRIVATE KEY-----" in data:
            keys.append(_key_entry(path))
        if b"BEGIN CERTIFICATE" in data:
            try:
                for c in x509.load_pem_x509_certificates(data):
                    certs.append({"path": str(path), "format": "pem", "pem": _pem(c)})
            except ValueError:
                pass
    elif ext in CERT_EXT:
        try:
            certs.append({"path": str(path), "format": "der", "pem": _pem(x509.load_der_x509_certificate(data))})
        except ValueError:
            pass
    elif ext in P12_EXT:
        for pw in ["", *passwords]:
            try:
                key, cert, extra = pkcs12.load_key_and_certificates(data, pw.encode() if pw else None)
            except ValueError:
                continue
            for c in [cert, *(extra or [])]:
                if c is not None:
                    certs.append({"path": str(path), "format": "pkcs12", "pem": _pem(c)})
            if key is not None:
                keys.append(_key_entry(path))
            break
    elif ext in JKS_EXT and shutil.which("keytool"):
        keytool = shutil.which("keytool")
        for pw in passwords or ["changeit"]:
            # the password goes through the environment, not argv, so other users cannot see it in ps
            r = subprocess.run([keytool, "-list", "-rfc", "-keystore", str(path), "-storepass:env", "CDL_STOREPASS"],  # noqa: S603
                               capture_output=True, text=True, timeout=30, env={**os.environ, "CDL_STOREPASS": pw})
            if r.returncode == 0:
                for c in x509.load_pem_x509_certificates(r.stdout.encode()) if "BEGIN" in r.stdout else []:
                    certs.append({"path": str(path), "format": "jks", "pem": _pem(c)})
                if "PrivateKeyEntry" in r.stdout:
                    keys.append(_key_entry(path))
                break
    return certs, keys


def scan(paths: list[str], passwords: list[str] | None = None, windows_stores: bool = True) -> dict:
    passwords = passwords or []
    certs: list[dict] = []
    keys: list[dict] = []
    for root in paths:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if any(dirpath == s or dirpath.startswith(s + "/") for s in SKIP_DIRS):
                dirnames[:] = []
                continue
            for name in filenames:
                p = Path(dirpath) / name
                if p.is_symlink() or not p.is_file():
                    continue
                c, k = scan_file(p, passwords)
                certs += c
                keys += k
    if windows_stores and sys.platform == "win32":
        for store in ("MY", "WebHosting"):
            try:
                for der, enc, _trust in ssl.enum_certificates(store):  # type: ignore[attr-defined]
                    if enc == "x509_asn":
                        certs.append({"path": f"windows-store:{store}", "format": "der",
                                      "pem": _pem(x509.load_der_x509_certificate(der))})
            except OSError:
                continue
    # one entry per certificate and place
    unique = {(c["path"], c["pem"]): c for c in certs}
    return {"certificates": list(unique.values()), "key_files": keys}
