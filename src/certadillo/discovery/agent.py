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


# ------------------------------------------------------------------ SSH keys
# Static SSH keys are the other half of machine identity: who can log in where
# with a key that never expires. The agent reports every authorized key and
# host public key with its fingerprint, type and size, the account it opens,
# its restrictions and when the file last changed. Public keys only.
SSH_TYPES = {"ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}
ECDSA_BITS = {"ecdsa-sha2-nistp256": 256, "ecdsa-sha2-nistp384": 384, "ecdsa-sha2-nistp521": 521,
              "sk-ecdsa-sha2-nistp256@openssh.com": 256}


def _ssh_strings(blob: bytes) -> list[bytes]:
    out, pos = [], 0
    while pos + 4 <= len(blob):
        n = int.from_bytes(blob[pos:pos + 4], "big")
        out.append(blob[pos + 4:pos + 4 + n])
        pos += 4 + n
    return out


def _ssh_bits(key_type: str, blob: bytes) -> int | None:
    parts = _ssh_strings(blob)
    if key_type == "ssh-rsa" and len(parts) >= 3:
        return int.from_bytes(parts[2], "big").bit_length()  # e, then n
    if key_type == "ssh-dss" and len(parts) >= 2:
        return int.from_bytes(parts[1], "big").bit_length()  # p
    if "ed25519" in key_type:
        return 256
    return ECDSA_BITS.get(key_type)


def _split_options(line: str) -> tuple[str, str]:
    """authorized_keys lines may start with options (quoted values can hold spaces)."""
    in_quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif ch in " \t" and not in_quote:
            return line[:i], line[i:].strip()
    return line, ""


def parse_ssh_key_line(line: str) -> dict | None:
    import base64
    import hashlib

    line = line.strip()
    if not line or line.startswith("#"):
        return None
    options = ""
    first = line.split(None, 1)[0]
    if first not in SSH_TYPES:
        options, line = _split_options(line)
    fields = line.split(None, 2)
    if len(fields) < 2 or fields[0] not in SSH_TYPES:
        return None
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError:
        return None
    if _ssh_strings(blob)[:1] != [fields[0].encode()]:
        return None  # the blob does not carry the type it claims
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    opts = {}
    for item in _option_items(options):
        name, _, value = item.partition("=")
        # keep the restriction, not the command line itself, which can carry secrets
        opts[name.lower()] = value.strip('"') if name.lower() in ("from", "permitopen", "principals") else bool(True)
    return {"key_type": fields[0], "bits": _ssh_bits(fields[0], blob), "fingerprint": fp,
            "comment": fields[2][:200] if len(fields) > 2 else "", "options": opts}


def _option_items(options: str) -> list[str]:
    items, cur, in_quote = [], "", False
    for ch in options:
        if ch == '"':
            in_quote = not in_quote
        if ch == "," and not in_quote:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        items.append(cur)
    return [i for i in items if i]


def _ssh_file(path: Path, kind: str, user: str | None, user_exists: bool) -> list[dict]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            return []
        text = path.read_text(errors="replace")
        mtime = path.stat().st_mtime
    except OSError:
        return []
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        k = parse_ssh_key_line(line)
        if k:
            out.append({**k, "kind": kind, "path": str(path), "line": n, "user": user,
                        "user_exists": user_exists, "file_mtime": int(mtime)})
    return out


def scan_ssh(homes: dict[str, str] | None = None, ssh_dir: str = "/etc/ssh") -> list[dict]:
    """Authorized keys for every account with a home directory, keys under
    AuthorizedKeysFile directories in /etc/ssh, and the host public keys."""
    if homes is None:
        homes = {}
        try:
            import pwd

            homes = {u.pw_name: u.pw_dir for u in pwd.getpwall() if u.pw_dir and u.pw_dir not in ("/", "/nonexistent")}
        except ImportError:
            pass
    keys: list[dict] = []
    for user, home in sorted(homes.items()):
        for name in ("authorized_keys", "authorized_keys2"):
            keys += _ssh_file(Path(home) / ".ssh" / name, "authorized", user, True)
    central = Path(ssh_dir) / "authorized_keys"
    if central.is_dir():  # AuthorizedKeysFile /etc/ssh/authorized_keys/%u
        for f in sorted(central.iterdir()):
            keys += _ssh_file(f, "authorized", f.name, f.name in homes)
    for f in sorted(Path(ssh_dir).glob("ssh_host_*_key.pub")):
        keys += _ssh_file(f, "host", None, True)
    return keys
