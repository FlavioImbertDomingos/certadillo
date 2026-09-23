"""OpenSSH certificate authority for user and host certificates.

Short-lived SSH certificates replace static authorized_keys files: hosts
trust the CA public key (TrustedUserCAKeys) and users get certificates
that expire in hours."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import ssh

from certadillo.crypto.signers import SoftwareKeyStore
from certadillo.db import SSHCertificate
from certadillo.policy.engine import PolicyError

USER_EXTENSIONS = [b"permit-pty", b"permit-port-forwarding", b"permit-agent-forwarding"]


class SSHCA:
    KEY_NAME = "ssh-ca"

    def __init__(self, session, settings, policies: dict):
        self.s = session
        self.policies = policies.get("ssh", {})
        self.store = SoftwareKeyStore(settings.data_dir / "ssh-ca", settings.key_passphrase)

    def _key(self):
        try:
            return self.store.load(f"file:{self.KEY_NAME}").private_key
        except FileNotFoundError:
            return self.store.generate(self.KEY_NAME, "ed25519").private_key

    def public_key_line(self) -> str:
        pub = self._key().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        return pub.decode() + " certadillo-ssh-ca"

    def issue(
        self,
        public_key_line: str,
        cert_type: str,
        principals: list[str],
        key_id: str,
        hours: int | None = None,
        days: int | None = None,
        app_id: int | None = None,
        source_address: str | None = None,
    ) -> SSHCertificate:
        if cert_type not in ("user", "host"):
            raise PolicyError([("ssh_type", "cert_type must be user or host")])
        if not principals:
            raise PolicyError([("ssh_principals", "at least one principal is required")])
        pol = self.policies.get(cert_type, {})
        if cert_type == "user":
            h = hours or pol.get("default_validity_hours", 8)
            if h > pol.get("max_validity_hours", 24):
                raise PolicyError([("validity", f"{h}h exceeds {pol.get('max_validity_hours')}h")])
            validity = timedelta(hours=h)
        else:
            d = days or pol.get("default_validity_days", 30)
            if d > pol.get("max_validity_days", 90):
                raise PolicyError([("validity", f"{d}d exceeds {pol.get('max_validity_days')}d")])
            validity = timedelta(days=d)

        pub = ssh.load_ssh_public_key(public_key_line.encode())
        now = datetime.now(timezone.utc)
        serial = secrets.randbits(63)
        b = (
            ssh.SSHCertificateBuilder()
            .public_key(pub)
            .serial(serial)
            .type(ssh.SSHCertificateType.USER if cert_type == "user" else ssh.SSHCertificateType.HOST)
            .key_id(key_id.encode())
            .valid_principals([p.encode() for p in principals])
            .valid_after(int((now - timedelta(minutes=2)).timestamp()))
            .valid_before(int((now + validity).timestamp()))
        )
        if cert_type == "user":
            for ext in USER_EXTENSIONS:
                b = b.add_extension(ext, b"")
            if source_address:
                b = b.add_critical_option(b"source-address", source_address.encode())
        cert = b.sign(self._key())
        text = cert.public_bytes().decode()
        raw = pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        row = SSHCertificate(
            serial=serial,
            key_id=key_id,
            cert_type=cert_type,
            principals=principals,
            app_id=app_id,
            public_key_fp="SHA256:" + hashlib.sha256(raw).hexdigest(),
            valid_after=now,
            valid_before=now + validity,
            cert_text=text,
        )
        self.s.add(row)
        self.s.flush()
        return row
