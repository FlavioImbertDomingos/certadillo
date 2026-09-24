"""Local certificate authority: hierarchy, issuance, revocation, CRL."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from certadillo.crypto.signers import SoftwareKeyStore, sign_x509
from certadillo.observability.metrics import CRL_GENERATED
from certadillo.db import Certificate, CertificateAuthority, as_utc
from certadillo.policy.engine import EKU, Decision, describe_key

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
}


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_row_fields(cert: x509.Certificate) -> dict:
    ktype, bits, _ = describe_key(cert.public_key())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(n.value) for n in san]
    except x509.ExtensionNotFound:
        sans = []
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return dict(
        serial_hex=format(cert.serial_number, "x"),
        fingerprint_sha256=fingerprint(cert),
        issuer=cert.issuer.rfc4514_string(),
        common_name=cn[0].value if cn else (sans[0] if sans else ""),
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=ktype,
        key_size=bits,
        sig_alg=cert.signature_algorithm_oid._name,
        pem=pem(cert),
    )


class CAService:
    def __init__(self, session, keystore, settings, policies: dict, ocsp_keystore: SoftwareKeyStore | None = None):
        self.s = session
        self.policies = policies
        self.keystore = keystore
        self.settings = settings
        # OCSP delegated responder keys stay in software: short-lived, low value,
        # and signed by the HSM-held issuing CA (RFC 6960 section 4.2.2.2).
        self.ocsp_keystore = ocsp_keystore or SoftwareKeyStore(settings.data_dir / "ocsp-keys", settings.key_passphrase)

    # ------------------------------------------------------------------ hierarchy
    def get(self, name: str) -> CertificateAuthority:
        ca = self.s.query(CertificateAuthority).filter_by(name=name).one_or_none()
        if ca is None:
            raise LookupError(f"CA {name} not found")
        return ca

    def default_issuing(self) -> CertificateAuthority:
        """Newest CA that issues end-entity certificates (pathlen 0)."""
        for ca in self.s.query(CertificateAuthority).filter_by(is_root=False).order_by(CertificateAuthority.id.desc()):
            if path_length(ca) == 0:
                return ca
        raise LookupError("no issuing CA; run `certadillo init`")

    def check_can_sign_ca(self, parent: CertificateAuthority) -> int | None:
        """Return the parent's pathlen, refusing parents that cannot have sub-CAs."""
        pl = path_length(parent)
        if pl == 0:
            raise ValueError(f"CA {parent.name} has pathlen 0 and cannot issue subordinate CAs")
        return pl

    def signer_for(self, ca: CertificateAuthority):
        return self.keystore.load(ca.key_ref)

    def _name(self, cn: str) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.settings.org_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Digital Certificate Services"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

    def create_root(self, name: str = "root-ca", years: int = 20, alg: str = "ec-p384") -> CertificateAuthority:
        signer = self.keystore.generate(name, alg)
        subject = self._name(f"{self.settings.org_name} Root CA")
        now = datetime.now(timezone.utc)
        pub = signer.public_key()
        b = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365 * years))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        )
        cert = sign_x509(b, signer)
        ca = CertificateAuthority(
            name=name,
            subject=subject.rfc4514_string(),
            cert_pem=pem(cert),
            key_ref=signer.key_ref,
            signer_type=signer.kind,
            is_root=True,
        )
        self.s.add(ca)
        self.s.flush()
        return ca

    def create_subordinate(
        self, parent: CertificateAuthority, name: str, years: int = 5, alg: str = "ec-p384", path_length: int = 0
    ) -> CertificateAuthority:
        parent_pl = self.check_can_sign_ca(parent)
        if parent_pl is not None:
            path_length = min(path_length, parent_pl - 1)
        parent_cert = x509.load_pem_x509_certificate(parent.cert_pem.encode())
        parent_signer = self.signer_for(parent)
        signer = self.keystore.generate(name, alg)
        subject = self._name(f"{self.settings.org_name} Issuing CA {name}")
        now = datetime.now(timezone.utc)
        pub = signer.public_key()
        not_after = min(now + timedelta(days=365 * years), parent_cert.not_valid_after_utc)
        b = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(parent_cert.subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key()), critical=False
            )
            .add_extension(self._cdp(parent.name), critical=False)
        )
        cert = sign_x509(b, parent_signer)
        ca = CertificateAuthority(
            name=name,
            parent_id=parent.id,
            subject=subject.rfc4514_string(),
            cert_pem=pem(cert),
            key_ref=signer.key_ref,
            signer_type=signer.kind,
            is_root=False,
        )
        self.s.add(ca)
        self.s.flush()
        self.rotate_ocsp_signer(ca)
        return ca

    def rotate_ocsp_signer(self, ca: CertificateAuthority, days: int = 30) -> None:
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        label = f"ocsp-{ca.name}-{int(datetime.now().timestamp())}"
        osigner = self.ocsp_keystore.generate(label, "ec-p256")
        now = datetime.now(timezone.utc)
        b = (
            x509.CertificateBuilder()
            .subject_name(self._name(f"OCSP Responder {ca.name}"))
            .issuer_name(ca_cert.subject)
            .public_key(osigner.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
            .add_extension(x509.OCSPNoCheck(), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
            )
        )
        cert = sign_x509(b, self.signer_for(ca))
        ca.ocsp_cert_pem = pem(cert)
        ca.ocsp_key_ref = osigner.key_ref

    def ensure_scep_ra(self, ca: CertificateAuthority):
        """RSA registration-authority certificate for SCEP. SCEP clients encrypt
        their request to it and it signs the CertRep; EC keys cannot do the
        key transport SCEP needs, so it is RSA even when the CA is EC."""
        now = datetime.now(timezone.utc)
        if ca.scep_ra_cert_pem:
            cert = x509.load_pem_x509_certificate(ca.scep_ra_cert_pem.encode())
            if cert.not_valid_after_utc - now > timedelta(days=30):
                return cert, self.ocsp_keystore.load(ca.scep_ra_key_ref).private_key
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        label = f"scep-ra-{ca.name}-{int(now.timestamp())}"
        rsigner = self.ocsp_keystore.generate(label, "rsa-3072")
        b = (
            x509.CertificateBuilder()
            .subject_name(self._name(f"SCEP RA {ca.name}"))
            .issuer_name(ca_cert.subject)
            .public_key(rsigner.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(min(now + timedelta(days=365), ca_cert.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        )
        cert = sign_x509(b, self.signer_for(ca))
        ca.scep_ra_cert_pem = pem(cert)
        ca.scep_ra_key_ref = rsigner.key_ref
        self.s.flush()
        return cert, rsigner.private_key

    def ensure_cmp_ra(self, ca: CertificateAuthority):
        """EC P-256 certificate that signs CMP responses, with the id-kp-cmcRA
        extended key usage RFC 9483 section 3.1 expects on a CMP protection
        certificate that is not the CA itself."""
        now = datetime.now(timezone.utc)
        if ca.cmp_ra_cert_pem:
            cert = x509.load_pem_x509_certificate(ca.cmp_ra_cert_pem.encode())
            if cert.not_valid_after_utc - now > timedelta(days=30):
                return cert, self.ocsp_keystore.load(ca.cmp_ra_key_ref).private_key
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        signer = self.ocsp_keystore.generate(f"cmp-ra-{ca.name}-{int(now.timestamp())}", "ec-p256")
        b = (
            x509.CertificateBuilder()
            .subject_name(self._name(f"CMP RA {ca.name}"))
            .issuer_name(ca_cert.subject)
            .public_key(signer.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(min(now + timedelta(days=365), ca_cert.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.28")]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(signer.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        )
        cert = sign_x509(b, self.signer_for(ca))
        ca.cmp_ra_cert_pem = pem(cert)
        ca.cmp_ra_key_ref = signer.key_ref
        self.s.flush()
        return cert, signer.private_key

    def chain(self, ca: CertificateAuthority) -> list[x509.Certificate]:
        out = []
        node = ca
        while node is not None:
            out.append(x509.load_pem_x509_certificate(node.cert_pem.encode()))
            node = self.s.get(CertificateAuthority, node.parent_id) if node.parent_id else None
        return out

    # ------------------------------------------------------------------ issuance
    def _cdp(self, ca_name: str) -> x509.CRLDistributionPoints:
        url = f"{self.settings.base_url}/pki/crl/{ca_name}.crl"
        return x509.CRLDistributionPoints(
            [x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, None)]
        )

    def issue(
        self,
        csr: x509.CertificateSigningRequest,
        decision: Decision,
        ca: CertificateAuthority | None = None,
        app_id: int | None = None,
    ) -> Certificate:
        ca = ca or self.default_issuing()
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        pub = csr.public_key()
        now = datetime.now(timezone.utc)
        not_after = min(now + decision.validity, ca_cert.not_valid_after_utc)
        subject_attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.settings.org_name)]
        if decision.common_name:
            subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, decision.common_name[:64]))
        san: list[x509.GeneralName] = [x509.DNSName(d) for d in decision.dns_names]
        san += [x509.UniformResourceIdentifier(u) for u in decision.uris]
        san += [x509.RFC822Name(e) for e in decision.emails]
        ekus = _profile_ekus(decision.profile, self.policies)
        eku = [EKU[e] for e in ekus]
        is_rsa = describe_key(pub)[0] == "rsa"
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(subject_attrs))
            .issuer_name(ca_cert.subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=is_rsa and "code_signing" not in ekus,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            .add_extension(self._cdp(ca.name), critical=False)
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(f"{self.settings.base_url}/pki/ocsp"),
                        ),
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(f"{self.settings.base_url}/pki/ca/{ca.name}.crt"),
                        ),
                    ]
                ),
                critical=False,
            )
        )
        if san:
            # SPIFFE: SAN is critical when the subject is empty (RFC 5280 4.2.1.6).
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=not decision.common_name)
        cert = sign_x509(b, self.signer_for(ca))
        row = Certificate(ca_id=ca.id, app_id=app_id, profile=decision.profile, source="issued", **cert_row_fields(cert))
        self.s.add(row)
        self.s.flush()
        return row

    # ------------------------------------------------------------------ revocation
    def revoke(self, row: Certificate, reason: str) -> Certificate:
        if reason not in REASONS:
            raise ValueError(f"unknown reason {reason}")
        if row.source != "issued":
            raise ValueError("only certificates issued by this platform can be revoked here")
        if row.status == "revoked":
            return row
        row.status = "revoked"
        row.revoked_at = datetime.now(timezone.utc)
        row.revocation_reason = reason
        self.s.flush()
        return row

    def generate_crl(self, ca: CertificateAuthority, next_update_hours: int = 24) -> x509.CertificateRevocationList:
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        now = datetime.now(timezone.utc)
        ca.crl_number += 1
        b = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(hours=next_update_hours))
            .add_extension(x509.CRLNumber(ca.crl_number), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        )
        revoked = self.s.query(Certificate).filter_by(ca_id=ca.id, status="revoked").all()
        for r in revoked:
            rc = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(r.serial_hex, 16))
                .revocation_date(as_utc(r.revoked_at))
                .add_extension(x509.CRLReason(REASONS[r.revocation_reason or "unspecified"]), critical=False)
                .build()
            )
            b = b.add_revoked_certificate(rc)
        crl = sign_x509(b, self.signer_for(ca))
        ca.crl_last_generated = now
        ca.crl_der = crl.public_bytes(serialization.Encoding.DER)
        self.s.flush()
        CRL_GENERATED.labels(ca=ca.name).inc()
        return crl

    def current_crl(self, ca: CertificateAuthority) -> bytes:
        """Serve the published CRL; only re-sign when none exists or it is past nextUpdate."""
        if ca.crl_der:
            crl = x509.load_der_x509_crl(ca.crl_der)
            if crl.next_update_utc and crl.next_update_utc > datetime.now(timezone.utc):
                return ca.crl_der
        self.generate_crl(ca, next_update_hours=24 * 30 if ca.is_root else 24)
        return ca.crl_der


def path_length(ca: CertificateAuthority) -> int | None:
    cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _profile_ekus(profile: str, policies: dict) -> list[str]:
    return policies.get("profiles", {}).get(profile, {}).get("extended_key_usage", ["server_auth"])


def spki_sha256(cert_or_csr) -> str:
    der = cert_or_csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def is_ec(pub) -> bool:
    return isinstance(pub, ec.EllipticCurvePublicKey)
