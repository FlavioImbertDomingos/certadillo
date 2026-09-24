"""Policy engine: one place that decides whether a request may be signed."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date, timedelta
from importlib import resources
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

EKU = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
}

# ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signature OIDs, for inventory grading.
PQC_SIG_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
PQC_SIG_OIDS.update({f"2.16.840.1.101.3.4.3.{n}": "SLH-DSA" for n in range(20, 32)})


class PolicyError(Exception):
    def __init__(self, violations: list[tuple[str, str]]):
        self.violations = violations
        super().__init__("; ".join(f"{r}: {m}" for r, m in violations))


@dataclass
class Decision:
    profile: str
    validity: timedelta
    dns_names: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    common_name: str | None = None
    dual_control: bool = False


class TemplateRequest:
    """A certificate request that is not a PKCS#10 CSR, such as a CMP/CRMF
    CertTemplate. It offers the parts of the CSR interface the policy engine
    and CA use. The protocol front end must have verified proof of
    possession before building one."""

    is_signature_valid = True

    def __init__(self, subject: x509.Name, public_key, extensions: list[x509.Extension] | None = None):
        self.subject = subject
        self._public_key = public_key
        self.extensions = x509.Extensions(extensions or [])

    def public_key(self):
        return self._public_key

    def to_payload(self) -> dict:
        import base64

        from cryptography.hazmat.primitives import serialization

        san = None
        try:
            san = self.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.public_bytes()
        except x509.ExtensionNotFound:
            pass
        spki = self._public_key.public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"subject": base64.b64encode(self.subject.public_bytes()).decode(),
                "spki": base64.b64encode(spki).decode(),
                "san": base64.b64encode(san).decode() if san else None}

    @classmethod
    def from_payload(cls, d: dict) -> "TemplateRequest":
        import base64

        from cryptography.hazmat.primitives.serialization import load_der_public_key

        exts = []
        if d.get("san"):
            san = _san_from_der(base64.b64decode(d["san"]))
            exts.append(x509.Extension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, False, san))
        return cls(name_from_der(base64.b64decode(d["subject"])), load_der_public_key(base64.b64decode(d["spki"])), exts)


def name_from_der(der: bytes) -> x509.Name:
    """cryptography has no public parser for a bare Name; wrap it in a throwaway CSR."""
    return _parse_via_csr(subject_der=der).subject


def extensions_from_der(der: bytes) -> x509.Extensions:
    """Parse a DER Extensions SEQUENCE the same way."""
    return _parse_via_csr(extensions_der=der).extensions


def _san_from_der(der: bytes) -> x509.SubjectAlternativeName:
    from certadillo.crypto.der import tlv

    ext = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("551d11")) + tlv(0x04, der)))
    return extensions_from_der(ext).get_extension_for_class(x509.SubjectAlternativeName).value


def _parse_via_csr(subject_der: bytes = b"\x30\x00", extensions_der: bytes | None = None):
    """Build an unsigned CSR around raw DER parts so cryptography parses them.
    Nothing here is trusted: the signature is a placeholder and never checked."""
    from certadillo.crypto.der import tlv

    spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + b"\x01" * 64
    attrs = b""
    if extensions_der is not None:
        attrs = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d01090e")) + tlv(0x31, extensions_der))
    cri = tlv(0x30, b"\x02\x01\x00" + subject_der + spki + tlv(0xA0, attrs))
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
    csr = tlv(0x30, cri + alg + tlv(0x03, b"\x00" + b"\x30\x06\x02\x01\x01\x02\x01\x01"))
    return x509.load_der_x509_csr(csr)


def load_policies(path: str | None = None) -> dict:
    if path:
        return yaml.safe_load(Path(path).read_text())
    return yaml.safe_load(resources.files("certadillo").joinpath("default_policies.yaml").read_text())


def describe_key(pub) -> tuple[str, int, str]:
    """Return (key_type, bits, curve_or_blank)."""
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa", pub.key_size, ""
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ec", pub.curve.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519", 256, "ed25519"
    return "unknown", 0, ""


def domain_allowed(name: str, patterns: list[str]) -> bool:
    name = name.lower().rstrip(".")
    for p in patterns:
        p = p.lower().rstrip(".")
        if p.startswith("*."):
            # "*.example.com" allows any depth of subdomain but not the apex.
            if name.endswith(p[1:]):
                return True
        elif fnmatch.fnmatchcase(name, p):
            return True
    return False


def public_tls_max_days(policies: dict, on: date) -> int:
    best = 398
    for step in policies.get("public_tls_schedule", []):
        if on >= date.fromisoformat(step["from"]):
            best = step["max_days"]
    return best


class PolicyEngine:
    def __init__(self, policies: dict):
        self.policies = policies
        self.profiles: dict = policies["profiles"]

    def profile(self, name: str) -> dict:
        if name not in self.profiles:
            raise PolicyError([("unknown_profile", f"profile '{name}' is not defined")])
        return self.profiles[name]

    def evaluate(
        self,
        csr: x509.CertificateSigningRequest,
        profile_name: str,
        allowed_domains: list[str],
        requested_days: int | None = None,
        requested_hours: int | None = None,
        previous_public_key_fp: str | None = None,
        pop_verified: bool = False,
    ) -> Decision:
        from certadillo.crypto.signers import key_fingerprint

        prof = self.profile(profile_name)
        v: list[tuple[str, str]] = []

        if not pop_verified and not csr.is_signature_valid:
            v.append(("csr_signature", "CSR signature does not verify (proof of possession failed)"))

        pub = csr.public_key()
        ktype, bits, curve = describe_key(pub)
        allowed = prof.get("allowed_keys", {})
        if ktype == "rsa" and bits < allowed.get("rsa_min_bits", 2048):
            v.append(("key_strength", f"RSA {bits} below minimum {allowed.get('rsa_min_bits')}"))
        elif ktype == "ec" and curve not in allowed.get("ec_curves", []):
            v.append(("key_curve", f"curve {curve} not allowed"))
        elif ktype not in ("rsa", "ec"):
            v.append(("key_type", f"key type {ktype} not allowed for this profile"))

        if prof.get("require_new_key_on_renewal") and previous_public_key_fp:
            if key_fingerprint(pub) == previous_public_key_fp:
                v.append(("key_reuse", "renewal must use a new key pair"))

        dns, uris, emails, ips = [], [], [], []
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns = san.get_values_for_type(x509.DNSName)
            uris = san.get_values_for_type(x509.UniformResourceIdentifier)
            emails = san.get_values_for_type(x509.RFC822Name)
            ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass
        cn_attrs = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else None
        if cn and prof.get("require_dns_san") and cn not in dns:
            dns = [cn, *dns]  # RFC 6125: names must be in SAN; fold CN in

        if prof.get("require_dns_san") and not dns:
            v.append(("san_required", "at least one DNS SAN is required"))
        for name in dns:
            if name.startswith("*.") and not prof.get("allow_wildcard", False):
                v.append(("wildcard", f"wildcard {name} not allowed"))
            if not domain_allowed(name, allowed_domains):
                v.append(("san_scope", f"{name} is outside the app's approved domains"))
        if ips:
            v.append(("ip_san", "IP SANs are not issued; use DNS names"))

        if prof.get("require_spiffe_id"):
            td = self.policies.get("spiffe_trust_domain", "")
            if len(uris) != 1 or not uris[0].startswith("spiffe://"):
                v.append(("spiffe_id", "exactly one URI SAN, a spiffe:// ID, is required"))
            else:
                sid = uris[0]
                if not sid.startswith(f"spiffe://{td}/"):
                    v.append(("spiffe_trust_domain", f"{sid} is not in trust domain {td}"))
                elif not domain_allowed(sid, allowed_domains):
                    v.append(("spiffe_scope", f"{sid} is outside the app's approved SPIFFE IDs"))
            cn = None
        elif uris:
            v.append(("uri_san", "URI SANs are only issued under the spiffe-svid profile"))

        if prof.get("require_email_san"):
            if not emails:
                v.append(("email_required", "an rfc822Name SAN is required"))
            for e in emails:
                if not domain_allowed(e.split("@")[-1], allowed_domains):
                    v.append(("email_scope", f"{e} is outside the app's approved mail domains"))
        elif emails:
            v.append(("email_san", "email SANs are only issued under the smime profile"))

        # A CN that looks like a host name is an identity claim for TLS
        # profiles even when DNS SANs are optional (tls-client).
        ekus = set(prof.get("extended_key_usage", []))
        if cn and not prof.get("require_spiffe_id") and ekus & {"server_auth", "client_auth"} and cn not in dns:
            if not domain_allowed(cn, allowed_domains):
                v.append(("cn_scope", f"CN {cn} is outside the app's approved domains"))
            elif cn.startswith("*.") and not prof.get("allow_wildcard", False):
                v.append(("wildcard", f"wildcard {cn} not allowed"))
            else:
                dns = [cn, *dns]  # RFC 9525: identities belong in the SAN

        if "max_validity_hours" in prof:
            hours = requested_hours or prof["default_validity_hours"]
            if hours > prof["max_validity_hours"]:
                v.append(("validity", f"{hours}h exceeds {prof['max_validity_hours']}h"))
            validity = timedelta(hours=hours)
        else:
            days = requested_days or prof["default_validity_days"]
            if days > prof["max_validity_days"]:
                v.append(("validity", f"{days}d exceeds {prof['max_validity_days']}d"))
            validity = timedelta(days=days)

        if v:
            raise PolicyError(v)
        return Decision(
            profile=profile_name,
            validity=validity,
            dns_names=dns,
            uris=uris,
            emails=emails,
            common_name=cn or (dns[0] if dns else (emails[0] if emails else None)),
            dual_control=bool(prof.get("dual_control")),
        )


def grade_certificate(cert: x509.Certificate, policies: dict, is_public: bool = False) -> list[tuple[str, str]]:
    """Findings for discovered or imported certificates (not issued by us)."""
    findings = []
    ktype, bits, curve = describe_key(cert.public_key())
    if ktype == "rsa" and bits < 2048:
        findings.append(("weak_key", f"RSA {bits}"))
    sig_oid = cert.signature_algorithm_oid.dotted_string
    if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name in ("sha1", "md5"):
        findings.append(("weak_signature", cert.signature_hash_algorithm.name))
    lifetime = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    if is_public:
        limit = public_tls_max_days(policies, cert.not_valid_before_utc.date())
        if lifetime > limit:
            findings.append(("public_validity", f"{lifetime}d exceeds CA/B limit {limit}d at issuance"))
    if sig_oid not in PQC_SIG_OIDS and ktype in ("rsa", "ec"):
        findings.append(("quantum_vulnerable", f"{ktype.upper()} key, plan PQC migration"))
    return findings
