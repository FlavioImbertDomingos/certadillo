"""CMS (RFC 5652) SignedData built around a signer that only signs bytes.

Works with every Certadillo signer (software, PKCS#11, Vault Transit): the
signer is given the DER of the signed attributes and never sees the artifact,
only its digest inside messageDigest.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from asn1crypto import algos, cms, core
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
DIGEST_LEN = {"sha256": 32, "sha384": 48, "sha512": 64}


def _acert(cert: x509.Certificate) -> ax509.Certificate:
    return ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _sig_alg(cert: x509.Certificate, digest_alg: str) -> algos.SignedDigestAlgorithm:
    if isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        return algos.SignedDigestAlgorithm({"algorithm": f"{digest_alg}_ecdsa"})
    return algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"})


def _attr(kind: str, value) -> cms.CMSAttribute:
    return cms.CMSAttribute({"type": kind, "values": [value]})


def signed_data(signer, cert: x509.Certificate, chain: list[x509.Certificate], digest_alg: str, digest: bytes,
                content_type: str = "data", content: bytes | None = None, extra_attrs: list | None = None,
                timestamper=None, include_certs: bool = True) -> cms.ContentInfo:
    """A SignedData whose single SignerInfo signs `digest` (the hash of the
    content, computed elsewhere). Detached unless `content` is given.
    `timestamper(signature) -> TimeStampToken` adds an RFC 3161 token over the
    signature value as an unsigned attribute (RFC 3161 appendix A)."""
    if digest_alg not in HASHES or len(digest) != DIGEST_LEN[digest_alg]:
        raise ValueError(f"digest must be {digest_alg} ({DIGEST_LEN.get(digest_alg)} bytes)")
    attrs = cms.CMSAttributes([
        _attr("content_type", cms.ContentType(content_type)),
        _attr("signing_time", cms.Time({"utc_time": core.UTCTime(datetime.now(timezone.utc))})),
        _attr("message_digest", core.OctetString(digest)),
        *(extra_attrs or []),
    ])
    sig = signer.sign(attrs.dump(), HASHES[digest_alg]())
    ac = _acert(cert)
    si = {
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": ac.issuer, "serial_number": ac.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": digest_alg}),
        "signed_attrs": attrs,
        "signature_algorithm": _sig_alg(cert, digest_alg),
        "signature": sig,
    }
    if timestamper is not None:
        si["unsigned_attrs"] = cms.CMSAttributes([_attr("signature_time_stamp_token", timestamper(sig))])
    encap = {"content_type": content_type}
    if content is not None:
        encap["content"] = cms.ParsableOctetString(content)
    sd = cms.SignedData({
        "version": "v3" if content_type != "data" else "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": digest_alg})],
        "encap_content_info": encap,
        "certificates": [_acert(c) for c in [cert, *chain]] if include_certs else [],
        "signer_infos": [cms.SignerInfo(si)],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd})


def signature_value(info: cms.ContentInfo) -> bytes:
    return info["content"]["signer_infos"][0]["signature"].native


def digest_of(data: bytes, alg: str) -> bytes:
    return hashlib.new(alg, data).digest()
