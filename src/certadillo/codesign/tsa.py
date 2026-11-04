"""RFC 3161 time-stamping unit.

POST /tsa with an application/timestamp-query body returns a signed
TimeStampResp. signtool /tr, jarsigner -tsa, osslsigncode -ts and
`openssl ts -query` all speak this. The TSA certificate is issued by the
default issuing CA with the critical timeStamping EKU and nothing else; its key
is generated where CA keys live, so with an HSM the time-stamping key never
leaves it either. Each token carries the ESS signing-certificate-v2 attribute
(RFC 5816) so verifiers bind it to this certificate.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from asn1crypto import algos, cms, tsp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from certadillo.codesign.cms import _acert, _attr, signed_data

# An OID under 2.25 (UUID arc, ITU-T X.667): unique without registration.
POLICY_OID = "2.25." + str(uuid.uuid5(uuid.NAMESPACE_URL, "https://certadillo.com/tsa/policy/v1").int)
ACCEPTED = {"sha256", "sha384", "sha512"}


class TsaError(Exception):
    def __init__(self, failure: str, text: str):
        super().__init__(text)
        self.failure, self.text = failure, text


def ensure_tsa(ca_service, ca):
    """The TSA certificate and signer for an issuing CA, created on first use
    and renewed when under 30 days remain."""
    from certadillo.crypto.signers import sign_x509

    now = datetime.now(timezone.utc)
    if ca.tsa_cert_pem and ca.tsa_key_ref:
        cert = x509.load_pem_x509_certificate(ca.tsa_cert_pem.encode())
        if cert.not_valid_after_utc - now > timedelta(days=30):
            return cert, ca_service.keystore.load(ca.tsa_key_ref)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    signer = ca_service.keystore.generate(f"tsa-{ca.name}-{int(now.timestamp())}", "ec-p384")
    b = (x509.CertificateBuilder()
         .subject_name(ca_service._name(f"Time Stamping Unit {ca.name}"))
         .issuer_name(ca_cert.subject).public_key(signer.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(minutes=5))
         .not_valid_after(min(now + timedelta(days=365), ca_cert.not_valid_after_utc))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         # RFC 3161 2.3: exactly one EKU, timeStamping, marked critical
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(signer.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
         .add_extension(ca_service._cdp(ca.name), critical=False))
    cert = sign_x509(b, ca_service.signer_for(ca))
    ca.tsa_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ca.tsa_key_ref = signer.key_ref
    ca_service.s.flush()
    return cert, signer


def make_token(ca_service, ca, hash_alg: str, hashed: bytes, nonce: int | None = None,
               include_cert: bool = True) -> tuple[cms.ContentInfo, dict]:
    if hash_alg not in ACCEPTED:
        raise TsaError("bad_alg", f"hash algorithm {hash_alg} is not accepted (sha256, sha384, sha512)")
    if len(hashed) != hashlib.new(hash_alg).digest_size:
        raise TsaError("bad_data_format", "the message imprint has the wrong length for its algorithm")
    cert, signer = ensure_tsa(ca_service, ca)
    serial = secrets.randbits(63) | 1
    gen = datetime.now(timezone.utc)
    info = {
        "version": "v1",
        "policy": POLICY_OID,
        "message_imprint": {"hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_alg}),
                            "hashed_message": hashed},
        "serial_number": serial,
        "gen_time": gen,
        "accuracy": {"seconds": 1},
        "ordering": False,
    }
    if nonce is not None:
        info["nonce"] = nonce
    tst = tsp.TSTInfo(info).dump()
    chain = []  # the verifier already trusts the CA chain; the TSA certificate is enough
    ess = tsp.SigningCertificateV2({"certs": [tsp.ESSCertIDv2({
        "hash_algorithm": {"algorithm": "sha256"},
        "cert_hash": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest(),
        "issuer_serial": {"issuer": [tsp.GeneralName({"directory_name": _acert(cert).issuer})],
                          "serial_number": cert.serial_number},
    })]})
    token = signed_data(signer, cert, chain, "sha384", hashlib.sha384(tst).digest(), content_type="tst_info",
                        content=tst, extra_attrs=[_attr("signing_certificate_v2", ess)], include_certs=include_cert)
    return token, {"serial": format(serial, "x"), "gen_time": gen.isoformat(), "policy": POLICY_OID}


def respond(ca_service, ca, query: bytes) -> tuple[bytes, dict]:
    """Answer a TimeStampReq. A malformed or unacceptable request gets a
    'rejection' response with the reason, never an exception."""
    try:
        try:
            req = tsp.TimeStampReq.load(query)
            imprint = req["message_imprint"]
            alg = imprint["hash_algorithm"]["algorithm"].native
            hashed = imprint["hashed_message"].native
            nonce = req["nonce"].native
            cert_req = bool(req["cert_req"].native)
            policy = req["req_policy"].native
            if req["extensions"].native:
                raise TsaError("unaccepted_extension", "extensions are not supported")
        except (ValueError, TypeError, KeyError):
            raise TsaError("bad_data_format", "the request is not a valid TimeStampReq") from None
        if policy not in (None, POLICY_OID):
            raise TsaError("unaccepted_policy", f"this TSA only issues under policy {POLICY_OID}")
        token, meta = make_token(ca_service, ca, alg, hashed, nonce, cert_req)
        resp = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token})
        return resp.dump(), {**meta, "hash_alg": alg}
    except TsaError as e:
        # TimeStampResp ::= SEQUENCE { status, timeStampToken OPTIONAL }; asn1crypto
        # insists on the token, so the rejection is assembled by hand
        from certadillo.crypto.der import tlv

        status = tsp.PKIStatusInfo({"status": "rejection", "status_string": [e.text], "fail_info": {e.failure}})
        return tlv(0x30, status.dump()), {"rejected": e.text}


def hashed_signature(signature: bytes, alg: str = "sha256") -> bytes:
    return hashlib.new(alg, signature).digest()

