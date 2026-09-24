"""CMP (RFC 4210 and RFC 9480) following the lightweight profile of RFC 9483,
for telecom, industrial and embedded gear that speaks CMP rather than
EST or SCEP.

Endpoint: POST /.well-known/cmp (or /.well-known/cmp/p/<app name>),
content type application/pkixcmp.

Supported messages:
  ir / cr / kur / p10cr -> ip / cp / kup   (one request per message)
  certConf -> pkiConf, or implicitConfirm when the client asks for it
  pollReq -> pollRep while a second person has not decided yet
  rr -> rp       revocation by the certificate holder
  genm -> genp   id-it-caCerts

Protection:
  MAC (PasswordBasedMac) with a one-time reference and secret from
  POST /api/v1/apps/{id}/cmp-secret, for first enrollment (RFC 9483 4.1.1)
  signature with a current certificate from this CA (cr, kur, rr, genm)
Responses use the same kind of protection as the request: the same shared
secret, or a signature by the CMP RA certificate (EKU id-kp-cmcRA).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from asn1crypto import core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from fastapi import APIRouter, Depends, Request, Response
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc4210

from certadillo.api.deps import platform
from certadillo.audit.log import record
from certadillo.crypto.der import _read_len, split_sequence, tlv
from certadillo.db import ApprovalRequest, App, Certificate, CertificateAuthority, CmpSecret, CmpTransaction, as_utc
from certadillo.observability.metrics import ISSUANCE_TOTAL
from certadillo.policy.engine import PolicyError, TemplateRequest, extensions_from_der, name_from_der
from certadillo.services import Actor, Forbidden, Platform

log = logging.getLogger("certadillo.cmp")
router = APIRouter(tags=["CMP"])
CONTENT_TYPE = "application/pkixcmp"

PBM = "1.2.840.113533.7.66.13"
OWF = {"1.3.14.3.2.26": hashlib.sha1, "2.16.840.1.101.3.4.2.1": hashlib.sha256,
       "2.16.840.1.101.3.4.2.2": hashlib.sha384, "2.16.840.1.101.3.4.2.3": hashlib.sha512}
MAC = {"1.3.6.1.5.5.8.1.2": hashlib.sha1, "1.2.840.113549.2.7": hashlib.sha1, "1.2.840.113549.2.9": hashlib.sha256,
       "1.2.840.113549.2.10": hashlib.sha384, "1.2.840.113549.2.11": hashlib.sha512}
SIG = {"1.2.840.10045.4.3.2": hashes.SHA256, "1.2.840.10045.4.3.3": hashes.SHA384,
       "1.2.840.10045.4.3.4": hashes.SHA512, "1.2.840.113549.1.1.11": hashes.SHA256,
       "1.2.840.113549.1.1.12": hashes.SHA384, "1.2.840.113549.1.1.13": hashes.SHA512}
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
IT_IMPLICIT_CONFIRM = "1.3.6.1.5.5.7.4.13"
IT_CA_CERTS = "1.3.6.1.5.5.7.4.17"
REG_CTRL_OLD_CERT_ID = "1.3.6.1.5.5.7.5.1.5"
MAX_PBM_ITERATIONS = 100_000

ACCEPTED, REJECTION, WAITING = 0, 2, 3
# PKIFailureInfo bit numbers (RFC 4210 5.2.3)
BAD_ALG, BAD_MESSAGE_CHECK, BAD_REQUEST, BAD_TIME, BAD_CERT_ID = 0, 1, 2, 3, 4
BAD_DATA_FORMAT, WRONG_AUTHORITY, INCORRECT_DATA, BAD_POP, CERT_REVOKED = 5, 6, 7, 9, 10
WRONG_INTEGRITY, BAD_RECIPIENT_NONCE, BAD_CERT_TEMPLATE, SIGNER_NOT_TRUSTED = 12, 13, 19, 20
NOT_AUTHORIZED, SYSTEM_FAILURE = 23, 25

REPLY_BODY = {"ir": ("ip", 1), "cr": ("cp", 3), "kur": ("kup", 8), "p10cr": ("cp", 3)}
BODY_TAG = {"ip": 1, "cp": 3, "kup": 8}


class CmpError(Exception):
    def __init__(self, fail: int, text: str):
        self.fail, self.text = fail, text
        super().__init__(text)


# ------------------------------------------------------------------ DER building blocks
def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def ctx(n: int, inner: bytes) -> bytes:
    """[n] EXPLICIT, which is what the CMP ASN.1 module uses throughout."""
    return tlv(0xA0 | n, inner)


def integer(n: int) -> bytes:
    return core.Integer(n).dump()


def octets(b: bytes) -> bytes:
    return core.OctetString(b).dump()


def oid(dotted: str) -> bytes:
    return core.ObjectIdentifier(dotted).dump()


def bits(data: bytes) -> bytes:
    return tlv(0x03, b"\x00" + data)


def free_text(*lines: str) -> bytes:
    return seq(*[core.UTF8String(x).dump() for x in lines])


def fail_info(*bit_numbers: int) -> bytes:
    n = max(bit_numbers) + 1
    size = (n + 7) // 8
    value = bytearray(size)
    for b in bit_numbers:
        value[b // 8] |= 0x80 >> (b % 8)
    return tlv(0x03, bytes([size * 8 - n]) + bytes(value))


def status_info(status: int, text: str | None = None, fails: tuple[int, ...] = ()) -> bytes:
    return seq(integer(status), free_text(text) if text else b"", fail_info(*fails) if fails else b"")


def inner(der: bytes) -> bytes:
    """Content of a TLV (drop an EXPLICIT tag wrapper)."""
    length, pos = _read_len(der, 1)
    return der[pos:pos + length]


def retag(der: bytes, tag: int = 0x30) -> bytes:
    """Undo an IMPLICIT tag on a constructed type."""
    return bytes([tag]) + der[1:]


# ------------------------------------------------------------------ requests
@dataclass
class CmpRequest:
    msg: object
    body: str
    header_tlv: bytes
    body_tlv: bytes
    sender_tlv: bytes
    pvno: int
    txid: bytes
    nonce: bytes
    sender_kid: bytes | None
    prot_alg: str | None
    prot_params: bytes | None
    protection: bytes | None
    extra_certs: list[x509.Certificate] = field(default_factory=list)
    implicit_confirm: bool = False


def parse(der: bytes) -> CmpRequest:
    try:
        msg, rest = decoder.decode(der, asn1Spec=rfc4210.PKIMessage())
        if rest:
            raise ValueError("trailing data")
        parts = split_sequence(der)
        header_tlv, body_tlv = parts[0], parts[1]
        h = msg["header"]
        prot_alg = prot_params = None
        if h["protectionAlg"].isValue:
            prot_alg = str(h["protectionAlg"]["algorithm"])
            if h["protectionAlg"]["parameters"].isValue:
                prot_params = h["protectionAlg"]["parameters"].asOctets()
        implicit = False
        if h["generalInfo"].isValue:
            implicit = any(str(i["infoType"]) == IT_IMPLICIT_CONFIRM for i in h["generalInfo"])
        extra = []
        if msg["extraCerts"].isValue:
            extra = [x509.load_der_x509_certificate(encoder.encode(c)) for c in msg["extraCerts"]]
        txid = h["transactionID"].asOctets() if h["transactionID"].isValue else b""
        nonce = h["senderNonce"].asOctets() if h["senderNonce"].isValue else b""
        if not txid or not nonce:
            raise ValueError("transactionID and senderNonce are required")
        return CmpRequest(
            msg=msg, body=msg["body"].getName(), header_tlv=header_tlv, body_tlv=body_tlv,
            sender_tlv=split_sequence(header_tlv)[1], pvno=int(h["pvno"]), txid=txid, nonce=nonce,
            sender_kid=h["senderKID"].asOctets() if h["senderKID"].isValue else None,
            prot_alg=prot_alg, prot_params=prot_params,
            protection=msg["protection"].asOctets() if msg["protection"].isValue else None,
            extra_certs=extra, implicit_confirm=implicit,
        )
    except CmpError:
        raise
    except Exception as e:  # noqa: BLE001
        raise CmpError(BAD_DATA_FORMAT, f"not a CMP PKIMessage: {e}") from None


def pbm_key(secret: bytes, salt: bytes, owf, iterations: int) -> bytes:
    """RFC 4210 5.1.3.1: the one-way function applied iterationCount times,
    first to (secret || salt)."""
    k = owf(secret + salt).digest()
    for _ in range(iterations - 1):
        k = owf(k).digest()
    return k


@dataclass
class Protection:
    kind: str  # mac | sig
    secret: bytes | None = None
    owf_alg: bytes = b""  # raw AlgorithmIdentifier DER, echoed back
    mac_alg: bytes = b""
    iterations: int = 500
    owf: object = None
    mac: object = None
    secret_row: CmpSecret | None = None
    sender: Certificate | None = None  # signature-protected: the Certificate row of the signer
    app: App | None = None


def _pbm_params(params: bytes):
    p, _ = decoder.decode(params, asn1Spec=rfc4210.PBMParameter())
    owf_oid, mac_oid = str(p["owf"]["algorithm"]), str(p["mac"]["algorithm"])
    iterations = int(p["iterationCount"])
    if owf_oid not in OWF or mac_oid not in MAC:
        raise CmpError(BAD_ALG, f"PBM with {owf_oid}/{mac_oid} is not supported")
    if not 1 <= iterations <= MAX_PBM_ITERATIONS:
        raise CmpError(BAD_ALG, f"PBM iterationCount {iterations} out of range")
    return p["salt"].asOctets(), encoder.encode(p["owf"]), encoder.encode(p["mac"]), iterations, OWF[owf_oid], MAC[mac_oid]


def authenticate(p: Platform, req: CmpRequest) -> Protection:
    if req.protection is None or req.prot_alg is None:
        raise CmpError(BAD_MESSAGE_CHECK, "unprotected requests are not accepted")
    protected_part = seq(req.header_tlv, req.body_tlv)
    if req.prot_alg == PBM:
        ref = (req.sender_kid or b"").decode("utf-8", "replace")
        row = p.s.query(CmpSecret).filter_by(reference=ref).one_or_none()
        if row is None:
            raise CmpError(SIGNER_NOT_TRUSTED, "unknown senderKID")
        continuing = p.s.query(CmpTransaction).filter_by(transaction_id=req.txid.hex(), secret_id=row.id).first()
        if (row.used and continuing is None) or as_utc(row.expires_at) < datetime.now(timezone.utc) and continuing is None:
            raise CmpError(SIGNER_NOT_TRUSTED, "the shared secret was already used or has expired")
        salt, owf_alg, mac_alg, iterations, owf, mac = _pbm_params(req.prot_params or b"")
        secret = p.cmp_secret_plain(row)
        key = pbm_key(secret, salt, owf, iterations)
        if not hmac.compare_digest(hmac.new(key, protected_part, mac).digest(), req.protection):
            raise CmpError(WRONG_INTEGRITY, "MAC does not verify")
        app = p.s.get(App, row.app_id)
        return Protection("mac", secret, owf_alg, mac_alg, iterations, owf, mac, secret_row=row, app=app)
    if req.prot_alg in SIG:
        if not req.extra_certs:
            raise CmpError(SIGNER_NOT_TRUSTED, "signature-protected messages must carry the signer's certificate first in extraCerts")
        cert = req.extra_certs[0]
        try:
            _verify(cert.public_key(), req.prot_alg, req.protection, protected_part)
        except InvalidSignature:
            raise CmpError(BAD_MESSAGE_CHECK, "signature protection does not verify") from None
        row = issued_here(p, cert, allow_revoked=req.body == "rr")
        if row is None and req.body in ("certConf", "pollReq"):
            # after kur the old certificate is superseded, but the client still
            # protects certConf with it (RFC 9483 4.1.3): accept it in its own transaction
            txn = p.s.query(CmpTransaction).filter_by(transaction_id=req.txid.hex()).one_or_none()
            if txn is not None and txn.sender_cert_pem and \
                    x509.load_pem_x509_certificate(txn.sender_cert_pem.encode()) == cert:
                row = p.s.query(Certificate).filter_by(
                    fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex()).one_or_none()
        if row is None:
            raise CmpError(SIGNER_NOT_TRUSTED, "the signing certificate was not issued here or is no longer current")
        app = p.s.get(App, row.app_id) if row.app_id else None
        if app is None or app.status != "active":
            raise CmpError(NOT_AUTHORIZED, "the signing certificate does not belong to an active app")
        return Protection("sig", sender=row, app=app)
    raise CmpError(BAD_ALG, f"protection algorithm {req.prot_alg} is not supported")


def _verify(pub, alg: str, signature: bytes, data: bytes) -> None:
    h = SIG[alg]()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, data, ec.ECDSA(h))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, data, padding.PKCS1v15(), h)
    else:
        raise InvalidSignature()


def issued_here(p: Platform, cert: x509.Certificate, allow_revoked: bool = False) -> Certificate | None:
    row = p.s.query(Certificate).filter_by(fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
                                           source="issued").one_or_none()
    if row is None or row.ca_id is None:
        return None
    if row.status != "active" and not (allow_revoked and row.status == "revoked"):
        return None
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        return None
    ca = p.s.get(CertificateAuthority, row.ca_id)
    try:
        cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.cert_pem.encode()))
    except Exception:  # noqa: BLE001
        return None
    return row


# ------------------------------------------------------------------ responses
class Responder:
    def __init__(self, p: Platform, req: CmpRequest, prot: Protection | None):
        self.p, self.req, self.prot = p, req, prot
        self.ca = p.ca.default_issuing()
        self.ra_cert, self.ra_key = p.ca.ensure_cmp_ra(self.ca)

    def message(self, body: bytes, extra: list[x509.Certificate] | None = None, implicit: bool = False) -> bytes:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        mac = self.prot is not None and self.prot.kind == "mac"
        if mac:
            salt = secrets.token_bytes(16)
            alg = seq(oid(PBM), seq(octets(salt), self.prot.owf_alg, integer(self.prot.iterations), self.prot.mac_alg))
            kid = self.req.sender_kid or b""
        else:
            alg = seq(oid(ECDSA_SHA256))
            kid = x509.SubjectKeyIdentifier.from_public_key(self.ra_cert.public_key()).digest
        sender = tlv(0xA4, self.ra_cert.subject.public_bytes())  # GeneralName directoryName
        header = [integer(self.req.pvno), sender, self.req.sender_tlv, ctx(0, core.GeneralizedTime(now).dump()),
                  ctx(1, alg), ctx(2, octets(kid)), ctx(4, octets(self.req.txid)),
                  ctx(5, octets(secrets.token_bytes(16))), ctx(6, octets(self.req.nonce))]
        if implicit:
            header.append(ctx(8, seq(seq(oid(IT_IMPLICIT_CONFIRM), b"\x05\x00"))))
        header_der = seq(*header)
        protected = seq(header_der, body)
        if mac:
            key = pbm_key(self.prot.secret, salt, self.prot.owf, self.prot.iterations)
            protection = hmac.new(key, protected, self.prot.mac).digest()
            certs = extra or []
        else:
            protection = self.ra_key.sign(protected, ec.ECDSA(hashes.SHA256()))
            # the RA certificate first, then what a client needs to chain it to the root
            certs = [self.ra_cert, *(extra or [])]
            certs += [c for c in self.chain()[:-1] if c not in certs]
        out = header_der + body + ctx(0, bits(protection))
        if certs:
            out += ctx(1, seq(*[c.public_bytes(serialization.Encoding.DER) for c in certs]))
        return tlv(0x30, out)

    def error(self, e: CmpError) -> bytes:
        return self.message(ctx(23, seq(status_info(REJECTION, e.text, (e.fail,)))))

    def chain(self) -> list[x509.Certificate]:
        return self.p.ca.chain(self.ca)


def _cert_response(req_id: int, status: int, cert: x509.Certificate | None = None, text: str | None = None,
                   fails: tuple[int, ...] = ()) -> bytes:
    key_pair = seq(ctx(0, cert.public_bytes(serialization.Encoding.DER))) if cert is not None else b""
    return seq(integer(req_id), status_info(status, text, fails), key_pair)


def _rep_body(kind: str, response: bytes, ca_pubs: list[x509.Certificate] | None = None) -> bytes:
    pubs = ctx(1, seq(*[c.public_bytes(serialization.Encoding.DER) for c in ca_pubs])) if ca_pubs else b""
    return ctx(BODY_TAG[kind], seq(pubs, seq(response)))


# ------------------------------------------------------------------ handlers
def _template(p: Platform, cert_req, previous: Certificate | None) -> TemplateRequest:
    tmpl = cert_req["certTemplate"]
    if not tmpl["publicKey"].isValue:
        raise CmpError(BAD_CERT_TEMPLATE, "the template has no public key (central key generation is not offered)")
    try:
        pub = load_der_public_key(retag(encoder.encode(tmpl["publicKey"])))
    except ValueError:
        raise CmpError(BAD_CERT_TEMPLATE, "cannot read the template public key") from None
    old = x509.load_pem_x509_certificate(previous.pem.encode()) if previous is not None else None
    if tmpl["subject"].isValue:
        subject = name_from_der(inner(encoder.encode(tmpl["subject"])))
    elif old is not None:
        subject = old.subject
    else:
        raise CmpError(BAD_CERT_TEMPLATE, "the template has no subject")
    exts = []
    san = None
    if tmpl["extensions"].isValue:
        parsed = extensions_from_der(retag(encoder.encode(tmpl["extensions"])))
        try:
            san = parsed.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            pass
    if san is None and old is not None:
        try:
            san = old.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            pass
    if san is not None:
        exts.append(x509.Extension(san.oid, False, san.value))
    return TemplateRequest(subject, pub, exts)


def _check_pop(cert_req_msg, pub) -> None:
    pop = cert_req_msg["popo"] if "popo" in cert_req_msg else cert_req_msg["pop"]
    if not pop.isValue or pop.getName() != "signature":
        raise CmpError(BAD_POP, "proof of possession must be a signature")
    sk = pop["signature"]
    if sk["poposkInput"].isValue:
        raise CmpError(BAD_POP, "poposkInput is only for requests without a subject; not supported")
    alg = str(sk["algorithmIdentifier"]["algorithm"])
    if alg not in SIG:
        raise CmpError(BAD_ALG, f"PoP signature algorithm {alg} not supported")
    try:
        _verify(pub, alg, sk["signature"].asOctets(), encoder.encode(cert_req_msg["certReq"]))
    except InvalidSignature:
        raise CmpError(BAD_POP, "proof of possession signature does not verify") from None


def handle_enrollment(p: Platform, r: Responder, req: CmpRequest, prot: Protection, label: str | None) -> bytes:
    app = prot.app
    reply_kind, _ = REPLY_BODY[req.body]
    previous = None
    if req.body == "kur":
        if prot.kind != "sig":
            raise CmpError(NOT_AUTHORIZED, "kur must be signed with the certificate being updated")
        previous = prot.sender
    if req.body == "p10cr":
        csr_der = inner(req.body_tlv)
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except ValueError:
            raise CmpError(BAD_DATA_FORMAT, "p10cr does not contain a PKCS#10 request") from None
        req_id, template, csr_pem = 0, None, csr.public_bytes(serialization.Encoding.PEM).decode()
    else:
        msgs = req.msg["body"][req.body]
        if len(msgs) != 1:
            raise CmpError(BAD_REQUEST, "send exactly one certificate request per message (RFC 9483 4.1)")
        crm = msgs[0]
        req_id = int(crm["certReq"]["certReqId"])
        template = _template(p, crm["certReq"], previous)
        _check_pop(crm, template.public_key())
        csr_pem = None
        if previous is not None:
            cn = template.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if (cn[0].value if cn else "") != previous.common_name:
                raise CmpError(BAD_CERT_TEMPLATE, "kur must keep the subject of the certificate being updated")
    who = Actor(f"cmp:{app.name}" if prot.kind == "mac" else f"cmp-cert:{prot.sender.serial_hex}", "app", app.id)
    try:
        result = p.request_certificate(who, app.id, csr_pem, protocol="cmp", template=template, previous=previous)
    except (PolicyError, Forbidden) as e:
        ISSUANCE_TOTAL.labels(profile=app.profile, protocol="cmp", result="rejected").inc()
        record(p.s, who.name, "certificate.rejected", app.name, {"protocol": "cmp", "reason": str(e)})
        p.commit()
        return r.message(_rep_body(reply_kind, _cert_response(req_id, REJECTION, text=str(e), fails=(BAD_CERT_TEMPLATE,))))
    if prot.secret_row is not None:
        prot.secret_row.used = True
    txn = CmpTransaction(transaction_id=req.txid.hex(), app_id=app.id,
                         secret_id=prot.secret_row.id if prot.secret_row else None,
                         sender_cert_pem=prot.sender.pem if prot.sender else None, cert_req_id=req_id,
                         body_type=reply_kind)
    p.s.add(txn)
    if isinstance(result, ApprovalRequest):
        txn.status, txn.approval_id = "pending", result.id
        record(p.s, who.name, "cmp.pending", req.txid.hex(), {"approval": result.id})
        p.commit()
        return r.message(_rep_body(reply_kind, _cert_response(req_id, WAITING, text="waiting for a second approver")))
    return _deliver(p, r, req, prot, txn, result)


def _deliver(p: Platform, r: Responder, req: CmpRequest, prot: Protection, txn: CmpTransaction,
             row: Certificate) -> bytes:
    cert = x509.load_pem_x509_certificate(row.pem.encode())
    txn.certificate_id = row.id
    implicit = req.implicit_confirm
    txn.status = "confirmed" if implicit else "waiting_conf"
    record(p.s, f"cmp:{txn.transaction_id[:16]}", "cmp.issue", row.serial_hex,
           {"body": txn.body_type, "implicit_confirm": implicit, "protection": prot.kind})
    p.commit()
    chain = r.chain()  # [issuing, ..., root]
    # a client enrolling with a shared secret has no trust anchor yet: send the root as caPubs
    ca_pubs = chain[-1:] if prot.kind == "mac" and txn.body_type == "ip" else None
    body = _rep_body(txn.body_type, _cert_response(txn.cert_req_id, ACCEPTED, cert), ca_pubs)
    return r.message(body, extra=chain[:-1], implicit=implicit)


def handle_cert_conf(p: Platform, r: Responder, req: CmpRequest, prot: Protection) -> bytes:
    txn = p.s.query(CmpTransaction).filter_by(transaction_id=req.txid.hex()).one_or_none()
    if txn is None or txn.status != "waiting_conf":
        raise CmpError(BAD_REQUEST, "no certificate is waiting for confirmation in this transaction")
    row = p.s.get(Certificate, txn.certificate_id)
    cert = x509.load_pem_x509_certificate(row.pem.encode())
    statuses = req.msg["body"]["certConf"]
    accepted = False
    if len(statuses):
        st = statuses[0]
        h = hashes.Hash(cert.signature_hash_algorithm)
        h.update(cert.public_bytes(serialization.Encoding.DER))
        if not hmac.compare_digest(st["certHash"].asOctets(), h.finalize()):
            raise CmpError(BAD_CERT_ID, "certHash does not match the issued certificate")
        accepted = not st["statusInfo"].isValue or int(st["statusInfo"]["status"]) in (0, 1)
    if accepted:
        txn.status = "confirmed"
        record(p.s, f"cmp:{txn.transaction_id[:16]}", "cmp.confirmed", row.serial_hex, {})
    else:
        # the client refused the certificate; it must not stay valid
        txn.status = "rejected"
        p.revoke(Actor(f"cmp:{txn.transaction_id[:16]}", "app", row.app_id), row.id, "cessation_of_operation")
        record(p.s, f"cmp:{txn.transaction_id[:16]}", "cmp.rejected_by_client", row.serial_hex, {})
    p.commit()
    return r.message(ctx(19, b"\x05\x00"))


def handle_poll(p: Platform, r: Responder, req: CmpRequest, prot: Protection) -> bytes:
    txn = p.s.query(CmpTransaction).filter_by(transaction_id=req.txid.hex()).one_or_none()
    if txn is None or txn.status != "pending":
        raise CmpError(BAD_REQUEST, "nothing is pending in this transaction")
    approval = p.s.get(ApprovalRequest, txn.approval_id)
    if approval is None or not p.approval_intact(approval):
        txn.status = "rejected"
        p.commit()
        raise CmpError(NOT_AUTHORIZED, "the approval for this request failed its integrity check")
    if approval.status == "pending":
        p.commit()
        return r.message(ctx(26, seq(seq(integer(txn.cert_req_id), integer(30)))))
    if approval.status == "rejected":
        txn.status = "rejected"
        p.commit()
        body = _rep_body(txn.body_type, _cert_response(txn.cert_req_id, REJECTION,
                                                       text=f"rejected by {approval.decided_by}", fails=(NOT_AUTHORIZED,)))
        return r.message(body)
    row = p.s.get(Certificate, approval.payload.get("certificate_id"))
    return _deliver(p, r, req, prot, txn, row)


REASON_CODES = {0: "unspecified", 1: "key_compromise", 3: "affiliation_changed", 4: "superseded",
                5: "cessation_of_operation"}


def handle_rr(p: Platform, r: Responder, req: CmpRequest, prot: Protection) -> bytes:
    if prot.kind != "sig":
        raise CmpError(NOT_AUTHORIZED, "revocation requests must be signed with a certificate of the same app")
    out = []
    for det in req.msg["body"]["rr"]:
        tmpl = det["certDetails"]
        if not tmpl["serialNumber"].isValue:
            out.append(status_info(REJECTION, "serialNumber is required", (BAD_CERT_ID,)))
            continue
        serial = format(int(tmpl["serialNumber"]), "x")
        row = next((c for c in p.s.query(Certificate).filter_by(serial_hex=serial, source="issued").all()
                    if c.app_id == prot.app.id), None)
        if row is None:
            out.append(status_info(REJECTION, "no such certificate for this app", (BAD_CERT_ID,)))
            continue
        if row.status == "revoked":
            out.append(status_info(REJECTION, "already revoked", (CERT_REVOKED,)))
            continue
        reason = "unspecified"
        if det["crlEntryDetails"].isValue:
            for ext in det["crlEntryDetails"]:
                if str(ext["extnID"]) == "2.5.29.21":
                    raw = ext["extnValue"].asOctets()  # ENUMERATED: 0a 01 <code>
                    code = int.from_bytes(raw[2:], "big") if raw[:1] == b"\x0a" else 0
                    reason = REASON_CODES.get(code, "unspecified")
        p.revoke(Actor(f"cmp-cert:{prot.sender.serial_hex}", "app", prot.app.id), row.id, reason)
        out.append(status_info(ACCEPTED))
    p.commit()
    return r.message(ctx(12, seq(seq(*out))))


def handle_genm(p: Platform, r: Responder, req: CmpRequest, prot: Protection) -> bytes:
    items = []
    for itv in req.msg["body"]["genm"]:
        if str(itv["infoType"]) == IT_CA_CERTS:
            certs = [c.public_bytes(serialization.Encoding.DER) for c in r.chain()]
            items.append(seq(oid(IT_CA_CERTS), seq(*certs)))
    return r.message(ctx(22, seq(*items)))


def handle(p: Platform, der: bytes, label: str | None = None) -> bytes:
    try:
        req = parse(der)
    except CmpError as e:
        # nothing to echo: answer with a bare, signed error
        dummy = CmpRequest(msg=None, body="", header_tlv=b"", body_tlv=b"", sender_tlv=tlv(0xA4, b"\x30\x00"),
                           pvno=2, txid=b"\x00", nonce=b"\x00", sender_kid=None, prot_alg=None, prot_params=None,
                           protection=None)
        return Responder(p, dummy, None).error(e)
    prot = None
    try:
        prot = authenticate(p, req)
        if label and prot.app.name != label:
            raise CmpError(WRONG_AUTHORITY, f"this credential is not for {label}")
        r = Responder(p, req, prot)
        if req.body in REPLY_BODY:
            return handle_enrollment(p, r, req, prot, label)
        if req.body == "certConf":
            return handle_cert_conf(p, r, req, prot)
        if req.body == "pollReq":
            return handle_poll(p, r, req, prot)
        if req.body == "rr":
            return handle_rr(p, r, req, prot)
        if req.body == "genm":
            return handle_genm(p, r, req, prot)
        raise CmpError(BAD_REQUEST, f"{req.body} is not supported")
    except (CmpError, Exception) as e:  # noqa: BLE001 - a CMP client always gets a CMP answer
        p.s.rollback()
        if not isinstance(e, CmpError):
            log.exception("cmp request failed")
            e = CmpError(SYSTEM_FAILURE, "internal error")
        record(p.s, "cmp", "cmp.error", req.txid.hex()[:32], {"body": req.body, "reason": e.text})
        p.commit()
        log.warning("cmp error", extra={"reason": e.text})
        # answer with the request's protection only when it verified
        return Responder(p, req, prot).error(e)


def housekeeping(session, now: datetime | None = None) -> dict:
    """Unconfirmed certificates are marked, not revoked: some clients never
    send certConf. Stale secrets are dropped."""
    now = now or datetime.now(timezone.utc)
    expired = 0
    for t in session.query(CmpTransaction).filter(CmpTransaction.status == "waiting_conf",
                                                   CmpTransaction.created_at < now - timedelta(minutes=15)).all():
        t.status = "expired"
        record(session, "cmp", "cmp.unconfirmed", t.transaction_id[:32], {"certificate_id": t.certificate_id})
        expired += 1
    dropped = session.query(CmpSecret).filter(CmpSecret.expires_at < now - timedelta(days=7)).delete()
    session.flush()
    return {"cmp_unconfirmed": expired, "cmp_secrets_dropped": dropped}


@router.post("/.well-known/cmp", operation_id="cmp")
@router.post("/.well-known/cmp/p/{label}", operation_id="cmp_label")
async def cmp_endpoint(request: Request, label: str | None = None, p: Platform = Depends(platform)):
    der = await request.body()
    body = await asyncio.to_thread(handle, p, der, label)
    return Response(body, media_type=CONTENT_TYPE, headers={"Cache-Control": "no-store"})
