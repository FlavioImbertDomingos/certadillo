"""SCEP (RFC 8894) for MDM-managed devices, network gear and legacy appliances.

Authentication, one of:
  - a one-time challenge password bound to an onboarded app
    (POST /api/v1/apps/{id}/scep-challenge), the NDES dynamic-challenge pattern
  - a validation webhook (Intune-style): for apps with
    options.scep_validation = "webhook", a challenge issued by the MDM is sent
    to CERTADILLO_SCEP_VALIDATION_URL together with the CSR before anything is
    signed, and the webhook is told afterwards whether issuance succeeded.
    These apps enroll at /scep/<app name>.
  - RenewalReq (messageType 17) signed by the device's current certificate
    from this CA: no challenge needed.

The request then goes through the normal RA and policy engine like every
other protocol. For profiles that need a second person the reply is PENDING
and the device polls with CertPoll (messageType 20, GetCertInitial) until
the request is approved or rejected.

Message flow (PKIOperation, messageType 19 PKCSReq):
  client SignedData( EnvelopedData(CSR) -> RA cert ), signed by a throwaway self-signed cert
  server SignedData( EnvelopedData(certs-only(issued cert)) -> client cert ), signed by the RA
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets

from asn1crypto import algos, cms, core
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, Depends, Request, Response

from certadillo.api.deps import platform
from certadillo.audit.log import record
from certadillo.db import App, ApprovalRequest, Certificate, CertificateAuthority, ScepChallenge, ScepTransaction
from certadillo.observability.metrics import ISSUANCE_TOTAL
from certadillo.policy.engine import PolicyError
from certadillo.services import Actor, Forbidden, Platform, hash_key

log = logging.getLogger("certadillo.scep")
router = APIRouter(tags=["SCEP"])

OID = {
    "message_type": "2.16.840.1.113733.1.9.2",
    "pki_status": "2.16.840.1.113733.1.9.3",
    "fail_info": "2.16.840.1.113733.1.9.4",
    "sender_nonce": "2.16.840.1.113733.1.9.5",
    "recipient_nonce": "2.16.840.1.113733.1.9.6",
    "transaction_id": "2.16.840.1.113733.1.9.7",
}
PKCS_REQ, RENEWAL_REQ, CERT_REP, GET_CERT_INITIAL = "19", "17", "3", "20"
SUCCESS, FAILURE, PENDING = "0", "2", "3"
BAD_ALG, BAD_MESSAGE_CHECK, BAD_REQUEST, BAD_TIME, BAD_CERT_ID = "0", "1", "2", "3", "4"
CAPS = "POSTPKIOperation\nRenewal\nSHA-256\nSHA-512\nAES\nSCEPStandard\n"
HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class ScepError(Exception):
    def __init__(self, fail_info: str, detail: str):
        self.fail_info, self.detail = fail_info, detail
        super().__init__(detail)


def _attrs(signer: cms.SignerInfo) -> dict:
    out = {}
    for attr in signer["signed_attrs"]:
        oid = attr["type"].dotted
        out[oid] = attr["values"][0]
    return out


def _str(value) -> str:
    if isinstance(value, core.Any):
        value = value.parse(core.PrintableString)
    return value.native


def _octets(value) -> bytes:
    if isinstance(value, core.Any):
        value = value.parse(core.OctetString)
    return value.native


def parse_pki_message(der: bytes):
    """Return (signed_data, signer_info, signer_cert, attrs, content). Verifies the signature."""
    try:
        ci = cms.ContentInfo.load(der)
        if ci["content_type"].native != "signed_data":
            raise ScepError(BAD_REQUEST, "PKIOperation must be CMS SignedData")
        sd = ci["content"]
        signer = sd["signer_infos"][0]
        content = sd["encap_content_info"]["content"].native or b""
    except ScepError:
        raise
    except Exception as e:  # noqa: BLE001 - any parse failure is a bad request
        raise ScepError(BAD_REQUEST, f"cannot parse SCEP message: {e}") from None

    sid = signer["sid"].chosen
    signer_cert = None
    for c in sd["certificates"]:
        cert = c.chosen
        if isinstance(sid, cms.IssuerAndSerialNumber) and cert.issuer == sid["issuer"] and \
                cert.serial_number == sid["serial_number"].native:
            signer_cert = x509.load_der_x509_certificate(cert.dump())
    if signer_cert is None:
        raise ScepError(BAD_MESSAGE_CHECK, "signer certificate not found in the message")

    attrs = _attrs(signer)
    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in HASHES:
        raise ScepError(BAD_REQUEST, f"digest {digest_name} not supported")
    h = hashes.Hash(HASHES[digest_name]())
    h.update(content)
    if _octets(attrs["1.2.840.113549.1.9.4"]) != h.finalize():
        raise ScepError(BAD_MESSAGE_CHECK, "messageDigest does not match content")
    signed_attrs = signer["signed_attrs"].dump()
    to_verify = b"\x31" + signed_attrs[1:]  # [0] IMPLICIT -> SET OF for the signature input
    try:
        signer_cert.public_key().verify(signer["signature"].native, to_verify, padding.PKCS1v15(),
                                        HASHES[digest_name]())
    except (InvalidSignature, TypeError, ValueError):
        raise ScepError(BAD_MESSAGE_CHECK, "request signature does not verify") from None
    return sd, signer, signer_cert, attrs, content


def decrypt_envelope(content: bytes, ra_cert: x509.Certificate, ra_key, allow_des: bool) -> bytes:
    """Open the client's EnvelopedData. Handles AES-CBC and 3DES, and single DES
    only when explicitly allowed (some deployed clients still send it)."""
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives import padding as sympad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    ci = cms.ContentInfo.load(content)
    if ci["content_type"].native != "enveloped_data":
        raise ValueError("pkcsPKIEnvelope must be EnvelopedData")
    env = ci["content"]
    serial = ra_cert.serial_number
    cek = None
    for ri in env["recipient_infos"]:
        ktri = ri.chosen
        rid = ktri["rid"].chosen
        if isinstance(rid, cms.IssuerAndSerialNumber) and rid["serial_number"].native != serial:
            continue
        kalg = ktri["key_encryption_algorithm"]["algorithm"].native
        pad = padding.PKCS1v15() if kalg == "rsaes_pkcs1v15" else padding.OAEP(
            padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
        cek = ra_key.decrypt(ktri["encrypted_key"].native, pad)
    if cek is None:
        raise ValueError("envelope is not addressed to the SCEP RA certificate")
    eci = env["encrypted_content_info"]
    alg = eci["content_encryption_algorithm"]["algorithm"].native
    iv = eci["content_encryption_algorithm"]["parameters"].native
    data = eci["encrypted_content"].native
    if alg in ("aes128_cbc", "aes192_cbc", "aes256_cbc"):
        cipher, block = algorithms.AES(cek), 128
    elif alg == "tripledes_3key":
        cipher, block = TripleDES(cek), 64
    elif alg == "des" and allow_des:
        cipher, block = TripleDES(cek), 64  # an 8-byte key makes 3DES behave as single DES
    else:
        raise ValueError(f"content encryption {alg} not accepted (set CERTADILLO_SCEP_ALLOW_DES=true for legacy DES clients)")
    dec = Cipher(cipher, modes.CBC(iv)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sympad.PKCS7(block).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def load_csr(der: bytes) -> tuple[x509.CertificateSigningRequest, bool, str | None]:
    """Return (csr, pop_verified, challenge).

    Several SCEP clients emit the CSR attribute SET in non-DER order, which
    strict parsers reject. We verify proof of possession over the client's
    original bytes, then hand the policy engine a DER-normalised copy."""
    from asn1crypto import csr as acsr

    req = acsr.CertificationRequest.load(der)
    challenge = None
    for attr in req["certification_request_info"]["attributes"]:
        if attr["type"].native == "challenge_password":
            v = attr["values"][0]
            challenge = v.native if not isinstance(v, core.Any) else v.parse(core.PrintableString).native
    try:
        return x509.load_der_x509_csr(der), False, challenge
    except ValueError:
        pass
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    cri = req["certification_request_info"]
    pub = load_der_public_key(cri["subject_pk_info"].dump())
    alg = req["signature_algorithm"]
    hash_name = alg.hash_algo
    pub.verify(req["signature"].native, cri.dump(), padding.PKCS1v15(), HASHES[hash_name]())
    # rebuild with the attribute SET sorted the way DER requires
    from certadillo.crypto.der import split_sequence, tlv

    parts = split_sequence(cri.dump())
    attrs_tlv = parts[-1]  # [0] IMPLICIT SET OF Attribute
    inner = split_sequence(b"\x30" + attrs_tlv[1:])
    fixed_attrs = bytes([attrs_tlv[0]]) + tlv(0x30, b"".join(sorted(inner)))[1:]
    new_cri = tlv(0x30, b"".join(parts[:-1]) + fixed_attrs)
    new_der = tlv(0x30, new_cri + alg.dump() + req["signature"].dump())
    return x509.load_der_x509_csr(new_der), True, challenge


def _attr(name_or_oid: str, value) -> cms.CMSAttribute:
    oid = OID.get(name_or_oid, name_or_oid)
    return cms.CMSAttribute({"type": cms.CMSAttributeType(oid), "values": [value]})


def build_cert_rep(ra_cert: x509.Certificate, ra_key, transaction_id: str, recipient_nonce: bytes,
                   status: str, envelope: bytes | None = None, fail_info: str | None = None) -> bytes:
    """Signed CertRep. On success the content is the EnvelopedData for the client."""
    content = envelope or b""
    attrs = [
        _attr("1.2.840.113549.1.9.3", cms.ContentType("data")),
        _attr("1.2.840.113549.1.9.4", core.OctetString(hashlib.sha256(content).digest())),
        _attr("message_type", core.PrintableString(CERT_REP)),
        _attr("pki_status", core.PrintableString(status)),
        _attr("transaction_id", core.PrintableString(transaction_id)),
        _attr("sender_nonce", core.OctetString(secrets.token_bytes(16))),
        _attr("recipient_nonce", core.OctetString(recipient_nonce)),
    ]
    if fail_info is not None:
        attrs.append(_attr("fail_info", core.PrintableString(fail_info)))
    signed_attrs = cms.CMSAttributes(attrs)
    signature = ra_key.sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    ra = ax509.Certificate.load(ra_cert.public_bytes(serialization.Encoding.DER))
    signer = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": ra.issuer, "serial_number": ra.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })
    encap = {"content_type": "data"}
    if envelope:
        encap["content"] = envelope
    sd = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": encap,
        "certificates": [ra],
        "signer_infos": [signer],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def validation_call(url: str, token: str | None, payload: dict) -> dict:
    """POST to the validation webhook. Overridable in tests."""
    import httpx

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = httpx.post(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json() if r.content else {}


def _issued_here(p: Platform, cert: x509.Certificate) -> Certificate | None:
    """The Certificate row for a signer cert this platform issued and that is still current."""
    from datetime import datetime, timezone

    row = p.s.query(Certificate).filter_by(
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(), source="issued").one_or_none()
    if row is None or row.ca_id is None or row.status != "active":
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


def _names(obj) -> list[str]:
    try:
        return sorted(str(n.value) for n in obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def handle_pki_operation(p: Platform, der: bytes, app_name: str | None = None) -> bytes:
    ca = p.ca.default_issuing()
    ra_cert, ra_key = p.ca.ensure_scep_ra(ca)
    sd, signer, client_cert, attrs, content = parse_pki_message(der)
    txid = _str(attrs[OID["transaction_id"]])
    nonce = _octets(attrs[OID["sender_nonce"]])
    mtype = _str(attrs[OID["message_type"]])
    webhook: dict = {}

    def fail(info: str, why: str) -> bytes:
        ISSUANCE_TOTAL.labels(profile="", protocol="scep", result="rejected").inc()
        record(p.s, "scep", "certificate.rejected", txid, {"protocol": "scep", "reason": why})
        p.commit()
        if webhook.get("validated"):
            _notify(p, {"event": "failure", "transactionId": txid, "app": webhook["app"], "reason": why})
        return build_cert_rep(ra_cert, ra_key, txid, nonce, FAILURE, fail_info=info)

    def success(row: Certificate) -> bytes:
        issued = x509.load_pem_x509_certificate(row.pem.encode())
        degenerate = pkcs7.serialize_certificates([issued], serialization.Encoding.DER)
        envelope = (pkcs7.PKCS7EnvelopeBuilder().set_data(degenerate).add_recipient(client_cert)
                    .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
        p.commit()
        if webhook.get("validated"):
            _notify(p, {"event": "success", "transactionId": txid, "app": webhook["app"], "serial": row.serial_hex,
                        "thumbprint": issued.fingerprint(hashes.SHA1()).hex(),  # what Intune reports
                        "notAfter": issued.not_valid_after_utc.isoformat(), "issuer": issued.issuer.rfc4514_string()})
        return build_cert_rep(ra_cert, ra_key, txid, nonce, SUCCESS, envelope=envelope)

    poll = lambda: _poll(p, txid, client_cert, fail, success,  # noqa: E731
                         lambda: build_cert_rep(ra_cert, ra_key, txid, nonce, PENDING))
    if mtype == GET_CERT_INITIAL:
        return poll()
    if mtype == PKCS_REQ and p.s.query(ScepTransaction).filter_by(transaction_id=txid).first() is not None:
        # some clients (micromdm scepclient) poll by re-sending the original PKCSReq
        return poll()
    if mtype not in (PKCS_REQ, RENEWAL_REQ):
        return fail(BAD_REQUEST, f"messageType {mtype} not supported")
    try:
        csr_der = decrypt_envelope(content, ra_cert, ra_key, p.settings.scep_allow_des)
    except Exception as e:  # noqa: BLE001
        return fail(BAD_REQUEST, f"cannot decrypt the request envelope: {e}")
    try:
        csr, pop_verified, challenge = load_csr(csr_der)
    except Exception as e:  # noqa: BLE001
        return fail(BAD_MESSAGE_CHECK, f"CSR is malformed or its signature does not verify: {e}")

    current = _issued_here(p, client_cert)
    previous = None
    if mtype == RENEWAL_REQ or (current is not None and not challenge):
        # renewal: the signature with the current certificate is the authentication
        if current is None:
            return fail(BAD_MESSAGE_CHECK, "RenewalReq must be signed by a current certificate issued here")
        app = p.s.get(App, current.app_id) if current.app_id else None
        if app is None or app.status != "active" or (app_name and app.name != app_name):
            return fail(BAD_REQUEST, "the signing certificate does not belong to an active app at this URL")
        cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if (cn[0].value if cn else "") != current.common_name or (_names(csr) and _names(csr) != sorted(current.sans)):
            return fail(BAD_REQUEST, "renewal must keep the subject and names of the current certificate")
        who, previous = Actor(f"scep-renewal:{current.serial_hex}", "app", app.id), current
    else:
        if not challenge:
            return fail(BAD_REQUEST, "CSR has no challengePassword")
        try:
            app = _authorize(p, challenge, csr_der, csr, txid, app_name, webhook)
        except Forbidden as e:
            return fail(BAD_REQUEST, str(e))
        who = Actor(f"scep:{app.name}", "app", app.id)
    try:
        result = p.request_certificate(who, app.id, csr.public_bytes(serialization.Encoding.PEM).decode(),
                                       protocol="scep", pop_verified=pop_verified, previous=previous)
    except (Forbidden, PolicyError) as e:
        return fail(BAD_REQUEST, str(e))
    if isinstance(result, ApprovalRequest):
        p.s.add(ScepTransaction(transaction_id=txid, app_id=app.id, approval_id=result.id,
                                signer_cert_pem=client_cert.public_bytes(serialization.Encoding.PEM).decode(),
                                subject=csr.subject.rfc4514_string()))
        record(p.s, who.name, "scep.pending", txid, {"approval": result.id, "app": app.name})
        p.commit()
        return build_cert_rep(ra_cert, ra_key, txid, nonce, PENDING)
    return success(result)


def _authorize(p: Platform, challenge: str, csr_der: bytes, csr, txid: str, app_name: str | None,
               webhook: dict) -> App:
    """Resolve the app for a challenge-authenticated request."""
    if app_name is None:
        return p.redeem_scep_challenge(challenge)
    app = p.s.query(App).filter_by(name=app_name).one_or_none()
    if app is None or app.status != "active":
        raise Forbidden(f"no active app {app_name}")
    if (app.options or {}).get("scep_validation") != "webhook":
        ch = p.s.query(ScepChallenge).filter_by(challenge_hash=hash_key(challenge)).one_or_none()
        if ch is None or ch.app_id != app.id:
            raise Forbidden("SCEP challenge password is unknown, used or expired")
        return p.redeem_scep_challenge(challenge)
    url = p.settings.scep_validation_url
    if not url:
        raise Forbidden("app uses webhook validation but CERTADILLO_SCEP_VALIDATION_URL is not set")
    payload = {"event": "validate", "transactionId": txid, "app": app.name, "challenge": challenge,
               "csr": base64.b64encode(csr_der).decode(), "subject": csr.subject.rfc4514_string(),
               "sans": _names(csr)}
    try:
        answer = validation_call(url, p.settings.scep_validation_token, payload)
    except Exception as e:  # noqa: BLE001 - fail closed
        raise Forbidden(f"validation webhook unavailable: {e}") from None
    if answer.get("valid") is not True:
        raise Forbidden(f"validation webhook refused the request: {answer.get('reason', 'no reason given')}")
    webhook.update(validated=True, app=app.name)
    record(p.s, f"scep:{app.name}", "scep.webhook.validated", txid, {"subject": payload["subject"]})
    return app


def _notify(p: Platform, payload: dict) -> None:
    try:
        validation_call(p.settings.scep_validation_url, p.settings.scep_validation_token, payload)
    except Exception:  # noqa: BLE001 - the device already has its answer; log and move on
        log.warning("validation webhook notification failed", extra={"event": payload.get("event")})


def _poll(p: Platform, txid: str, client_cert: x509.Certificate, fail, success, pending) -> bytes:
    """CertPoll / GetCertInitial (RFC 8894 3.3.3). Only the device that sent the
    original request, identified by its signing key, gets the answer."""
    txn = (p.s.query(ScepTransaction).filter_by(transaction_id=txid)
           .order_by(ScepTransaction.id.desc()).first())
    if txn is None:
        return fail(BAD_CERT_ID, "no pending request with this transactionID")
    original = x509.load_pem_x509_certificate(txn.signer_cert_pem.encode())
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if original.public_key().public_bytes(serialization.Encoding.DER, spki) != \
            client_cert.public_key().public_bytes(serialization.Encoding.DER, spki):
        return fail(BAD_MESSAGE_CHECK, "CertPoll must be signed by the key that sent the request")
    req = p.s.get(ApprovalRequest, txn.approval_id) if txn.approval_id else None
    if req is not None and not p.approval_intact(req):
        txn.status = "rejected"
        return fail(BAD_REQUEST, "the approval for this request failed its integrity check")
    if req is None or req.status == "rejected":
        txn.status = "rejected"
        return fail(BAD_REQUEST, f"request rejected by {req.decided_by if req else 'the RA'}")
    if req.status == "pending":
        p.commit()
        return pending()
    row = p.s.get(Certificate, req.payload.get("certificate_id")) if req.payload.get("certificate_id") else None
    if row is None:
        return fail(BAD_REQUEST, "approved, but no certificate was issued")
    txn.status, txn.certificate_id = "issued", row.id
    return success(row)


@router.get("/scep", operation_id="scep_get")
@router.post("/scep", operation_id="scep_post")
@router.get("/scep/pkiclient.exe", include_in_schema=False)
@router.post("/scep/pkiclient.exe", include_in_schema=False)
async def scep(request: Request, p: Platform = Depends(platform)):
    return await _scep(request, p, None)


@router.get("/scep/{app_name}", operation_id="scep_app_get")
@router.post("/scep/{app_name}", operation_id="scep_app_post")
@router.get("/scep/{app_name}/pkiclient.exe", include_in_schema=False)
@router.post("/scep/{app_name}/pkiclient.exe", include_in_schema=False)
async def scep_for_app(app_name: str, request: Request, p: Platform = Depends(platform)):
    """Per-app SCEP URL. Required for apps whose challenges are validated by a webhook."""
    return await _scep(request, p, app_name)


async def _scep(request: Request, p: Platform, app_name: str | None):
    import asyncio

    op = request.query_params.get("operation", "")
    if op == "GetCACaps":
        return Response(CAPS, media_type="text/plain")
    if op == "GetCACert":
        ca = p.ca.default_issuing()
        ra_cert, _ = p.ca.ensure_scep_ra(ca)
        p.commit()
        certs = [ra_cert, *p.ca.chain(ca)[:-1]]
        return Response(pkcs7.serialize_certificates(certs, serialization.Encoding.DER),
                        media_type="application/x-x509-ca-ra-cert")
    if op == "PKIOperation":
        if request.method == "POST":
            der = await request.body()
        else:
            der = base64.b64decode(request.query_params.get("message", ""))
        try:
            # off the event loop: a validation webhook call can take seconds
            body = await asyncio.to_thread(handle_pki_operation, p, der, app_name)
        except ScepError as e:
            log.warning("scep rejected", extra={"reason": e.detail})
            return Response(e.detail, status_code=400, media_type="text/plain")
        return Response(body, media_type="application/x-pki-message")
    return Response("operation must be GetCACaps, GetCACert or PKIOperation", status_code=400)
