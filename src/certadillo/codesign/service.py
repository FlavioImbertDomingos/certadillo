"""The code-signing service.

A signing key belongs to one app and lives where CA keys live (PKCS#11 HSM,
Vault Transit, or the software store in a lab). Nobody downloads it. A build
computes the artifact's digest, asks Certadillo to sign it, and gets back a
CMS detached signature (RFC 5652) carrying the code-signing certificate and an
RFC 3161 timestamp, which `openssl cms -verify` and other CMS tooling check.

  - Creating a key is always a second-person decision (`codesign_key_create`).
  - A `release` key needs a second person for every signature (`code_sign`); a
    `test` key signs straight away, for CI.
  - Only the owning app's credentials (or an admin/operator acting for it) can
    ask for a signature.
  - Every request, approval and signature is in the audit trail with the
    artifact name, version and digest.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from certadillo.audit.log import record
from certadillo.codesign import cms as cmslib
from certadillo.codesign import tsa
from certadillo.db import App, Certificate, CertificateAuthority, SigningKey, SigningRequest

NAME = re.compile(r"[a-z0-9][a-z0-9-]{2,60}")
ALGS = {"ec-p384", "rsa-3072", "rsa-4096"}  # what the code-signing profile accepts


def request_key(p, actor, name: str, app_id: int, purpose: str = "release", alg: str = "ec-p384"):
    actor.require("admin", "operator")
    if not NAME.fullmatch(name):
        raise ValueError("key names are 3-61 lowercase letters, digits and hyphens")
    if purpose not in ("release", "test"):
        raise ValueError("purpose must be release or test")
    if alg not in ALGS:
        raise ValueError(f"alg must be one of {', '.join(sorted(ALGS))}")
    app = p.s.get(App, app_id)
    if app is None or app.status != "active":
        raise ValueError("the app must exist and be active")
    if p.s.query(SigningKey).filter_by(name=name).first():
        raise ValueError(f"a signing key named {name} already exists")
    return p._request_approval(actor, "codesign_key_create",
                               {"name": name, "app_id": app_id, "purpose": purpose, "alg": alg})


def create_key_now(p, requested_by: str, decided_by: str, payload: dict) -> dict:
    """Runs when the approval is granted: key in the keystore, certificate from
    the code-signing profile, both recorded."""
    from certadillo.crypto.signers import sign_x509

    app = p.s.get(App, payload["app_id"])
    signer = p.ca.keystore.generate(f"codesign-{payload['name']}", payload["alg"])
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, p.settings.org_name),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, app.name),
                         x509.NameAttribute(NameOID.COMMON_NAME, f"{app.name} code signing ({payload['name']})")])
    csr = sign_x509(x509.CertificateSigningRequestBuilder().subject_name(subject), signer)
    decision = p._evaluate(csr, app, "code-signing")
    from certadillo.services import Actor

    row = p._sign(csr, decision, app, "codesign", Actor(requested_by, "operator"))
    key = SigningKey(name=payload["name"], app_id=app.id, purpose=payload["purpose"], alg=payload["alg"],
                     key_ref=signer.key_ref, signer_type=signer.kind, certificate_id=row.id, created_by=requested_by)
    p.s.add(key)
    p.s.flush()
    record(p.s, decided_by, "codesign.key.create", key.name,
           {"app": app.name, "purpose": key.purpose, "key_ref": key.key_ref, "signer": key.signer_type,
            "certificate": row.serial_hex, "requested_by": requested_by})
    return {"signing_key_id": key.id, "certificate_id": row.id}


def _may_sign(actor, key: SigningKey) -> None:
    if actor.role == "app":
        if actor.app_id != key.app_id:
            raise PermissionError("this signing key belongs to another app")
    elif actor.role not in ("admin", "operator"):
        raise PermissionError("only the owning app, an operator or an admin can request signatures")


def request_signature(p, actor, key_name: str, digest_alg: str, digest_hex: str, artifact: dict) -> SigningRequest:
    from certadillo.services import Forbidden

    key = p.s.query(SigningKey).filter_by(name=key_name).one_or_none()
    if key is None or key.status != "active":
        raise LookupError(f"no active signing key named {key_name}")
    try:
        _may_sign(actor, key)
    except PermissionError as exc:
        raise Forbidden(str(exc)) from None
    digest_alg = (digest_alg or "").lower()
    if digest_alg not in cmslib.HASHES:
        raise ValueError("digest_alg must be sha256, sha384 or sha512")
    if not re.fullmatch(rf"[0-9a-fA-F]{{{cmslib.DIGEST_LEN[digest_alg] * 2}}}", digest_hex or ""):
        raise ValueError(f"digest must be {cmslib.DIGEST_LEN[digest_alg] * 2} hex characters for {digest_alg}")
    art = {k: str(v)[:200] for k, v in (artifact or {}).items() if k in ("name", "version", "commit", "pipeline")}
    if not art.get("name"):
        raise ValueError("artifact.name is required, so the audit trail says what was signed")
    req = SigningRequest(key_id=key.id, requested_by=actor.name, digest_alg=digest_alg,
                         digest_hex=digest_hex.lower(), artifact=art)
    p.s.add(req)
    p.s.flush()
    record(p.s, actor.name, "codesign.request", key.name,
           {"request": req.id, "digest_alg": digest_alg, "digest": req.digest_hex, **art})
    if key.purpose == "release":
        approval = p._request_approval(actor, "code_sign", {"request_id": req.id, "key": key.name,
                                                             "digest": req.digest_hex, **art})
        req.approval_id = approval.id
    else:
        sign_now(p, req.id, "policy:test-key")
    return req


def sign_now(p, request_id: int, decided_by: str) -> None:
    req = p.s.get(SigningRequest, request_id)
    key = p.s.get(SigningKey, req.key_id)
    if req.status != "pending":
        raise ValueError(f"signing request already {req.status}")
    if key.status != "active":
        raise ValueError("the signing key was retired")
    cert_row = p.s.get(Certificate, key.certificate_id)
    from certadillo import integrity

    if cert_row is None or cert_row.status != "active" or not integrity.verify(cert_row):
        raise ValueError("the signing key's certificate is not active")
    cert = x509.load_pem_x509_certificate(cert_row.pem.encode())
    if cert.not_valid_after_utc <= datetime.now(timezone.utc):
        raise ValueError("the signing key's certificate has expired")
    ca = p.s.get(CertificateAuthority, cert_row.ca_id) if cert_row.ca_id else None
    chain = p.ca.chain(ca)[:-1] if ca is not None else []
    signer = p.ca.keystore.load(key.key_ref)
    meta = {}

    def timestamp(signature: bytes):
        token, m = tsa.make_token(p.ca, p.ca.default_issuing(), "sha256", tsa.hashed_signature(signature))
        meta.update(m)
        return token

    info = cmslib.signed_data(signer, cert, chain, req.digest_alg, bytes.fromhex(req.digest_hex),
                              timestamper=timestamp)
    req.signature_der = info.dump()
    req.status, req.signed_at = "signed", datetime.now(timezone.utc)
    record(p.s, decided_by, "codesign.sign", key.name,
           {"request": req.id, "digest_alg": req.digest_alg, "digest": req.digest_hex,
            "certificate": cert_row.serial_hex, "timestamp_serial": meta["serial"], **req.artifact})


def reject(p, request_id: int, decided_by: str) -> None:
    req = p.s.get(SigningRequest, request_id)
    if req is not None and req.status == "pending":
        req.status = "rejected"
        record(p.s, decided_by, "codesign.reject", str(req.id), {"key_id": req.key_id, **req.artifact})


def key_json(p, k: SigningKey) -> dict:
    cert = p.s.get(Certificate, k.certificate_id) if k.certificate_id else None
    app = p.s.get(App, k.app_id)
    return {"id": k.id, "name": k.name, "app": app.name if app else None, "app_id": k.app_id, "purpose": k.purpose,
            "alg": k.alg, "signer": k.signer_type, "status": k.status, "created_by": k.created_by,
            "certificate_id": k.certificate_id, "certificate_pem": cert.pem if cert else None,
            "not_after": cert.not_after.isoformat() if cert else None}


def request_json(p, r: SigningRequest, include_signature: bool = True) -> dict:
    import base64

    key = p.s.get(SigningKey, r.key_id)
    out = {"id": r.id, "key": key.name if key else None, "status": r.status, "requested_by": r.requested_by,
           "digest_alg": r.digest_alg, "digest": r.digest_hex, "artifact": r.artifact,
           "approval_id": r.approval_id, "created_at": r.created_at.isoformat(),
           "signed_at": r.signed_at.isoformat() if r.signed_at else None}
    if include_signature and r.signature_der:
        out["signature_cms"] = base64.b64encode(r.signature_der).decode()
        out["signature_pem"] = "-----BEGIN CMS-----\n" + "\n".join(
            base64.b64encode(r.signature_der).decode()[i:i + 64] for i in range(0, len(base64.b64encode(
                r.signature_der)), 64)) + "\n-----END CMS-----\n"
    return out


def chain_pem(p, key: SigningKey) -> str:
    cert = p.s.get(Certificate, key.certificate_id)
    ca = p.ca.default_issuing() if cert is None or cert.ca_id is None else p.s.get(CertificateAuthority, cert.ca_id)
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in p.ca.chain(ca))
