"""Persistence model. SQLite for dev and tests; PostgreSQL or Oracle Database in production.

Integer primary keys are identity columns, which every supported database
has (Oracle has no SERIAL and no implicit rowid key), and nothing stores an
empty string in a NOT NULL column, because Oracle reads '' back as NULL."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    LargeBinary,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    UniqueConstraint,
    TypeDecorator,
    create_engine,
)
from sqlalchemy.dialects import oracle
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

# Timestamps are timezone-aware everywhere. On Oracle, DateTime(timezone=True)
# would become DATE, which drops the microseconds the audit hash covers, so it
# is TIMESTAMP WITH TIME ZONE there.
TZDateTime = DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), "oracle")


class JSONText(TypeDecorator):
    """JSON kept as text. Oracle's native JSON type hands numbers back as
    Decimal, which would change the canonical form the integrity seals and the
    audit hash are computed over; text round-trips exactly."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else json.dumps(value, separators=(",", ":"), default=str)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return json.loads(value.read() if hasattr(value, "read") else value)


PortableJSON = JSON().with_variant(JSONText(), "oracle")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read; normalise everything to aware UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: PortableJSON, list[str]: PortableJSON}


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    contact_email: Mapped[str] = mapped_column(String(255))
    chat_channel: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # encrypted at rest (webhook URLs are bearer secrets); webhook_url is legacy plaintext
    webhook_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    cost_center: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    apps: Mapped[list["App"]] = relationship(back_populates="team")


class App(Base):
    __tablename__ = "apps"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    environment: Mapped[str] = mapped_column(String(16))  # dev | test | prod
    profile: Mapped[str] = mapped_column(String(64))
    allowed_domains: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    data_classification: Mapped[str] = mapped_column(String(32), default="internal")  # internal | confidential | pci
    status: Mapped[str] = mapped_column(String(32), default="pending_approval")
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    # per-app protocol settings, e.g. {"scep_validation": "webhook"}
    options: Mapped[dict[str, Any] | None] = mapped_column(PortableJSON, nullable=True)
    # where the app sits in the policy tree (None: only its profile applies)
    folder_id: Mapped[int | None] = mapped_column(ForeignKey("policy_folders.id"), nullable=True, index=True)
    # sealed: scope, profile, status and folder decide what the app can get
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)
    team: Mapped[Team] = relationship(back_populates="apps")


class PolicyFolder(Base):
    """A node in the policy tree. settings maps a setting name to
    {"value": ..., "locked": bool}; children inherit values and cannot override
    a locked one. Apps sit in folders and get the merged result."""

    __tablename__ = "policy_folders"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("policy_folders.id"), nullable=True, index=True)
    settings: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Principal(Base):
    """An API caller: a human operator or an onboarded application."""

    __tablename__ = "principals"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    role: Mapped[str] = mapped_column(String(32))  # admin | approver | operator | auditor | app
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(120), default="system")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    # HMAC over the fields that decide access; see certadillo.integrity
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CertificateAuthority(Base):
    __tablename__ = "cas"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("cas.id"), nullable=True)
    subject: Mapped[str] = mapped_column(String(512))
    cert_pem: Mapped[str] = mapped_column(Text)
    key_ref: Mapped[str] = mapped_column(String(255))
    signer_type: Mapped[str] = mapped_column(String(32))
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    crl_number: Mapped[int] = mapped_column(Integer, default=0)
    crl_last_generated: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    crl_der: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ocsp_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    ocsp_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scep_ra_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    scep_ra_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cmp_ra_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    cmp_ra_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # RFC 3161 time-stamping unit signed by this CA (EKU timeStamping)
    tsa_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    tsa_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    serial_hex: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    ca_id: Mapped[int | None] = mapped_column(ForeignKey("cas.id"), nullable=True)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    issuer: Mapped[str] = mapped_column(String(512))
    common_name: Mapped[str] = mapped_column(String(255))
    sans: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    not_before: Mapped[datetime] = mapped_column(TZDateTime)
    not_after: Mapped[datetime] = mapped_column(TZDateTime, index=True)
    key_type: Mapped[str] = mapped_column(String(16))
    key_size: Mapped[int] = mapped_column(Integer)
    sig_alg: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pem: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | revoked | superseded
    source: Mapped[str] = mapped_column(String(16), default="issued")  # issued | discovered | imported
    backend: Mapped[str] = mapped_column(String(32), default="local")
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)  # rest | est | acme | ui
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    replaced_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # for certificates from an upstream CA: its id there (order, ARN, URL) and its chain
    backend_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    chain_pem: Mapped[str | None] = mapped_column(Text, nullable=True)


class ApprovalRequest(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | rejected
    decided_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    ts: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    # unique: two writers racing on the same chain head fail loudly instead of forking it
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64))


class AlertState(Base):
    __tablename__ = "alerts"
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    labels: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_notified: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class SSHCertificate(Base):
    __tablename__ = "ssh_certificates"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    serial: Mapped[int] = mapped_column(BigInteger)
    key_id: Mapped[str] = mapped_column(String(255))
    cert_type: Mapped[str] = mapped_column(String(8))  # user | host
    principals: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    public_key_fp: Mapped[str] = mapped_column(String(128))
    valid_after: Mapped[datetime] = mapped_column(TZDateTime)
    valid_before: Mapped[datetime] = mapped_column(TZDateTime)
    cert_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AcmeAccount(Base):
    __tablename__ = "acme_accounts"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    thumbprint: Mapped[str] = mapped_column(String(64), unique=True)
    jwk: Mapped[dict[str, Any]] = mapped_column(PortableJSON)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    status: Mapped[str] = mapped_column(String(16), default="valid")
    contact: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AcmeOrder(Base):
    __tablename__ = "acme_orders"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("acme_accounts.id"))
    identifiers: Mapped[list[str]] = mapped_column(PortableJSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    expires: Mapped[datetime] = mapped_column(TZDateTime)
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ARI (RFC 9773): the certificate this order renews, as its ARI CertID
    replaces: Mapped[str | None] = mapped_column(String(255), nullable=True)
    replaces_cert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AcmeAuthz(Base):
    __tablename__ = "acme_authz"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("acme_orders.id"))
    identifier: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    token: Mapped[str] = mapped_column(String(64))
    challenge_status: Mapped[str] = mapped_column(String(16), default="pending")
    validated_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    # identifier is the base domain; wildcard orders ("*.x") validate x with dns-01 only
    wildcard: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    challenge_type: Mapped[str | None] = mapped_column(String(16), nullable=True)  # the one that was attempted
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AcmeEab(Base):
    """External Account Binding credential: ties an ACME account to an onboarded app."""

    __tablename__ = "acme_eab"
    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    hmac_key_b64: Mapped[str | None] = mapped_column(String(128), nullable=True)  # legacy plaintext; NULL once encrypted
    hmac_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class ScepChallenge(Base):
    """One-time SCEP challenge password bound to an app (the NDES / Intune dynamic-challenge pattern)."""

    __tablename__ = "scep_challenges"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    challenge_hash: Mapped[str] = mapped_column(String(64), unique=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class RenewalCampaign(Base):
    """A planned early renewal of a set of certificates, advertised to ACME
    clients through ARI (RFC 9773) so they replace certificates on the
    server's schedule, e.g. ahead of a mass revocation."""

    __tablename__ = "renewal_campaigns"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(Text)
    revocation_reason: Mapped[str] = mapped_column(String(32), default="superseded")
    explanation_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    criteria: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    window_start: Mapped[datetime] = mapped_column(TZDateTime)
    window_end: Mapped[datetime] = mapped_column(TZDateTime)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | closed
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class RenewalAdvice(Base):
    __tablename__ = "renewal_advice"
    certificate_id: Mapped[int] = mapped_column(ForeignKey("certificates.id"), primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("renewal_campaigns.id"), index=True)
    window_start: Mapped[datetime] = mapped_column(TZDateTime)
    window_end: Mapped[datetime] = mapped_column(TZDateTime)
    revoked_by_campaign: Mapped[bool] = mapped_column(Boolean, default=False)


class AgilityDrill(Base):
    """A crypto-agility drill: move a set of certificates to a new issuing CA
    (for example an ML-DSA one) and measure how long the estate takes to get
    there. The set is frozen when the drill starts so the percentage means
    the same thing from start to finish."""

    __tablename__ = "agility_drills"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    target_ca: Mapped[str] = mapped_column(String(120))
    source_cas: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    certificate_ids: Mapped[list[int]] = mapped_column(PortableJSON, default=list)
    campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | closed
    started_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)  # final status, kept at close
    created_by: Mapped[str] = mapped_column(String(120))


class Lease(Base):
    """Leader election for background work. Every replica runs the same loops;
    only the one holding an unexpired lease for a task does the work, so CRLs
    are signed once, alerts sent once and audit records shipped once."""

    __tablename__ = "leases"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)  # housekeeping | audit-shipping
    holder: Mapped[str] = mapped_column(String(120))
    acquired_at: Mapped[datetime] = mapped_column(TZDateTime)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)


class ScepTransaction(Base):
    """A SCEP request waiting for a second person (dual-control profiles). The
    client polls with CertPoll (GetCertInitial) until it is approved or rejected."""

    __tablename__ = "scep_transactions"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    transaction_id: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("approvals.id"), nullable=True)
    signer_cert_pem: Mapped[str] = mapped_column(Text)  # the client's cert; the reply is encrypted to it
    subject: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | issued | rejected
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class CmpTransaction(Base):
    """CMP (RFC 9483) transaction state between the certificate response and certConf."""

    __tablename__ = "cmp_transactions"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    transaction_id: Mapped[str] = mapped_column(String(64), unique=True)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    secret_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # MAC-protected transactions
    sender_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)  # signature-protected ones
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    approval_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cert_req_id: Mapped[int] = mapped_column(Integer, default=0)
    body_type: Mapped[str] = mapped_column(String(8), default="ip")  # ip | cp | kup: what the final answer is
    # waiting_conf | confirmed | rejected | pending (a second person must approve) | expired
    status: Mapped[str] = mapped_column(String(16), default="waiting_conf")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class CmpSecret(Base):
    """One-time shared secret for MAC-protected CMP initial enrollment (RFC 9483 4.1.1)."""

    __tablename__ = "cmp_secrets"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    reference: Mapped[str] = mapped_column(String(64), unique=True)  # senderKID
    secret_enc: Mapped[str] = mapped_column(Text)  # encrypted at rest; the MAC needs the plaintext
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    expires_at: Mapped[datetime] = mapped_column(TZDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class EstTrustAnchor(Base):
    """A manufacturer (IDevID) CA whose device certificates may enroll into an app over EST."""

    __tablename__ = "est_trust_anchors"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    name: Mapped[str] = mapped_column(String(120))
    cert_pem: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AdcsJob(Base):
    """Work handed to the AD CS gateway: a domain-joined worker that submits to
    a Microsoft CA with certreq/certutil and posts the result back. Certadillo
    stays the RA (policy, scope, audit); AD CS is the issuing backend."""

    __tablename__ = "adcs_jobs"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    job_type: Mapped[str] = mapped_column(String(16))  # issue | revoke | inventory
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|claimed|done|failed
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    profile: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adcs_ca: Mapped[str | None] = mapped_column(String(255), nullable=True)  # the Microsoft CA config string
    adcs_template: Mapped[str | None] = mapped_column(String(255), nullable=True)
    csr_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    csr_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # dedupe pending issues
    serial_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)  # revoke target
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_chain_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AdcsFinding(Base):
    """A misconfiguration found by the AD CS template audit (read-only).

    One row per (audit run, object, ESC). Kept so the API and alerting can
    show what the last audit found and whether it is new since the previous
    run."""

    __tablename__ = "adcs_findings"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    source: Mapped[str] = mapped_column(String(16), default="ldap")  # ldap | json
    object_type: Mapped[str] = mapped_column(String(16))  # template | ca
    object_name: Mapped[str] = mapped_column(String(255))
    esc: Mapped[str] = mapped_column(String(8), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text)
    principals: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    remark: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class AcmeNonce(Base):
    __tablename__ = "acme_nonces"
    value: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


_engine = None
SessionLocal: sessionmaker | None = None


def drop_everything(engine) -> None:
    """Drop every Certadillo table and the migration history (test databases)."""
    from sqlalchemy import inspect, text

    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        if inspect(conn).has_table("alembic_version"):
            conn.execute(text("DROP TABLE alembic_version"))
        if engine.dialect.name == "postgresql":
            conn.execute(text("DROP FUNCTION IF EXISTS certadillo_audit_append_only() CASCADE"))


def make_engine(url: str, schema: str | None = None):
    """An engine for url. With schema, every connection works in that schema,
    so a restricted application user sees the owner's tables unqualified."""
    import re

    from sqlalchemy import event

    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
    engine = create_engine(url, future=True, **kwargs)
    if schema:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]{0,127}", schema):
            raise ValueError("CERTADILLO_DB_SCHEMA must be a plain identifier")
        if engine.dialect.name == "oracle":
            stmt = f"ALTER SESSION SET CURRENT_SCHEMA = {schema}"
        elif engine.dialect.name == "postgresql":
            stmt = f'SET search_path TO "{schema}"'
        else:
            stmt = None
        if stmt:
            @event.listens_for(engine, "connect")
            def _set_schema(dbapi_conn, _record):
                cur = dbapi_conn.cursor()
                cur.execute(stmt)
                cur.close()
    engine.info_schema = schema  # where the tables (and alembic_version) live, for the migration code
    return engine


def init_db(url: str, auto_migrate: bool = True, schema: str | None = None):
    """Connect, and bring the schema to the newest migration (or, with
    auto_migrate=False, refuse to start on an out-of-date schema so a
    deployment can run `certadillo db migrate` as its own step)."""
    global _engine, SessionLocal
    if _engine is not None:
        _engine.dispose()  # a re-init (tests, CLI) must not leave connections holding locks
    _engine = make_engine(url, schema)
    if auto_migrate:
        migrate(_engine)
    else:
        st = schema_status(_engine)
        if not st["up_to_date"]:
            raise RuntimeError(f"database schema is at {st['current'] or 'nothing'}, this version needs "
                               f"{st['head']}; run `certadillo db migrate` first")
    install_audit_guards(_engine)
    SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


# ------------------------------------------------------------------ migrations (Alembic)
BASELINE = "0001"
_MIGRATE_LOCK = 7243902  # PostgreSQL advisory lock: one replica migrates, the others wait


def _alembic_config():
    from importlib import resources

    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(resources.files("certadillo").joinpath("migrations")))
    return cfg


def schema_status(engine) -> dict:
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    with engine.connect() as conn:
        current = MigrationContext.configure(conn, opts=_version_opts(engine)).get_current_revision()
    return {"current": current, "head": head, "up_to_date": current == head}


def _version_opts(engine) -> dict:
    schema = getattr(engine, "info_schema", None)
    return {"version_table_schema": schema} if schema else {}


def migrate(engine) -> dict:
    """Bring the schema to the newest revision.

    - An empty database gets every table from the model and is stamped at head
      (the migrations and the model are checked against each other in CI).
    - A database made before migrations existed has its missing nullable
      columns added (what start-up used to do), is stamped at the baseline,
      and is then upgraded.
    - Anything else is upgraded from the revision it is at.
    """
    from alembic import command
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect, text

    cfg = _alembic_config()
    with engine.begin() as conn:
        pg = conn.dialect.name == "postgresql"
        if pg:
            conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _MIGRATE_LOCK})
        cfg.attributes["connection"] = conn
        cfg.attributes["version_table_schema"] = getattr(engine, "info_schema", None)
        before = MigrationContext.configure(conn, opts=_version_opts(engine)).get_current_revision()
        ours = {t.name for t in Base.metadata.sorted_tables}
        existing = set(inspect(conn).get_table_names(schema=getattr(engine, "info_schema", None))) & ours
        if before is None and not existing:
            Base.metadata.create_all(conn)
            command.stamp(cfg, "head")
            action = "created"
        elif before is None:
            # tables and nullable columns of the baseline that an older version never created
            baseline = _baseline_metadata()
            baseline.create_all(conn, tables=[t for t in baseline.sorted_tables if t.name not in existing])
            added = add_missing_columns(conn)
            command.stamp(cfg, BASELINE)
            command.upgrade(cfg, "head")
            action = f"adopted ({len(added)} column(s) added)"
        else:
            command.upgrade(cfg, "head")
            action = "upgraded"
        after = MigrationContext.configure(conn, opts=_version_opts(engine)).get_current_revision()
    return {"action": action, "from": before, "to": after}


def autogenerate_filter(dialect_name: str):
    """include_object for Alembic comparisons. Oracle stores an index on a
    TIMESTAMP WITH TIME ZONE column as a function index on SYS_EXTRACT_UTC(col),
    which reflects as an expression, not the column; such indexes are the same
    index, not drift."""
    tz_indexes = set()
    if dialect_name == "oracle":
        for table in Base.metadata.sorted_tables:
            for ix in table.indexes:
                if any(isinstance(getattr(c, "type", None), DateTime) and c.type.timezone for c in ix.columns):
                    tz_indexes.add(ix.name)

    def include(obj, name, type_, reflected, compare_to):
        return not (type_ == "index" and name in tz_indexes)

    return include


def _baseline_metadata():
    """The model as it stood at the baseline migration: current tables cut
    down to the frozen column lists in migrations/baseline_schema.py."""
    from sqlalchemy import MetaData

    from certadillo.migrations.baseline_schema import BASELINE_COLUMNS

    md = MetaData()
    for table in Base.metadata.sorted_tables:
        keep = BASELINE_COLUMNS.get(table.name)
        if keep is None:
            continue
        copy = table.to_metadata(md)
        for col in list(copy.columns):
            if col.name not in keep:
                copy._columns.remove(col)
    return md


def add_missing_columns(conn) -> list[str]:
    """Nullable baseline columns missing from a database made before migrations
    existed (what start-up used to do). Everything since goes through a migration."""
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    added = []
    for table in _baseline_metadata().sorted_tables:
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have or not col.nullable:
                continue
            ddl = col.type.compile(dialect=conn.dialect)
            conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}'))
            added.append(f"{table.name}.{col.name}")
    return added


AUDIT_GUARD_SQLITE = [
    "CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events "
    "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events "
    "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END",
]

AUDIT_GUARD_POSTGRES = [
    "CREATE OR REPLACE FUNCTION certadillo_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
    "BEGIN RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'integrity_constraint_violation'; END $$",
    "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events "
    "FOR EACH ROW EXECUTE FUNCTION certadillo_audit_append_only()",
    "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
    "FOR EACH STATEMENT EXECUTE FUNCTION certadillo_audit_append_only()",
]


AUDIT_GUARD_ORACLE = [
    # row trigger for UPDATE and DELETE; ORA-20001 carries the message
    "CREATE OR REPLACE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW "
    "BEGIN RAISE_APPLICATION_ERROR(-20001, 'audit_events is append-only'); END;",
    # Oracle has no TRUNCATE trigger on a table; a schema DDL trigger refuses it instead
    "CREATE OR REPLACE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON SCHEMA "
    "BEGIN IF ora_dict_obj_name = 'AUDIT_EVENTS' THEN "
    "RAISE_APPLICATION_ERROR(-20001, 'audit_events is append-only'); END IF; END;",
]


def install_audit_guards(engine) -> str:
    """Make audit_events append-only in the database itself, so a bug, an
    injected UPDATE or a hand-run DELETE is refused rather than merely detected
    later by the hash chain. On PostgreSQL the table owner can still drop the
    trigger; `certadillo db harden` moves ownership away from the application
    role so its credential cannot. Returns what was done, for logging."""
    import logging

    from sqlalchemy import text

    name = engine.dialect.name
    try:
        with engine.begin() as conn:
            # OCSP and the CRL look up revocation events by serial
            if name == "sqlite" or (name == "postgresql" and not conn.execute(
                    text("SELECT 1 FROM pg_indexes WHERE indexname = 'ix_audit_action_target'")).first()):
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_action_target "
                                  "ON audit_events (action, target)"))
            if name == "sqlite":
                for stmt in AUDIT_GUARD_SQLITE:
                    conn.execute(text(stmt))
                return "sqlite triggers"
            if name == "postgresql":
                have = {r[0] for r in conn.execute(text(
                    "SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal"))}
                conn.execute(text(AUDIT_GUARD_POSTGRES[0]))  # replaced every start: older versions raised a bare error
                if {"audit_events_append_only", "audit_events_no_truncate"} <= have:
                    return "postgresql triggers present"
                if "audit_events_append_only" not in have:
                    conn.execute(text(AUDIT_GUARD_POSTGRES[1]))
                if "audit_events_no_truncate" not in have:
                    conn.execute(text(AUDIT_GUARD_POSTGRES[2]))
                return "postgresql triggers installed"
            if name == "oracle":
                if not conn.execute(text("SELECT 1 FROM user_indexes WHERE index_name = 'IX_AUDIT_ACTION_TARGET'")).first():
                    conn.execute(text("CREATE INDEX ix_audit_action_target ON audit_events (action, target)"))
                have = {r[0] for r in conn.execute(text(
                    "SELECT trigger_name FROM user_triggers WHERE trigger_name IN "
                    "('AUDIT_EVENTS_APPEND_ONLY', 'AUDIT_EVENTS_NO_TRUNCATE') AND status = 'ENABLED'"))}
                for stmt in AUDIT_GUARD_ORACLE:
                    conn.execute(text(stmt))  # CREATE OR REPLACE also re-enables a disabled trigger's definition
                if have != {"AUDIT_EVENTS_APPEND_ONLY", "AUDIT_EVENTS_NO_TRUNCATE"}:
                    for trg in ("audit_events_append_only", "audit_events_no_truncate"):
                        conn.execute(text(f"ALTER TRIGGER {trg} ENABLE"))
                    return "oracle triggers installed"
                return "oracle triggers present"
    except Exception as exc:  # noqa: BLE001 - a hardened app role may not own the table; harden installs them
        logging.getLogger("certadillo").warning("could not install audit guards: %s", exc)
        return f"not installed: {exc}"
    return f"no guard for {name}"


def get_session():
    if SessionLocal is None:
        raise RuntimeError("database not initialised")
    return SessionLocal()


def harden(engine, app_role: str) -> dict:
    """Least privilege for the application's database role: DML on every
    table, but only SELECT and INSERT on audit_events, and no ownership, so it
    cannot drop or disable the append-only triggers. Run as the owner."""
    import re

    from sqlalchemy import text

    name = engine.dialect.name
    if name == "postgresql":
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", app_role):
            raise ValueError("role names are lowercase letters, digits and underscores")
        r = f'"{app_role}"'
        with engine.begin() as conn:
            if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": app_role}).first():
                raise ValueError(f"role {app_role} does not exist; create it first (CREATE ROLE {app_role} "
                                 "LOGIN PASSWORD '...'), then rerun")
            owner = conn.execute(text("SELECT tableowner FROM pg_tables WHERE tablename = 'audit_events'")).scalar()
            if owner == app_role:
                raise ValueError(f"{app_role} owns the tables; the application role must not be the owner. "
                                 "Run this as a separate owner role and point the app at the restricted role")
            for stmt in (
                f"GRANT USAGE ON SCHEMA public TO {r}",
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {r}",
                f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {r}",
                f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {r}",
                f"REVOKE INSERT, UPDATE, DELETE ON alembic_version FROM {r}",
                f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {r}",
                f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {r}",
            ):
                conn.execute(text(stmt))
        return {"hardened": True, "owner": owner, "app_role": app_role,
                "audit_events": "SELECT, INSERT only for the app role"}
    if name == "oracle":
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_$#]{0,127}", app_role):
            raise ValueError("Oracle user names are letters, digits, _, $ and #, starting with a letter")
        user = app_role.upper()
        with engine.begin() as conn:
            owner = conn.execute(text("SELECT USER FROM dual")).scalar()
            if owner == user:
                raise ValueError(f"{app_role} owns the tables; connect as the owner and pass the application user")
            if not conn.execute(text("SELECT 1 FROM all_users WHERE username = :u"), {"u": user}).first():
                raise ValueError(f"user {app_role} does not exist; create it first (CREATE USER {app_role} "
                                 "IDENTIFIED BY ...; GRANT CREATE SESSION TO ...), then rerun")
            tables = [t.name for t in Base.metadata.sorted_tables] + ["alembic_version"]
            for table in tables:
                if table == "audit_events":
                    privs = "SELECT, INSERT"
                elif table == "alembic_version":
                    privs = "SELECT"
                else:
                    privs = "SELECT, INSERT, UPDATE, DELETE"
                conn.execute(text(f"GRANT {privs} ON {table} TO {user}"))
            # a grant made earlier with more rights is narrowed (REVOKE of a right not held fails)
            held = {r[0] for r in conn.execute(text(
                "SELECT privilege FROM user_tab_privs_made WHERE grantee = :u AND table_name = 'AUDIT_EVENTS'"),
                {"u": user})}
            for priv in held & {"UPDATE", "DELETE"}:
                conn.execute(text(f"REVOKE {priv} ON audit_events FROM {user}"))
        return {"hardened": True, "owner": owner, "app_role": user, "tables": len(tables),
                "audit_events": "SELECT, INSERT only for the app user",
                "next": f"start the application as {user} with CERTADILLO_DB_SCHEMA={owner}"}
    raise ValueError("db harden is for PostgreSQL and Oracle")


class ProvisioningTarget(Base):
    """A place Certadillo pushes certificates to: a load balancer, a host over
    SSH, a Kubernetes cluster or a cloud certificate store. Credentials are a
    reference (env:, file: or vault:), never the secret itself."""

    __tablename__ = "provisioning_targets"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # ssh | kubernetes | f5 | aws-acm
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"))  # only this team's apps may use it
    config: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    credential_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")  # active | pending_approval | disabled
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    # sealed: a database write must not be able to repoint a target or change its reload command
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Installation(Base):
    """One certificate kept installed at one place on a target: Certadillo
    issues it, pushes it, checks the endpoint serves it, and renews it."""

    __tablename__ = "installations"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("provisioning_targets.id"), index=True)
    common_name: Mapped[str] = mapped_column(String(255))
    sans: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    key_type: Mapped[str] = mapped_column(String(16), default="ec-p256")  # ec-p256 | ec-p384 | rsa-2048 | rsa-3072
    key_location: Mapped[str] = mapped_column(String(16), default="central")  # central | device
    params: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)  # driver-specific placement
    validate_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)  # host:port to check
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new")  # new | installed | validated | failed
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    seal: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ProvisioningRun(Base):
    __tablename__ = "provisioning_runs"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id"), index=True)
    trigger: Mapped[str] = mapped_column(String(32))  # manual | renewal | retry | campaign
    status: Mapped[str] = mapped_column(String(16))  # running | ok | failed
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    steps: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str] = mapped_column(String(120))
    started_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class DiscoveryRun(Base):
    """One run of a configured discovery source (cloud stores, CT monitoring)."""

    __tablename__ = "discovery_runs"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    source: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(16))  # ok | failed
    found: Mapped[int] = mapped_column(Integer, default=0)
    new: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class DiscoveryFinding(Base):
    """Something discovery found that is not a certificate property: a private
    key other users can read, or a public certificate for one of our zones that
    nobody requested through Certadillo. Open until it stops being seen or is
    acknowledged."""

    __tablename__ = "discovery_findings"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # key_readable | unknown_public_cert
    key: Mapped[str] = mapped_column(String(255), unique=True)  # dedupe: kind + location / serial
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | resolved | acknowledged
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    acknowledged_by: Mapped[str | None] = mapped_column(String(120), nullable=True)


class SshKey(Base):
    """A static SSH public key found by a host agent: an authorized key (who
    can log in as whom) or a host key. One row per place it was found."""

    __tablename__ = "ssh_keys"
    __table_args__ = (UniqueConstraint("host", "path", "fingerprint", name="uq_ssh_key_place"),)
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # SHA256:..., as ssh-keygen -l prints it
    key_type: Mapped[str] = mapped_column(String(48))
    bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    comment: Mapped[str | None] = mapped_column(String(200), nullable=True)
    kind: Mapped[str] = mapped_column(String(16))  # authorized | host
    host: Mapped[str] = mapped_column(String(255), index=True)
    account: Mapped[str | None] = mapped_column(String(120), nullable=True)
    account_exists: Mapped[bool] = mapped_column(Boolean, default=True)
    path: Mapped[str] = mapped_column(String(512))
    options: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    file_mtime: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="present")  # present | removed
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    owner_note: Mapped[str | None] = mapped_column(String(500), nullable=True)


class ExternalAsset(Base):
    """A cryptographic asset Certadillo does not manage itself, imported from
    another inventory (keycensus: HSM, KMS, Vault and Voltage keys, and the
    certificates it saw), with the applications linked to it there."""

    __tablename__ = "external_assets"
    __table_args__ = (UniqueConstraint("source", "asset_id", name="uq_external_asset"),)
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    source: Mapped[str] = mapped_column(String(32))  # keycensus
    asset_id: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16))  # key | certificate | protocol
    name: Mapped[str] = mapped_column(String(255))
    origin: Mapped[str | None] = mapped_column(String(255), nullable=True)  # the source system in keycensus
    origin_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # pkcs11, aws-kms, vault ...
    algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    curve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hardware_backed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exportable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    expires: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_rotated: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    applications: Mapped[list[str]] = mapped_column(PortableJSON, default=list)
    used_by: Mapped[list[dict[str, Any]]] = mapped_column(PortableJSON, default=list)
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # matched Certadillo certificate
    status: Mapped[str] = mapped_column(String(16), default="present")  # present | removed
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class SigningKey(Base):
    """A code-signing key held where CA keys live (HSM, Vault), owned by one app.
    The key never leaves; Certadillo signs digests with it on request."""

    __tablename__ = "signing_keys"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    purpose: Mapped[str] = mapped_column(String(16))  # release (every signature approved) | test
    alg: Mapped[str] = mapped_column(String(16))
    key_ref: Mapped[str] = mapped_column(String(255))
    signer_type: Mapped[str] = mapped_column(String(32))
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | retired
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class SigningRequest(Base):
    """One request to sign one artifact digest, and its result."""

    __tablename__ = "signing_requests"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    key_id: Mapped[int] = mapped_column(ForeignKey("signing_keys.id"))
    requested_by: Mapped[str] = mapped_column(String(120))
    digest_alg: Mapped[str] = mapped_column(String(16))
    digest_hex: Mapped[str] = mapped_column(String(128))
    artifact: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | signed | rejected | failed
    approval_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature_der: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    signed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class AuditShipCursor(Base):
    """How far each audit sink has been sent. At-least-once: a batch is sent,
    then the cursor moves. Receivers de-duplicate by event hash, and every
    record carries prev_hash, so a skipped range shows up as a break in the
    receiver's copy of the chain."""

    __tablename__ = "audit_ship_cursors"
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    sink: Mapped[str] = mapped_column(String(255), unique=True)
    last_event_id: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
