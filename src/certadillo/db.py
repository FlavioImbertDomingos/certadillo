"""Persistence model. SQLite for dev and tests, PostgreSQL in production."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    LargeBinary,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read; normalise everything to aware UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON}


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    contact_email: Mapped[str] = mapped_column(String(255))
    chat_channel: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    cost_center: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    apps: Mapped[list["App"]] = relationship(back_populates="team")


class App(Base):
    __tablename__ = "apps"
    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    environment: Mapped[str] = mapped_column(String(16))  # dev | test | prod
    profile: Mapped[str] = mapped_column(String(64))
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    data_classification: Mapped[str] = mapped_column(String(32), default="internal")  # internal | confidential | pci
    status: Mapped[str] = mapped_column(String(32), default="pending_approval")
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    team: Mapped[Team] = relationship(back_populates="apps")


class Principal(Base):
    """An API caller: a human operator or an onboarded application."""

    __tablename__ = "principals"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    role: Mapped[str] = mapped_column(String(32))  # admin | approver | operator | auditor | app
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(120), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CertificateAuthority(Base):
    __tablename__ = "cas"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("cas.id"), nullable=True)
    subject: Mapped[str] = mapped_column(String(512))
    cert_pem: Mapped[str] = mapped_column(Text)
    key_ref: Mapped[str] = mapped_column(String(255))
    signer_type: Mapped[str] = mapped_column(String(32))
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    crl_number: Mapped[int] = mapped_column(Integer, default=0)
    crl_last_generated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    crl_der: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ocsp_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    ocsp_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[int] = mapped_column(primary_key=True)
    serial_hex: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    ca_id: Mapped[int | None] = mapped_column(ForeignKey("cas.id"), nullable=True)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    issuer: Mapped[str] = mapped_column(String(512))
    common_name: Mapped[str] = mapped_column(String(255))
    sans: Mapped[list[str]] = mapped_column(JSON, default=list)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
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
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    replaced_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | rejected
    decided_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # unique: two writers racing on the same chain head fail loudly instead of forking it
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64))


class AlertState(Base):
    __tablename__ = "alerts"
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_notified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SSHCertificate(Base):
    __tablename__ = "ssh_certificates"
    id: Mapped[int] = mapped_column(primary_key=True)
    serial: Mapped[int] = mapped_column(BigInteger)
    key_id: Mapped[str] = mapped_column(String(255))
    cert_type: Mapped[str] = mapped_column(String(8))  # user | host
    principals: Mapped[list[str]] = mapped_column(JSON, default=list)
    app_id: Mapped[int | None] = mapped_column(ForeignKey("apps.id"), nullable=True)
    public_key_fp: Mapped[str] = mapped_column(String(128))
    valid_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    cert_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AcmeAccount(Base):
    __tablename__ = "acme_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    thumbprint: Mapped[str] = mapped_column(String(64), unique=True)
    jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    status: Mapped[str] = mapped_column(String(16), default="valid")
    contact: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AcmeOrder(Base):
    __tablename__ = "acme_orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("acme_accounts.id"))
    identifiers: Mapped[list[str]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    certificate_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AcmeAuthz(Base):
    __tablename__ = "acme_authz"
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("acme_orders.id"))
    identifier: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    token: Mapped[str] = mapped_column(String(64))
    challenge_status: Mapped[str] = mapped_column(String(16), default="pending")
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AcmeEab(Base):
    """External Account Binding credential: ties an ACME account to an onboarded app."""

    __tablename__ = "acme_eab"
    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    hmac_key_b64: Mapped[str] = mapped_column(String(128))
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id"))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AcmeNonce(Base):
    __tablename__ = "acme_nonces"
    value: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_engine = None
SessionLocal: sessionmaker | None = None


def init_db(url: str):
    global _engine, SessionLocal
    kwargs: dict[str, Any] = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, future=True, **kwargs)
    Base.metadata.create_all(_engine)
    SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def get_session():
    if SessionLocal is None:
        raise RuntimeError("database not initialised")
    return SessionLocal()
