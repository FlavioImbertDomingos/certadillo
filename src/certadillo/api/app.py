"""HTTP API: REST v1, PKI repository (CA certs, CRL, OCSP, SPIFFE bundle),
EST, ACME, Prometheus metrics and the web console."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from importlib import resources

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from certadillo import __version__
from certadillo.alerting.evaluator import reconcile
from certadillo.alerting.notifiers import build_global_notifiers
from certadillo.api.deps import actor, platform
from certadillo.audit.log import verify_chain
from certadillo.config import Settings
from certadillo.db import AlertState, App, ApprovalRequest, AuditEvent, Certificate, CertificateAuthority, Team, as_utc
from certadillo.discovery.connectors import parse_pem_bundle
from certadillo.discovery.scanner import scan
from certadillo.enrollment import acme, est
from certadillo.observability.logging import configure_logging, request_id
from certadillo.observability.metrics import HTTP_SECONDS
from certadillo.policy.engine import PolicyError
from certadillo.reporting import reports
from certadillo.revocation import ocsp
from certadillo.runtime import get_runtime, init_runtime
from certadillo.services import Actor, Forbidden, NotFound, Platform

log = logging.getLogger("certadillo.api")


# ------------------------------------------------------------------ schemas
class TeamIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    contact_email: str
    chat_channel: str | None = None
    webhook_url: str | None = None
    cost_center: str | None = None


class AppIn(BaseModel):
    team_id: int
    name: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9][a-z0-9-]+$")
    environment: str
    profile: str
    allowed_domains: list[str]
    data_classification: str = "internal"


class PrincipalIn(BaseModel):
    name: str
    role: str


class CertRequestIn(BaseModel):
    app_id: int | None = None
    csr_pem: str
    profile: str | None = None
    validity_days: int | None = Field(default=None, ge=1)
    validity_hours: int | None = Field(default=None, ge=1)


class RenewIn(BaseModel):
    csr_pem: str


class RevokeIn(BaseModel):
    reason: str = "unspecified"
    change_ref: str | None = None


class AssignIn(BaseModel):
    app_id: int


class DecisionIn(BaseModel):
    comment: str | None = None


class SSHIn(BaseModel):
    public_key: str
    cert_type: str = "user"
    principals: list[str]
    key_id: str
    validity_hours: int | None = None
    validity_days: int | None = None
    source_address: str | None = None


class ScanIn(BaseModel):
    targets: list[str]
    timeout: float = 4.0


class ImportIn(BaseModel):
    pem: str
    location: str | None = None
    app_id: int | None = None


class SubCAIn(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    parent: str = "root-ca"
    years: int = 5


# ------------------------------------------------------------------ serializers
def cert_json(c: Certificate, include_pem: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    d = {
        "id": c.id,
        "serial": c.serial_hex,
        "common_name": c.common_name,
        "sans": c.sans,
        "issuer": c.issuer,
        "not_before": as_utc(c.not_before).isoformat(),
        "not_after": as_utc(c.not_after).isoformat(),
        "days_left": (as_utc(c.not_after) - now).days,
        "hours_left": int((as_utc(c.not_after) - now).total_seconds() // 3600),
        "key": f"{c.key_type}-{c.key_size}",
        "signature": c.sig_alg,
        "profile": c.profile,
        "status": c.status,
        "source": c.source,
        "protocol": c.protocol,
        "backend": c.backend,
        "location": c.location,
        "app_id": c.app_id,
        "fingerprint_sha256": c.fingerprint_sha256,
        "revocation_reason": c.revocation_reason,
        "replaced_by": c.replaced_by,
    }
    if include_pem:
        d["pem"] = c.pem
    return d


def issued_json(p: Platform, c: Certificate) -> dict:
    """Leaf plus intermediates (root excluded; clients get it out of band)."""
    out = cert_json(c, include_pem=True)
    chain = p.ca.chain(p.s.get(CertificateAuthority, c.ca_id)) if c.ca_id else []
    out["chain_pem"] = "".join(x.public_bytes(serialization.Encoding.PEM).decode() for x in chain[:-1])
    return out


def app_json(a: App) -> dict:
    return {
        "id": a.id, "name": a.name, "team_id": a.team_id, "environment": a.environment, "profile": a.profile,
        "allowed_domains": a.allowed_domains, "data_classification": a.data_classification, "status": a.status,
        "created_by": a.created_by, "created_at": as_utc(a.created_at).isoformat(),
    }


def approval_json(r: ApprovalRequest) -> dict:
    payload = {k: v for k, v in r.payload.items() if k != "csr_pem"}
    return {
        "id": r.id, "action": r.action, "payload": payload, "requested_by": r.requested_by, "status": r.status,
        "decided_by": r.decided_by, "comment": r.comment, "created_at": as_utc(r.created_at).isoformat(),
    }


# ------------------------------------------------------------------ background jobs
def run_housekeeping() -> dict:
    """Publish CRLs that are due, then evaluate alerts."""
    rt = get_runtime()
    with rt.platform() as p:
        now = datetime.now(timezone.utc)
        for ca in p.s.query(CertificateAuthority).filter_by(is_root=False).all():
            last = as_utc(ca.crl_last_generated)
            if last is None or now - last >= timedelta(hours=rt.settings.crl_interval_hours):
                p.ca.generate_crl(ca)
            if ca.ocsp_cert_pem:
                ocsp_cert = x509.load_pem_x509_certificate(ca.ocsp_cert_pem.encode())
                if ocsp_cert.not_valid_after_utc - now < timedelta(days=7):
                    p.ca.rotate_ocsp_signer(ca)
        return reconcile(p.s, rt.settings, rt.policies, build_global_notifiers(rt.settings))


async def _loop(interval: int):
    while True:
        try:
            await asyncio.to_thread(run_housekeeping)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")
        await asyncio.sleep(interval)


# ------------------------------------------------------------------ app factory
def create_app(settings: Settings | None = None, background: bool = True) -> FastAPI:
    configure_logging()
    init_runtime(settings)

    @asynccontextmanager
    async def lifespan(_app):
        task = asyncio.create_task(_loop(get_runtime().settings.alert_interval_seconds)) if background else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Certadillo", version=__version__, lifespan=lifespan,
                  description="Open source PKI and certificate lifecycle platform")

    @app.middleware("http")
    async def observe(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        token = request_id.set(rid)
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            route = request.scope.get("route")
            path = getattr(route, "path", "unmatched")
            HTTP_SECONDS.labels(request.method, path, str(status)).observe(time.perf_counter() - start)
            if path not in ("/metrics", "/healthz"):
                log.info("request", extra={"method": request.method, "path": path, "status": status,
                                           "ms": round((time.perf_counter() - start) * 1000, 1)})
            request_id.reset(token)

    @app.exception_handler(PolicyError)
    async def _policy(_r, e: PolicyError):
        return JSONResponse({"error": "policy_violation", "violations": [{"rule": r, "message": m} for r, m in e.violations]}, 422)

    @app.exception_handler(Forbidden)
    async def _forbidden(_r, e):
        return JSONResponse({"error": "forbidden", "message": str(e)}, 403)

    @app.exception_handler(NotFound)
    async def _nf(_r, e):
        return JSONResponse({"error": "not_found", "message": str(e)}, 404)

    @app.exception_handler(LookupError)
    async def _lookup(_r, e):
        return JSONResponse({"error": "not_found", "message": str(e)}, 404)

    @app.exception_handler(ValueError)
    async def _value(_r, e):
        return JSONResponse({"error": "bad_request", "message": str(e)}, 400)

    # ---------------------------------------------------------- health, metrics
    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    def readyz(p: Platform = Depends(platform)):
        p.ca.default_issuing()
        return {"status": "ready"}

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ---------------------------------------------------------- identity
    @app.get("/api/v1/me", tags=["identity"])
    def me(who: Actor = Depends(actor)):
        return {"name": who.name, "role": who.role, "app_id": who.app_id}

    @app.post("/api/v1/principals", status_code=201, tags=["identity"])
    def create_principal(body: PrincipalIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        key = p.create_principal(who, body.name, body.role)
        p.commit()
        return {"name": body.name, "role": body.role, "api_key": key, "note": "shown once; store it in your vault"}

    @app.post("/api/v1/principals/{name}/deactivate", tags=["identity"])
    def deactivate_principal(name: str, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        p.deactivate_principal(who, name)
        p.commit()
        return {"name": name, "active": False}

    # ---------------------------------------------------------- onboarding
    @app.get("/api/v1/profiles", tags=["onboarding"])
    def profiles(p: Platform = Depends(platform)):
        return {k: {"description": v.get("description", ""), "max_validity_days": v.get("max_validity_days"),
                    "max_validity_hours": v.get("max_validity_hours"), "dual_control": bool(v.get("dual_control"))}
                for k, v in p.policies["profiles"].items()}

    @app.post("/api/v1/teams", status_code=201, tags=["onboarding"])
    def create_team(body: TeamIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        t = p.create_team(who, **body.model_dump())
        p.commit()
        return {"id": t.id, "name": t.name}

    @app.get("/api/v1/teams", tags=["onboarding"])
    def list_teams(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return [{"id": t.id, "name": t.name, "contact_email": t.contact_email, "chat_channel": t.chat_channel,
                 "cost_center": t.cost_center, "apps": len(t.apps)} for t in p.s.query(Team).order_by(Team.name)]

    @app.post("/api/v1/apps", status_code=201, tags=["onboarding"])
    def create_app_(body: AppIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        a, approval = p.onboard_app(who, **body.model_dump())
        p.commit()
        out = app_json(a)
        if approval:
            out["approval_id"] = approval.id
        return out

    @app.get("/api/v1/apps", tags=["onboarding"])
    def list_apps(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return [app_json(a) for a in p.s.query(App).order_by(App.name)]

    @app.get("/api/v1/apps/{app_id}", tags=["onboarding"])
    def get_app(app_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        a = p.s.get(App, app_id)
        if a is None or (who.role == "app" and who.app_id != app_id):
            raise NotFound("app not found")
        return app_json(a)

    @app.post("/api/v1/apps/{app_id}/credentials", status_code=201, tags=["onboarding"])
    def app_credentials(app_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        key = p.mint_app_credential(who, app_id)
        p.commit()
        return {"api_key": key, "note": "shown once; use it as X-API-Key, Bearer token, or EST Basic password"}

    @app.post("/api/v1/apps/{app_id}/acme-eab", status_code=201, tags=["onboarding"])
    def app_eab(app_id: int, request: Request, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        cred = p.mint_acme_eab(who, app_id)
        p.commit()
        server = str(request.base_url).rstrip("/") + "/acme/directory"
        cred["example"] = (f"certbot certonly --server {server} --eab-kid {cred['kid']} "
                           f"--eab-hmac-key {cred['hmac_key']} -d <name>")
        return cred

    @app.get("/api/v1/approvals", tags=["governance"])
    def list_approvals(status: str | None = None, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        q = p.s.query(ApprovalRequest)
        if status:
            q = q.filter_by(status=status)
        return [approval_json(r) for r in q.order_by(ApprovalRequest.id.desc())]

    @app.post("/api/v1/approvals/{approval_id}/approve", tags=["governance"])
    def approve(approval_id: int, body: DecisionIn | None = None, p: Platform = Depends(platform),
                who: Actor = Depends(actor)):
        r = p.decide(who, approval_id, True, body.comment if body else None)
        p.commit()
        return approval_json(r)

    @app.post("/api/v1/approvals/{approval_id}/reject", tags=["governance"])
    def reject(approval_id: int, body: DecisionIn | None = None, p: Platform = Depends(platform),
               who: Actor = Depends(actor)):
        r = p.decide(who, approval_id, False, body.comment if body else None)
        p.commit()
        return approval_json(r)

    # ---------------------------------------------------------- certificates
    @app.post("/api/v1/certificates", tags=["certificates"])
    def request_cert(body: CertRequestIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        app_id = body.app_id or who.app_id
        if app_id is None:
            raise ValueError("app_id is required")
        result = p.request_certificate(who, app_id, body.csr_pem, body.profile, body.validity_days,
                                       body.validity_hours, protocol="rest")
        p.commit()
        if isinstance(result, ApprovalRequest):
            return JSONResponse({"status": "pending_approval", "approval_id": result.id}, 202)
        return JSONResponse(issued_json(p, result), 201)

    @app.get("/api/v1/certificates", tags=["certificates"])
    def list_certs(status: str | None = None, source: str | None = None, app_id: int | None = None,
                   expiring_within_days: int | None = None, renewal_due: bool = False,
                   limit: int = Query(500, le=5000),
                   p: Platform = Depends(platform), who: Actor = Depends(actor)):
        q = p.s.query(Certificate)
        if who.role == "app":
            q = q.filter_by(app_id=who.app_id)
        if status:
            q = q.filter_by(status=status)
        if source:
            q = q.filter_by(source=source)
        if app_id:
            q = q.filter_by(app_id=app_id)
        if expiring_within_days is not None:
            q = q.filter(Certificate.not_after <= datetime.now(timezone.utc) + timedelta(days=expiring_within_days))
        rows = q.order_by(Certificate.not_after).limit(limit).all()
        if renewal_due:
            from certadillo.alerting.evaluator import expiry_state

            rows = [c for c in rows if expiry_state(c.not_before, c.not_after, p.settings)]
        return [cert_json(c) for c in rows]

    @app.get("/api/v1/certificates/{cert_id}", tags=["certificates"])
    def get_cert(cert_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        c = p.s.get(Certificate, cert_id)
        if c is None or (who.role == "app" and c.app_id != who.app_id):
            raise NotFound("certificate not found")
        return cert_json(c, include_pem=True)

    @app.post("/api/v1/certificates/{cert_id}/renew", tags=["certificates"])
    def renew(cert_id: int, body: RenewIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        result = p.renew(who, cert_id, body.csr_pem)
        p.commit()
        if isinstance(result, ApprovalRequest):
            return JSONResponse({"status": "pending_approval", "approval_id": result.id}, 202)
        return JSONResponse(issued_json(p, result), 201)

    @app.post("/api/v1/certificates/{cert_id}/revoke", tags=["certificates"])
    def revoke(cert_id: int, body: RevokeIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        row = p.revoke(who, cert_id, body.reason, body.change_ref)
        p.commit()
        return cert_json(row)

    @app.post("/api/v1/certificates/{cert_id}/assign", tags=["inventory"])
    def assign(cert_id: int, body: AssignIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.audit.log import record

        who.require("admin", "operator")
        c = p.s.get(Certificate, cert_id)
        if c is None or p.s.get(App, body.app_id) is None:
            raise NotFound("certificate or app not found")
        c.app_id = body.app_id
        record(p.s, who.name, "certificate.assign", c.serial_hex, {"app_id": body.app_id})
        p.commit()
        return cert_json(c)

    # ---------------------------------------------------------- SSH
    @app.get("/api/v1/ssh/ca", tags=["ssh"], response_class=PlainTextResponse)
    def ssh_ca(p: Platform = Depends(platform)):
        return p.ssh.public_key_line() + "\n"

    @app.post("/api/v1/ssh/certificates", status_code=201, tags=["ssh"])
    def ssh_issue(body: SSHIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        row = p.issue_ssh(who, body.public_key, body.cert_type, body.principals, body.key_id,
                          body.validity_hours, body.validity_days, body.source_address)
        p.commit()
        return {"id": row.id, "serial": row.serial, "valid_before": as_utc(row.valid_before).isoformat(),
                "certificate": row.cert_text}

    # ---------------------------------------------------------- discovery / inventory
    @app.post("/api/v1/discovery/scan", tags=["inventory"])
    def discovery(body: ScanIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator")
        out = []
        for r in scan(body.targets, timeout=body.timeout):
            if r.cert is None:
                out.append({"target": r.target, "error": r.error})
                continue
            row, findings, new = p.ingest(who.name, r.cert, "discovered", r.target)
            out.append({"target": r.target, "certificate_id": row.id, "new": new, "common_name": row.common_name,
                        "not_after": as_utc(row.not_after).isoformat(),
                        "findings": [{"rule": a, "message": b} for a, b in findings]})
        p.commit()
        return out

    @app.post("/api/v1/inventory/import", tags=["inventory"])
    def import_pem(body: ImportIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator")
        out = []
        for cert in parse_pem_bundle(body.pem):
            row, findings, new = p.ingest(who.name, cert, "imported", body.location, body.app_id)
            out.append({"certificate_id": row.id, "new": new, "findings": [f[0] for f in findings]})
        p.commit()
        return out

    # ---------------------------------------------------------- CA admin
    @app.get("/api/v1/cas", tags=["ca"])
    def list_cas(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        out = []
        for ca in p.s.query(CertificateAuthority).all():
            c = x509.load_pem_x509_certificate(ca.cert_pem.encode())
            out.append({"name": ca.name, "subject": ca.subject, "root": ca.is_root, "signer": ca.signer_type,
                        "not_after": c.not_valid_after_utc.isoformat(), "crl_number": ca.crl_number})
        return out

    @app.post("/api/v1/cas", status_code=202, tags=["ca"])
    def create_sub_ca(body: SubCAIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin")
        p.ca.check_can_sign_ca(p.ca.get(body.parent))
        if p.s.query(CertificateAuthority).filter_by(name=body.name).first():
            raise ValueError(f"CA {body.name} already exists")
        req = p._request_approval(who, "create_ca", body.model_dump())
        p.commit()
        return {"status": "pending_approval", "approval_id": req.id}

    # ---------------------------------------------------------- alerts, audit, reports
    @app.get("/api/v1/alerts", tags=["observability"])
    def alerts(include_resolved: bool = False, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        q = p.s.query(AlertState)
        if not include_resolved:
            q = q.filter(AlertState.resolved_at.is_(None))
        order = {"critical": 0, "warning": 1, "info": 2}
        rows = sorted(q.all(), key=lambda a: (order.get(a.severity, 3), a.rule))
        return [{"fingerprint": a.fingerprint, "rule": a.rule, "severity": a.severity, "summary": a.summary,
                 "labels": a.labels, "first_seen": as_utc(a.first_seen).isoformat(),
                 "resolved_at": as_utc(a.resolved_at).isoformat() if a.resolved_at else None} for a in rows]

    @app.post("/api/v1/alerts/evaluate", tags=["observability"])
    def evaluate_now(who: Actor = Depends(actor)):
        who.require("admin", "operator")
        return run_housekeeping()

    @app.get("/api/v1/audit", tags=["governance"])
    def audit(limit: int = Query(100, le=1000), p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "auditor", "approver", "operator")
        return [{"id": e.id, "ts": as_utc(e.ts).isoformat(), "actor": e.actor, "action": e.action, "target": e.target,
                 "details": e.details, "hash": e.hash}
                for e in p.s.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)]

    @app.get("/api/v1/audit/verify", tags=["governance"])
    def audit_verify(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return verify_chain(p.s)

    @app.get("/api/v1/reports/summary", tags=["reports"])
    def report_summary(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return reports.summary(p.s, p.settings)

    @app.get("/api/v1/reports/crypto", tags=["reports"])
    def report_crypto(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return reports.crypto_report(p.s)

    @app.get("/api/v1/reports/cbom", tags=["reports"])
    def report_cbom(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        return reports.cbom(p.s)

    @app.get("/api/v1/reports/pci-inventory", tags=["reports"])
    def report_pci(format: str = "json", p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "approver", "auditor")
        data = reports.pci_inventory(p.s, format)
        if format == "csv":
            return PlainTextResponse(data, media_type="text/csv",
                                     headers={"Content-Disposition": 'attachment; filename="pci-4.2.1.1-inventory.csv"'})
        return data

    # ---------------------------------------------------------- public PKI repository
    @app.get("/pki/ca/{name}.crt", tags=["pki"])
    def ca_der(name: str, p: Platform = Depends(platform)):
        c = x509.load_pem_x509_certificate(p.ca.get(name).cert_pem.encode())
        return Response(c.public_bytes(serialization.Encoding.DER), media_type="application/pkix-cert")

    @app.get("/pki/ca/{name}.pem", tags=["pki"], response_class=PlainTextResponse)
    def ca_pem(name: str, p: Platform = Depends(platform)):
        return p.ca.get(name).cert_pem

    @app.get("/pki/crl/{name}.crl", tags=["pki"])
    def crl(name: str, p: Platform = Depends(platform)):
        der = p.ca.current_crl(p.ca.get(name))
        p.commit()
        return Response(der, media_type="application/pkix-crl", headers={"Cache-Control": "max-age=300"})

    @app.post("/pki/ocsp", tags=["pki"])
    async def ocsp_post(request: Request, p: Platform = Depends(platform)):
        der = ocsp.respond(p.s, p.ca, await request.body())
        p.commit()
        return Response(der, media_type="application/ocsp-response")

    @app.get("/pki/ocsp/{encoded:path}", tags=["pki"])
    def ocsp_get(encoded: str, p: Platform = Depends(platform)):
        from urllib.parse import unquote

        der = ocsp.respond(p.s, p.ca, base64.b64decode(unquote(encoded)))
        p.commit()
        return Response(der, media_type="application/ocsp-response", headers={"Cache-Control": "max-age=300"})

    @app.get("/pki/spiffe/bundle", tags=["pki"])
    def spiffe_bundle(p: Platform = Depends(platform)):
        """SPIFFE trust bundle (JWKS form) for workloads and SPIRE federation."""
        from certadillo.enrollment.acme import b64u

        keys = []
        for ca in p.s.query(CertificateAuthority).all():
            c = x509.load_pem_x509_certificate(ca.cert_pem.encode())
            if not ca.is_root:
                continue
            pub = c.public_key()
            jwk = {"use": "x509-svid", "x5c": [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()]}
            nums = pub.public_numbers()
            if hasattr(nums, "curve"):
                size = (pub.curve.key_size + 7) // 8
                jwk.update(kty="EC", crv={"secp256r1": "P-256", "secp384r1": "P-384"}.get(pub.curve.name, pub.curve.name),
                           x=b64u(nums.x.to_bytes(size, "big")), y=b64u(nums.y.to_bytes(size, "big")))
            else:
                jwk.update(kty="RSA", n=b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
                           e=b64u(nums.e.to_bytes(3, "big")))
            keys.append(jwk)
        return {"keys": keys, "spiffe_sequence": 1, "spiffe_refresh_hint": 300,
                "trust_domain": p.policies.get("spiffe_trust_domain")}

    app.include_router(est.router)
    app.include_router(acme.router)

    # ---------------------------------------------------------- web console
    static_dir = resources.files("certadillo").joinpath("web/static")
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(static_dir.joinpath("index.html")))

    return app


def main_app() -> FastAPI:  # uvicorn --factory certadillo.api.app:main_app
    return create_app()
