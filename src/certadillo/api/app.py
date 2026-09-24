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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from certadillo import __version__
from certadillo.alerting.evaluator import reconcile
from certadillo.alerting.notifiers import build_global_notifiers
from certadillo.api.deps import actor, platform
from certadillo.audit.log import verify_chain
from certadillo.config import Settings
from certadillo.db import (
    AdcsJob,
    AlertState,
    App,
    ApprovalRequest,
    AuditEvent,
    Certificate,
    CertificateAuthority,
    Team,
    as_utc,
)
from certadillo.discovery.connectors import parse_pem_bundle
from certadillo.discovery.scanner import scan
from certadillo.enrollment import acme, cmp, est, scep
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


class CampaignIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    reason: str = Field(min_length=3)
    criteria: dict
    renew_within_hours: int = Field(default=24, ge=1, le=720)
    explanation_url: str | None = None
    revocation_reason: str = "superseded"
    immediate: bool = False


class ChangeRefIn(BaseModel):
    change_ref: str | None = None


class AppOptionsIn(BaseModel):
    scep_validation: str | None = Field(default=None, pattern=r"^(challenge|webhook)$")


class TrustAnchorIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    cert_pem: str


class SubCAIn(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    parent: str = "root-ca"
    years: int = 5


class AdcsImportIn(BaseModel):
    """The document produced by Export-CertadilloAdcsTemplates."""

    document: dict


class AdcsJobCompleteIn(BaseModel):
    certificate_pem: str | None = None
    chain_pem: str | None = None
    error: str | None = None
    certificates: list[dict] | None = None  # inventory results


class AdcsInventoryIn(BaseModel):
    ca: str


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


def gateway_job_json(j: AdcsJob) -> dict:
    return {
        "id": j.id, "type": j.job_type, "status": j.status,
        "app_id": j.app_id, "profile": j.profile,
        "adcs_ca": j.adcs_ca, "adcs_template": j.adcs_template,
        "csr_pem": j.csr_pem, "serial": j.serial_hex, "reason": j.reason,
        "certificate_id": j.certificate_id, "error": j.error,
        "created_at": as_utc(j.created_at).isoformat() if j.created_at else None,
        "claimed_by": j.claimed_by,
    }


def app_json(a: App) -> dict:
    return {
        "id": a.id, "name": a.name, "team_id": a.team_id, "environment": a.environment, "profile": a.profile,
        "allowed_domains": a.allowed_domains, "data_classification": a.data_classification, "status": a.status,
        "created_by": a.created_by, "created_at": as_utc(a.created_at).isoformat(), "options": a.options or {},
    }


def approval_json(r: ApprovalRequest) -> dict:
    payload = {k: v for k, v in r.payload.items() if not k.endswith("_pem")}
    return {
        "id": r.id, "action": r.action, "payload": payload, "requested_by": r.requested_by, "status": r.status,
        "decided_by": r.decided_by, "comment": r.comment, "created_at": as_utc(r.created_at).isoformat(),
    }


# ------------------------------------------------------------------ background jobs
def run_housekeeping() -> dict:
    """Publish CRLs that are due, clean up protocol state, then evaluate alerts."""
    rt = get_runtime()
    with rt.platform() as p:
        acme.housekeeping(p.s)
        cmp.housekeeping(p.s)
        now = datetime.now(timezone.utc)
        for ca in p.s.query(CertificateAuthority).filter_by(is_root=False).all():
            last = as_utc(ca.crl_last_generated)
            if last is None or now - last >= timedelta(hours=rt.settings.crl_interval_hours):
                p.ca.generate_crl(ca)
            if ca.ocsp_cert_pem:
                ocsp_cert = x509.load_pem_x509_certificate(ca.ocsp_cert_pem.encode())
                if ocsp_cert.not_valid_after_utc - now < timedelta(days=7):
                    p.ca.rotate_ocsp_signer(ca)
        from certadillo.audit.log import maybe_anchor

        maybe_anchor(p.s, rt.settings)
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

    @app.post("/api/v1/apps/{app_id}/scep-challenge", status_code=201, tags=["onboarding"])
    def app_scep_challenge(app_id: int, request: Request, ttl_minutes: int = Query(60, ge=5, le=1440),
                           p: Platform = Depends(platform), who: Actor = Depends(actor)):
        out = p.mint_scep_challenge(who, app_id, ttl_minutes)
        p.commit()
        out["server_url"] = str(request.base_url).rstrip("/") + "/scep"
        return out

    @app.put("/api/v1/apps/{app_id}/options", tags=["onboarding"])
    def set_app_options(app_id: int, body: AppOptionsIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Protocol settings per app. scep_validation: "challenge" (one-time challenges
        from this platform) or "webhook" (challenges issued by an MDM such as Intune,
        checked by CERTADILLO_SCEP_VALIDATION_URL)."""
        from certadillo.audit.log import record

        who.require("admin", "operator")
        a = p.s.get(App, app_id)
        if a is None:
            raise NotFound("app not found")
        opts = dict(a.options or {})
        opts.update({k: v for k, v in body.model_dump().items() if v is not None})
        a.options = opts
        record(p.s, who.name, "app.options", a.name, opts)
        p.commit()
        return app_json(a)

    @app.post("/api/v1/apps/{app_id}/est-trust-anchors", status_code=201, tags=["onboarding"])
    def add_trust_anchor(app_id: int, body: TrustAnchorIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Let devices with a manufacturer (IDevID) certificate from this CA enroll into the app over EST.
        For production apps this needs a second person."""
        out = p.add_est_trust_anchor(who, app_id, body.name, body.cert_pem)
        p.commit()
        if isinstance(out, ApprovalRequest):
            return JSONResponse({"status": "pending_approval", "approval_id": out.id}, 202)
        return out

    @app.get("/api/v1/apps/{app_id}/est-trust-anchors", tags=["onboarding"])
    def list_trust_anchors(app_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.db import EstTrustAnchor

        who.require("admin", "operator", "approver", "auditor")
        return [{"id": t.id, "name": t.name, "subject": x509.load_pem_x509_certificate(t.cert_pem.encode()).subject.rfc4514_string(),
                 "created_by": t.created_by, "created_at": as_utc(t.created_at).isoformat()}
                for t in p.s.query(EstTrustAnchor).filter_by(app_id=app_id)]

    @app.post("/api/v1/apps/{app_id}/cmp-secret", status_code=201, tags=["onboarding"])
    def app_cmp_secret(app_id: int, request: Request, ttl_minutes: int = Query(60, ge=5, le=1440),
                       p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """One-time reference and shared secret for a device's first CMP enrollment (MAC protection)."""
        out = p.mint_cmp_secret(who, app_id, ttl_minutes)
        p.commit()
        host = request.base_url.netloc
        out["server"] = f"{host}/.well-known/cmp"
        out["example"] = (f"openssl cmp -cmd ir -server {host} -path .well-known/cmp -ref {out['reference']} "
                          f"-secret pass:{out['secret']} -newkey device.key -subject /CN=<name> -sans <name> "
                          "-certout device.crt -cacertsout root.pem -implicit_confirm")
        return out

    @app.get("/api/v1/approvals", tags=["governance"])
    def list_approvals(status: str | None = None, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        q = p.s.query(ApprovalRequest)
        if status:
            q = q.filter_by(status=status)
        rows = q.order_by(ApprovalRequest.id.desc()).all()
        if who.role == "app":  # an app sees only requests about itself
            rows = [r for r in rows if r.payload.get("app_id") == who.app_id]
        return [approval_json(r) for r in rows]

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
        if isinstance(result, AdcsJob):
            return JSONResponse({"status": "gateway_queued", "job_id": result.id,
                                 "poll": f"/api/v1/adcs/gateway/jobs/{result.id}"}, 202)
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
        if isinstance(result, AdcsJob):
            return JSONResponse({"status": "gateway_queued", "job_id": result.id,
                                 "poll": f"/api/v1/adcs/gateway/jobs/{result.id}"}, 202)
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

    @app.get("/api/v1/certificates/{cert_id}/renewal-info", tags=["certificates"])
    def cert_renewal_info(cert_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """The ARI window for any certificate issued here, for clients that do not speak ACME."""
        from certadillo.enrollment import ari

        c = p.s.get(Certificate, cert_id)
        if c is None or c.source != "issued" or (who.role == "app" and c.app_id != who.app_id):
            raise NotFound("certificate not found")
        start, end, why = ari.suggested_window(p.s, c)
        return {"cert_id": ari.cert_id(x509.load_pem_x509_certificate(c.pem.encode())),
                "suggested_window": {"start": start.isoformat(), "end": end.isoformat()},
                "explanation_url": why, "renew_now": datetime.now(timezone.utc) >= start}

    # ---------------------------------------------------------- renewal campaigns (ARI)
    @app.post("/api/v1/renewal-campaigns", status_code=201, tags=["renewal campaigns"])
    def create_campaign(body: CampaignIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.enrollment import ari

        camp = p.create_campaign(who, **body.model_dump())
        p.commit()
        out = ari.campaign_status(p.s, camp)
        out["warnings"] = ari.campaign_warnings(body.renew_within_hours, p.settings.ari_retry_after_seconds)
        return out

    @app.get("/api/v1/renewal-campaigns", tags=["renewal campaigns"])
    def list_campaigns(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.db import RenewalCampaign
        from certadillo.enrollment import ari

        who.require("admin", "operator", "approver", "auditor")
        out = []
        for camp in p.s.query(RenewalCampaign).order_by(RenewalCampaign.id.desc()).all():
            st = ari.campaign_status(p.s, camp)
            st.pop("certificates")
            out.append(st)
        return out

    @app.get("/api/v1/renewal-campaigns/{campaign_id}", tags=["renewal campaigns"])
    def get_campaign(campaign_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.db import RenewalCampaign
        from certadillo.enrollment import ari

        who.require("admin", "operator", "approver", "auditor")
        camp = p.s.get(RenewalCampaign, campaign_id)
        if camp is None:
            raise NotFound("campaign not found")
        return ari.campaign_status(p.s, camp)

    @app.post("/api/v1/renewal-campaigns/{campaign_id}/revoke-replaced", tags=["renewal campaigns"])
    def campaign_revoke_replaced(campaign_id: int, body: ChangeRefIn, p: Platform = Depends(platform),
                                 who: Actor = Depends(actor)):
        n = p.campaign_revoke(who, campaign_id, "replaced", body.change_ref)
        p.commit()
        return {"revoked": n}

    @app.post("/api/v1/renewal-campaigns/{campaign_id}/revoke-remaining", status_code=202, tags=["renewal campaigns"])
    def campaign_revoke_remaining(campaign_id: int, body: ChangeRefIn, p: Platform = Depends(platform),
                                  who: Actor = Depends(actor)):
        req = p.campaign_revoke(who, campaign_id, "remaining", body.change_ref)
        p.commit()
        return {"status": "pending_approval", "approval_id": req.id}

    @app.post("/api/v1/renewal-campaigns/{campaign_id}/close", tags=["renewal campaigns"])
    def close_campaign(campaign_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        from certadillo.audit.log import record
        from certadillo.db import RenewalCampaign
        from certadillo.enrollment import ari

        who.require("admin", "operator")
        camp = p.s.get(RenewalCampaign, campaign_id)
        if camp is None:
            raise NotFound("campaign not found")
        camp.status = "closed"
        record(p.s, who.name, "renewal_campaign.close", f"campaign:{camp.id}", {})
        p.commit()
        return ari.campaign_status(p.s, camp)

    # ---------------------------------------------------------- AD CS audit
    @app.post("/api/v1/adcs/audit/import", tags=["adcs"])
    def adcs_import(body: AdcsImportIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Audit templates exported by Export-CertadilloAdcsTemplates (read-only)."""
        from certadillo.adcs.audit import audit_from_json

        who.require("admin", "operator")
        run_id, findings = audit_from_json(p.s, body.document, who.name)
        p.commit()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"run_id": run_id, "findings": findings, "counts": by_sev}

    @app.post("/api/v1/adcs/audit/ldap", tags=["adcs"])
    def adcs_ldap(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Audit the live directory over LDAP using the configured CERTADILLO_ADCS_LDAP_* settings."""
        from certadillo.adcs.audit import audit_from_ldap
        from certadillo.adcs.collector import LdapCollector

        who.require("admin", "operator")
        s = p.settings
        if not (s.adcs_ldap_url and s.adcs_ldap_user and s.adcs_ldap_base):
            raise PolicyError("set CERTADILLO_ADCS_LDAP_URL, _USER, _PASSWORD and _BASE first")
        collector = LdapCollector(s.adcs_ldap_url, s.adcs_ldap_user, s.adcs_ldap_password or "", s.adcs_ldap_base)
        run_id, findings = audit_from_ldap(p.s, collector, who.name)
        p.commit()
        return {"run_id": run_id, "findings": findings}

    @app.get("/api/v1/adcs/findings", tags=["adcs"])
    def adcs_findings(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """The findings of the most recent AD CS audit run."""
        from certadillo.adcs.audit import latest_run
        from certadillo.adcs.analyzer import ESC_TITLES

        who.require("admin", "operator", "approver", "auditor")
        run_id, rows = latest_run(p.s)
        return {
            "run_id": run_id,
            "esc_catalogue": ESC_TITLES,
            "findings": [
                {"object_type": r.object_type, "object_name": r.object_name, "esc": r.esc,
                 "severity": r.severity, "title": r.title, "detail": r.detail,
                 "principals": r.principals, "remark": r.remark, "source": r.source}
                for r in rows
            ],
        }

    # ---------------------------------------------------------- AD CS gateway
    @app.post("/api/v1/adcs/gateway/jobs/claim", tags=["adcs"])
    def gateway_claim(limit: int = Query(10, ge=1, le=100), p: Platform = Depends(platform),
                      who: Actor = Depends(actor)):
        """A gateway worker claims pending jobs to submit to a Microsoft CA."""
        jobs = p.gateway_claim(who, limit)
        p.commit()
        return {"jobs": [gateway_job_json(j) for j in jobs]}

    @app.post("/api/v1/adcs/gateway/jobs/{job_id}/complete", tags=["adcs"])
    def gateway_complete(job_id: int, body: AdcsJobCompleteIn, p: Platform = Depends(platform),
                         who: Actor = Depends(actor)):
        job = p.gateway_complete(who, job_id, certificate_pem=body.certificate_pem, chain_pem=body.chain_pem,
                                 error=body.error, certificates=body.certificates)
        p.commit()
        return gateway_job_json(job)

    @app.get("/api/v1/adcs/gateway/jobs/{job_id}", tags=["adcs"])
    def gateway_job(job_id: int, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """The requester (or a gateway) polls a job."""
        job = p.s.get(AdcsJob, job_id)
        if job is None:
            raise NotFound("job not found")
        if who.role == "app" and job.app_id != who.app_id:
            raise NotFound("job not found")
        out = gateway_job_json(job)
        if job.certificate_id:
            out["certificate"] = cert_json(p.s.get(Certificate, job.certificate_id), include_pem=True)
        return out

    @app.get("/api/v1/adcs/gateway/jobs", tags=["adcs"])
    def gateway_jobs(status: str | None = None, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        who.require("admin", "operator", "gateway", "auditor")
        q = p.s.query(AdcsJob)
        if status:
            q = q.filter_by(status=status)
        return [gateway_job_json(j) for j in q.order_by(AdcsJob.id.desc()).limit(500).all()]

    @app.post("/api/v1/adcs/inventory", status_code=202, tags=["adcs"])
    def adcs_inventory(body: AdcsInventoryIn, p: Platform = Depends(platform), who: Actor = Depends(actor)):
        job = p.request_inventory(who, body.ca)
        p.commit()
        return {"job_id": job.id}

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

    @app.get("/api/v1/cas/keys", tags=["ca"])
    def ca_keys(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Where each CA key lives and whether it is reachable and intact (a live check for Vault-held keys)."""
        who.require("admin", "operator", "auditor")
        return p.ca.key_health()

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

    @app.get("/api/v1/audit/head", tags=["governance"])
    def audit_head(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """The current chain head as a signed anchor, for an external monitor to
        pull and keep. Nothing is written or sent."""
        from certadillo.audit.log import make_anchor

        who.require("admin", "auditor")
        a = make_anchor(p.s, p.settings.base_url)
        if a is None:
            raise PolicyError([("audit_chain", "the chain is empty or broken; nothing to anchor")])
        return a

    @app.post("/api/v1/audit/anchor", tags=["governance"])
    def audit_anchor(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Anchor now, to the configured file and/or URL."""
        from certadillo.audit.log import make_anchor, publish_anchor
        from certadillo.audit.log import record as audit_record

        who.require("admin")
        a = make_anchor(p.s, p.settings.base_url)
        if a is None:
            raise PolicyError([("audit_chain", "the chain is empty or broken; nothing to anchor")])
        sinks = publish_anchor(a, p.settings)
        if not sinks:
            raise PolicyError([("audit_anchor", "set CERTADILLO_AUDIT_ANCHOR_FILE or CERTADILLO_AUDIT_ANCHOR_URL")])
        audit_record(p.s, who.name, "audit.anchor", f"event:{a['event_id']}", {"hash": a["hash"], "sinks": sinks})
        p.commit()
        return {**a, "sinks": sinks}

    @app.get("/api/v1/integrity", tags=["governance"])
    def integrity_scan(p: Platform = Depends(platform), who: Actor = Depends(actor)):
        """Rows whose integrity seal does not match (changed outside Certadillo),
        and active certificates the audit trail says were revoked."""
        from certadillo import integrity

        who.require("admin", "operator", "auditor")
        problems = integrity.scan(p.s)
        return {"ok": not problems, "problems": problems}

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
    app.include_router(scep.router)
    app.include_router(cmp.router)

    # ---------------------------------------------------------- web console
    static_dir = resources.files("certadillo").joinpath("web/static")

    @app.get("/kb", include_in_schema=False)
    def kb_redirect():
        return RedirectResponse("/kb/")

    app.mount("/kb", StaticFiles(directory=str(static_dir.joinpath("kb")), html=True), name="kb")
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(static_dir.joinpath("index.html")))

    return app


def main_app() -> FastAPI:  # uvicorn --factory certadillo.api.app:main_app
    return create_app()
