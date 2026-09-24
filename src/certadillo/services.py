"""Registration authority (RA) layer.

Protocol front ends (REST, EST, ACME, CLI, UI) call these functions and
nothing else, so onboarding rules, policy checks, dual control, audit and
metrics apply the same way to every enrollment path."""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509

from certadillo.audit.log import record
from certadillo.ca.authority import CAService, cert_row_fields, spki_sha256
from certadillo.ca.backends import get_backend
from certadillo.ca.ssh import SSHCA
from certadillo.db import (
    App,
    ApprovalRequest,
    Certificate,
    CertificateAuthority,
    Principal,
    Team,
)
from certadillo.observability.metrics import ISSUANCE_TOTAL, POLICY_VIOLATIONS, REVOCATIONS
from certadillo.policy.engine import PolicyEngine, PolicyError, grade_certificate

ROLES = {"admin", "approver", "operator", "auditor", "app"}
ENVIRONMENTS = {"dev", "test", "prod"}


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_api_key() -> str:
    return "cdl_" + secrets.token_urlsafe(32)


@dataclass
class Actor:
    name: str
    role: str
    app_id: int | None = None

    def require(self, *roles: str) -> None:
        if self.role not in roles:
            raise Forbidden(f"role '{self.role}' cannot perform this action (needs one of {', '.join(roles)})")


class Platform:
    def __init__(self, session, settings, policies: dict, keystore):
        self.s = session
        self.settings = settings
        self.policies = policies
        self.engine = PolicyEngine(policies)
        self.ca = CAService(session, keystore, settings, policies)
        self.ssh = SSHCA(session, settings, policies)

    def commit(self) -> None:
        self.s.commit()

    # ------------------------------------------------------------- principals
    def create_principal(self, actor: Actor | None, name: str, role: str, app_id: int | None = None,
                         raw_key: str | None = None) -> str:
        if actor is not None:
            actor.require("admin")
        if role not in ROLES:
            raise ValueError(f"unknown role {role}")
        raw = raw_key or new_api_key()
        creator = actor.name if actor else "system"
        self.s.add(Principal(name=name, role=role, key_hash=hash_key(raw), app_id=app_id, created_by=creator))
        self.s.flush()
        record(self.s, creator, "principal.create", name, {"role": role, "app_id": app_id})
        return raw

    def deactivate_principal(self, actor: Actor, name: str) -> None:
        actor.require("admin")
        p = self.s.query(Principal).filter_by(name=name).one_or_none()
        if p is None:
            raise NotFound("principal not found")
        p.active = False
        record(self.s, actor.name, "principal.deactivate", name, {"role": p.role})

    def authenticate(self, raw_key: str | None) -> Actor | None:
        if not raw_key:
            return None
        p = self.s.query(Principal).filter_by(key_hash=hash_key(raw_key), active=True).one_or_none()
        if p is None:
            return None
        if p.app_id:
            app = self.s.get(App, p.app_id)
            if app is None or app.status != "active":
                return None
        return Actor(p.name, p.role, p.app_id)

    # ------------------------------------------------------------- onboarding
    def create_team(self, actor: Actor, name: str, contact_email: str, chat_channel: str | None = None,
                    webhook_url: str | None = None, cost_center: str | None = None) -> Team:
        actor.require("admin", "operator")
        if self.s.query(Team).filter_by(name=name).first():
            raise ValueError(f"team {name} already exists")
        t = Team(name=name, contact_email=contact_email, chat_channel=chat_channel,
                 webhook_url=webhook_url, cost_center=cost_center)
        self.s.add(t)
        self.s.flush()
        record(self.s, actor.name, "team.create", name, {"contact": contact_email, "cost_center": cost_center})
        return t

    def onboard_app(self, actor: Actor, team_id: int, name: str, environment: str, profile: str,
                    allowed_domains: list[str], data_classification: str = "internal") -> tuple[App, ApprovalRequest | None]:
        actor.require("admin", "operator")
        if environment not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(ENVIRONMENTS)}")
        self.engine.profile(profile)
        if not allowed_domains:
            raise ValueError("allowed_domains is required (the RA scope for this app)")
        if self.s.get(Team, team_id) is None:
            raise NotFound("team not found")
        needs_approval = environment == "prod" and "onboard_prod_app" in self.settings.dual_control_actions
        app = App(team_id=team_id, name=name, environment=environment, profile=profile,
                  allowed_domains=allowed_domains, data_classification=data_classification,
                  status="pending_approval" if needs_approval else "active", created_by=actor.name)
        self.s.add(app)
        self.s.flush()
        approval = None
        if needs_approval:
            approval = self._request_approval(actor, "onboard_prod_app", {"app_id": app.id})
        record(self.s, actor.name, "app.onboard", name, {
            "team_id": team_id, "environment": environment, "profile": profile,
            "allowed_domains": allowed_domains, "classification": data_classification, "status": app.status,
        })
        return app, approval

    def mint_app_credential(self, actor: Actor, app_id: int) -> str:
        actor.require("admin", "operator")
        app = self.s.get(App, app_id)
        if app is None:
            raise NotFound("app not found")
        if app.status != "active":
            raise Forbidden(f"app is {app.status}; credentials are issued only to active apps")
        n = self.s.query(Principal).filter_by(app_id=app_id).count()
        raw = new_api_key()
        self.s.add(Principal(name=f"app:{app.name}:{n + 1}", role="app", key_hash=hash_key(raw), app_id=app.id,
                             created_by=actor.name))
        self.s.flush()
        record(self.s, actor.name, "principal.create", f"app:{app.name}:{n + 1}", {"role": "app", "app_id": app.id})
        return raw

    def mint_acme_eab(self, actor: Actor, app_id: int) -> dict:
        """One-time External Account Binding credential for ACME clients."""
        import base64

        from certadillo.db import AcmeEab

        actor.require("admin", "operator")
        app = self.s.get(App, app_id)
        if app is None:
            raise NotFound("app not found")
        if app.status != "active":
            raise Forbidden(f"app is {app.status}")
        kid = "eab_" + secrets.token_hex(8)
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        self.s.add(AcmeEab(kid=kid, hmac_key_b64=key, app_id=app_id))
        self.s.flush()
        record(self.s, actor.name, "acme.eab.create", app.name, {"kid": kid})
        return {"kid": kid, "hmac_key": key}

    def mint_scep_challenge(self, actor: Actor, app_id: int, ttl_minutes: int = 60) -> dict:
        """One-time SCEP challenge password for a device enrolling into this app."""
        from datetime import timedelta

        from certadillo.db import ScepChallenge

        actor.require("admin", "operator")
        app = self.s.get(App, app_id)
        if app is None:
            raise NotFound("app not found")
        if app.status != "active":
            raise Forbidden(f"app is {app.status}")
        raw = secrets.token_hex(16)
        expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        self.s.add(ScepChallenge(challenge_hash=hash_key(raw), app_id=app_id, expires_at=expires))
        self.s.flush()
        record(self.s, actor.name, "scep.challenge.create", app.name, {"expires": expires.isoformat()})
        return {"challenge": raw, "expires": expires.isoformat()}

    def redeem_scep_challenge(self, raw: str) -> App:
        from certadillo.db import ScepChallenge, as_utc

        ch = self.s.query(ScepChallenge).filter_by(challenge_hash=hash_key(raw)).one_or_none()
        if ch is None or ch.used or as_utc(ch.expires_at) < datetime.now(timezone.utc):
            raise Forbidden("SCEP challenge password is unknown, used or expired")
        ch.used = True
        self.s.flush()
        return self.s.get(App, ch.app_id)

    def add_est_trust_anchor(self, actor: Actor, app_id: int, name: str, cert_pem: str):
        actor.require("admin", "operator")
        app = self.s.get(App, app_id)
        if app is None:
            raise NotFound("app not found")
        try:
            ca = x509.load_pem_x509_certificate(cert_pem.encode())
        except ValueError:
            raise ValueError("cert_pem is not a PEM certificate") from None
        try:
            if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("the trust anchor must be a CA certificate")
        except x509.ExtensionNotFound:
            raise ValueError("the trust anchor must be a CA certificate") from None
        payload = {"app_id": app_id, "name": name, "cert_pem": cert_pem}
        if app.environment == "prod":
            return self._request_approval(actor, "add_est_trust_anchor", payload)
        return self._add_trust_anchor(actor.name, payload)

    def _add_trust_anchor(self, who: str, p: dict) -> dict:
        from certadillo.db import EstTrustAnchor

        ta = EstTrustAnchor(app_id=p["app_id"], name=p["name"], cert_pem=p["cert_pem"], created_by=who)
        self.s.add(ta)
        self.s.flush()
        subject = x509.load_pem_x509_certificate(p["cert_pem"].encode()).subject.rfc4514_string()
        record(self.s, who, "est.trust_anchor.add", f"app:{p['app_id']}", {"name": p["name"], "subject": subject})
        return {"id": ta.id, "name": ta.name, "subject": subject}

    # ------------------------------------------------------------- dual control
    def _request_approval(self, actor: Actor, action: str, payload: dict) -> ApprovalRequest:
        req = ApprovalRequest(action=action, payload=payload, requested_by=actor.name)
        self.s.add(req)
        self.s.flush()
        record(self.s, actor.name, "approval.request", f"approval:{req.id}", {"action": action, **payload})
        return req

    def decide(self, actor: Actor, approval_id: int, approve: bool, comment: str | None = None) -> ApprovalRequest:
        actor.require("approver")  # separation of duties: admins request, approvers decide
        req = self.s.get(ApprovalRequest, approval_id)
        if req is None:
            raise NotFound("approval not found")
        if req.status != "pending":
            raise ValueError(f"approval already {req.status}")
        if req.requested_by == actor.name:
            raise Forbidden("maker-checker: the requester cannot approve their own request")
        me = self.s.query(Principal).filter_by(name=actor.name).one_or_none()
        if me is not None and me.created_by == req.requested_by:
            raise Forbidden("maker-checker: this approver credential was issued by the requester")
        req.status = "approved" if approve else "rejected"
        req.decided_by = actor.name
        req.decided_at = datetime.now(timezone.utc)
        req.comment = comment
        record(self.s, actor.name, f"approval.{req.status}", f"approval:{req.id}", {"action": req.action, "comment": comment})
        if approve:
            self._execute(req)
        elif req.action == "onboard_prod_app":
            app = self.s.get(App, req.payload["app_id"])
            app.status = "rejected"
        return req

    def _execute(self, req: ApprovalRequest) -> None:
        p = dict(req.payload)
        if req.action == "onboard_prod_app":
            app = self.s.get(App, p["app_id"])
            app.status = "active"
            record(self.s, req.decided_by, "app.activate", app.name, {"approval": req.id})
        elif req.action == "issue_certificate":
            app = self.s.get(App, p["app_id"])
            csr = x509.load_pem_x509_csr(p["csr_pem"].encode())
            # pop_verified: the protocol front end checked proof of possession over the
            # client's original bytes before normalising the CSR (SCEP clients)
            decision = self.engine.evaluate(csr, p["profile"], app.allowed_domains, p.get("days"), p.get("hours"),
                                            pop_verified=bool(p.get("pop_verified")))
            row = self._sign(csr, decision, app, p.get("protocol", "rest"), Actor(req.requested_by, "app", app.id))
            if p.get("previous_id"):
                prev = self.s.get(Certificate, p["previous_id"])
                if prev is not None and prev.status == "active":
                    prev.status, prev.replaced_by = "superseded", row.id
            p["certificate_id"] = row.id
            req.payload = p
        elif req.action == "create_ca":
            parent = self.ca.get(p["parent"])
            self.ca.create_subordinate(parent, p["name"], years=p.get("years", 5))
            record(self.s, req.decided_by, "ca.create", p["name"], {"parent": p["parent"], "approval": req.id})
        elif req.action == "add_est_trust_anchor":
            self._add_trust_anchor(req.requested_by, p)
        elif req.action == "campaign_revoke_remaining":
            n = self._campaign_revoke(Actor(req.requested_by, "operator"), p["campaign_id"], "remaining",
                                      p.get("change_ref"))
            p["revoked"] = n
            req.payload = p

    # ------------------------------------------------------------- issuance
    def request_certificate(self, actor: Actor, app_id: int, csr_pem: str, profile: str | None = None,
                            days: int | None = None, hours: int | None = None, protocol: str = "rest",
                            previous: Certificate | None = None,
                            pop_verified: bool = False) -> Certificate | ApprovalRequest:
        """pop_verified: the front end already checked the CSR signature over the
        client's original encoding (SCEP clients that emit non-DER CSRs)."""
        app = self.s.get(App, app_id)
        if app is None:
            raise NotFound("app not found")
        if actor.role == "app" and actor.app_id != app_id:
            raise Forbidden("an app credential can only request certificates for its own app")
        if actor.role not in ("app", "admin", "operator"):
            raise Forbidden("role cannot request certificates")
        if app.status != "active":
            raise Forbidden(f"app is {app.status}")
        profile = profile or app.profile
        if profile != app.profile:
            ISSUANCE_TOTAL.labels(profile=profile, protocol=protocol, result="rejected").inc()
            POLICY_VIOLATIONS.labels(rule="profile_not_onboarded").inc()
            violations = [("profile_not_onboarded", f"app is onboarded for '{app.profile}', not '{profile}'")]
            record(self.s, actor.name, "certificate.rejected", app.name,
                   {"profile": profile, "protocol": protocol, "violations": violations})
            self.s.commit()
            raise PolicyError(violations)
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError:
            raise PolicyError([("csr_format", "CSR is not valid PEM PKCS#10")]) from None
        prev_fp = spki_sha256(x509.load_pem_x509_certificate(previous.pem.encode())) if previous else None
        try:
            decision = self.engine.evaluate(csr, profile, app.allowed_domains, days, hours, prev_fp, pop_verified)
        except PolicyError as e:
            ISSUANCE_TOTAL.labels(profile=profile, protocol=protocol, result="rejected").inc()
            for rule, _ in e.violations:
                POLICY_VIOLATIONS.labels(rule=rule).inc()
            record(self.s, actor.name, "certificate.rejected", app.name,
                   {"profile": profile, "protocol": protocol, "violations": e.violations})
            self.s.commit()  # keep the rejection in the audit trail
            raise
        if decision.dual_control:
            ISSUANCE_TOTAL.labels(profile=profile, protocol=protocol, result="pending_approval").inc()
            return self._request_approval(actor, "issue_certificate", {
                "app_id": app.id, "csr_pem": csr_pem, "profile": profile, "days": days, "hours": hours,
                "protocol": protocol, "previous_id": previous.id if previous else None,
                "pop_verified": pop_verified,
            })
        row = self._sign(csr, decision, app, protocol, actor)
        if previous is not None:
            previous.status = "superseded"
            previous.replaced_by = row.id
            record(self.s, actor.name, "certificate.renew", previous.serial_hex, {"new_serial": row.serial_hex})
        return row

    def _sign(self, csr, decision, app: App, protocol: str, actor: Actor) -> Certificate:
        issuer = self.policies["profiles"][decision.profile].get("issuer", "local")
        if issuer == "local":
            row = self.ca.issue(csr, decision, app_id=app.id)
        else:
            backend = get_backend(issuer)
            if backend is None:
                raise RuntimeError(f"issuer backend '{issuer}' is not configured")
            leaf, _chain = backend.sign(csr, decision)
            row = Certificate(app_id=app.id, profile=decision.profile, source="issued", backend=issuer,
                              **cert_row_fields(leaf))
            self.s.add(row)
            self.s.flush()
        row.protocol = protocol
        ISSUANCE_TOTAL.labels(profile=decision.profile, protocol=protocol, result="issued").inc()
        record(self.s, actor.name, "certificate.issue", row.serial_hex, {
            "app": app.name, "profile": decision.profile, "protocol": protocol, "backend": row.backend,
            "sans": row.sans, "not_after": row.not_after.isoformat(),
        })
        return row

    def renew(self, actor: Actor, cert_id: int, csr_pem: str, protocol: str = "rest") -> Certificate | ApprovalRequest:
        prev = self.s.get(Certificate, cert_id)
        if prev is None or prev.source != "issued":
            raise NotFound("certificate not found or not issued here")
        if prev.status != "active":
            raise ValueError(f"certificate is {prev.status}")
        return self.request_certificate(actor, prev.app_id, csr_pem, prev.profile, protocol=protocol, previous=prev)

    def revoke(self, actor: Actor, cert_id: int, reason: str, change_ref: str | None = None) -> Certificate:
        row = self.s.get(Certificate, cert_id)
        if row is None:
            raise NotFound("certificate not found")
        if actor.role == "app":
            if row.app_id != actor.app_id:
                raise Forbidden("an app can only revoke its own certificates")
        else:
            actor.require("admin", "operator")
        app = self.s.get(App, row.app_id) if row.app_id else None
        if app and app.environment == "prod" and actor.role != "app" and reason != "key_compromise" and not change_ref:
            raise PolicyError([("change_ref", "production revocations need a change ticket reference")])
        if row.backend != "local":
            backend = get_backend(row.backend)
            if backend is None:
                raise RuntimeError(f"backend {row.backend} not configured")
            backend.revoke(row.serial_hex, reason)
            row.status, row.revoked_at, row.revocation_reason = "revoked", datetime.now(timezone.utc), reason
        else:
            self.ca.revoke(row, reason)
            # publish a fresh CRL right away; OCSP already answers from live state
            self.ca.generate_crl(self.s.get(CertificateAuthority, row.ca_id))
        REVOCATIONS.labels(reason=reason).inc()
        record(self.s, actor.name, "certificate.revoke", row.serial_hex, {"reason": reason, "change_ref": change_ref})
        return row

    # ------------------------------------------------------------- renewal campaigns (ARI)
    def create_campaign(self, actor: Actor, name: str, reason: str, criteria: dict, renew_within_hours: int = 24,
                        explanation_url: str | None = None, revocation_reason: str = "superseded",
                        immediate: bool = False):
        from certadillo.ca.authority import REASONS
        from certadillo.enrollment import ari

        actor.require("admin", "operator")
        if revocation_reason not in REASONS:
            raise ValueError(f"unknown revocation reason {revocation_reason}")
        return ari.create_campaign(self.s, actor.name, name, reason, criteria, renew_within_hours, explanation_url,
                                   revocation_reason, immediate)

    def campaign_revoke(self, actor: Actor, campaign_id: int, which: str, change_ref: str | None = None):
        """which = 'replaced': revoke certificates that already have a successor,
        so nothing breaks. which = 'remaining': the hard cutoff for everything
        else, which can take services down, so it needs a second person."""
        actor.require("admin", "operator")
        if which == "remaining":
            return self._request_approval(actor, "campaign_revoke_remaining",
                                          {"campaign_id": campaign_id, "change_ref": change_ref})
        return self._campaign_revoke(actor, campaign_id, which, change_ref)

    def _campaign_revoke(self, actor: Actor, campaign_id: int, which: str, change_ref: str | None) -> int:
        from certadillo.db import RenewalAdvice, RenewalCampaign, as_utc
        from certadillo.enrollment import ari

        camp = self.s.get(RenewalCampaign, campaign_id)
        if camp is None:
            raise NotFound("campaign not found")
        since = as_utc(camp.created_at)
        n = 0
        for adv in self.s.query(RenewalAdvice).filter_by(campaign_id=camp.id).all():
            c = self.s.get(Certificate, adv.certificate_id)
            if c.status == "revoked":
                continue
            has_successor = ari.replacement_for(self.s, c, since) is not None
            if (which == "replaced") != has_successor:
                continue
            self.revoke(actor, c.id, camp.revocation_reason, change_ref)
            adv.revoked_by_campaign = True
            n += 1
        record(self.s, actor.name, f"renewal_campaign.revoke_{which}", f"campaign:{camp.id}",
               {"revoked": n, "reason": camp.revocation_reason, "change_ref": change_ref})
        return n

    # ------------------------------------------------------------- SSH
    def issue_ssh(self, actor: Actor, public_key: str, cert_type: str, principals: list[str], key_id: str,
                  hours: int | None = None, days: int | None = None, source_address: str | None = None):
        actor.require("admin", "operator", "app")
        row = self.ssh.issue(public_key, cert_type, principals, key_id, hours, days,
                             app_id=actor.app_id, source_address=source_address)
        record(self.s, actor.name, "ssh.issue", key_id, {"type": cert_type, "principals": principals,
                                                        "valid_before": row.valid_before.isoformat()})
        return row

    # ------------------------------------------------------------- inventory
    def ingest(self, actor_name: str, cert: x509.Certificate, source: str, location: str | None = None,
               app_id: int | None = None) -> tuple[Certificate, list[tuple[str, str]], bool]:
        fields = cert_row_fields(cert)
        existing = self.s.query(Certificate).filter_by(fingerprint_sha256=fields["fingerprint_sha256"]).one_or_none()
        now = datetime.now(timezone.utc)
        # Publicly trusted TLS certificates carry embedded Certificate Transparency
        # SCTs; private enterprise certificates do not.
        try:
            cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
            is_public = True
        except (x509.ExtensionNotFound, ValueError):
            is_public = False
        findings = grade_certificate(cert, self.policies, is_public)
        if existing:
            existing.last_seen = now
            if location and not existing.location:
                existing.location = location
            self._retire_replaced(actor_name, existing, source, location)
            return existing, findings, False
        row = Certificate(source=source, location=location, app_id=app_id, last_seen=now, **fields)
        self.s.add(row)
        self.s.flush()
        self._retire_replaced(actor_name, row, source, location)
        record(self.s, actor_name, f"certificate.{source}", row.serial_hex, {
            "location": location, "cn": row.common_name, "not_after": row.not_after.isoformat(),
            "findings": [f[0] for f in findings],
        })
        return row, findings, True

    def _retire_replaced(self, actor_name: str, current: Certificate, source: str, location: str | None) -> None:
        """A scan that sees a different certificate at the same endpoint means the
        old one was replaced there; stop tracking (and alerting on) the old one."""
        if source != "discovered" or not location:
            return
        stale = (
            self.s.query(Certificate)
            .filter(Certificate.location == location, Certificate.source == "discovered",
                    Certificate.status == "active", Certificate.id != current.id)
            .all()
        )
        for old in stale:
            old.status = "superseded"
            old.replaced_by = current.id
            record(self.s, actor_name, "certificate.replaced_at_endpoint", old.serial_hex,
                   {"location": location, "new_serial": current.serial_hex})
