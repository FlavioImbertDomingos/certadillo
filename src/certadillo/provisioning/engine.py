"""Targets, installations and provisioning runs.

A run issues a certificate for an installation under its app's policy, pushes
it with the target's driver, checks the endpoint serves it, and only then
retires the previous certificate. A centrally generated private key exists
only in the memory of the run: it is never written to the database or a log,
and if the install fails the new certificate is revoked, because nobody holds
its key any more.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from certadillo.audit.log import record
from certadillo.db import (
    App,
    Certificate,
    CertificateAuthority,
    Installation,
    ProvisioningRun,
    ProvisioningTarget,
    RenewalAdvice,
    as_utc,
)
from certadillo.policy.engine import PolicyError, domain_allowed
from certadillo.provisioning import credentials
from certadillo.provisioning.drivers import InstallBundle, ProvisioningError, driver_for
from certadillo.provisioning.validation import wait_until_served

KEY_TYPES = ("ec-p256", "ec-p384", "rsa-2048", "rsa-3072")
SECRET_WORDS = re.compile(r"pass|secret|token|private|apikey|api_key", re.I)
ENDPOINT = re.compile(r"^[A-Za-z0-9.-]+:\d{1,5}$|^\[[0-9a-fA-F:]+\]:\d{1,5}$")
MAX_BACKOFF = timedelta(hours=24)
PER_CYCLE = 20

# Tests (and only tests) put an httpx transport here per target kind.
test_transports: dict = {}
# Tests shorten endpoint validation retries.
validation_attempts = {"attempts": 5, "delay": 1.0}


# ------------------------------------------------------------------ targets
def create_target(p, actor, name: str, kind: str, team_id: int, config: dict, credential_ref: str | None):
    actor.require("admin")
    from certadillo.db import Team

    if p.s.get(Team, team_id) is None:
        raise LookupError("team not found")
    cls = driver_for(kind)
    bad = [k for k in _walk_keys(config) if SECRET_WORDS.search(k)]
    if bad:
        raise ValueError(f"config holds what looks like a secret ({', '.join(bad)}); "
                         "put it behind credential_ref (env:, file: or vault:)")
    credentials.check_ref(credential_ref)
    config = cls.check_config(dict(config))
    t = ProvisioningTarget(name=name, kind=kind, team_id=team_id, config=config,
                           credential_ref=credential_ref, created_by=actor.name)
    p.s.add(t)
    p.s.flush()
    record(p.s, actor.name, "provisioning.target.create", name,
           {"kind": kind, "team_id": team_id, "credential": _ref_kind(credential_ref)})
    return t


def _walk_keys(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield f"{prefix}{k}"
            yield from _walk_keys(v, f"{prefix}{k}.")


def _ref_kind(ref: str | None) -> str | None:
    return ref.split(":", 1)[0] if ref else None


def target_json(t: ProvisioningTarget) -> dict:
    return {"id": t.id, "name": t.name, "kind": t.kind, "team_id": t.team_id, "config": t.config,
            "credential": _ref_kind(t.credential_ref), "status": t.status, "created_by": t.created_by}


# ------------------------------------------------------------------ installations
def create_installation(p, actor, app_id: int, target_id: int, common_name: str, sans: list[str] | None = None,
                        key_type: str = "ec-p256", key_location: str = "central", params: dict | None = None,
                        validate_endpoint: str | None = None, auto_renew: bool = True) -> Installation:
    from certadillo.services import Forbidden

    if actor.role == "app":
        if actor.app_id != app_id:
            raise Forbidden("an app credential can only bind its own app's certificates")
    else:
        actor.require("admin", "operator")
    app = p.s.get(App, app_id)
    target = p.s.get(ProvisioningTarget, target_id)
    if app is None or target is None:
        raise LookupError("app or target not found")
    if app.status != "active" or target.status != "active":
        raise Forbidden("both the app and the target must be active")
    if target.team_id != app.team_id:
        raise Forbidden("this target belongs to another team")
    from certadillo import integrity

    if not integrity.verify(target):
        raise Forbidden("this target failed its integrity check")
    prof = p.policies["profiles"].get(app.profile, {})
    if prof.get("dual_control") or prof.get("issuer") == "adcs":
        raise ValueError(f"profile {app.profile} needs approval or a gateway for each issuance; "
                         "push provisioning needs certificates issued on the spot")
    if key_type not in KEY_TYPES:
        raise ValueError(f"key_type must be one of {KEY_TYPES}")
    cls = driver_for(target.kind)
    if key_location not in cls.key_locations:
        raise ValueError(f"{target.kind} targets support key_location {cls.key_locations}")
    params = cls(target.config, None, p.settings).check_params(dict(params or {}))
    if validate_endpoint is not None and not ENDPOINT.match(validate_endpoint):
        raise ValueError("validate_endpoint must be host:port")
    sans = list(sans or [])
    for name in [common_name, *sans]:
        if not domain_allowed(name, app.allowed_domains):
            raise PolicyError([("san_scope", f"{name} is outside the app's approved domains")])
    inst = Installation(app_id=app.id, target_id=target.id, common_name=common_name, sans=sans,
                        key_type=key_type, key_location=key_location, params=params,
                        validate_endpoint=validate_endpoint, auto_renew=auto_renew, created_by=actor.name)
    p.s.add(inst)
    p.s.flush()
    record(p.s, actor.name, "provisioning.installation.create", common_name,
           {"installation": inst.id, "app": app.name, "target": target.name, "key_location": key_location})
    return inst


def installation_json(i: Installation, runs: list[ProvisioningRun] | None = None) -> dict:
    out = {"id": i.id, "app_id": i.app_id, "target_id": i.target_id, "common_name": i.common_name,
           "sans": i.sans, "key_type": i.key_type, "key_location": i.key_location, "params": i.params,
           "validate_endpoint": i.validate_endpoint, "auto_renew": i.auto_renew,
           "certificate_id": i.certificate_id, "status": i.status, "last_error": i.last_error,
           "failures": i.failures,
           "next_attempt_at": as_utc(i.next_attempt_at).isoformat() if i.next_attempt_at else None}
    if runs is not None:
        out["runs"] = [{"id": r.id, "trigger": r.trigger, "status": r.status, "certificate_id": r.certificate_id,
                        "steps": r.steps, "error": r.error, "actor": r.actor,
                        "started_at": as_utc(r.started_at).isoformat()} for r in runs]
    return out


# ------------------------------------------------------------------ a run
def _new_key(key_type: str):
    if key_type.startswith("ec-"):
        return ec.generate_private_key(ec.SECP256R1() if key_type == "ec-p256" else ec.SECP384R1())
    return rsa.generate_private_key(65537, int(key_type.split("-")[1]))


def _csr(key, common_name: str, sans: list[str]) -> str:
    names = [x509.DNSName(n) for n in dict.fromkeys([common_name, *sans])]
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
           .add_extension(x509.SubjectAlternativeName(names), critical=False)
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def provision(p, installation_id: int, actor_name: str, trigger: str = "manual") -> ProvisioningRun:
    from certadillo.services import Actor

    inst = p.s.get(Installation, installation_id)
    if inst is None:
        raise LookupError("installation not found")
    app = p.s.get(App, inst.app_id)
    target = p.s.get(ProvisioningTarget, inst.target_id)
    run = ProvisioningRun(installation_id=inst.id, trigger=trigger, status="running", actor=actor_name, steps=[])
    p.s.add(run)
    p.s.flush()
    steps: list[str] = []
    issued: Certificate | None = None
    installed = False
    try:
        if app.status != "active" or target.status != "active":
            raise ProvisioningError("the app or the target is not active")
        from certadillo import integrity

        if not integrity.verify(target) or not integrity.verify(inst):
            raise ProvisioningError("the target or installation failed its integrity check (changed outside "
                                    "Certadillo); nothing was pushed")
        cls = driver_for(target.kind)
        driver = cls(target.config, credentials.resolve(target.credential_ref, p.settings), p.settings,
                     transport=test_transports.get(target.kind))
        params = driver.check_params(dict(inst.params))  # re-checked against today's target config
        if inst.key_location == "central":
            key = _new_key(inst.key_type)
            csr_pem = _csr(key, inst.common_name, inst.sans)
            key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            del key
            steps.append(f"generated a {inst.key_type} key in memory")
        else:
            csr_pem = driver.device_csr(params, inst.common_name, inst.sans, inst.key_type)
            key_pem = None
            steps.append(f"the target generated a {inst.key_type} key and returned a CSR")
        result = p.request_certificate(Actor(f"provisioner:{inst.id}", "app", app.id), app.id, csr_pem,
                                       protocol="push")
        if not isinstance(result, Certificate):
            raise ProvisioningError("the profile did not issue on the spot (approval or gateway required)")
        issued = result
        steps.append(f"issued serial {issued.serial_hex}")
        ca = p.s.get(CertificateAuthority, issued.ca_id) if issued.ca_id else None
        chain = p.ca.chain(ca)[:-1] if ca else []
        bundle = InstallBundle(common_name=inst.common_name, cert_pem=issued.pem,
                               chain_pem="".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain),
                               key_pem=key_pem, serial_hex=issued.serial_hex, fingerprint=issued.fingerprint_sha256,
                               steps=steps)
        updates = driver.install(params, bundle)
        key_pem = bundle.key_pem = None
        installed = True
        if updates:
            inst.params = {**inst.params, **updates}
        inst.status = "installed"
        if inst.validate_endpoint:
            ok, seen = wait_until_served(inst.validate_endpoint, inst.common_name, issued.fingerprint_sha256,
                                         **validation_attempts)
            if not ok:
                raise ProvisioningError(f"{inst.validate_endpoint} does not serve the new certificate "
                                        f"(saw {seen[:24]})")
            steps.append(f"{inst.validate_endpoint} serves the new certificate")
            inst.status = "validated"
        previous = p.s.get(Certificate, inst.certificate_id) if inst.certificate_id else None
        if previous is not None and previous.status == "active" and previous.id != issued.id:
            previous.status, previous.replaced_by = "superseded", issued.id
            steps.append(f"superseded serial {previous.serial_hex}")
        inst.certificate_id = issued.id
        inst.failures, inst.last_error, inst.next_attempt_at = 0, None, None
        run.status, run.certificate_id = "ok", issued.id
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the run and retried later
        message = _message(exc)
        if issued is not None and not installed and issued.status == "active":
            # the only copy of a central key is gone; a device key was never activated
            try:
                p.revoke(Actor(f"provisioner:{inst.id}", "app", app.id), issued.id, "cessation_of_operation")
                steps.append(f"revoked undelivered serial {issued.serial_hex}")
            except Exception as rexc:  # noqa: BLE001
                steps.append(f"could not revoke undelivered serial {issued.serial_hex}: {_message(rexc)}")
        if issued is not None and installed:
            inst.certificate_id = issued.id  # it is on the target; the next run replaces it
        inst.status = "failed"
        inst.failures = (inst.failures or 0) + 1
        inst.last_error = message
        inst.next_attempt_at = datetime.now(timezone.utc) + min(timedelta(minutes=5 * 2 ** min(inst.failures, 10)),
                                                                MAX_BACKOFF)
        run.status, run.error = "failed", message
        if issued is not None:
            run.certificate_id = issued.id
    run.steps = list(steps)
    run.finished_at = datetime.now(timezone.utc)
    record(p.s, actor_name, "provisioning.run", inst.common_name,
           {"installation": inst.id, "target": target.name if target else None, "trigger": trigger,
            "status": run.status, "serial": issued.serial_hex if issued else None, "error": run.error})
    return run


def _message(exc: Exception) -> str:
    if isinstance(exc, PolicyError):
        return "policy: " + "; ".join(f"{r}: {m}" for r, m in exc.violations)
    if isinstance(exc, (ProvisioningError, credentials.CredentialError)):
        return str(exc)[:500]
    return f"{type(exc).__name__}: {exc}"[:500]


# ------------------------------------------------------------------ scheduler
def due(p, now: datetime | None = None) -> list[Installation]:
    from certadillo.alerting.evaluator import expiry_state

    now = now or datetime.now(timezone.utc)
    out = []
    for inst in p.s.query(Installation).filter_by(auto_renew=True).order_by(Installation.id).all():
        if inst.next_attempt_at is not None and as_utc(inst.next_attempt_at) > now:
            continue
        cert = p.s.get(Certificate, inst.certificate_id) if inst.certificate_id else None
        if cert is None or inst.status == "failed" or cert.status != "active":
            out.append(inst)
        elif expiry_state(cert.not_before, cert.not_after, p.settings, now):
            out.append(inst)
        else:
            advice = p.s.get(RenewalAdvice, cert.id)
            if advice is not None and as_utc(advice.window_start) <= now:
                out.append(inst)
        if len(out) >= PER_CYCLE:
            break
    return out


def renew_due(p) -> list[dict]:
    results = []
    for inst in due(p):
        run = provision(p, inst.id, "system", "retry" if inst.status == "failed" else "renewal")
        p.commit()
        results.append({"installation": inst.id, "status": run.status})
    return results
