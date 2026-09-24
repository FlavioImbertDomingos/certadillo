"""The AD CS gateway job queue.

Certadillo is the registration authority: it applies policy, scope, dual
control and audit, then hands an approved job to a domain-joined gateway
worker that talks to a Microsoft CA (certreq / certutil) and posts the result
back. These helpers manage the queue; Platform wraps them with authorization
and inventory ingest.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from certadillo.db import AdcsJob, Certificate


def csr_hash(csr_pem: str) -> str:
    return hashlib.sha256(csr_pem.strip().encode()).hexdigest()


def enqueue_issue(session, app_id: int, profile: str, csr_pem: str, ca: str | None, template: str | None,
                  requested_by: str) -> AdcsJob:
    """Queue an issuance. If an identical CSR is already pending or claimed for
    the app, return that job instead of duplicating the submission."""
    h = csr_hash(csr_pem)
    existing = (
        session.query(AdcsJob)
        .filter(AdcsJob.job_type == "issue", AdcsJob.app_id == app_id, AdcsJob.csr_hash == h,
                AdcsJob.status.in_(["pending", "claimed"]))
        .first()
    )
    if existing:
        return existing
    job = AdcsJob(job_type="issue", app_id=app_id, profile=profile, adcs_ca=ca, adcs_template=template,
                  csr_pem=csr_pem, csr_hash=h, requested_by=requested_by)
    session.add(job)
    session.flush()
    return job


def enqueue_revoke(session, cert: Certificate, reason: str, ca: str | None, requested_by: str) -> AdcsJob:
    job = AdcsJob(job_type="revoke", app_id=cert.app_id, serial_hex=cert.serial_hex, reason=reason,
                  adcs_ca=ca, certificate_id=cert.id, requested_by=requested_by)
    session.add(job)
    session.flush()
    return job


def enqueue_inventory(session, ca: str, requested_by: str) -> AdcsJob:
    job = AdcsJob(job_type="inventory", adcs_ca=ca, requested_by=requested_by)
    session.add(job)
    session.flush()
    return job


def claim(session, worker: str, limit: int = 10) -> list[AdcsJob]:
    """Hand the oldest pending jobs to a worker and mark them claimed."""
    jobs = session.query(AdcsJob).filter_by(status="pending").order_by(AdcsJob.id).limit(limit).all()
    now = datetime.now(timezone.utc)
    for j in jobs:
        j.status = "claimed"
        j.claimed_by = worker
        j.claimed_at = now
    session.flush()
    return jobs


def fail(session, job: AdcsJob, error: str) -> None:
    job.status = "failed"
    job.error = error[:2000]
    job.completed_at = datetime.now(timezone.utc)
    session.flush()
