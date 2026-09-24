"""ACME Renewal Information (RFC 9773) and renewal campaigns.

ARI lets the server tell each ACME client when to renew. Normally the
suggested window sits a little past the middle of the certificate's life,
before the platform's expiry warning would fire. A renewal campaign pulls
the window forward for a chosen set of certificates, so clients replace
them within hours. Once a certificate has been replaced, revoking it breaks
nothing; that is how a mass revocation (CA key compromise, a mis-issued
batch) gets absorbed without an outage.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from certadillo.audit.log import record
from certadillo.db import (
    App,
    Certificate,
    CertificateAuthority,
    RenewalAdvice,
    RenewalCampaign,
    Team,
    as_utc,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def serial_bytes(serial: int) -> bytes:
    """DER INTEGER value octets: big-endian two's complement, minimal length."""
    return serial.to_bytes(serial.bit_length() // 8 + 1, "big")


def cert_id(cert: x509.Certificate) -> str:
    """ARI CertID: base64url(AKI keyIdentifier) '.' base64url(serial)."""
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    return f"{_b64u(aki)}.{_b64u(serial_bytes(cert.serial_number))}"


def parse_cert_id(value: str) -> tuple[bytes, int]:
    try:
        aki_s, serial_s = value.split(".")
        aki, serial = _b64u_dec(aki_s), _b64u_dec(serial_s)
    except ValueError:
        raise ValueError("CertID must be base64url(AKI).base64url(serial)") from None
    if not aki or not serial or serial[0] & 0x80:
        raise ValueError("CertID has an empty key identifier or a negative serial")
    return aki, int.from_bytes(serial, "big")


def find_by_cert_id(session, value: str) -> Certificate | None:
    aki, serial = parse_cert_id(value)
    for row in session.query(Certificate).filter_by(serial_hex=format(serial, "x")).all():
        if row.ca_id is None:
            continue
        ca = session.get(CertificateAuthority, row.ca_id)
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ski = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key()).digest
        if ski == aki:
            return row
    return None


def default_window(not_before: datetime, not_after: datetime) -> tuple[datetime, datetime]:
    """Renew between 50% and 60% of the lifetime. The expiry warning fires at
    min(30 days, lifetime/3) remaining, so a client that follows ARI renews
    before anyone gets paged."""
    nb, na = as_utc(not_before), as_utc(not_after)
    life = na - nb
    return nb + life * 0.5, nb + life * 0.6


def suggested_window(session, row: Certificate, now: datetime | None = None) -> tuple[datetime, datetime, str | None]:
    """(start, end, explanationURL) for a certificate."""
    now = now or datetime.now(timezone.utc)
    if row.status == "revoked":
        # RFC 9773: a revoked certificate gets a window in the past, meaning renew now
        return now - timedelta(hours=2), now - timedelta(hours=1), None
    start, end = default_window(row.not_before, row.not_after)
    advice = session.get(RenewalAdvice, row.id)
    if advice is not None:
        camp = session.get(RenewalCampaign, advice.campaign_id)
        if camp is not None and camp.status == "active" and as_utc(advice.window_end) < end:
            return as_utc(advice.window_start), as_utc(advice.window_end), camp.explanation_url
    return start, end, None


# ------------------------------------------------------------------ campaigns
def _matching(session, criteria: dict) -> list[Certificate]:
    q = session.query(Certificate).filter(Certificate.status == "active", Certificate.source == "issued")
    if criteria.get("cert_ids"):
        q = q.filter(Certificate.id.in_(criteria["cert_ids"]))
    if criteria.get("serials"):
        q = q.filter(Certificate.serial_hex.in_([s.lower().replace(":", "").lstrip("0") for s in criteria["serials"]]))
    if criteria.get("app_ids"):
        q = q.filter(Certificate.app_id.in_(criteria["app_ids"]))
    if criteria.get("profiles"):
        q = q.filter(Certificate.profile.in_(criteria["profiles"]))
    if criteria.get("protocols"):
        q = q.filter(Certificate.protocol.in_(criteria["protocols"]))
    if criteria.get("ca"):
        ca = session.query(CertificateAuthority).filter_by(name=criteria["ca"]).one_or_none()
        if ca is None:
            raise LookupError(f"CA {criteria['ca']} not found")
        q = q.filter(Certificate.ca_id == ca.id)
    if criteria.get("issued_before"):
        q = q.filter(Certificate.not_before < datetime.fromisoformat(criteria["issued_before"]))
    if criteria.get("issued_after"):
        q = q.filter(Certificate.not_before >= datetime.fromisoformat(criteria["issued_after"]))
    if criteria.get("key_types"):
        q = q.filter(Certificate.key_type.in_(criteria["key_types"]))
    return q.all()


ALLOWED_CRITERIA = {"cert_ids", "serials", "app_ids", "profiles", "protocols", "ca", "issued_before", "issued_after",
                    "key_types"}


def create_campaign(session, actor_name: str, name: str, reason: str, criteria: dict, renew_within_hours: int,
                    explanation_url: str | None = None, revocation_reason: str = "superseded",
                    immediate: bool = False) -> RenewalCampaign:
    """ARI clients pick a random moment inside the window, which spreads the
    load. immediate=True advertises a window that has already passed, so every
    client renews on its next check (RFC 9773 section 4.2); keep it for
    emergencies, since it sends the whole set at once."""
    unknown = set(criteria) - ALLOWED_CRITERIA
    if unknown:
        raise ValueError(f"unknown criteria: {', '.join(sorted(unknown))}")
    if not any(criteria.get(k) for k in ALLOWED_CRITERIA):
        raise ValueError("a campaign needs at least one selection criterion; it will not select every certificate")
    if not 1 <= renew_within_hours <= 24 * 30:
        raise ValueError("renew_within_hours must be between 1 and 720")
    now = datetime.now(timezone.utc)
    certs = _matching(session, criteria)
    camp = RenewalCampaign(name=name, reason=reason, criteria=criteria, explanation_url=explanation_url,
                           revocation_reason=revocation_reason, window_start=now,
                           window_end=now + timedelta(hours=renew_within_hours), created_by=actor_name)
    session.add(camp)
    session.flush()
    adv_start, adv_end = (now - timedelta(hours=2), now - timedelta(hours=1)) if immediate else (now, camp.window_end)
    for c in certs:
        existing = session.get(RenewalAdvice, c.id)
        if existing is not None:
            # keep the earliest deadline if two campaigns overlap
            if as_utc(existing.window_end) <= camp.window_end:
                continue
            session.delete(existing)
            session.flush()
        if immediate:
            start, end = adv_start, adv_end
        else:
            # never ask for a window that ends after the certificate does
            end = max(min(adv_end, as_utc(c.not_after) - timedelta(minutes=5)), now + timedelta(minutes=5))
            start = adv_start
        session.add(RenewalAdvice(certificate_id=c.id, campaign_id=camp.id, window_start=start, window_end=end))
    session.flush()
    record(session, actor_name, "renewal_campaign.create", f"campaign:{camp.id}", {
        "name": name, "reason": reason, "criteria": criteria, "certificates": len(certs),
        "window_end": camp.window_end.isoformat(), "immediate": immediate,
    })
    return camp


def replacement_for(session, c: Certificate, since: datetime) -> Certificate | None:
    """The certificate that replaced c: an explicit link (ACME 'replaces',
    REST renew, EST re-enroll) or a newer active certificate for the same
    app with the same names issued after the campaign started."""
    if c.replaced_by:
        return session.get(Certificate, c.replaced_by)
    if c.app_id is None:
        return None
    for n in session.query(Certificate).filter(Certificate.app_id == c.app_id, Certificate.id != c.id,
                                               Certificate.status == "active", Certificate.source == "issued",
                                               Certificate.created_at >= since).all():
        if sorted(n.sans) == sorted(c.sans) and n.common_name == c.common_name:
            return n
    return None


def campaign_warnings(renew_within_hours: int, retry_after_seconds: int) -> list[str]:
    out = []
    poll = retry_after_seconds / 3600
    if renew_within_hours < poll + 12:
        out.append(f"clients re-check ARI only every {poll:g}h (Retry-After) and certbot's timer runs twice a day; "
                   f"a {renew_within_hours}h deadline can pass before some clients see the new window. "
                   "Lower CERTADILLO_ARI_RETRY_AFTER ahead of planned campaigns.")
    return out


def campaign_status(session, camp: RenewalCampaign) -> dict:
    rows = session.query(RenewalAdvice).filter_by(campaign_id=camp.id).all()
    apps = {a.id: a for a in session.query(App).all()}
    teams = {t.id: t for t in session.query(Team).all()}
    now = datetime.now(timezone.utc)
    items, counts = [], {"total": len(rows), "replaced": 0, "revoked": 0, "remaining": 0}
    for adv in rows:
        c = session.get(Certificate, adv.certificate_id)
        new = replacement_for(session, c, as_utc(camp.created_at))
        if c.status == "revoked":
            state = "revoked"
        elif new is not None:
            state = "replaced"
        else:
            state = "remaining"
        counts[state] += 1
        app = apps.get(c.app_id)
        items.append({
            "certificate_id": c.id, "serial": c.serial_hex, "common_name": c.common_name, "state": state,
            "replaced_by": new.id if new else None, "protocol": c.protocol,
            "app": app.name if app else None, "team": teams[app.team_id].name if app else None,
            "not_after": as_utc(c.not_after).isoformat(),
        })
    overdue = camp.status == "active" and now > as_utc(camp.window_end) and counts["remaining"] > 0
    return {
        "id": camp.id, "name": camp.name, "reason": camp.reason, "status": camp.status,
        "criteria": camp.criteria, "revocation_reason": camp.revocation_reason,
        "explanation_url": camp.explanation_url, "created_by": camp.created_by,
        "created_at": as_utc(camp.created_at).isoformat(),
        "window_start": as_utc(camp.window_start).isoformat(), "window_end": as_utc(camp.window_end).isoformat(),
        "overdue": overdue, "counts": counts, "certificates": sorted(items, key=lambda i: (i["state"], i["common_name"])),
    }

