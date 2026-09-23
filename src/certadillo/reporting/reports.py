"""Compliance and crypto-agility reports."""
from __future__ import annotations

import csv
import io
import uuid
from collections import Counter
from datetime import datetime, timezone

from cryptography import x509

from certadillo import __version__
from certadillo.db import AlertState, App, ApprovalRequest, Certificate, CertificateAuthority, SSHCertificate, Team, as_utc
from certadillo.policy.engine import PQC_SIG_OIDS, describe_key

# NIST IR 8547 (initial public draft): 112-bit RSA/ECC deprecated after 2030,
# all quantum-vulnerable public-key algorithms disallowed after 2035.
PQC_DEPRECATE = datetime(2031, 1, 1, tzinfo=timezone.utc)
PQC_DISALLOW = datetime(2036, 1, 1, tzinfo=timezone.utc)


def summary(s, settings) -> dict:
    from certadillo.alerting.evaluator import expiry_state

    now = datetime.now(timezone.utc)
    certs = s.query(Certificate).all()
    active = [c for c in certs if c.status == "active"]
    states = Counter(expiry_state(c.not_before, c.not_after, settings, now) for c in active)

    alerts = s.query(AlertState).filter(AlertState.resolved_at.is_(None)).all()
    sev = Counter(a.severity for a in alerts)
    return {
        "certificates": {
            "total": len(certs),
            "active": len(active),
            "expired": states.get("expired", 0),
            "renewal_critical": states.get("critical", 0),
            "renewal_warning": states.get("warning", 0),
            "revoked": sum(1 for c in certs if c.status == "revoked"),
            "by_source": dict(Counter(c.source for c in active)),
            "by_profile": dict(Counter(c.profile or "external" for c in active)),
            "unmanaged": sum(1 for c in active if c.source != "issued" and not c.app_id),
        },
        "ssh_certificates": s.query(SSHCertificate).count(),
        "teams": s.query(Team).count(),
        "apps": dict(Counter(a.status for a in s.query(App).all())),
        "pending_approvals": s.query(ApprovalRequest).filter_by(status="pending").count(),
        "alerts": {"critical": sev.get("critical", 0), "warning": sev.get("warning", 0), "info": sev.get("info", 0)},
        "automation_coverage": _automation(active),
        "health": "critical" if sev.get("critical") else ("warning" if sev.get("warning") else "ok"),
    }


def _automation(active) -> float:
    issued = [c for c in active if c.source == "issued"]
    if not issued:
        return 0.0
    auto = sum(1 for c in issued if c.protocol in ("acme", "est", "rest"))
    return round(auto / len(issued), 3)


def crypto_report(s) -> dict:
    now = datetime.now(timezone.utc)
    active = [c for c in s.query(Certificate).all() if c.status == "active" and as_utc(c.not_after) > now]
    by_alg = Counter(f"{c.key_type.upper()}-{c.key_size}" for c in active)
    by_sig = Counter(c.sig_alg for c in active)
    pqc = sum(1 for c in active if x509.load_pem_x509_certificate(c.pem.encode()).signature_algorithm_oid.dotted_string in PQC_SIG_OIDS)
    past_deprecation = [c for c in active if c.key_type in ("rsa", "ec") and as_utc(c.not_after) >= PQC_DEPRECATE]
    ca_rows = []
    for ca in s.query(CertificateAuthority).all():
        cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        kt, bits, curve = describe_key(cert.public_key())
        ca_rows.append({
            "ca": ca.name,
            "algorithm": f"{kt.upper()}-{curve or bits}",
            "not_after": cert.not_valid_after_utc.isoformat(),
            "signer": ca.signer_type,
            "outlives_2035_cutoff": cert.not_valid_after_utc >= PQC_DISALLOW,
        })
    return {
        "generated_at": now.isoformat(),
        "active_certificates": len(active),
        "by_public_key": dict(by_alg),
        "by_signature_algorithm": dict(by_sig),
        "pqc_signed": pqc,
        "quantum_vulnerable": len(active) - pqc,
        "valid_past_2030_deprecation": len(past_deprecation),
        "certificate_authorities": ca_rows,
        "automation_coverage": _automation(active),
        "recommendations": _recommendations(active, ca_rows),
    }


def _recommendations(active, ca_rows) -> list[str]:
    recs = []
    if any(r["outlives_2035_cutoff"] for r in ca_rows):
        recs.append("Plan a PQC (ML-DSA) or composite root before 2030; current CA certificates outlive the 2035 cutoff.")
    if _automation(active) < 0.9:
        recs.append("Move manual issuance to ACME/EST; 47-day public TLS (March 2029) and PQC rollover both assume automated renewal.")
    weak = sum(1 for c in active if c.key_type == "rsa" and c.key_size < 2048)
    if weak:
        recs.append(f"Replace now: {weak} certificate(s) with RSA keys under 2048 bits.")
    rsa_2048 = sum(1 for c in active if c.key_type == "rsa" and 2048 <= c.key_size < 3072)
    if rsa_2048:
        recs.append(f"{rsa_2048} RSA-2048 certificate(s): acceptable until 2030 under NIST IR 8547; move to P-256/P-384 at next renewal.")
    recs.append("Track TLS key exchange separately: enable hybrid X25519MLKEM768 on edge terminators to limit harvest-now-decrypt-later exposure.")
    return recs


def _alg_ref(c: Certificate) -> tuple[str, dict]:
    ref = f"alg:{c.sig_alg}"
    return ref, {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": c.sig_alg,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "signature",
                "cryptoFunctions": ["sign", "verify"],
                "nistQuantumSecurityLevel": 0 if c.key_type in ("rsa", "ec", "ed25519") else 2,
            },
        },
    }


def cbom(s) -> dict:
    """CycloneDX 1.6 cryptography bill of materials for the certificate estate."""
    comps: dict[str, dict] = {}
    for c in s.query(Certificate).filter(Certificate.status == "active").all():
        alg_ref, alg = _alg_ref(c)
        comps.setdefault(alg_ref, alg)
        key_ref = f"key:{c.key_type}-{c.key_size}"
        comps.setdefault(key_ref, {
            "type": "cryptographic-asset",
            "bom-ref": key_ref,
            "name": f"{c.key_type.upper()} {c.key_size} public key",
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": "public-key", "size": c.key_size},
            },
        })
        comps[f"cert:{c.fingerprint_sha256}"] = {
            "type": "cryptographic-asset",
            "bom-ref": f"cert:{c.fingerprint_sha256}",
            "name": c.common_name or c.serial_hex,
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": c.common_name,
                    "issuerName": c.issuer,
                    "notValidBefore": as_utc(c.not_before).isoformat(),
                    "notValidAfter": as_utc(c.not_after).isoformat(),
                    "signatureAlgorithmRef": alg_ref,
                    "subjectPublicKeyRef": key_ref,
                    "certificateFormat": "X.509",
                    "certificateExtension": "crt",
                },
            },
            "properties": [
                {"name": "certadillo:source", "value": c.source},
                {"name": "certadillo:location", "value": c.location or ""},
                {"name": "certadillo:serial", "value": c.serial_hex},
            ],
        }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "certadillo", "version": __version__}]},
        },
        "components": list(comps.values()),
    }


PCI_FIELDS = ["common_name", "sans", "serial", "issuer", "not_after", "key", "signature", "status", "source",
              "location", "app", "team", "classification"]


def pci_inventory(s, fmt: str = "json"):
    """PCI DSS v4.0 requirement 4.2.1.1: inventory of trusted keys and certificates."""
    apps = {a.id: a for a in s.query(App).all()}
    teams = {t.id: t for t in s.query(Team).all()}
    rows = []
    for c in s.query(Certificate).filter(Certificate.status == "active").order_by(Certificate.not_after).all():
        app = apps.get(c.app_id) if c.app_id else None
        rows.append({
            "common_name": c.common_name,
            "sans": " ".join(c.sans),
            "serial": c.serial_hex,
            "issuer": c.issuer,
            "not_after": as_utc(c.not_after).isoformat(),
            "key": f"{c.key_type.upper()}-{c.key_size}",
            "signature": c.sig_alg,
            "status": c.status,
            "source": c.source,
            "location": c.location or "",
            "app": app.name if app else "",
            "team": teams[app.team_id].name if app else "",
            "classification": app.data_classification if app else "unknown",
        })
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=PCI_FIELDS)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue()
    return {"requirement": "PCI DSS v4.0 4.2.1.1", "generated_at": datetime.now(timezone.utc).isoformat(), "rows": rows}
