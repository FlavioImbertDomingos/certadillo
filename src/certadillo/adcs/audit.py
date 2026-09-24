"""Run an AD CS audit and persist its findings.

Ties the collector and the analyzer together and records the result in the
adcs_findings table. Called from the API and the CLI. Read-only against AD:
it only reads templates and CA config and writes findings into Certadillo's
own database.
"""
from __future__ import annotations

import uuid

from certadillo.adcs.analyzer import analyze_ca, analyze_template
from certadillo.adcs.collector import LdapCollector, from_json
from certadillo.adcs.model import CaConfig, Template
from certadillo.audit.log import record
from certadillo.db import AdcsFinding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def audit_objects(
    templates: list[Template], cas: list[CaConfig], *, source: str = "json", ntauth: list[str] | None = None
) -> tuple[str, list[dict]]:
    """Analyze already-collected objects. Returns (run_id, findings-as-dicts)."""
    run_id = str(uuid.uuid4())
    results: list[dict] = []
    for tmpl in templates:
        for f in analyze_template(tmpl):
            d = f.to_dict()
            d.update(run_id=run_id, source=source, object_type="template", object_name=tmpl.name)
            results.append(d)
    for ca in cas:
        for f in analyze_ca(ca):
            d = f.to_dict()
            d.update(run_id=run_id, source=source, object_type="ca", object_name=ca.name)
            results.append(d)
    results.sort(key=lambda d: (SEVERITY_ORDER.get(d["severity"], 9), d["object_name"], d["esc"]))
    return run_id, results


def store_findings(session, run_id: str, findings: list[dict], actor: str = "system") -> None:
    for d in findings:
        session.add(
            AdcsFinding(
                run_id=run_id,
                source=d.get("source", "json"),
                object_type=d["object_type"],
                object_name=d["object_name"],
                esc=d["esc"],
                severity=d["severity"],
                title=d["title"],
                detail=d["detail"],
                principals=d.get("principals", []),
                remark=d.get("remark") or None,
            )
        )
    session.flush()
    record(session, actor, "adcs.audit", run_id,
           {"findings": len(findings), "source": findings[0]["source"] if findings else "json"})


def audit_from_json(session, doc: dict, actor: str = "system") -> tuple[str, list[dict]]:
    templates, cas, ntauth = from_json(doc)
    run_id, findings = audit_objects(templates, cas, source="json", ntauth=ntauth)
    store_findings(session, run_id, findings, actor)
    return run_id, findings


def audit_from_ldap(session, collector: LdapCollector, actor: str = "system") -> tuple[str, list[dict]]:
    collector.connect()
    templates, cas, ntauth = collector.collect()
    run_id, findings = audit_objects(templates, cas, source="ldap", ntauth=ntauth)
    store_findings(session, run_id, findings, actor)
    return run_id, findings


def latest_run(session) -> tuple[str | None, list[AdcsFinding]]:
    row = session.query(AdcsFinding).order_by(AdcsFinding.created_at.desc()).first()
    if row is None:
        return None, []
    findings = (
        session.query(AdcsFinding)
        .filter_by(run_id=row.run_id)
        .order_by(AdcsFinding.severity, AdcsFinding.object_name)
        .all()
    )
    return row.run_id, findings
