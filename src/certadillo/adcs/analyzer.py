"""Turn a Template / CaConfig into ESC findings.

The conditions follow Certipy's find command and the SpecterOps "Certified
Pre-Owned" catalogue. Each finding is a fact about a misconfiguration, with
the principals who can reach it, so a PKI team can prioritise the fix. The
auditor draws no conclusion about exploitability beyond the stated
prerequisites, and it never acts on a template.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from certadillo.adcs.model import (
    GUID_ALL,
    GUID_AUTOENROLL,
    GUID_ENROLL,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    OID_NTDS_CA_SECURITY_EXT,
    CaConfig,
    Template,
    is_admin,
    is_low_priv,
)
from certadillo.adcs.sd import (
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_DS_WRITE_PROP,
    RIGHT_GENERIC_ALL,
    RIGHT_GENERIC_WRITE,
    RIGHT_WRITE_DACL,
    RIGHT_WRITE_OWNER,
    Ace,
)

ESC_TITLES = {
    "ESC1": "Enrollee supplies subject on a client-auth template",
    "ESC2": "Template usable for any purpose",
    "ESC3": "Enrollment-agent template enrollable by low-privileged users",
    "ESC4": "Low-privileged users can edit the template",
    "ESC6": "CA honours a SAN from the request (EDITF_ATTRIBUTESUBJECTALTNAME2)",
    "ESC8": "Web enrollment over HTTP without channel binding",
    "ESC9": "Client-auth template omits the SID security extension",
    "ESC11": "CA accepts unencrypted (unauthenticated) RPC requests",
    "ESC13": "Client-auth template linked to a privileged group via issuance policy",
    "ESC15": "Schema v1 enrollee-supplies-subject template (CVE-2024-49019)",
    "ESC16": "CA disables the SID security extension for all certificates",
}

DANGEROUS_RIGHTS = RIGHT_GENERIC_ALL | RIGHT_GENERIC_WRITE | RIGHT_WRITE_DACL | RIGHT_WRITE_OWNER


@dataclass
class Finding:
    esc: str
    severity: str  # critical | high | medium | info
    title: str
    detail: str
    principals: list[str] = field(default_factory=list)  # SIDs that reach it
    remark: str = ""

    def to_dict(self) -> dict:
        return {
            "esc": self.esc,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "principals": self.principals,
            "remark": self.remark,
        }


def _enrollers(tmpl: Template, resolve=None) -> list[str]:
    """SIDs granted Enroll (or AutoEnroll / all-extended / GenericAll) on the template."""
    out: list[str] = []
    if not tmpl.sd:
        return out
    for ace in tmpl.sd.aces:
        if _ace_grants_enroll(ace):
            out.append(ace.sid)
    return sorted(set(out))


def _ace_grants_enroll(ace: Ace) -> bool:
    if ace.has(RIGHT_GENERIC_ALL):
        return True
    if ace.has(RIGHT_DS_CONTROL_ACCESS):
        # control access with the Enroll/AutoEnroll GUID, or with no GUID
        # (all-extended-rights) grants enrollment
        if ace.object_type in (GUID_ENROLL, GUID_AUTOENROLL, GUID_ALL, None):
            return True
    return False


def _low_priv_enrollers(tmpl: Template) -> list[str]:
    return [s for s in _enrollers(tmpl) if is_low_priv(s)]


def _writers(tmpl: Template) -> list[str]:
    """Non-admin SIDs that can edit the template object (ESC4)."""
    out: list[str] = []
    if not tmpl.sd:
        return out
    for ace in tmpl.sd.aces:
        if is_admin(ace.sid):
            continue
        if ace.mask & DANGEROUS_RIGHTS:
            out.append(ace.sid)
        elif ace.has(RIGHT_DS_WRITE_PROP) and ace.object_type in (GUID_ALL, None):
            out.append(ace.sid)
    if tmpl.sd.owner and not is_admin(tmpl.sd.owner):
        out.append(tmpl.sd.owner)
    return sorted(set(out))


def analyze_template(tmpl: Template) -> list[Finding]:
    findings: list[Finding] = []
    low = _low_priv_enrollers(tmpl)
    enrollable_by_low = bool(low)
    # requests that need a second signature or manager approval cannot be
    # driven by a low-priv user alone, so the enrollment-based ESCs do not apply
    gated = tmpl.requires_manager_approval or tmpl.ra_signatures > 0

    if enrollable_by_low and not gated:
        if tmpl.enrollee_supplies_subject and tmpl.client_authentication:
            findings.append(Finding("ESC1", "critical", ESC_TITLES["ESC1"],
                "The template lets the enrollee choose the subject and allows client "
                "authentication, so a low-privileged enroller can request a certificate "
                "naming another account.", low))
        if tmpl.any_purpose:
            findings.append(Finding("ESC2", "critical", ESC_TITLES["ESC2"],
                "The template has the Any Purpose EKU (or no EKU), so its certificates "
                "can be used for any purpose including client authentication.", low))
        if tmpl.enrollment_agent:
            findings.append(Finding("ESC3", "high", ESC_TITLES["ESC3"],
                "The template grants the Certificate Request Agent EKU, so an enroller "
                "can request enrollment-agent certificates and enrol on behalf of others.", low))
        if tmpl.no_security_extension and tmpl.client_authentication:
            findings.append(Finding("ESC9", "high", ESC_TITLES["ESC9"],
                "The template sets CT_FLAG_NO_SECURITY_EXTENSION (0x80000), so issued "
                "certificates omit the SID security extension.", low,
                remark="Exploitable only with weak certificate mapping or an ESC6/ESC16 "
                       "CA; on a fully KB5014754-enforced domain (since 2025) this is hardened."))
        if tmpl.client_authentication and tmpl.certificate_policies and tmpl.linked_groups:
            groups = ", ".join(tmpl.linked_groups)
            findings.append(Finding("ESC13", "high", ESC_TITLES["ESC13"],
                f"The template allows client authentication and its issuance policy is "
                f"linked to group(s) via msDS-OIDToGroupLink: {groups}. Certificates carry "
                f"that group's membership.", low))
        if tmpl.enrollee_supplies_subject and tmpl.schema_version == 1:
            findings.append(Finding("ESC15", "high", ESC_TITLES["ESC15"],
                "Schema version 1 template with enrollee-supplied subject. Application "
                "policies can be injected in the request (CVE-2024-49019, EKUwu).", low,
                remark="Only on domains not patched for CVE-2024-49019."))

    # ESC4 does not depend on enrollment rights
    writers = _writers(tmpl)
    if writers:
        findings.append(Finding("ESC4", "high", ESC_TITLES["ESC4"],
            "Non-administrative principals can edit this template object (WriteDacl, "
            "WriteOwner, GenericAll/Write or full-property write), so they could turn it "
            "into an ESC1 template.", writers))
    return findings


def analyze_ca(ca: CaConfig, user_can_enroll: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    will_issue = ca.request_disposition in ("issue", "unknown")

    if will_issue and (ca.edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2):
        findings.append(Finding("ESC6", "critical", ESC_TITLES["ESC6"],
            "The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set, so any enroller can add a "
            "SAN through the request attributes, regardless of the template.", [],
            remark="On a KB5014754-enforced domain this needs an ESC9/ESC16 template or "
                   "weak mapping to escalate."))
    if will_issue and ca.enforce_encrypt_request is False:
        findings.append(Finding("ESC11", "medium", ESC_TITLES["ESC11"],
            "The CA does not enforce encryption on ICertRequest (RPC) traffic "
            "(IF_ENFORCEENCRYPTICERTREQUEST is off), which allows relay of RPC "
            "enrollment.", []))
    if will_issue and OID_NTDS_CA_SECURITY_EXT in ca.disabled_extensions:
        findings.append(Finding("ESC16", "critical", ESC_TITLES["ESC16"],
            "The CA is configured to omit the SID security extension "
            "(1.3.6.1.4.1.311.25.2) from every certificate it issues.", [],
            remark="Combined with EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) or enrollee-"
                   "supplied SAN this defeats strong certificate mapping domain-wide."))
    if will_issue and ca.web_enrollment_http:
        findings.append(Finding("ESC8", "high", ESC_TITLES["ESC8"],
            "HTTP web enrollment (/certsrv) is enabled without channel binding, which "
            "is an NTLM relay target.", []))
    elif will_issue and ca.web_enrollment_https and ca.https_channel_binding is False:
        findings.append(Finding("ESC8", "high", ESC_TITLES["ESC8"],
            "HTTPS web enrollment is enabled with channel binding disabled, an NTLM "
            "relay target.", []))
    return findings
