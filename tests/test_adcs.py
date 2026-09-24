"""AD CS template audit: analyzer, security-descriptor parser and JSON import."""
from __future__ import annotations

import base64

import pytest

from adcs_sd_builder import allowed_ace, allowed_object_ace, build_sd
from conftest import ADMIN, onboard
from certadillo.adcs import analyze_ca, analyze_template
from certadillo.adcs.collector import from_json
from certadillo.adcs.model import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_NO_SECURITY_EXTENSION,
    CT_FLAG_PEND_ALL_REQUESTS,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    EKU_CLIENT_AUTH,
    EKU_CERT_REQUEST_AGENT,
    EKU_SERVER_AUTH,
    GUID_ENROLL,
    OID_NTDS_CA_SECURITY_EXT,
    CaConfig,
    Template,
)
from certadillo.adcs.sd import (
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_GENERIC_ALL,
    RIGHT_WRITE_DACL,
    SecurityDescriptor,
)

DOMAIN = "S-1-5-21-1111111111-2222222222-3333333333"
DOMAIN_USERS = f"{DOMAIN}-513"
DOMAIN_ADMINS = f"{DOMAIN}-512"
AUTH_USERS = "S-1-5-11"


def enroll_sd(sid=DOMAIN_USERS, owner=DOMAIN_ADMINS):
    """SD granting the Enroll extended right to `sid`, owned by admins."""
    return SecurityDescriptor.parse(
        build_sd(owner, [allowed_object_ace(sid, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL)])
    )


def escs(findings):
    return {f.esc for f in findings}


# --------------------------------------------------------------------------- SD parser
def test_sd_parser_reads_owner_and_object_ace():
    sd = enroll_sd()
    assert sd.owner == DOMAIN_ADMINS
    assert len(sd.aces) == 1
    ace = sd.aces[0]
    assert ace.sid == DOMAIN_USERS
    assert ace.object_type == GUID_ENROLL
    assert ace.has(RIGHT_DS_CONTROL_ACCESS)


def test_sd_parser_plain_ace_has_no_object_type():
    sd = SecurityDescriptor.parse(build_sd(DOMAIN_ADMINS, [allowed_ace(DOMAIN_USERS, RIGHT_GENERIC_ALL)]))
    assert sd.aces[0].object_type is None
    assert sd.aces[0].has(RIGHT_GENERIC_ALL)


# --------------------------------------------------------------------------- ESC1 / ESC15
def test_esc1_client_auth_enrollee_supplies_subject():
    t = Template(name="VulnUser", schema_version=2, name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd())
    found = escs(analyze_template(t))
    assert "ESC1" in found
    assert "ESC15" not in found  # schema v2


def test_esc15_is_schema_v1_ess():
    t = Template(name="V1", schema_version=1, name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd())
    found = escs(analyze_template(t))
    assert {"ESC1", "ESC15"} <= found


def test_manager_approval_suppresses_enrollment_escs():
    t = Template(name="Gated", schema_version=2,
                 name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 enrollment_flags=CT_FLAG_PEND_ALL_REQUESTS,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd())
    assert "ESC1" not in escs(analyze_template(t))


def test_ra_signature_suppresses_enrollment_escs():
    t = Template(name="Signed", schema_version=2, name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 ra_signatures=1, ekus=[EKU_CLIENT_AUTH], sd=enroll_sd())
    assert "ESC1" not in escs(analyze_template(t))


def test_esc1_needs_low_priv_enroller():
    # only Domain Admins can enroll -> not an ESC1 for a low-priv user
    t = Template(name="AdminOnly", schema_version=2, name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd(sid=DOMAIN_ADMINS))
    assert "ESC1" not in escs(analyze_template(t))


def test_authenticated_users_counts_as_low_priv():
    t = Template(name="AU", schema_version=2, name_flags=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd(sid=AUTH_USERS))
    assert "ESC1" in escs(analyze_template(t))


# --------------------------------------------------------------------------- ESC2 / ESC3
def test_esc2_any_purpose():
    t = Template(name="Any", schema_version=2, ekus=[], sd=enroll_sd())  # empty EKU = any purpose
    found = escs(analyze_template(t))
    assert "ESC2" in found


def test_esc3_enrollment_agent():
    t = Template(name="Agent", schema_version=2, ekus=[EKU_CERT_REQUEST_AGENT], sd=enroll_sd())
    assert "ESC3" in escs(analyze_template(t))


# --------------------------------------------------------------------------- ESC9
def test_esc9_no_security_extension_on_client_auth():
    t = Template(name="NoSid", schema_version=2, enrollment_flags=CT_FLAG_NO_SECURITY_EXTENSION,
                 ekus=[EKU_CLIENT_AUTH], sd=enroll_sd())
    assert "ESC9" in escs(analyze_template(t))


def test_esc9_needs_client_auth():
    t = Template(name="NoSidServer", schema_version=2, enrollment_flags=CT_FLAG_NO_SECURITY_EXTENSION,
                 ekus=[EKU_SERVER_AUTH], sd=enroll_sd())
    assert "ESC9" not in escs(analyze_template(t))


# --------------------------------------------------------------------------- ESC13
def test_esc13_issuance_policy_group_link():
    t = Template(name="Linked", schema_version=2, ekus=[EKU_CLIENT_AUTH],
                 certificate_policies=["1.3.6.1.4.1.311.21.8.1.2.3"],
                 policy_group_links={"1.3.6.1.4.1.311.21.8.1.2.3": "CN=PKI Admins,..."},
                 sd=enroll_sd())
    found = analyze_template(t)
    assert "ESC13" in escs(found)
    assert any("PKI Admins" in f.detail for f in found if f.esc == "ESC13")


# --------------------------------------------------------------------------- ESC4
def test_esc4_low_priv_writedacl():
    sd = SecurityDescriptor.parse(build_sd(DOMAIN_ADMINS, [
        allowed_object_ace(DOMAIN_ADMINS, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL),
        allowed_ace(DOMAIN_USERS, RIGHT_WRITE_DACL),
    ]))
    t = Template(name="Editable", schema_version=2, ekus=[EKU_CLIENT_AUTH], sd=sd)
    found = analyze_template(t)
    assert "ESC4" in escs(found)
    assert DOMAIN_USERS in [p for f in found if f.esc == "ESC4" for p in f.principals]


def test_esc4_admin_writer_is_not_flagged():
    sd = SecurityDescriptor.parse(build_sd(DOMAIN_ADMINS, [allowed_ace(DOMAIN_ADMINS, RIGHT_WRITE_DACL)]))
    t = Template(name="AdminEdit", schema_version=2, ekus=[EKU_SERVER_AUTH], sd=sd)
    assert "ESC4" not in escs(analyze_template(t))


def test_esc4_non_admin_owner_flagged():
    sd = SecurityDescriptor.parse(build_sd(DOMAIN_USERS, [allowed_ace(DOMAIN_ADMINS, RIGHT_GENERIC_ALL)]))
    t = Template(name="Owned", schema_version=2, ekus=[EKU_SERVER_AUTH], sd=sd)
    assert "ESC4" in escs(analyze_template(t))


# --------------------------------------------------------------------------- CA (ESC6/8/11/16)
def test_esc6_editf_san():
    ca = CaConfig(name="ca-1", edit_flags=EDITF_ATTRIBUTESUBJECTALTNAME2)
    assert "ESC6" in escs(analyze_ca(ca))


def test_esc16_disabled_sid_extension():
    ca = CaConfig(name="ca-1", disabled_extensions=[OID_NTDS_CA_SECURITY_EXT])
    assert "ESC16" in escs(analyze_ca(ca))


def test_esc8_http_web_enrollment():
    ca = CaConfig(name="ca-1", web_enrollment_http=True)
    assert "ESC8" in escs(analyze_ca(ca))


def test_esc11_unencrypted_rpc():
    ca = CaConfig(name="ca-1", enforce_encrypt_request=False)
    assert "ESC11" in escs(analyze_ca(ca))


def test_pending_disposition_suppresses_ca_findings():
    ca = CaConfig(name="ca-1", edit_flags=EDITF_ATTRIBUTESUBJECTALTNAME2, request_disposition="pending")
    assert "ESC6" not in escs(analyze_ca(ca))


# --------------------------------------------------------------------------- JSON import
def test_from_json_roundtrip():
    sd_b64 = base64.b64encode(build_sd(DOMAIN_ADMINS, [
        allowed_object_ace(DOMAIN_USERS, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL)
    ])).decode()
    doc = {
        "templates": [{
            "name": "WebServerEss", "schema_version": 1,
            "name_flags": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, "enrollment_flags": 0,
            "ekus": [EKU_CLIENT_AUTH], "certificate_policies": [],
            "security_descriptor": sd_b64,
        }],
        "cas": [{"name": "ca-1", "edit_flags": EDITF_ATTRIBUTESUBJECTALTNAME2}],
        "oid_group_links": {},
    }
    templates, cas, ntauth = from_json(doc)
    assert templates[0].enrollee_supplies_subject
    assert templates[0].sd.owner == DOMAIN_ADMINS
    assert {"ESC1", "ESC15"} <= escs(analyze_template(templates[0]))
    assert "ESC6" in escs(analyze_ca(cas[0]))


def test_from_json_oid_links_attach_to_template():
    doc = {
        "templates": [{"name": "L", "schema_version": 2, "ekus": [EKU_CLIENT_AUTH],
                       "certificate_policies": ["1.2.3.4"]}],
        "cas": [],
        "oid_group_links": {"1.2.3.4": "CN=Admins"},
    }
    templates, _, _ = from_json(doc)
    assert templates[0].linked_groups == ["CN=Admins"]


# --------------------------------------------------------------------------- LDAP collector
class _FakeEntry:
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self._attrs = attrs

    @property
    def entry_attributes_as_dict(self):
        return dict(self._attrs)


class _FakeConn:
    """Answers LdapCollector._search by the objectClass in the filter."""

    def __init__(self, by_class):
        self.by_class = by_class
        self.entries = []

    def search(self, base, filt, search_scope=None, attributes=None):
        for cls, entries in self.by_class.items():
            if cls in filt:
                self.entries = entries
                return True
        # NTAuth container search uses (objectClass=*)
        self.entries = self.by_class.get("*", [])
        return True


def test_ldap_collector_maps_attributes():
    from certadillo.adcs.collector import LdapCollector

    sd = build_sd(DOMAIN_ADMINS, [allowed_object_ace(DOMAIN_USERS, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL)])
    fake = _FakeConn({
        "msPKI-Enterprise-Oid": [
            _FakeEntry("CN=oid1,...", {"msPKI-Cert-Template-OID": ["1.2.3.4"],
                                       "msDS-OIDToGroupLink": ["CN=PKI Admins,..."]}),
        ],
        "pKICertificateTemplate": [
            _FakeEntry("CN=VulnUser,...", {
                "cn": ["VulnUser"], "displayName": ["Vuln User"],
                "msPKI-Template-Schema-Version": [1],
                "msPKI-Certificate-Name-Flag": [CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT],
                "msPKI-Enrollment-Flag": [0], "msPKI-RA-Signature": [0],
                "pKIExtendedKeyUsage": [EKU_CLIENT_AUTH],
                "msPKI-Certificate-Policy": ["1.2.3.4"],
                "nTSecurityDescriptor": [sd],
            }),
        ],
        "pKIEnrollmentService": [
            _FakeEntry("CN=ca-1,...", {"cn": ["ca-1"], "dNSHostName": ["ca1.bank.internal"]}),
        ],
        "*": [],
    })
    collector = LdapCollector("ldaps://dc/", "u", "p", "DC=bank,DC=internal")
    collector._conn = fake  # inject; skip the real bind
    templates, cas, ntauth = collector.collect()
    assert templates[0].name == "VulnUser"
    assert templates[0].schema_version == 1
    assert templates[0].linked_groups == ["CN=PKI Admins,..."]
    assert {"ESC1", "ESC13", "ESC15"} <= escs(analyze_template(templates[0]))
    assert cas[0].name == "ca-1"


# --------------------------------------------------------------------------- API + store
def test_api_import_and_findings(client):
    sd_b64 = base64.b64encode(build_sd(DOMAIN_ADMINS, [
        allowed_object_ace(DOMAIN_USERS, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL)
    ])).decode()
    doc = {
        "templates": [{"name": "VulnUser", "schema_version": 1,
                       "name_flags": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                       "ekus": [EKU_CLIENT_AUTH], "security_descriptor": sd_b64}],
        "cas": [{"name": "ca-1", "edit_flags": EDITF_ATTRIBUTESUBJECTALTNAME2}],
    }
    r = client.post("/api/v1/adcs/audit/import", json={"document": doc}, headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"].get("critical", 0) >= 1
    got = {f["esc"] for f in body["findings"]}
    assert {"ESC1", "ESC6", "ESC15"} <= got

    r = client.get("/api/v1/adcs/findings", headers=ADMIN)
    assert r.status_code == 200
    latest = r.json()
    assert latest["run_id"] == body["run_id"]
    assert "ESC1" in latest["esc_catalogue"]
    assert {f["esc"] for f in latest["findings"]} == got


def test_api_import_requires_operator(client):
    _, app_headers = onboard(client)
    r = client.post("/api/v1/adcs/audit/import", json={"document": {"templates": [], "cas": []}},
                    headers=app_headers)
    assert r.status_code == 403


def test_adcs_alert_fires(client, tmp_path):
    """A critical finding surfaces as an AdcsTemplateVulnerable alert."""
    sd_b64 = base64.b64encode(build_sd(DOMAIN_ADMINS, [
        allowed_object_ace(DOMAIN_USERS, RIGHT_DS_CONTROL_ACCESS, GUID_ENROLL)
    ])).decode()
    doc = {"templates": [{"name": "VulnUser", "schema_version": 2,
                          "name_flags": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                          "ekus": [EKU_CLIENT_AUTH], "security_descriptor": sd_b64}], "cas": []}
    assert client.post("/api/v1/adcs/audit/import", json={"document": doc}, headers=ADMIN).status_code == 200
    assert client.post("/api/v1/alerts/evaluate", headers=ADMIN).status_code == 200
    alerts = client.get("/api/v1/alerts", headers=ADMIN).json()
    rules = {a["rule"] for a in alerts}
    assert "AdcsTemplateVulnerable" in rules


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
