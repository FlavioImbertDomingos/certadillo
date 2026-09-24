"""Data model for an AD CS certificate template and CA configuration.

A Template is built from LDAP attributes (from the live collector) or from
the JSON that the Export-CertadilloAdcsTemplates PowerShell script produces.
Both paths land here, so the analyzer never sees the transport.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from certadillo.adcs.sd import SecurityDescriptor

# msPKI-Certificate-Name-Flag (MS-CRTD 2.28)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# msPKI-Enrollment-Flag (MS-CRTD 2.26)
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# EKU OIDs
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

AUTH_EKUS = {EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON, EKU_PKINIT_CLIENT}

# The two extended-right GUIDs that grant enrollment (MS-CRTD / MS-ADTS)
GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
GUID_ALL = "00000000-0000-0000-0000-000000000000"  # all-extended-rights / all-properties

# Well-known low-privilege principals. Enrollment granted to any of these is
# "anyone in the domain can enroll". RIDs 513 Domain Users, 515 Domain
# Computers, 545 Users, plus Authenticated Users and Everyone.
LOW_PRIV_SIDS = {"S-1-1-0", "S-1-5-11"}
LOW_PRIV_RIDS = {"513", "515", "545"}


def is_low_priv(sid: str) -> bool:
    if sid in LOW_PRIV_SIDS:
        return True
    return sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in LOW_PRIV_RIDS


# Admin principals whose control over a template is expected, not a finding.
_ADMIN_RIDS = {"512", "516", "518", "519", "500", "502", "498", "521"}


def is_admin(sid: str) -> bool:
    if sid in {"S-1-5-9", "S-1-5-32-544"}:
        return True
    return sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in _ADMIN_RIDS


@dataclass
class Template:
    name: str
    display_name: str = ""
    schema_version: int = 1
    name_flags: int = 0
    enrollment_flags: int = 0
    ra_signatures: int = 0  # msPKI-RA-Signature: authorized signatures required
    ekus: list[str] = field(default_factory=list)  # pKIExtendedKeyUsage OIDs
    application_policies: list[str] = field(default_factory=list)  # msPKI-RA-Application-Policies
    certificate_policies: list[str] = field(default_factory=list)  # msPKI-Certificate-Policy (issuance OIDs)
    sd: SecurityDescriptor | None = None
    # issuance-policy OID -> group DN, from msDS-OIDToGroupLink on the OID object
    policy_group_links: dict[str, str] = field(default_factory=dict)

    @property
    def enrollee_supplies_subject(self) -> bool:
        return bool(self.name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    @property
    def requires_manager_approval(self) -> bool:
        return bool(self.enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS)

    @property
    def no_security_extension(self) -> bool:
        return bool(self.enrollment_flags & CT_FLAG_NO_SECURITY_EXTENSION)

    @property
    def any_purpose(self) -> bool:
        return EKU_ANY_PURPOSE in self.ekus or not self.ekus

    @property
    def client_authentication(self) -> bool:
        return self.any_purpose or any(e in self.ekus for e in AUTH_EKUS)

    @property
    def server_authentication(self) -> bool:
        return self.any_purpose or EKU_SERVER_AUTH in self.ekus

    @property
    def enrollment_agent(self) -> bool:
        return self.any_purpose or EKU_CERT_REQUEST_AGENT in self.ekus

    @property
    def linked_groups(self) -> list[str]:
        return [self.policy_group_links[o] for o in self.certificate_policies if o in self.policy_group_links]


@dataclass
class CaConfig:
    name: str
    dns: str = ""
    # CA policy edit flags (the EDITF_* bitfield in the registry Policy\EditFlags)
    edit_flags: int = 0
    # security-extension OIDs the CA is configured to omit (DisableExtensionList)
    disabled_extensions: list[str] = field(default_factory=list)
    request_disposition: str = "issue"  # issue | pending | unknown
    web_enrollment_http: bool = False
    web_enrollment_https: bool = False
    https_channel_binding: bool | None = None
    enforce_encrypt_request: bool | None = None  # IF_ENFORCEENCRYPTICERTREQUEST
    ntauth_thumbprints: list[str] = field(default_factory=list)


# EDITF_ATTRIBUTESUBJECTALTNAME2: the CA honours a SAN in the request attributes
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
OID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"
