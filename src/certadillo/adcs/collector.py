"""Collect AD CS templates and CA configuration.

Two sources feed the same model:

* ``from_json`` parses the file produced by the Export-CertadilloAdcsTemplates
  PowerShell script (runs on a domain-joined host, no extra rights beyond
  read). It carries the CA registry flags that LDAP does not expose.
* ``LdapCollector`` reads the Configuration naming context over LDAP/LDAPS
  with ldap3. It sees templates, enrollment services and the OID-to-group
  links, but not the CA registry, so ESC6/8/11/16 need the JSON export or a
  separate CA-flags import.

Both are read-only.
"""
from __future__ import annotations

import base64

from certadillo.adcs.model import CaConfig, Template
from certadillo.adcs.sd import SecurityDescriptor

TEMPLATE_CONTAINER = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
OID_CONTAINER = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
ENROLLMENT_CONTAINER = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base}"
NTAUTH_DN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,{base}"


def _as_int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# --------------------------------------------------------------------------- JSON
def from_json(doc: dict) -> tuple[list[Template], list[CaConfig], list[str]]:
    """Parse the Export-CertadilloAdcsTemplates document.

    Returns (templates, cas, ntauth_thumbprints). Security descriptors are
    base64 DER; flags are integers; oid_group_links maps issuance-policy OID
    to the linked group's name.
    """
    oid_links = {k: v for k, v in (doc.get("oid_group_links") or {}).items()}
    templates = []
    for t in doc.get("templates", []):
        sd = None
        raw = t.get("security_descriptor")
        if raw:
            sd = SecurityDescriptor.parse(base64.b64decode(raw))
        templates.append(
            Template(
                name=t.get("name", ""),
                display_name=t.get("display_name", ""),
                schema_version=_as_int(t.get("schema_version"), 1),
                name_flags=_as_int(t.get("name_flags")),
                enrollment_flags=_as_int(t.get("enrollment_flags")),
                ra_signatures=_as_int(t.get("ra_signatures")),
                ekus=_as_list(t.get("ekus")),
                application_policies=_as_list(t.get("application_policies")),
                certificate_policies=_as_list(t.get("certificate_policies")),
                sd=sd,
                policy_group_links={o: oid_links[o] for o in _as_list(t.get("certificate_policies")) if o in oid_links},
            )
        )
    cas = []
    for c in doc.get("cas", []):
        cas.append(
            CaConfig(
                name=c.get("name", ""),
                dns=c.get("dns", ""),
                edit_flags=_as_int(c.get("edit_flags")),
                disabled_extensions=_as_list(c.get("disabled_extensions")),
                request_disposition=c.get("request_disposition", "issue"),
                web_enrollment_http=bool(c.get("web_enrollment_http", False)),
                web_enrollment_https=bool(c.get("web_enrollment_https", False)),
                https_channel_binding=c.get("https_channel_binding"),
                enforce_encrypt_request=c.get("enforce_encrypt_request"),
                ntauth_thumbprints=_as_list(c.get("ntauth_thumbprints")),
            )
        )
    return templates, cas, _as_list(doc.get("ntauth_thumbprints"))


# --------------------------------------------------------------------------- LDAP
class LdapCollector:
    """Read templates and OID links from the AD Configuration NC.

    ldap3 is an optional dependency (the ``adcs`` extra). Import is deferred so
    the rest of Certadillo runs without it.
    """

    def __init__(self, url: str, user: str, password: str, base_dn: str, *, use_ssl: bool | None = None):
        self.url = url
        self.user = user
        self.password = password
        self.base_dn = base_dn
        self.use_ssl = use_ssl if use_ssl is not None else url.lower().startswith("ldaps")
        self._conn = None

    def connect(self, server_factory=None, connection_factory=None):
        try:
            import ldap3
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the LDAP collector needs ldap3; install with 'pip install certadillo[adcs]'"
            ) from exc
        make_server = server_factory or ldap3.Server
        make_conn = connection_factory or ldap3.Connection
        server = make_server(self.url, use_ssl=self.use_ssl, get_info=ldap3.ALL)
        self._conn = make_conn(server, user=self.user, password=self.password, auto_bind=True)
        return self._conn

    def _search(self, base: str, filt: str, attrs: list[str]) -> list[dict]:
        import ldap3

        self._conn.search(base, filt, search_scope=ldap3.SUBTREE, attributes=attrs)
        out = []
        for entry in self._conn.entries:
            raw = entry.entry_attributes_as_dict
            out.append({"dn": entry.entry_dn, **raw})
        return out

    def collect(self) -> tuple[list[Template], list[CaConfig], list[str]]:
        base = self.base_dn
        oid_links = self._oid_group_links(base)
        templates = self._templates(base, oid_links)
        cas, ntauth = self._enrollment_services(base)
        return templates, cas, ntauth

    def _oid_group_links(self, base: str) -> dict[str, str]:
        entries = self._search(
            OID_CONTAINER.format(base=base),
            "(objectClass=msPKI-Enterprise-Oid)",
            ["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
        )
        links = {}
        for e in entries:
            oid = _first(e.get("msPKI-Cert-Template-OID"))
            grp = _first(e.get("msDS-OIDToGroupLink"))
            if oid and grp:
                links[oid] = grp
        return links

    def _templates(self, base: str, oid_links: dict[str, str]) -> list[Template]:
        attrs = [
            "cn", "displayName", "msPKI-Template-Schema-Version", "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage",
            "msPKI-RA-Application-Policies", "msPKI-Certificate-Policy", "nTSecurityDescriptor",
        ]
        entries = self._search(
            TEMPLATE_CONTAINER.format(base=base), "(objectClass=pKICertificateTemplate)", attrs
        )
        out = []
        for e in entries:
            sd = None
            raw_sd = _first(e.get("nTSecurityDescriptor"))
            if raw_sd:
                sd = SecurityDescriptor.parse(raw_sd if isinstance(raw_sd, bytes) else bytes(raw_sd))
            policies = _as_list(e.get("msPKI-Certificate-Policy"))
            out.append(
                Template(
                    name=_first(e.get("cn")) or "",
                    display_name=_first(e.get("displayName")) or "",
                    schema_version=_as_int(_first(e.get("msPKI-Template-Schema-Version")), 1),
                    name_flags=_as_int(_first(e.get("msPKI-Certificate-Name-Flag"))),
                    enrollment_flags=_as_int(_first(e.get("msPKI-Enrollment-Flag"))),
                    ra_signatures=_as_int(_first(e.get("msPKI-RA-Signature"))),
                    ekus=[str(x) for x in _as_list(e.get("pKIExtendedKeyUsage"))],
                    application_policies=[str(x) for x in _as_list(e.get("msPKI-RA-Application-Policies"))],
                    certificate_policies=[str(x) for x in policies],
                    sd=sd,
                    policy_group_links={o: oid_links[o] for o in policies if o in oid_links},
                )
            )
        return out

    def _enrollment_services(self, base: str) -> tuple[list[CaConfig], list[str]]:
        entries = self._search(
            ENROLLMENT_CONTAINER.format(base=base),
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "certificateTemplates"],
        )
        cas = [
            CaConfig(name=_first(e.get("cn")) or "", dns=_first(e.get("dNSHostName")) or "",
                     request_disposition="unknown")
            for e in entries
        ]
        ntauth_entries = self._search(NTAUTH_DN.format(base=base), "(objectClass=*)", ["cACertificate"])
        ntauth = []
        for e in ntauth_entries:
            for c in _as_list(e.get("cACertificate")):
                import hashlib

                data = c if isinstance(c, bytes) else bytes(c)
                ntauth.append(hashlib.sha1(data).hexdigest())  # noqa: S324  fingerprint, not a security check
        return cas, ntauth


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v
