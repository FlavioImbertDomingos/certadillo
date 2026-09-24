"""Resolve a UPN to its account SID in Active Directory, for Windows logon
certificates.

The SID that goes into a logon certificate must come from the directory, never
from the request: otherwise an enroller could claim any account's SID and defeat
strong mapping. The lookup fails closed (any error means no certificate), a
disabled account is refused, and a sensitive account (adminCount=1) is flagged
so the RA can require a second approver.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

UF_ACCOUNTDISABLE = 0x0002


@dataclass
class Account:
    upn: str
    sid: str
    enabled: bool
    admin_count: bool
    dn: str = ""


class DirectoryError(Exception):
    pass


def sid_bytes_to_string(data: bytes) -> str:
    revision = data[0]
    count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    for i in range(count):
        parts.append(str(struct.unpack_from("<I", data, 8 + 4 * i)[0]))
    return "-".join(parts)


class DirectoryResolver:
    def __init__(self, url: str, user: str, password: str, base_dn: str, *, use_ssl: bool | None = None):
        self.url = url
        self.user = user
        self.password = password
        self.base_dn = base_dn
        self.use_ssl = use_ssl if use_ssl is not None else url.lower().startswith("ldaps")

    def resolve_upn(self, upn: str) -> Account:
        try:
            import ldap3
        except ImportError as exc:  # pragma: no cover
            raise DirectoryError("the directory resolver needs ldap3 (pip install certadillo[adcs])") from exc
        server = ldap3.Server(self.url, use_ssl=self.use_ssl, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=self.user, password=self.password, auto_bind=True)
        try:
            conn.search(
                self.base_dn,
                f"(&(objectClass=user)(userPrincipalName={_escape(upn)}))",
                search_scope=ldap3.SUBTREE,
                attributes=["objectSid", "userAccountControl", "adminCount"],
            )
            return self._account_from(upn, conn.entries)
        finally:
            conn.unbind()

    @staticmethod
    def _account_from(upn: str, entries) -> Account:
        if len(entries) != 1:
            raise DirectoryError(
                f"UPN {upn!r} matched {len(entries)} accounts; a logon certificate needs exactly one"
            )
        e = entries[0].entry_attributes_as_dict
        raw_sid = _first(e.get("objectSid"))
        if raw_sid is None:
            raise DirectoryError(f"account for {upn!r} has no objectSid")
        sid = raw_sid if isinstance(raw_sid, str) and raw_sid.startswith("S-") else sid_bytes_to_string(bytes(raw_sid))
        uac = int(_first(e.get("userAccountControl")) or 0)
        admin_count = int(_first(e.get("adminCount")) or 0) == 1
        return Account(upn=upn, sid=sid, enabled=not (uac & UF_ACCOUNTDISABLE),
                       admin_count=admin_count, dn=entries[0].entry_dn)


def _escape(value: str) -> str:
    for ch, rep in (("\\", "\\5c"), ("*", "\\2a"), ("(", "\\28"), (")", "\\29"), ("\x00", "\\00")):
        value = value.replace(ch, rep)
    return value


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v
