"""LDAP connections that cannot be read or altered on the wire.

The logon-certificate path trusts the objectSid the directory returns, and the
bind sends the service account's password, so both need an authenticated,
encrypted channel. ldaps:// is used as is; ldap:// is upgraded with StartTLS
before the bind. Either way the domain controller's certificate must chain to
a trusted CA (CERTADILLO_ADCS_LDAP_CACERT, or the system store) and match the
host name. Plain LDAP is refused unless CERTADILLO_ADCS_LDAP_ALLOW_PLAIN=true,
which is meant for a lab directory only.
"""
from __future__ import annotations

import os
import ssl


class LdapTransportError(Exception):
    pass


def _allow_plain() -> bool:
    return (os.environ.get("CERTADILLO_ADCS_LDAP_ALLOW_PLAIN", "") or "").lower() == "true"


def open_connection(ldap3, url: str, user: str, password: str, *, get_info=None,
                    server_factory=None, connection_factory=None):
    ca_file = os.environ.get("CERTADILLO_ADCS_LDAP_CACERT") or None
    make_server = server_factory or ldap3.Server
    make_conn = connection_factory or ldap3.Connection
    info = ldap3.NONE if get_info is None else get_info
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_file=ca_file)
    if url.lower().startswith("ldaps://"):
        server = make_server(url, use_ssl=True, tls=tls, get_info=info)
        return make_conn(server, user=user, password=password, auto_bind=True)
    if not url.lower().startswith("ldap://"):
        raise LdapTransportError(f"unsupported LDAP URL {url!r}; use ldaps:// or ldap:// with StartTLS")
    if _allow_plain():
        server = make_server(url, use_ssl=False, get_info=info)
        return make_conn(server, user=user, password=password, auto_bind=True)
    server = make_server(url, use_ssl=False, tls=tls, get_info=info)
    return make_conn(server, user=user, password=password, auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND)
