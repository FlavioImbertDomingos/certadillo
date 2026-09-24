"""dns-01 lookups for the ACME server (RFC 8555 section 8.4).

Banks usually run split-horizon DNS: internal zones only exist on internal
resolvers, and the same name can resolve differently inside and outside.
The resolver used for a lookup is picked by zone (CERTADILLO_ACME_DNS_VIEWS,
longest suffix wins), falling back to CERTADILLO_ACME_DNS_RESOLVERS and then
to the host's resolver configuration.

CNAMEs are followed, so teams can delegate _acme-challenge.<name> to a zone
their automation is allowed to write, a common pattern when the main zone
is managed by a separate team.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

import dns.exception
import dns.resolver


@dataclass
class Nameserver:
    host: str
    port: int = 53


def parse_servers(raw: str) -> list[Nameserver]:
    out = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("["):  # [v6]:port
            host, _, port = item[1:].partition("]")
            out.append(Nameserver(host, int(port.lstrip(":") or 53)))
        elif item.count(":") == 1:  # v4:port or name:port
            host, port = item.split(":")
            out.append(Nameserver(host, int(port)))
        else:
            out.append(Nameserver(item))
    return out


def parse_views(raw: str) -> dict[str, list[Nameserver]]:
    """"bank.internal=10.1.0.53,10.2.0.53;example.com=1.1.1.1" -> {zone: servers}"""
    views = {}
    for part in raw.split(";"):
        if "=" not in part:
            continue
        zone, servers = part.split("=", 1)
        zone = zone.strip().lower().strip(".")
        if zone:
            views[zone] = parse_servers(servers)
    return views


def servers_for(name: str, views: dict[str, list[Nameserver]], default: list[Nameserver]) -> tuple[str, list[Nameserver]]:
    """Return (view name, servers). The view is 'default' or the matching zone."""
    name = name.lower().strip(".")
    best = None
    for zone in views:
        if name == zone or name.endswith("." + zone):
            if best is None or len(zone) > len(best):
                best = zone
    if best is not None:
        return best, views[best]
    return "default", default


def key_authorization_digest(token: str, account_thumbprint: str) -> str:
    """The TXT value an ACME client publishes: base64url(SHA-256(keyAuthorization))."""
    ka = f"{token}.{account_thumbprint}".encode()
    return base64.urlsafe_b64encode(hashlib.sha256(ka).digest()).rstrip(b"=").decode()


class DnsLookupError(Exception):
    pass


def lookup_txt(name: str, settings) -> tuple[list[str], str]:
    """TXT strings at name, and the view that answered."""
    views = parse_views(settings.acme_dns_views)
    default = parse_servers(",".join(settings.acme_dns_resolvers))
    view, servers = servers_for(name, views, default)
    if servers:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [s.host for s in servers]
        # dnspython keeps one port per resolver; views put their port on every server
        r.port = servers[0].port
    else:
        r = dns.resolver.Resolver()
    r.lifetime = settings.acme_dns_timeout
    r.cache = None
    try:
        answer = r.resolve(name, "TXT", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        raise DnsLookupError(f"{name} does not exist in the {view} view") from None
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DnsLookupError(f"no answer for {name} from the {view} view: {e}") from None
    values = []
    if answer.rrset is not None:
        for rdata in answer.rrset:
            values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
    return values, view
