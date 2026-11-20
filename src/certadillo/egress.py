"""Outbound HTTP allow-list.

Certadillo calls out to many systems: alert webhooks, Slack, Jira and
ServiceNow, the SCEP validation webhook, DNS provider APIs, upstream CAs,
Vault, cloud certificate stores, the IdP's JWKS, audit sinks. Several of those
URLs are configured by people other than the platform team (a team's webhook,
a provisioning target, a discovery source), which makes them a way to reach
things inside the network (SSRF) or to send data out.

With CERTADILLO_EGRESS_ALLOW set, every one of those calls must go to a listed
destination, checked when the request is made (after redirects too). Entries
are host names (`hooks.slack.com`), wildcard suffixes (`*.bank.internal`),
`host:port`, or IP networks (`10.20.0.0/16`). Without the setting nothing is
restricted except cloud instance-metadata addresses, which are refused unless
listed explicitly: they hand out cloud credentials.

ACME http-01 validation, TLS discovery scans and push-provisioning endpoint
checks are not covered: their destinations are already limited to an app's
approved names and to configured scan targets. SSH and AWS SDK traffic does
not use HTTP here; restrict those with a network policy (the Helm chart has
one).
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import httpx

from certadillo.observability.metrics import EGRESS_DENIED

METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata.azure.internal",
                  "100.100.100.200"}


class EgressDenied(Exception):
    pass


def _allow_list() -> list[str]:
    try:
        from certadillo.runtime import get_runtime

        return get_runtime().settings.egress_allow
    except Exception:  # noqa: BLE001 - no runtime (CLI client, unit test): nothing configured
        return []


def _matches(entry: str, host: str, port: int | None) -> bool:
    entry = entry.strip().lower()
    if not entry:
        return False
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    want_port = None
    if entry.count(":") == 1 and entry.rsplit(":", 1)[1].isdigit():
        entry, p = entry.rsplit(":", 1)
        want_port = int(p)
    if want_port is not None and want_port != port:
        return False
    if entry.startswith("*."):
        return host.endswith(entry[1:])  # any name under the suffix, not the suffix itself
    return host == entry


def check(url: str, purpose: str = "http", allow: list[str] | None = None) -> None:
    """Raise EgressDenied unless url may be called."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port or {"https": 443, "http": 80}.get(parts.scheme)
    except ValueError:
        port = None
    rules = _allow_list() if allow is None else allow
    listed = any(_matches(e, host, port) for e in rules)
    if host in METADATA_HOSTS and not listed:
        EGRESS_DENIED.labels(purpose=purpose).inc()
        raise EgressDenied(f"{purpose}: {host} is a cloud instance-metadata address and is never called "
                           "unless CERTADILLO_EGRESS_ALLOW lists it")
    if rules and not listed:
        EGRESS_DENIED.labels(purpose=purpose).inc()
        raise EgressDenied(f"{purpose}: {host}{':' + str(port) if port else ''} is not in CERTADILLO_EGRESS_ALLOW")


def _hook(purpose: str):
    def on_request(request: httpx.Request) -> None:
        check(str(request.url), purpose)

    return on_request


def client(purpose: str = "http", **kwargs) -> httpx.Client:
    """httpx.Client that checks every request, redirects included, against the allow-list."""
    hooks = kwargs.pop("event_hooks", {}) or {}
    hooks = {**hooks, "request": [*hooks.get("request", []), _hook(purpose)]}
    return httpx.Client(event_hooks=hooks, **kwargs)


def post(url: str, purpose: str = "http", **kwargs) -> httpx.Response:
    with client(purpose) as c:
        return c.post(url, **kwargs)
