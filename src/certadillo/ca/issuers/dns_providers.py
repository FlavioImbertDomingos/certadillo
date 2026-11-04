"""DNS updates for ACME dns-01 when Certadillo is the ACME client.

  rfc2136    dynamic update (RFC 2136) signed with TSIG (RFC 8945), the way
             BIND, Infoblox, PowerDNS and Windows DNS accept automated changes
  http-hook  POST {"host", "value"} to set_url and {"host"} to clear_url, for an
             in-house DNS automation API (also what Pebble's challtestsrv speaks)
"""
from __future__ import annotations

import httpx

from certadillo.provisioning import credentials


class DnsError(Exception):
    pass


def build(cfg: dict, settings=None):
    kind = cfg.get("provider")
    if kind == "rfc2136":
        return Rfc2136(cfg, settings)
    if kind == "http-hook":
        return HttpHook(cfg, settings)
    raise ValueError("dns.provider must be rfc2136 or http-hook")


class Rfc2136:
    def __init__(self, cfg: dict, settings=None):
        for k in ("server", "zone", "tsig_name", "tsig_secret_ref"):
            if not cfg.get(k):
                raise ValueError(f"rfc2136 dns needs {k}")
        credentials.check_ref(cfg["tsig_secret_ref"])
        self.cfg = cfg
        self.settings = settings

    def _update(self):
        import dns.tsigkeyring
        import dns.update

        secret = credentials.resolve(self.cfg["tsig_secret_ref"], self.settings)
        ring = dns.tsigkeyring.from_text({self.cfg["tsig_name"]: secret})
        return dns.update.UpdateMessage(self.cfg["zone"], keyring=ring,
                                        keyalgorithm=self.cfg.get("tsig_algorithm", "hmac-sha256"))

    def _send(self, msg) -> None:
        import dns.query
        import dns.rcode

        resp = dns.query.tcp(msg, self.cfg["server"], port=int(self.cfg.get("port", 53)), timeout=10)
        if resp.rcode() != dns.rcode.NOERROR:
            raise DnsError(f"DNS update refused: {dns.rcode.to_text(resp.rcode())}")

    def set_txt(self, fqdn: str, value: str) -> None:
        msg = self._update()
        msg.add(fqdn, int(self.cfg.get("ttl", 60)), "TXT", f'"{value}"')
        self._send(msg)

    def clear_txt(self, fqdn: str, value: str) -> None:
        msg = self._update()
        msg.delete(fqdn, "TXT", f'"{value}"')
        self._send(msg)


class HttpHook:
    def __init__(self, cfg: dict, settings=None):
        for k in ("set_url", "clear_url"):
            if not str(cfg.get(k, "")).startswith(("https://", "http://")):
                raise ValueError(f"http-hook dns needs {k}")
        credentials.check_ref(cfg.get("token_ref"))
        self.cfg = cfg
        self.settings = settings

    def _post(self, url: str, body: dict) -> None:
        headers = {}
        if self.cfg.get("token_ref"):
            headers["Authorization"] = "Bearer " + credentials.resolve(self.cfg["token_ref"], self.settings)
        r = httpx.post(url, json=body, headers=headers, timeout=15)
        if r.status_code >= 300:
            raise DnsError(f"DNS hook {url} returned {r.status_code}")

    def set_txt(self, fqdn: str, value: str) -> None:
        self._post(self.cfg["set_url"], {"host": fqdn, "value": value})

    def clear_txt(self, fqdn: str, value: str) -> None:
        self._post(self.cfg["clear_url"], {"host": fqdn})
