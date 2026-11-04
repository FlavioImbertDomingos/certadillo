"""Discovery sources configured in the policy file, run on a schedule:

    discovery:
      sources:
        acm-prod:   {type: aws-acm, regions: [us-east-1, us-west-2], interval_hours: 24}
        kv-payments: {type: azure-keyvault, vault_url: https://kv-pay.vault.azure.net, token_ref: env:...}
        gcp-edge:   {type: gcp-certmanager, project: bank-edge, location: global, token_ref: file:...}
        ct-public:  {type: ct, zones: [bank.example], provider: certspotter, token_ref: env:...}

Cloud sources put every certificate they can read into the inventory. The CT
source watches public Certificate Transparency for certificates under the
bank's zones and raises a finding for each one Certadillo did not issue or
already know about: a public certificate nobody requested through the platform
is either shadow IT or someone else holding a certificate for your name.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Iterator

import httpx
from cryptography import x509

from certadillo.db import Certificate, DiscoveryFinding, DiscoveryRun, as_utc
from certadillo.provisioning import credentials

# Tests put an httpx transport here per source type.
test_transports: dict = {}
POISON = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")  # CT precertificate poison


class SourceError(Exception):
    pass


def build(name: str, cfg: dict, settings=None):
    kind = cfg.get("type")
    for k in ("token_ref",):
        credentials.check_ref(cfg.get(k))
    if kind == "aws-acm":
        return AwsAcmSource(name, cfg)
    if kind == "azure-keyvault":
        return AzureKeyVaultSource(name, cfg, settings)
    if kind == "gcp-certmanager":
        return GcpCertManagerSource(name, cfg, settings)
    if kind == "ct":
        return CtSource(name, cfg, settings)
    raise ValueError(f"discovery source {name}: unknown type {kind!r} (aws-acm, azure-keyvault, gcp-certmanager, ct)")


def configured(policies: dict, settings=None) -> dict:
    return {n: build(n, c or {}, settings) for n, c in ((policies.get("discovery") or {}).get("sources") or {}).items()}


def _client(kind: str, cfg: dict, settings, base_url: str) -> httpx.Client:
    headers = {}
    if cfg.get("token_ref"):
        headers["Authorization"] = "Bearer " + credentials.resolve(cfg["token_ref"], settings)
    return httpx.Client(base_url=base_url, headers=headers, timeout=30, transport=test_transports.get(kind))


# ------------------------------------------------------------------ cloud stores
class AwsAcmSource:
    kind = "aws-acm"

    def __init__(self, name: str, cfg: dict):
        if not cfg.get("regions"):
            raise ValueError(f"discovery source {name}: aws-acm needs regions")
        self.name, self.cfg = name, cfg

    def collect(self) -> Iterator[tuple[x509.Certificate, str]]:
        import boto3

        for region in self.cfg["regions"]:
            acm = boto3.client("acm", region_name=region)
            for page in acm.get_paginator("list_certificates").paginate(
                    Includes={"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1",
                                           "EC_secp384r1", "EC_secp521r1"]}):
                for summary in page["CertificateSummaryList"]:
                    arn = summary["CertificateArn"]
                    try:
                        body = acm.get_certificate(CertificateArn=arn)["Certificate"]
                    except acm.exceptions.RequestInProgressException:
                        continue  # a pending ACM-issued certificate has no body yet
                    yield x509.load_pem_x509_certificate(body.encode()), f"acm:{arn}"


class AzureKeyVaultSource:
    """Key Vault certificates over REST (api-version 7.4). The token is an Entra
    ID access token for https://vault.azure.net with certificates/list and get."""

    kind = "azure-keyvault"

    def __init__(self, name: str, cfg: dict, settings=None):
        if not str(cfg.get("vault_url", "")).startswith("https://") or not cfg.get("token_ref"):
            raise ValueError(f"discovery source {name}: azure-keyvault needs an https vault_url and token_ref")
        self.name, self.cfg, self.settings = name, cfg, settings

    def collect(self):
        with _client(self.kind, self.cfg, self.settings, self.cfg["vault_url"].rstrip("/")) as c:
            url = "/certificates?api-version=7.4"
            while url:
                r = c.get(url)
                if r.status_code != 200:
                    raise SourceError(f"Key Vault list returned {r.status_code}")
                page = r.json()
                for item in page.get("value", []):
                    cert = c.get(item["id"].split(".net", 1)[-1] + "?api-version=7.4")
                    if cert.status_code == 200 and cert.json().get("cer"):
                        der = base64.b64decode(cert.json()["cer"])
                        yield x509.load_der_x509_certificate(der), f"keyvault:{item['id']}"
                nxt = page.get("nextLink")
                url = nxt.split(".net", 1)[-1] if nxt else None


class GcpCertManagerSource:
    """Google Certificate Manager certificates (v1 REST); the token is an OAuth
    access token with certificatemanager.certs.list."""

    kind = "gcp-certmanager"

    def __init__(self, name: str, cfg: dict, settings=None):
        if not cfg.get("project") or not cfg.get("token_ref"):
            raise ValueError(f"discovery source {name}: gcp-certmanager needs project and token_ref")
        self.name, self.cfg, self.settings = name, cfg, settings

    def collect(self):
        loc = self.cfg.get("location", "global")
        base = self.cfg.get("api_url", "https://certificatemanager.googleapis.com")
        with _client(self.kind, self.cfg, self.settings, base) as c:
            token = None
            while True:
                params = {"pageToken": token} if token else {}
                r = c.get(f"/v1/projects/{self.cfg['project']}/locations/{loc}/certificates", params=params)
                if r.status_code != 200:
                    raise SourceError(f"Certificate Manager list returned {r.status_code}")
                page = r.json()
                for item in page.get("certificates", []):
                    if item.get("pemCertificate"):
                        yield x509.load_pem_x509_certificates(item["pemCertificate"].encode())[0], f"gcp:{item['name']}"
                token = page.get("nextPageToken")
                if not token:
                    break


# ------------------------------------------------------------------ Certificate Transparency
class CtSource:
    """Watches CT through SSLMate Cert Spotter's issuance API (zone search,
    subdomains included). Matching is by serial number, because a CT entry may
    be the precertificate rather than the final certificate."""

    kind = "ct"

    def __init__(self, name: str, cfg: dict, settings=None):
        if not cfg.get("zones"):
            raise ValueError(f"discovery source {name}: ct needs zones")
        if cfg.get("provider", "certspotter") != "certspotter":
            raise ValueError(f"discovery source {name}: provider must be certspotter")
        self.name, self.cfg, self.settings = name, cfg, settings

    def issuances(self) -> Iterator[dict]:
        base = self.cfg.get("api_url", "https://api.certspotter.com")
        with _client(self.kind, self.cfg, self.settings, base) as c:
            for zone in self.cfg["zones"]:
                after = None
                while True:
                    params = [("domain", zone), ("include_subdomains", "true"), ("expand", "dns_names"),
                              ("expand", "issuer"), ("expand", "cert")]
                    if after:
                        params.append(("after", after))
                    r = c.get("/v1/issuances", params=params)
                    if r.status_code != 200:
                        raise SourceError(f"Cert Spotter returned {r.status_code}: {r.text[:200]}")
                    batch = r.json()
                    yield from batch
                    if len(batch) < int(self.cfg.get("page_size", 100)):
                        break
                    after = batch[-1]["id"]


# ------------------------------------------------------------------ running
def run_source(p, name: str, src, actor: str = "system") -> DiscoveryRun:
    run = DiscoveryRun(source=name, status="ok")
    p.s.add(run)
    p.s.flush()
    try:
        if isinstance(src, CtSource):
            run.found, run.new = _run_ct(p, name, src, actor)
        else:
            for cert, location in src.collect():
                run.found += 1
                _, _, is_new = p.ingest(actor, cert, "cloud", location)
                run.new += int(is_new)
    except Exception as exc:  # noqa: BLE001 - recorded on the run and alerted on
        run.status, run.error = "failed", f"{type(exc).__name__}: {exc}"[:500]
    run.finished_at = datetime.now(timezone.utc)
    from certadillo.audit.log import record

    record(p.s, actor, "discovery.source.run", name, {"status": run.status, "found": run.found, "new": run.new,
                                                      "error": run.error})
    return run


def _run_ct(p, name: str, src: CtSource, actor: str) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    found = new = 0
    for iss in src.issuances():
        not_after = datetime.fromisoformat(iss["not_after"].replace("Z", "+00:00"))
        if not_after < now:
            continue
        found += 1
        der = base64.b64decode(iss["cert"]["data"]) if iss.get("cert") else None
        cert = x509.load_der_x509_certificate(der) if der else None
        serial = format(cert.serial_number, "x") if cert else iss.get("serial", "").lower().lstrip("0")
        known = p.s.query(Certificate).filter(Certificate.serial_hex == serial).first()
        if known is not None and known.source in ("issued", "imported"):
            continue
        if cert is not None:
            try:
                cert.extensions.get_extension_for_oid(POISON)
            except x509.ExtensionNotFound:
                p.ingest(actor, cert, "ct", f"ct:{iss.get('id')}")  # a final certificate: track its expiry too
        key = f"unknown_public_cert:{serial}"
        f = p.s.query(DiscoveryFinding).filter_by(key=key).one_or_none()
        detail = {"serial": serial, "dns_names": iss.get("dns_names", []),
                  "issuer": (iss.get("issuer") or {}).get("friendly_name") or (iss.get("issuer") or {}).get("name"),
                  "not_after": iss["not_after"], "source": name}
        if f is None:
            p.s.add(DiscoveryFinding(kind="unknown_public_cert", key=key, location=f"ct:{iss.get('id')}",
                                     detail=detail))
            new += 1
        else:
            f.last_seen = now
    return found, new


def run_due(p, sources: dict, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out = []
    for name, src in sources.items():
        last = p.s.query(DiscoveryRun).filter_by(source=name).order_by(DiscoveryRun.id.desc()).first()
        every = timedelta(hours=float(src.cfg.get("interval_hours", 24)))
        if last is not None and now - as_utc(last.started_at) < every:
            continue
        run = run_source(p, name, src)
        p.commit()
        out.append({"source": name, "status": run.status, "found": run.found, "new": run.new})
    return out


# ------------------------------------------------------------------ host agent reports
def ingest_agent_report(p, actor, host: str, items: list[dict], key_files: list[dict]) -> dict:
    """What a host agent found: certificates (public parts only) and private key
    files with their permission bits. Keys themselves never leave the host."""
    from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

    found = new = 0
    for item in items:
        data = item.get("pem") or ""
        cert = load_pem_x509_certificate(data.encode()) if "BEGIN" in data else \
            load_der_x509_certificate(base64.b64decode(data))
        _, _, is_new = p.ingest(actor.name, cert, "agent", f"{host}:{item.get('path', '?')}"[:255])
        found += 1
        new += int(is_new)
    now = datetime.now(timezone.utc)
    seen = set()
    exposed = 0
    for k in key_files:
        location = f"{host}:{k.get('path')}"[:500]
        key = f"key_readable:{location}"[:255]
        if not k.get("world_readable"):
            continue
        seen.add(key)
        exposed += 1
        f = p.s.query(DiscoveryFinding).filter_by(key=key).one_or_none()
        if f is None:
            p.s.add(DiscoveryFinding(kind="key_readable", key=key, location=location,
                                     detail={"mode": k.get("mode"), "owner": k.get("owner"), "host": host}))
        else:
            f.last_seen, f.status = now, "open" if f.status == "resolved" else f.status
    # keys on this host that were exposed before and are not any more
    for f in p.s.query(DiscoveryFinding).filter(DiscoveryFinding.kind == "key_readable",
                                                DiscoveryFinding.location.like(f"{host}:%")).all():
        if f.key not in seen and f.status == "open":
            f.status = "resolved"
    from certadillo.audit.log import record

    record(p.s, actor.name, "discovery.agent.report", host, {"certificates": found, "new": new,
                                                              "keys_exposed": exposed})
    return {"certificates": found, "new": new, "keys_exposed": exposed}
