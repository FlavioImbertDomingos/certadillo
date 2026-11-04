"""Upstream issuers configured in the policy file:

    issuers:
      letsencrypt: {type: acme, directory: ..., contact: ..., dns: {...}}
      digicert:    {type: digicert, product: ssl_basic, organization_id: 1234, api_key_ref: env:...}
      aws-pca:     {type: aws-pca, ca_arn: ..., region: us-east-1}
      ejbca:       {type: ejbca, url: ..., ca_name: ..., certificate_profile: ..., end_entity_profile: ...}

A profile's `issuer:` or a policy folder's `issuer` setting names one. The
policy engine, scope checks, approvals, audit, inventory and alerts are the
same whichever CA signs; only the signing call differs. Credentials are
references (env:, file:, vault:), as for push targets.
"""
from __future__ import annotations

import logging

from certadillo.ca.backends import register_backend

log = logging.getLogger("certadillo.issuers")

REASON_CODES = {"unspecified": 0, "key_compromise": 1, "ca_compromise": 2, "affiliation_changed": 3,
                "superseded": 4, "cessation_of_operation": 5, "certificate_hold": 6, "privilege_withdrawn": 9}


def build(name: str, cfg: dict, settings=None):
    kind = cfg.get("type")
    if kind == "acme":
        from certadillo.ca.issuers.acme_client import AcmeIssuer
        return AcmeIssuer(name, cfg, settings)
    if kind == "digicert":
        from certadillo.ca.issuers.digicert import DigiCertIssuer
        return DigiCertIssuer(name, cfg, settings)
    if kind == "aws-pca":
        from certadillo.ca.issuers.aws_pca import AwsPcaIssuer
        return AwsPcaIssuer(name, cfg, settings)
    if kind == "ejbca":
        from certadillo.ca.issuers.ejbca import EjbcaIssuer
        return EjbcaIssuer(name, cfg, settings)
    raise ValueError(f"issuer {name}: unknown type {kind!r} (acme, digicert, aws-pca, ejbca)")


def register_from_policies(policies: dict, settings=None) -> list[str]:
    names = []
    for name, cfg in (policies.get("issuers") or {}).items():
        if name in ("local", "adcs"):
            raise ValueError(f"issuer name {name} is reserved")
        register_backend(build(name, cfg or {}, settings))
        names.append(name)
    if names:
        log.info("issuers registered", extra={"issuers": names})
    return names


# ------------------------------------------------------------------ inventory of issuers (for the console)
_SECRETISH = ("ref", "secret", "key", "token", "password", "hmac", "pin")
SAFE_FIELDS = {
    "acme": ("directory", "contact", "propagation_seconds"),
    "digicert": ("product", "organization_id", "api_url", "validation"),
    "aws-pca": ("ca_arn", "region", "signing_algorithm", "template_arn"),
    "ejbca": ("url", "ca_name", "certificate_profile", "end_entity_profile"),
}


def _ref_kind(v) -> str:
    return f"{str(v).split(':', 1)[0]} reference" if isinstance(v, str) and ":" in v else "set"


def describe(name: str, backend) -> dict:
    """What an issuer is and how it is reached, without any secret: credentials
    are shown only as the kind of reference that holds them."""
    cfg = getattr(backend, "cfg", None)
    if cfg is None and name == "vault":
        return {"name": name, "type": "vault", "config": {"addr": backend.addr, "mount": backend.mount,
                                                          "role": backend.role}, "credentials": {"token": "set"}}
    cfg = cfg or {}
    kind = cfg.get("type", "?")
    safe = {k: cfg[k] for k in SAFE_FIELDS.get(kind, ()) if k in cfg}
    creds = {k: _ref_kind(v) for k, v in cfg.items() if any(s in k for s in _SECRETISH) and v}
    if kind == "acme":
        dns = cfg.get("dns") or {}
        safe["dns"] = {k: v for k, v in dns.items() if not any(s in k for s in _SECRETISH)}
        creds.update({f"dns.{k}": _ref_kind(v) for k, v in dns.items() if any(s in k for s in _SECRETISH) and v})
        if cfg.get("eab"):
            safe["eab"] = {"kid": (cfg["eab"] or {}).get("kid")}
            creds["eab.hmac"] = _ref_kind((cfg["eab"] or {}).get("hmac_ref"))
    return {"name": name, "type": kind, "config": safe, "credentials": creds}
