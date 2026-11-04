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
