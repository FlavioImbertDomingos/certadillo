"""The policy tree.

Folders hold settings; apps sit in folders. A setting set on a folder applies
to everything under it unless a subfolder sets its own value, and a setting
marked locked cannot be changed below that folder at all. The effective policy
of an app is its profile, narrowed by the merged settings of its folder and
every folder above it. This is how a central PKI team sets bank-wide rules
(the issuing CA, minimum key sizes, the DNS zones a business line owns) and
lets each line of business tighten them, without a per-app exception list.
"""
from __future__ import annotations

import re
from datetime import timedelta

from certadillo.db import PolicyFolder
from certadillo.policy.engine import PolicyError, describe_key, within_domains

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,119}$")
CURVES = {"secp256r1", "secp384r1", "secp521r1"}


def _list_of_str(v):
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ValueError("must be a list of strings")
    return v


def _pos_int(v):
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise ValueError("must be a positive integer")
    return v


def _bool(v):
    if not isinstance(v, bool):
        raise ValueError("must be true or false")
    return v


def _curves(v):
    _list_of_str(v)
    bad = set(v) - CURVES
    if bad:
        raise ValueError(f"unknown curves {sorted(bad)}; use {sorted(CURVES)}")
    return v


def _ca_name(v):
    if not isinstance(v, str) or not v:
        raise ValueError("must be a CA name")
    return v


def _zones(v):
    from certadillo.policy.engine import validate_scope

    _list_of_str(v)
    validate_scope([z.lstrip("*.") for z in v])
    return [z.lower().lstrip("*.").rstrip(".") for z in v]


SETTINGS = {
    "allowed_profiles": (_list_of_str, "profiles apps in this folder may be onboarded with"),
    "allowed_zones": (_zones, "DNS zones every name an app here may get must fall under"),
    "rsa_min_bits": (_pos_int, "smallest RSA key accepted"),
    "ec_curves": (_curves, "EC curves accepted"),
    "max_validity_days": (_pos_int, "longest validity; longer requests are refused, defaults are shortened"),
    "issuing_ca": (_ca_name, "the CA that signs for apps here"),
    "dual_control": (_bool, "every issuance needs a second approver"),
}


# ------------------------------------------------------------------ tree
def ancestors(s, folder: PolicyFolder | None) -> list[PolicyFolder]:
    """Root first, ending with folder itself."""
    chain: list[PolicyFolder] = []
    seen: set[int] = set()
    while folder is not None:
        if folder.id in seen:
            raise ValueError("the policy tree has a cycle")
        seen.add(folder.id)
        chain.append(folder)
        folder = s.get(PolicyFolder, folder.parent_id) if folder.parent_id else None
    return list(reversed(chain))


def path(s, folder: PolicyFolder | None) -> str:
    return "\\" + "\\".join(f.name for f in ancestors(s, folder)) if folder else "\\"


def effective(s, folder_id: int | None) -> dict[str, dict]:
    """{setting: {"value", "folder" (path where it was set), "locked"}}."""
    if folder_id is None:
        return {}
    folder = s.get(PolicyFolder, folder_id)
    out: dict[str, dict] = {}
    for f in ancestors(s, folder):
        for key, spec in (f.settings or {}).items():
            if key in out and out[key]["locked"]:
                continue
            out[key] = {"value": spec["value"], "locked": bool(spec.get("locked")), "folder": path(s, f)}
    return out


def check_settings(s, parent_id: int | None, settings: dict) -> dict:
    """Validate a folder's own settings against the schema and its parents' locks."""
    if not isinstance(settings, dict):
        raise ValueError("settings must be an object")
    inherited = effective(s, parent_id)
    out = {}
    for key, spec in settings.items():
        if key not in SETTINGS:
            raise ValueError(f"unknown setting {key!r}; one of {sorted(SETTINGS)}")
        if not isinstance(spec, dict) or "value" not in spec:
            raise ValueError(f"{key}: give {{\"value\": ..., \"locked\": true|false}}")
        if key in inherited and inherited[key]["locked"]:
            raise ValueError(f"{key} is locked at {inherited[key]['folder']}")
        try:
            value = SETTINGS[key][0](spec["value"])
        except ValueError as exc:
            raise ValueError(f"{key}: {exc}") from None
        if key == "issuing_ca":
            from certadillo.db import CertificateAuthority

            ca = s.query(CertificateAuthority).filter_by(name=value).one_or_none()
            if ca is None or ca.is_root:
                raise ValueError(f"issuing_ca: {value} is not an issuing CA here")
        out[key] = {"value": value, "locked": bool(spec.get("locked", False))}
    return out


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME.match(name):
        raise ValueError("folder names use letters, digits, spaces, '.', '_' and '-'")
    return name


# ------------------------------------------------------------------ enforcement
def check_app(eff: dict, profile: str, scope: list[str]) -> None:
    """At onboarding and when an app moves: the profile and scope must fit the folder."""
    v = []
    if "allowed_profiles" in eff and profile not in eff["allowed_profiles"]["value"]:
        v.append(("folder_profile", f"profile {profile} is not allowed in {eff['allowed_profiles']['folder']}"))
    if "allowed_zones" in eff:
        zones = eff["allowed_zones"]["value"]
        for entry in scope:
            if not within_domains(entry, zones):
                v.append(("folder_zone", f"{entry} is outside the zones of {eff['allowed_zones']['folder']}"))
    if v:
        raise PolicyError(v)


def apply(eff: dict, decision, csr, requested_days: int | None, requested_hours: int | None):
    """Narrow a profile decision with the folder policy. Returns the decision."""
    if not eff:
        return decision
    v = []
    if "allowed_zones" in eff:
        zones = eff["allowed_zones"]["value"]
        names = list(decision.dns_names) + [e.split("@")[-1] for e in decision.emails] + \
            [u.split("@")[-1] for u in decision.upns] + list(decision.uris)
        for n in names:
            if not within_domains(n, zones):
                v.append(("folder_zone", f"{n} is outside the zones of {eff['allowed_zones']['folder']}"))
    ktype, bits, curve = describe_key(csr.public_key())
    if "rsa_min_bits" in eff and ktype == "rsa" and bits < eff["rsa_min_bits"]["value"]:
        v.append(("folder_key_strength", f"RSA {bits} below {eff['rsa_min_bits']['value']} "
                                         f"required by {eff['rsa_min_bits']['folder']}"))
    if "ec_curves" in eff and ktype == "ec" and curve not in eff["ec_curves"]["value"]:
        v.append(("folder_key_curve", f"curve {curve} not allowed by {eff['ec_curves']['folder']}"))
    if "max_validity_days" in eff:
        cap = timedelta(days=eff["max_validity_days"]["value"])
        if decision.validity > cap:
            if requested_days or requested_hours:
                v.append(("folder_validity", f"{decision.validity.days}d exceeds {cap.days}d set by "
                                             f"{eff['max_validity_days']['folder']}"))
            else:
                decision.validity = cap
    if v:
        raise PolicyError(v)
    if "issuing_ca" in eff:
        decision.ca = eff["issuing_ca"]["value"]
    if eff.get("dual_control", {}).get("value"):
        decision.dual_control = True
    return decision
