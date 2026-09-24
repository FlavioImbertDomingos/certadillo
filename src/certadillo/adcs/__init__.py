"""AD CS template security audit.

Reads Microsoft AD CS certificate templates and the CA configuration and
flags the misconfigurations that let a low-privileged account obtain a
certificate for a more privileged identity (the ESC family described by
SpecterOps and detected by Certipy). This is a read-only auditor: it finds
and reports, so a PKI team can fix templates before they are abused. It
never issues, edits or exploits anything.
"""
from certadillo.adcs.analyzer import ESC_TITLES, analyze_ca, analyze_template
from certadillo.adcs.model import CaConfig, Template
from certadillo.adcs.sd import SecurityDescriptor

__all__ = [
    "Template",
    "CaConfig",
    "SecurityDescriptor",
    "analyze_template",
    "analyze_ca",
    "ESC_TITLES",
]
