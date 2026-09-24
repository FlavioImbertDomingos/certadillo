"""Encoders for the Microsoft-specific extensions on a Windows logon certificate.

* UPN in an otherName SAN (used by the KDC to find the account).
* The SID security extension szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2),
  which pins the certificate to one account's SID so that strong certificate
  mapping (KB5014754, full enforcement since 2025) accepts it.

The DER matches what AD CS itself emits and what Certipy parses.
"""
from __future__ import annotations

from asn1crypto.core import OctetString, UTF8String
from cryptography import x509

UPN_OTHERNAME_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
NTDS_OBJECTSID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")


def upn_othername(upn: str) -> x509.OtherName:
    """A UPN otherName GeneralName for the SubjectAlternativeName."""
    return x509.OtherName(UPN_OTHERNAME_OID, UTF8String(upn).dump())


def sid_security_extension(sid: str) -> x509.UnrecognizedExtension:
    """The szOID_NTDS_CA_SECURITY_EXT extension carrying one account SID.

    Structure: GeneralNames ::= SEQUENCE OF one otherName { OID
    1.3.6.1.4.1.311.25.2.1, [0] EXPLICIT OCTET STRING("S-1-5-21-...") }. The
    GeneralNames encoding is identical to a SubjectAlternativeName value, so we
    reuse that to produce it.
    """
    other = x509.OtherName(NTDS_OBJECTSID_OID, OctetString(sid.encode()).dump())
    general_names = x509.SubjectAlternativeName([other]).public_bytes()
    return x509.UnrecognizedExtension(NTDS_CA_SECURITY_EXT, general_names)
