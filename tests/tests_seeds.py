"""Valid protocol messages for the fuzz tests to corrupt."""
from __future__ import annotations

import os

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from conftest import ADMIN


def scep_seed(client) -> bytes:
    """A real, signed and encrypted SCEP PKCSReq for an onboarded app."""
    from test_scep import _client_identity, _pkcs_req

    app_id = next(a["id"] for a in client.get("/api/v1/apps", headers=ADMIN).json() if a["name"] == "fuzz-api")
    challenge = client.post(f"/api/v1/apps/{app_id}/scep-challenge", headers=ADMIN).json()["challenge"]
    certs = pkcs7.load_der_pkcs7_certificates(client.get("/scep?operation=GetCACert").content)
    ra = next(c for c in certs if c.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment)
    key, cert = _client_identity()
    msg, _ = _pkcs_req(ra, key, cert, "dev.fuzz.bank.internal", challenge)
    return msg


def cmp_seed() -> bytes:
    """A well-formed CMP general message (genm, id-it-caCerts) without
    protection: the server must reject it, which is the unauthenticated path."""
    from pyasn1.codec.der import encoder
    from pyasn1.type import univ
    from pyasn1_modules import rfc2459, rfc4210

    msg = rfc4210.PKIMessage()
    hdr = msg["header"]
    hdr["pvno"] = 2
    for field in ("sender", "recipient"):
        hdr[field]["directoryName"][""] = rfc2459.RDNSequence()
    hdr["transactionID"] = hdr["transactionID"].clone(os.urandom(16))
    hdr["senderNonce"] = hdr["senderNonce"].clone(os.urandom(16))
    body = msg["body"]
    genm = body["genm"]
    itv = rfc4210.InfoTypeAndValue()
    itv["infoType"] = univ.ObjectIdentifier("1.3.6.1.5.5.7.4.17")
    genm.append(itv)
    return encoder.encode(msg)
