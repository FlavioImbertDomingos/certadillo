"""Windows smart-card / PKINIT logon profile: UPN scoping, directory SID lookup,
fail-closed behaviour, disabled-account refusal, adminCount dual control, and the
emitted UPN otherName + SID security extension."""
from __future__ import annotations


import pytest
from asn1crypto.core import UTF8String
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ADMIN, APPROVER, make_settings
from certadillo.adcs.directory import Account, DirectoryError, sid_bytes_to_string
from certadillo.api.app import create_app
from fastapi.testclient import TestClient

UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
SEC_EXT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
NTDS_SID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

DOMAIN = "S-1-5-21-10-20-30"
ALICE_SID = f"{DOMAIN}-1104"


class FakeResolver:
    """Stands in for the LDAP directory in tests."""

    def __init__(self, accounts: dict[str, Account]):
        self.accounts = accounts
        self.calls: list[str] = []

    def resolve_upn(self, upn: str) -> Account:
        self.calls.append(upn)
        if upn not in self.accounts:
            raise DirectoryError(f"UPN {upn!r} matched 0 accounts")
        return self.accounts[upn]


def upn_csr(upn: str, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    other = x509.OtherName(UPN_OID, UTF8String(upn).dump())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .add_extension(x509.SubjectAlternativeName([other]), critical=False)
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def onboard_logon(client, domains=("corp.bank.internal",)):
    r = client.post("/api/v1/teams", json={"name": "team-wl", "contact_email": "t@e.com"}, headers=ADMIN)
    team = r.json()["id"]
    r = client.post("/api/v1/apps", json={"team_id": team, "name": "vpn-logon", "environment": "dev",
                                          "profile": "windows-logon", "allowed_domains": list(domains)}, headers=ADMIN)
    app = r.json()
    if app.get("status") == "pending_approval":
        client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER)
    key = client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]
    return app["id"], {"X-API-Key": key}


@pytest.fixture
def logon_client(tmp_path):
    app = create_app(make_settings(tmp_path), background=False)
    with TestClient(app) as c:
        # inject the fake directory into the running platform
        from certadillo.runtime import get_runtime
        c._runtime = get_runtime()
        yield c


def _set_resolver(client, resolver):
    from certadillo.runtime import get_runtime

    rt = get_runtime()
    # patch every platform() to use our resolver
    orig = rt.platform

    import contextlib

    @contextlib.contextmanager
    def patched():
        with orig() as p:
            p.directory_resolver = resolver
            yield p

    rt.platform = patched


def test_sid_bytes_roundtrip():
    # S-1-5-21-10-20-30-1104
    raw = bytes([1, 5]) + (5).to_bytes(6, "big")
    for v in (21, 10, 20, 30, 1104):
        raw += v.to_bytes(4, "little")
    assert sid_bytes_to_string(raw) == ALICE_SID


def test_logon_issues_with_upn_and_sid(logon_client):
    resolver = FakeResolver({"alice@corp.bank.internal": Account("alice@corp.bank.internal", ALICE_SID, True, False)})
    _set_resolver(logon_client, resolver)
    app_id, hdr = onboard_logon(logon_client)
    _, csr = upn_csr("alice@corp.bank.internal")
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 201, r.text
    cert = x509.load_pem_x509_certificate(r.json()["pem"].encode())
    # UPN otherName present
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    upns = [o for o in san.get_values_for_type(x509.OtherName) if o.type_id == UPN_OID]
    assert UTF8String.load(upns[0].value).native == "alice@corp.bank.internal"
    # SID security extension present and correct
    raw = cert.extensions.get_extension_for_oid(SEC_EXT_OID).value.value
    assert ALICE_SID.encode() in raw
    assert resolver.calls == ["alice@corp.bank.internal"]


def test_upn_outside_scope_rejected(logon_client):
    _set_resolver(logon_client, FakeResolver({}))
    app_id, hdr = onboard_logon(logon_client, domains=("corp.bank.internal",))
    _, csr = upn_csr("attacker@evil.example")
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 422
    assert "upn_scope" in r.text


def test_unknown_account_fails_closed(logon_client):
    _set_resolver(logon_client, FakeResolver({}))  # directory returns nothing
    app_id, hdr = onboard_logon(logon_client)
    _, csr = upn_csr("ghost@corp.bank.internal")
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 422
    assert "directory" in r.text


def test_disabled_account_refused(logon_client):
    resolver = FakeResolver({"bob@corp.bank.internal": Account("bob@corp.bank.internal", f"{DOMAIN}-1200", False, False)})
    _set_resolver(logon_client, resolver)
    app_id, hdr = onboard_logon(logon_client)
    _, csr = upn_csr("bob@corp.bank.internal")
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 422
    assert "account_disabled" in r.text


def test_admin_account_forces_dual_control(logon_client):
    resolver = FakeResolver({"admin@corp.bank.internal": Account("admin@corp.bank.internal", f"{DOMAIN}-500", True, True)})
    _set_resolver(logon_client, resolver)
    app_id, hdr = onboard_logon(logon_client)
    _, csr = upn_csr("admin@corp.bank.internal")
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    # sensitive account: not issued outright, an approval is created
    assert r.status_code in (202, 201)
    body = r.json()
    assert body.get("status") == "pending_approval" or body.get("approval_id"), body


def test_no_upn_san_rejected(logon_client):
    _set_resolver(logon_client, FakeResolver({}))
    app_id, hdr = onboard_logon(logon_client)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "nobody")]))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    r = logon_client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=hdr)
    assert r.status_code == 422
    assert "upn_required" in r.text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
