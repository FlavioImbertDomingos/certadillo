"""Regression tests for issues found in review: scope bypasses, separation of
duties, read access, CRL publishing, CA path length."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ADMIN, APPROVER, issue, make_csr, onboard


def test_names_outside_scope_are_refused_in_every_san_type(client):
    _, mtls = onboard(client, "svc-a", profile="mtls-service", domains=["*.a.bank.internal"])
    _, csr = make_csr("x.a.bank.internal", dns=["x.a.bank.internal"], uris=["spiffe://bank.internal/core/admin"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=mtls)
    assert r.status_code == 422 and "uri_san" in [v["rule"] for v in r.json()["violations"]]
    _, csr = make_csr("x.a.bank.internal", dns=["x.a.bank.internal"], emails=["ceo@other.example"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=mtls)
    assert r.status_code == 422 and "email_san" in [v["rule"] for v in r.json()["violations"]]
    _, client_h = onboard(client, "svc-b", profile="tls-client", domains=["*.b.bank.internal"])
    _, csr = make_csr("payments-admin.core.bank.internal")
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=client_h)
    assert r.status_code == 422 and r.json()["violations"][0]["rule"] == "cn_scope"
    _, csr = make_csr("batch.b.bank.internal")
    assert client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=client_h).status_code == 201


def test_sub_ca_path_length_is_enforced(client):
    r = client.post("/api/v1/cas", json={"name": "under-issuing", "parent": "issuing-ca-1"}, headers=ADMIN)
    assert r.status_code == 400
    r = client.post("/api/v1/cas", json={"name": "issuing-ca-2"}, headers=ADMIN)
    client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER)
    _, h = onboard(client)
    _, cert = issue(client, h)
    leaf = x509.load_pem_x509_certificate(cert["pem"].encode())
    new_ca = x509.load_pem_x509_certificate(client.get("/pki/ca/issuing-ca-2.pem").text.encode())
    leaf.verify_directly_issued_by(new_ca)
    assert new_ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0


def test_admin_cannot_approve_through_a_minted_approver(client):
    team = client.post("/api/v1/teams", json={"name": "core", "contact_email": "c@x"}, headers=ADMIN).json()
    app = client.post("/api/v1/apps", json={"team_id": team["id"], "name": "ledger", "environment": "prod",
                                            "profile": "tls-server", "allowed_domains": ["ledger.bank.internal"]},
                      headers=ADMIN).json()
    sock = client.post("/api/v1/principals", json={"name": "sock-puppet", "role": "approver"}, headers=ADMIN).json()
    r = client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers={"X-API-Key": sock["api_key"]})
    assert r.status_code == 403
    assert client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER).status_code == 200


def test_app_credentials_cannot_read_the_estate(client):
    app_id, h = onboard(client)
    for path in ("/api/v1/apps", "/api/v1/teams", "/api/v1/approvals", "/api/v1/alerts", "/api/v1/cas",
                 "/api/v1/reports/summary", "/api/v1/reports/cbom", "/api/v1/reports/pci-inventory",
                 "/api/v1/audit", "/api/v1/audit/verify"):
        assert client.get(path, headers=h).status_code == 403, path
    assert client.get(f"/api/v1/apps/{app_id}", headers=h).status_code == 200
    assert client.get(f"/api/v1/apps/{app_id + 1}", headers=h).status_code == 404


def test_principal_deactivation(client):
    key = client.post("/api/v1/principals", json={"name": "ops1", "role": "operator"}, headers=ADMIN).json()["api_key"]
    assert client.get("/api/v1/me", headers={"X-API-Key": key}).status_code == 200
    client.post("/api/v1/principals/ops1/deactivate", headers=ADMIN)
    assert client.get("/api/v1/me", headers={"X-API-Key": key}).status_code == 401


def _crl_number(client):
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, crl


def test_crl_is_cached_and_republished_on_revoke(client):
    n1, _ = _crl_number(client)
    n2, _ = _crl_number(client)
    assert n1 == n2  # anonymous GETs do not re-sign
    _, h = onboard(client)
    _, cert = issue(client, h)
    client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "superseded"}, headers=h)
    n3, crl = _crl_number(client)
    assert n3 == n1 + 1
    assert crl.get_revoked_certificate_by_serial_number(int(cert["serial"], 16)) is not None


def test_dual_control_renewal_supersedes_previous(client):
    _, h = onboard(client, "signer", profile="code-signing", domains=["release.bank.internal"])
    _, csr = make_csr("Release Signing", key=ec.generate_private_key(ec.SECP384R1()))
    a1 = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).json()["approval_id"]
    first = client.post(f"/api/v1/approvals/{a1}/approve", headers=APPROVER).json()["payload"]["certificate_id"]
    _, csr2 = make_csr("Release Signing", key=ec.generate_private_key(ec.SECP384R1()))
    a2 = client.post(f"/api/v1/certificates/{first}/renew", json={"csr_pem": csr2}, headers=h).json()["approval_id"]
    second = client.post(f"/api/v1/approvals/{a2}/approve", headers=APPROVER).json()["payload"]["certificate_id"]
    old = client.get(f"/api/v1/certificates/{first}", headers=h).json()
    assert old["status"] == "superseded" and old["replaced_by"] == second


def test_public_certificates_graded_against_cab_schedule():
    from certadillo.policy.engine import grade_certificate, load_policies

    key = ec.generate_private_key(ec.SECP256R1())
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "www.bank.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(start + timedelta(days=398))
            .sign(key, hashes.SHA256()))
    rules = [r for r, _ in grade_certificate(cert, load_policies(), is_public=True)]
    assert "public_validity" in rules  # 398 days issued after 15 Mar 2026, when the cap is 200
    assert cert.public_bytes(serialization.Encoding.PEM)
