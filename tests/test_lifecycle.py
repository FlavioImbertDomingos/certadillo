"""CA hierarchy, onboarding, policy, renewal, revocation, CRL, OCSP."""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp

from conftest import ADMIN, APPROVER, issue, make_csr, onboard


def _cas(client):
    root = x509.load_pem_x509_certificate(client.get("/pki/ca/root-ca.pem").text.encode())
    sub = x509.load_pem_x509_certificate(client.get("/pki/ca/issuing-ca-1.pem").text.encode())
    return root, sub


def test_hierarchy_is_valid(client):
    root, sub = _cas(client)
    sub.verify_directly_issued_by(root)
    root.verify_directly_issued_by(root)
    assert sub.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey) and root.public_key().curve.name == "secp384r1"


def test_issued_certificate_profile(client):
    _, h = onboard(client)
    _, body = issue(client, h)
    _, sub = _cas(client)
    leaf = x509.load_pem_x509_certificate(body["pem"].encode())
    leaf.verify_directly_issued_by(sub)
    assert body["chain_pem"].count("BEGIN CERTIFICATE") == 1
    ext = leaf.extensions
    assert ext.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext.get_extension_for_class(x509.ExtendedKeyUsage).value
    aia = ext.get_extension_for_class(x509.AuthorityInformationAccess).value
    assert any(d.access_location.value.endswith("/pki/ocsp") for d in aia)
    assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 31


def test_prod_onboarding_needs_second_person(client):
    team = client.post("/api/v1/teams", json={"name": "core", "contact_email": "c@example.com"}, headers=ADMIN).json()
    r = client.post("/api/v1/apps", json={"team_id": team["id"], "name": "ledger", "environment": "prod",
                                          "profile": "tls-server", "allowed_domains": ["ledger.bank.internal"]},
                    headers=ADMIN)
    app = r.json()
    assert app["status"] == "pending_approval"
    assert client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).status_code == 403
    assert client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=ADMIN).status_code == 403
    assert client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER).status_code == 200
    assert client.get(f"/api/v1/apps/{app['id']}", headers=ADMIN).json()["status"] == "active"


def test_policy_violations(client):
    _, h = onboard(client)
    cases = [
        (make_csr("evil.example.com", dns=["evil.example.com"])[1], "san_scope"),
        (make_csr("*.pay.bank.internal", dns=["*.pay.bank.internal"])[1], "wildcard"),
        (make_csr("a.pay.bank.internal", dns=["a.pay.bank.internal"],
                  key=rsa.generate_private_key(65537, 1024))[1], "key_strength"),
        (make_csr("a.pay.bank.internal", dns=["a.pay.bank.internal"],
                  key=ec.generate_private_key(ec.SECP521R1()))[1], "key_curve"),
    ]
    for csr, rule in cases:
        r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
        assert r.status_code == 422, r.text
        assert rule in [v["rule"] for v in r.json()["violations"]]
    r = client.post("/api/v1/certificates", json={"csr_pem": make_csr("a.pay.bank.internal", dns=["a.pay.bank.internal"])[1],
                                                  "validity_days": 400}, headers=h)
    assert r.status_code == 422 and r.json()["violations"][0]["rule"] == "validity"
    r = client.post("/api/v1/certificates", json={"csr_pem": make_csr("a.pay.bank.internal", dns=["a.pay.bank.internal"])[1],
                                                  "profile": "code-signing"}, headers=h)
    assert r.status_code == 422 and r.json()["violations"][0]["rule"] == "profile_not_onboarded"
    # rejections are audited
    actions = [e["action"] for e in client.get("/api/v1/audit", headers=ADMIN).json()]
    assert actions.count("certificate.rejected") >= 5


def test_app_isolation_and_rbac(client):
    a_id, a = onboard(client, "app-a", domains=["*.a.bank.internal"])
    b_id, b = onboard(client, "app-b", domains=["*.b.bank.internal"])
    _, cert = issue(client, a, "x.a.bank.internal")
    assert client.get(f"/api/v1/certificates/{cert['id']}", headers=b).status_code == 404
    csr = make_csr("x.a.bank.internal", dns=["x.a.bank.internal"])[1]
    assert client.post("/api/v1/certificates", json={"app_id": a_id, "csr_pem": csr}, headers=b).status_code == 403
    assert client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={}, headers=b).status_code == 403
    auditor = client.post("/api/v1/principals", json={"name": "aud", "role": "auditor"}, headers=ADMIN).json()["api_key"]
    assert client.post("/api/v1/teams", json={"name": "xx", "contact_email": "x@x"}, headers={"X-API-Key": auditor}).status_code == 403
    assert client.get("/api/v1/audit", headers={"X-API-Key": auditor}).status_code == 200
    assert client.get("/api/v1/me").status_code == 401


def test_renewal_requires_new_key(client):
    _, h = onboard(client)
    key, cert = issue(client, h)
    _, same_key_csr = make_csr("api.pay.bank.internal", dns=["api.pay.bank.internal"], key=key)
    r = client.post(f"/api/v1/certificates/{cert['id']}/renew", json={"csr_pem": same_key_csr}, headers=h)
    assert r.status_code == 422 and r.json()["violations"][0]["rule"] == "key_reuse"
    _, new_csr = make_csr("api.pay.bank.internal", dns=["api.pay.bank.internal"])
    r = client.post(f"/api/v1/certificates/{cert['id']}/renew", json={"csr_pem": new_csr}, headers=h)
    assert r.status_code == 201
    old = client.get(f"/api/v1/certificates/{cert['id']}", headers=h).json()
    assert old["status"] == "superseded" and old["replaced_by"] == r.json()["id"]


def _ocsp(client, leaf, issuer):
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    r = client.post("/pki/ocsp", content=req.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"})
    resp = ocsp.load_der_ocsp_response(r.content)
    assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    responder = resp.certificates[0]
    responder.verify_directly_issued_by(issuer)
    responder.public_key().verify(resp.signature, resp.tbs_response_bytes, ec.ECDSA(resp.signature_hash_algorithm))
    return resp


def test_revocation_crl_and_ocsp(client):
    _, h = onboard(client)
    _, cert = issue(client, h)
    _, sub = _cas(client)
    leaf = x509.load_pem_x509_certificate(cert["pem"].encode())
    assert _ocsp(client, leaf, sub).certificate_status == ocsp.OCSPCertStatus.GOOD
    r = client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    resp = _ocsp(client, leaf, sub)
    assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert resp.revocation_reason == x509.ReasonFlags.key_compromise
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
    assert crl.is_signature_valid(sub.public_key())
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None


def test_prod_revocation_needs_change_ticket(client):
    _, h = onboard(client, "ledger", env="prod", domains=["ledger.bank.internal"])
    _, cert = issue(client, h, "ledger.bank.internal")
    r = client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "superseded"}, headers=ADMIN)
    assert r.status_code == 422 and r.json()["violations"][0]["rule"] == "change_ref"
    r = client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "superseded", "change_ref": "CHG0012345"},
                    headers=ADMIN)
    assert r.status_code == 200


def test_code_signing_dual_control(client):
    _, h = onboard(client, "release-signing", profile="code-signing", domains=["release.bank.internal"])
    key = ec.generate_private_key(ec.SECP384R1())
    _, csr = make_csr("Release Signing", key=key)
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
    assert r.status_code == 202
    approval = r.json()["approval_id"]
    r = client.post(f"/api/v1/approvals/{approval}/approve", json={"comment": "release 4.2"}, headers=APPROVER)
    assert r.status_code == 200
    cid = r.json()["payload"]["certificate_id"]
    cert = client.get(f"/api/v1/certificates/{cid}", headers=h).json()
    leaf = x509.load_pem_x509_certificate(cert["pem"].encode())
    assert x509.oid.ExtendedKeyUsageOID.CODE_SIGNING in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value


def test_smime_profile(client):
    _, h = onboard(client, "mail-gw", profile="smime", domains=["bank.example"])
    _, csr = make_csr("Jane Doe", emails=["jane@bank.example"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
    assert r.status_code == 201, r.text
    _, csr = make_csr("Evil", emails=["evil@other.example"])
    assert client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).status_code == 422


def test_spiffe_svid_and_bundle(client):
    _, h = onboard(client, "payments-workloads", profile="spiffe-svid",
                   domains=["spiffe://bank.internal/payments/*"])
    _, csr = make_csr(uris=["spiffe://bank.internal/payments/card-api"])
    r = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
    assert r.status_code == 201, r.text
    leaf = x509.load_pem_x509_certificate(r.json()["pem"].encode())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.critical and san.value.get_values_for_type(x509.UniformResourceIdentifier) == [
        "spiffe://bank.internal/payments/card-api"]
    assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() <= 24 * 3600 + 120
    _, bad = make_csr(uris=["spiffe://other.domain/payments/x"])
    assert client.post("/api/v1/certificates", json={"csr_pem": bad}, headers=h).status_code == 422
    bundle = client.get("/pki/spiffe/bundle").json()
    assert bundle["keys"][0]["use"] == "x509-svid" and bundle["keys"][0]["crv"] == "P-384"


def test_sub_ca_creation_is_dual_control(client):
    r = client.post("/api/v1/cas", json={"name": "issuing-ca-2"}, headers=ADMIN)
    assert r.status_code == 202
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
    names = [c["name"] for c in client.get("/api/v1/cas", headers=ADMIN).json()]
    assert "issuing-ca-2" in names
