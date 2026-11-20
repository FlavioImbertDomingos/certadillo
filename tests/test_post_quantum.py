"""Post-quantum issuance: ML-DSA-65 and ML-DSA-87 (FIPS 204) CA keys and
end-entity keys, through every path that signs: certificates, CRLs, OCSP,
the external (HSM-style) signing path and the offline root."""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from certadillo.crypto.signers import ExternalOnlySigner, Pkcs11KeyStore, _generate, ml_dsa_params, sign_x509
from conftest import ADMIN, APPROVER, issue, onboard

mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")

ML_DSA_OIDS = {"ml-dsa-65": "2.16.840.1.101.3.4.3.18", "ml-dsa-87": "2.16.840.1.101.3.4.3.19"}


def _csr(key, cn="pq.pay.bank.internal"):
    b = (x509.CertificateSigningRequestBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False))
    h = None if ml_dsa_params(key) else hashes.SHA256()
    return b.sign(key, h).public_bytes(serialization.Encoding.PEM).decode()


def _new_ca(client, name, alg):
    r = client.post("/api/v1/cas", json={"name": name, "alg": alg}, headers=ADMIN)
    assert r.status_code == 202, r.text
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
    return x509.load_pem_x509_certificate(client.get(f"/pki/ca/{name}.pem").text.encode())


@pytest.mark.parametrize("alg", ["ml-dsa-65", "ml-dsa-87"])
def test_ml_dsa_issuing_ca_signs_certificates_crls_and_ocsp(client, alg):
    root = x509.load_pem_x509_certificate(client.get("/pki/ca/root-ca.pem").text.encode())
    sub = _new_ca(client, "issuing-pq", alg)
    assert ml_dsa_params(sub.public_key()) == alg
    sub.verify_directly_issued_by(root)  # an EC root vouches for the ML-DSA CA

    # the newest issuing CA becomes the default, so this EC leaf is ML-DSA signed
    _, h = onboard(client)
    _, body = issue(client, h)
    leaf = x509.load_pem_x509_certificate(body["pem"].encode())
    assert leaf.signature_algorithm_oid.dotted_string == ML_DSA_OIDS[alg]
    leaf.verify_directly_issued_by(sub)

    client.post(f"/api/v1/certificates/{body['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-pq.crl").content)
    assert crl.signature_algorithm_oid.dotted_string == ML_DSA_OIDS[alg]
    assert crl.is_signature_valid(sub.public_key())
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None

    # OCSP: the issuerKeyHash of an ML-DSA CA key is found, and the delegated
    # responder certificate is signed by the ML-DSA CA
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, sub, hashes.SHA256()).build()
    resp = ocsp.load_der_ocsp_response(
        client.post("/pki/ocsp", content=req.public_bytes(serialization.Encoding.DER)).content)
    assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
    resp.certificates[0].verify_directly_issued_by(sub)


def test_ml_dsa_leaf_needs_a_profile_that_allows_it(client):
    _, h = onboard(client)  # tls-server: classical keys only
    r = client.post("/api/v1/certificates", json={"csr_pem": _csr(_generate("ml-dsa-65"))}, headers=h)
    assert r.status_code == 422 and "ML-DSA-65 is not allowed" in r.text

    _, hpq = onboard(client, name="pq-api", profile="tls-server-pq", domains=("*.pq.bank.internal",))
    for alg in ("ml-dsa-65", "ml-dsa-87"):
        key = _generate(alg)
        r = client.post("/api/v1/certificates", json={"csr_pem": _csr(key, "web.pq.bank.internal")}, headers=hpq)
        assert r.status_code == 201, r.text
        cert = x509.load_pem_x509_certificate(r.json()["pem"].encode())
        assert ml_dsa_params(cert.public_key()) == alg
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature and not ku.key_encipherment
    rows = client.get("/api/v1/certificates", headers=ADMIN).json()
    rows = rows.get("items", rows) if isinstance(rows, dict) else rows
    assert {r["key"] for r in rows if r["common_name"] == "web.pq.bank.internal"} == {"ml-dsa-65", "ml-dsa-87"}

    # the post-quantum profile refuses classical keys, so it cannot be used to slip them in
    for key in (ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 3072)):
        r = client.post("/api/v1/certificates", json={"csr_pem": _csr(key, "old.pq.bank.internal")}, headers=hpq)
        assert r.status_code == 422, r.text


def test_ml_dsa_csr_with_a_bad_signature_is_refused(client):
    _, hpq = onboard(client, name="pq-api", profile="tls-server-pq", domains=("*.pq.bank.internal",))
    pem = _csr(_generate("ml-dsa-65"), "web.pq.bank.internal")
    der = bytearray(x509.load_pem_x509_csr(pem.encode()).public_bytes(serialization.Encoding.DER))
    der[-10] ^= 0x01  # flip a bit inside the signature
    bad = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM).decode()
    r = client.post("/api/v1/certificates", json={"csr_pem": bad}, headers=hpq)
    assert r.status_code == 422 and "proof of possession" in r.text


@pytest.mark.parametrize("alg", ["ml-dsa-65", "ml-dsa-87"])
def test_external_signing_path_handles_ml_dsa(alg):
    """The HSM code path (throwaway key of the same parameter set, real
    signature spliced in) must produce valid ML-DSA certificates, CSRs and CRLs."""
    key = _generate(alg)
    signer = ExternalOnlySigner("test", key)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ext-pq")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = sign_x509(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                     .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), True), signer)
    cert.verify_directly_issued_by(cert)
    assert cert.signature_algorithm_oid.dotted_string == ML_DSA_OIDS[alg]
    csr = sign_x509(x509.CertificateSigningRequestBuilder().subject_name(name), signer)
    assert csr.is_signature_valid and ml_dsa_params(csr.public_key()) == alg
    crl = sign_x509(x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now)
                    .next_update(now + dt.timedelta(hours=1)), signer)
    assert crl.is_signature_valid(key.public_key())


def test_hsm_refuses_ml_dsa_instead_of_falling_back_to_software():
    store = object.__new__(Pkcs11KeyStore)  # no token needed: the refusal comes first
    with pytest.raises(ValueError, match="PKCS#11"):
        store.generate("pq-ca", "ml-dsa-87")


def test_offline_ml_dsa_root_signs_an_issuing_ca(tmp_path):
    from certadillo.ca.offline import offline_crl, offline_init, offline_sign

    res = offline_init(tmp_path / "root", "Example Bank", "correct horse battery", alg="ml-dsa-87")
    root = x509.load_pem_x509_certificate((tmp_path / "root" / "root.pem").read_bytes())
    assert ml_dsa_params(root.public_key()) == "ml-dsa-87" and res["sha256"]
    root.verify_directly_issued_by(root)
    issuing_key = ec.generate_private_key(ec.SECP384R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuing CA pq")]))
           .sign(issuing_key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM).decode())
    sub = x509.load_pem_x509_certificate(offline_sign(tmp_path / "root", csr, "correct horse battery").encode())
    sub.verify_directly_issued_by(root)
    crl = x509.load_pem_x509_crl(offline_crl(tmp_path / "root", "correct horse battery"))
    assert crl.is_signature_valid(root.public_key())


def test_crypto_report_and_cbom_know_ml_dsa(client):
    _new_ca(client, "issuing-pq", "ml-dsa-87")
    _, h = onboard(client)
    issue(client, h)
    rep = client.get("/api/v1/reports/crypto", headers=ADMIN).json()
    pq = next(r for r in rep["certificate_authorities"] if r["ca"] == "issuing-pq")
    assert pq["algorithm"] == "ML-DSA-87" and pq["post_quantum"] and not pq["outlives_2035_cutoff"]
    assert rep["pqc_signed"] >= 1
    bom = client.get("/api/v1/reports/cbom", headers=ADMIN).json()
    levels = {c["name"]: c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
              for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"}
    assert levels.get("ML-DSA-87") == 5


def test_spiffe_bundle_lists_an_ml_dsa_root(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo.api.app import create_app
    from certadillo.runtime import get_runtime
    from conftest import make_settings

    with TestClient(create_app(make_settings(tmp_path, auto_init_ca=False), background=False)) as c:
        with get_runtime().platform() as p:
            p.ca.create_root("root-pq", alg="ml-dsa-65")
            p.commit()
        keys = c.get("/pki/spiffe/bundle").json()["keys"]
        assert keys[0]["kty"] == "AKP" and keys[0]["alg"] == "ML-DSA-65" and keys[0]["pub"]


def test_folder_can_narrow_ml_dsa_parameter_sets(client):
    """A CNSA 2.0 folder accepts ML-DSA-87 only, even where the profile allows ML-DSA-65."""
    bad = client.post("/api/v1/folders", headers=ADMIN, json={
        "name": "typo", "settings": {"ml_dsa": {"value": ["ml-dsa-99"]}}})
    assert bad.status_code in (400, 422) and "ml-dsa-99" in bad.text
    r = client.post("/api/v1/folders", headers=ADMIN, json={
        "name": "Cnsa", "settings": {"ml_dsa": {"value": ["ml-dsa-87"], "locked": True}}})
    assert r.status_code == 202, r.text
    ok = client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER)
    folder = ok.json()["payload"]["folder_id"]
    team = client.post("/api/v1/teams", json={"name": "team-cnsa", "contact_email": "t@example.com"},
                       headers=ADMIN).json()["id"]
    app = client.post("/api/v1/apps", headers=ADMIN, json={
        "team_id": team, "name": "cnsa-api", "environment": "dev", "profile": "tls-server-pq",
        "allowed_domains": ["*.pq.bank.internal"], "folder_id": folder}).json()
    if app["status"] == "pending_approval":
        client.post(f"/api/v1/approvals/{app['approval_id']}/approve", headers=APPROVER)
    h = {"X-API-Key": client.post(f"/api/v1/apps/{app['id']}/credentials", headers=ADMIN).json()["api_key"]}
    r65 = client.post("/api/v1/certificates", headers=h,
                      json={"csr_pem": _csr(_generate("ml-dsa-65"), "a.pq.bank.internal")})
    assert r65.status_code == 422 and "ML-DSA-65 not allowed by" in r65.text
    r87 = client.post("/api/v1/certificates", headers=h,
                      json={"csr_pem": _csr(_generate("ml-dsa-87"), "b.pq.bank.internal")})
    assert r87.status_code == 201, r87.text


def test_cli_makes_ml_dsa_keys_and_csrs():
    from certadillo.cli import _key_and_csr

    key_pem, csr_pem = _key_and_csr("web.pq.bank.internal", ["web.pq.bank.internal"], None, "ml-dsa-87")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.is_signature_valid and ml_dsa_params(csr.public_key()) == "ml-dsa-87"
    assert ml_dsa_params(serialization.load_pem_private_key(key_pem, None)) == "ml-dsa-87"
