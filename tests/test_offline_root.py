"""Offline root ceremony: the root key is never on the server, and the server
only accepts an issuing CA that carries its own key and chains to the root."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from certadillo.api.app import create_app, run_housekeeping
from certadillo.ca import offline
from certadillo.cli import main
from certadillo.db import CertificateAuthority
from certadillo.runtime import get_runtime
from conftest import ADMIN, issue, make_settings, onboard

PW = "correct horse battery staple"


@pytest.fixture
def root_dir(tmp_path):
    d = tmp_path / "usb" / "root-ca"
    pw = tmp_path / "pw.txt"
    pw.write_text(PW)
    r = CliRunner().invoke(main, ["offline-root", "init", "--dir", str(d), "--org", "Example Bank",
                                  "--passphrase-file", str(pw)])
    assert r.exit_code == 0, r.output
    return d


def _sign(root_dir, csr_pem, tmp_path, *extra):
    (tmp_path / "issuing.csr").write_text(csr_pem)
    out = tmp_path / "issuing.pem"
    r = CliRunner().invoke(main, ["offline-root", "sign", "--dir", str(root_dir), "--csr", str(tmp_path / "issuing.csr"),
                                  "--out", str(out), "--passphrase-file", str(tmp_path / "pw.txt"),
                                  "--crl-url", "http://testserver/pki/crl/root-ca.crl", *extra])
    assert r.exit_code == 0, r.output
    return out.read_text()


def _server(tmp_path, **kw):
    return create_app(make_settings(tmp_path / "server", auto_init_ca=False, **kw), background=False)


def test_ceremony_end_to_end_root_key_never_on_server(tmp_path, root_dir):
    assert (root_dir / "root.key.pem").stat().st_mode & 0o077 == 0
    assert b"ENCRYPTED" in (root_dir / "root.key.pem").read_bytes()
    with TestClient(_server(tmp_path)) as c:
        assert c.get("/readyz").status_code >= 400  # no issuing CA yet
        with get_runtime().platform() as p:
            csr = offline.prepare_issuing(p, "issuing-ca-1", operator="alice", witness="bob")
            p.commit()
        cert_pem = _sign(root_dir, csr, tmp_path)
        with get_runtime().platform() as p:
            res = offline.import_issuing(p, "issuing-ca-1", cert_pem, (root_dir / "root.pem").read_text(),
                                         operator="alice", witness="bob")
            p.commit()
            root = p.s.query(CertificateAuthority).filter_by(name="root-ca").one()
            assert root.key_ref == f"offline:{res['root_sha256']}" and root.signer_type == "offline"
            with pytest.raises(RuntimeError, match="offline"):
                p.ca.signer_for(root)
            with pytest.raises(RuntimeError, match="offline"):
                p.ca.create_subordinate(root, "issuing-ca-2")
        # no root key anywhere in the server's data directory
        server_keys = [f.name for f in (tmp_path / "server").rglob("*.key.pem")]
        assert "root-ca.key.pem" not in server_keys and "issuing-ca-1.key.pem" in server_keys
        assert c.get("/readyz").status_code == 200

        # issue through the normal path; the chain ends at the offline root
        _, h = onboard(c)
        leaf = x509.load_pem_x509_certificate(issue(c, h)[1]["pem"].encode())
        issuing = x509.load_pem_x509_certificate(cert_pem.encode())
        root_cert = x509.load_pem_x509_certificate((root_dir / "root.pem").read_bytes())
        leaf.verify_directly_issued_by(issuing)
        issuing.verify_directly_issued_by(root_cert)

        audit = [e["action"] for e in c.get("/api/v1/audit?limit=200", headers=ADMIN).json()]
        assert "ca.offline.csr" in audit and "ca.offline.import" in audit


def test_root_crl_is_signed_offline_and_cannot_be_replayed(tmp_path, root_dir):
    with TestClient(_server(tmp_path)) as c:
        with get_runtime().platform() as p:
            csr = offline.prepare_issuing(p, "issuing-ca-1", operator="alice", witness="bob")
            p.commit()
        cert_pem = _sign(root_dir, csr, tmp_path)
        with get_runtime().platform() as p:
            offline.import_issuing(p, "issuing-ca-1", cert_pem, (root_dir / "root.pem").read_text(), "alice", "bob")
            p.commit()
        assert c.get("/pki/crl/root-ca.crl").status_code == 404
        run_housekeeping()
        alerts = {a["rule"]: a for a in c.get("/api/v1/alerts", headers=ADMIN).json()}
        assert alerts["CRLStale"]["severity"] == "critical"

        def offline_crl():
            out = tmp_path / "root.crl"
            r = CliRunner().invoke(main, ["offline-root", "crl", "--dir", str(root_dir), "--out", str(out),
                                          "--passphrase-file", str(tmp_path / "pw.txt")])
            assert r.exit_code == 0, r.output
            return out.read_text()

        first = offline_crl()
        r = c.post("/api/v1/cas/root-ca/crl", json={"crl_pem": first}, headers=ADMIN)
        assert r.status_code == 200 and r.json()["crl_number"] == 1
        served = x509.load_der_x509_crl(c.get("/pki/crl/root-ca.crl").content)
        assert served.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1

        # revoke the issuing CA offline: the next CRL lists it
        serial = format(x509.load_pem_x509_certificate(cert_pem.encode()).serial_number, "x")
        assert CliRunner().invoke(main, ["offline-root", "revoke", "--dir", str(root_dir), "--serial", serial,
                                         "--reason", "key_compromise"]).exit_code == 0
        second = offline_crl()
        assert c.post("/api/v1/cas/root-ca/crl", json={"crl_pem": second}, headers=ADMIN).status_code == 200
        served = x509.load_der_x509_crl(c.get("/pki/crl/root-ca.crl").content)
        assert served.get_revoked_certificate_by_serial_number(int(serial, 16)) is not None

        # replaying the older CRL (to un-revoke) is refused
        r = c.post("/api/v1/cas/root-ca/crl", json={"crl_pem": first}, headers=ADMIN)
        assert r.status_code == 400 and "not newer" in r.text
        # a CRL from some other root is refused
        other = tmp_path / "other"
        CliRunner().invoke(main, ["offline-root", "init", "--dir", str(other), "--org", "Mallory",
                                  "--passphrase-file", str(tmp_path / "pw.txt")])
        out = tmp_path / "other.crl"
        CliRunner().invoke(main, ["offline-root", "crl", "--dir", str(other), "--out", str(out),
                                  "--passphrase-file", str(tmp_path / "pw.txt")])
        r = c.post("/api/v1/cas/root-ca/crl", json={"crl_pem": out.read_text()}, headers=ADMIN)
        assert r.status_code == 400 and "not signed by root-ca" in r.text
        # only an admin may publish
        assert c.post("/api/v1/cas/root-ca/crl", json={"crl_pem": second},
                      headers={"X-API-Key": "approver-key"}).status_code == 403

        run_housekeeping()
        assert "CRLStale" not in [a["rule"] for a in c.get("/api/v1/alerts", headers=ADMIN).json()]


def _forge(csr_pem, root_dir, *, key=None, path_length=0, drop_nc=False, issuer_key=None, issuer_cert=None):
    """Build an issuing CA certificate by hand, to show what the import refuses."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    root_key = issuer_key or serialization.load_pem_private_key((root_dir / "root.key.pem").read_bytes(), PW.encode())
    root = issuer_cert or x509.load_pem_x509_certificate((root_dir / "root.pem").read_bytes())
    now = datetime.now(timezone.utc)
    pub = key.public_key() if key else csr.public_key()
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(root.subject).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
         .not_valid_after(now + timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
         .add_extension(offline._ku(), critical=True))
    if not drop_nc:
        for ext in csr.extensions:
            if isinstance(ext.value, x509.NameConstraints):
                b = b.add_extension(ext.value, critical=True)
    return b.sign(root_key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM).decode()


def test_import_refuses_what_does_not_chain_or_carry_our_key(tmp_path, root_dir):
    with TestClient(_server(tmp_path, ca_permitted_dns=["bank.internal"])):
        with get_runtime().platform() as p:
            with pytest.raises(offline.CeremonyError, match="witness"):
                offline.prepare_issuing(p, "issuing-ca-1", operator="alice", witness="Alice")
            csr = offline.prepare_issuing(p, "issuing-ca-1", operator="alice", witness="bob")
            p.commit()
            root_pem = (root_dir / "root.pem").read_text()

            def refused(cert_pem, match, root=root_pem):
                with pytest.raises(offline.CeremonyError, match=match):
                    offline.import_issuing(p, "issuing-ca-1", cert_pem, root, "alice", "bob")

            # someone else's key in a certificate the real root signed
            refused(_forge(csr, root_dir, key=ec.generate_private_key(ec.SECP384R1())), "key generated")
            # pathlen 1 would let the issuing CA mint more CAs
            refused(_forge(csr, root_dir, path_length=1), "pathLenConstraint 0")
            # the root dropped the name constraints the server requires
            refused(_forge(csr, root_dir, drop_nc=True), "name constraints")
            # signed by a different root that copied the subject name
            imposter = ec.generate_private_key(ec.SECP384R1())
            real_root = x509.load_pem_x509_certificate(root_pem.encode())
            now = datetime.now(timezone.utc)
            fake_root = (x509.CertificateBuilder().subject_name(real_root.subject).issuer_name(real_root.subject)
                         .public_key(imposter.public_key()).serial_number(1)
                         .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=3650))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                         .add_extension(offline._ku(), critical=True).sign(imposter, hashes.SHA384()))
            refused(_forge(csr, root_dir, issuer_key=imposter, issuer_cert=fake_root), "does not verify")

            # the genuine one goes through, with the name constraints carried over
            good = _sign(root_dir, csr, tmp_path)
            assert x509.load_pem_x509_certificate(good.encode()).extensions.get_extension_for_class(
                x509.NameConstraints).critical
            offline.import_issuing(p, "issuing-ca-1", good, root_pem, "alice", "bob")
            p.commit()
            # the ceremony is closed: the same certificate cannot be imported twice
            with pytest.raises(offline.CeremonyError, match="no open ceremony"):
                offline.import_issuing(p, "issuing-ca-1", good, root_pem, "alice", "bob")


def test_offline_tool_guards(tmp_path, root_dir):
    pw = tmp_path / "pw.txt"
    bad = tmp_path / "bad.txt"
    bad.write_text("wrong passphrase, long enough")
    csr_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(
        x509.NameOID.COMMON_NAME, "x")])).sign(csr_key, hashes.SHA256()))
    (tmp_path / "x.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    r = CliRunner().invoke(main, ["offline-root", "sign", "--dir", str(root_dir), "--csr", str(tmp_path / "x.csr"),
                                  "--out", str(tmp_path / "x.pem"), "--passphrase-file", str(bad)])
    assert r.exit_code != 0 and "wrong passphrase" in r.output
    short = tmp_path / "short.txt"
    short.write_text("short")
    r = CliRunner().invoke(main, ["offline-root", "init", "--dir", str(tmp_path / "r2"), "--org", "X",
                                  "--passphrase-file", str(short)])
    assert r.exit_code != 0 and "16 characters" in r.output
    r = CliRunner().invoke(main, ["offline-root", "init", "--dir", str(root_dir), "--org", "X",
                                  "--passphrase-file", str(pw)])
    assert r.exit_code != 0 and "already holds" in r.output
    r = CliRunner().invoke(main, ["offline-root", "revoke", "--dir", str(root_dir), "--serial", "abc123"])
    assert r.exit_code != 0 and "not signed by this root" in r.output
    log = [json.loads(ln) for ln in (root_dir / "signed.jsonl").read_text().splitlines()]
    assert log[0]["event"] == "root"


def test_csr_signed_through_the_external_key_path():
    """HSM and Vault keys never expose the private key; the CSR is signed over
    its to-be-signed bytes and reassembled, and must still verify."""
    from certadillo.crypto.signers import ExternalOnlySigner, sign_x509

    from cryptography.hazmat.primitives.asymmetric import rsa

    for key in (ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP256R1()),
                rsa.generate_private_key(65537, 3072)):
        signer = ExternalOnlySigner("test:x", key)
        assert signer.private_key is None
        b = (x509.CertificateSigningRequestBuilder()
             .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Issuing CA")]))
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True))
        csr = sign_x509(b, signer)
        assert csr.is_signature_valid and csr.public_key() == key.public_key()


def test_ceremony_with_the_issuing_key_in_an_hsm(tmp_path, root_dir, softhsm):
    # SoftHSM reads its token directory once per process, so the label is unique
    # rather than shared with the other HSM test
    with TestClient(_server(tmp_path, signer="pkcs11", pkcs11_lib=softhsm, pkcs11_pin="1234")) as c:
        with get_runtime().platform() as p:
            csr = offline.prepare_issuing(p, "issuing-ca-hsm", operator="alice", witness="bob")
            p.commit()
        assert x509.load_pem_x509_csr(csr.encode()).is_signature_valid
        cert_pem = _sign(root_dir, csr, tmp_path)
        with get_runtime().platform() as p:
            res = offline.import_issuing(p, "issuing-ca-hsm", cert_pem, (root_dir / "root.pem").read_text(),
                                         "alice", "bob")
            p.commit()
        assert res["signer"] == "pkcs11"
        _, h = onboard(c)
        leaf = x509.load_pem_x509_certificate(issue(c, h)[1]["pem"].encode())
        leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(cert_pem.encode()))
