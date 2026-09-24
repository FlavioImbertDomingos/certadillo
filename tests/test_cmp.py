"""CMP (RFC 9483 lightweight profile) against the OpenSSL CMP client.

The server runs for real on a local port because `openssl cmp` speaks HTTP;
the tests skip when the OpenSSL on the machine has no cmp app (OpenSSL < 3.0).
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.request

import pytest
import uvicorn
from cryptography import x509

from certadillo.api.app import create_app
from certadillo.enrollment.cmp import fail_info, handle, pbm_key
from conftest import make_settings


def _openssl_has_cmp() -> bool:
    if not shutil.which("openssl"):
        return False
    return subprocess.run(["openssl", "cmp", "-help"], capture_output=True).returncode == 0


needs_openssl = pytest.mark.skipif(not _openssl_has_cmp(), reason="needs OpenSSL 3 with the cmp app")


@pytest.fixture
def live(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    settings = make_settings(tmp_path)
    settings.base_url = f"http://127.0.0.1:{port}"
    app = create_app(settings, background=False)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield port, tmp_path
    server.should_exit = True
    t.join(5)


def api(port, method, path, body=None, key="admin-key"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-API-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:  # noqa: S310 - local test server
        return json.load(r)


def ossl(*args, cwd=None, check=True):
    r = subprocess.run(["openssl", *args], capture_output=True, text=True, cwd=cwd,
                       env={"PATH": "/usr/bin:/bin", "NO_PROXY": "*"})
    if check and r.returncode != 0:
        raise AssertionError(r.stderr[-2000:])
    return r


def _setup(port, profile="tls-client", name="plant-sensors"):
    team = api(port, "POST", "/api/v1/teams", {"name": f"team-{name}", "contact_email": "ot@bank.example"})
    app = api(port, "POST", "/api/v1/apps", {"team_id": team["id"], "name": name, "environment": "dev",
                                             "profile": profile, "allowed_domains": ["*.plant.bank.internal"]})
    return app["id"]


@needs_openssl
def test_ir_kur_rr_genm(live):
    port, d = live
    app_id = _setup(port)
    sec = api(port, "POST", f"/api/v1/apps/{app_id}/cmp-secret")
    base = ["-server", f"127.0.0.1:{port}", "-path", ".well-known/cmp"]
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "k1.pem", cwd=d)
    ossl("cmp", "-cmd", "ir", *base, "-ref", sec["reference"], "-secret", f"pass:{sec['secret']}", "-newkey", "k1.pem",
         "-subject", "/CN=s1.plant.bank.internal", "-sans", "s1.plant.bank.internal", "-certout", "c1.pem",
         "-cacertsout", "root.pem", "-extracertsout", "chain.pem", cwd=d)
    c1 = x509.load_pem_x509_certificate((d / "c1.pem").read_bytes())
    root = x509.load_pem_x509_certificate((d / "root.pem").read_bytes())
    issuing = x509.load_pem_x509_certificate((d / "chain.pem").read_bytes())
    c1.verify_directly_issued_by(issuing)
    issuing.verify_directly_issued_by(root)
    assert c1.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["s1.plant.bank.internal"]
    audit = [e["action"] for e in api(port, "GET", "/api/v1/audit?limit=20")]
    assert "cmp.confirmed" in audit  # the client sent certConf

    # the one-time secret cannot enroll a second device
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "kx.pem", cwd=d)
    r = ossl("cmp", "-cmd", "ir", *base, "-ref", sec["reference"], "-secret", f"pass:{sec['secret']}", "-newkey", "kx.pem",
             "-subject", "/CN=s9.plant.bank.internal", "-certout", "cx.pem", "-unprotected_errors", cwd=d, check=False)
    assert r.returncode != 0 and not (d / "cx.pem").exists()

    trusted = [*base, "-trusted", "root.pem"]
    # key update, signed with the current certificate; the subject is carried over
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "k2.pem", cwd=d)
    ossl("cmp", "-cmd", "kur", *trusted, "-cert", "c1.pem", "-key", "k1.pem", "-extracerts", "chain.pem",
         "-newkey", "k2.pem", "-certout", "c2.pem", cwd=d)
    c2 = x509.load_pem_x509_certificate((d / "c2.pem").read_bytes())
    assert c2.subject == c1.subject and c2.serial_number != c1.serial_number
    rows = {c["serial"]: c["status"] for c in api(port, "GET", "/api/v1/certificates")}
    assert rows[format(c1.serial_number, "x")] == "superseded"
    # the superseded certificate can no longer sign requests
    r = ossl("cmp", "-cmd", "genm", *trusted, "-cert", "c1.pem", "-key", "k1.pem", "-infotype", "caCerts",
             cwd=d, check=False)
    assert r.returncode != 0

    # CA certificates on request
    r = ossl("cmp", "-cmd", "genm", *trusted, "-cert", "c2.pem", "-key", "k2.pem", "-infotype", "caCerts", cwd=d)
    assert "id-it-caCerts" in r.stderr + r.stdout

    # p10cr with implicit confirmation, then revoke that certificate with rr
    ossl("req", "-new", "-key", "k2.pem", "-subj", "/CN=s3.plant.bank.internal",
         "-addext", "subjectAltName=DNS:s3.plant.bank.internal", "-out", "s3.csr", cwd=d)
    ossl("cmp", "-cmd", "p10cr", *trusted, "-cert", "c2.pem", "-key", "k2.pem", "-csr", "s3.csr", "-certout", "c3.pem",
         "-implicit_confirm", cwd=d)
    ossl("cmp", "-cmd", "rr", *trusted, "-cert", "c2.pem", "-key", "k2.pem", "-oldcert", "c3.pem", "-revreason", "4", cwd=d)
    c3 = x509.load_pem_x509_certificate((d / "c3.pem").read_bytes())
    row = next(c for c in api(port, "GET", "/api/v1/certificates") if c["serial"] == format(c3.serial_number, "x"))
    assert row["status"] == "revoked" and row["revocation_reason"] == "superseded"


@needs_openssl
def test_out_of_scope_is_rejected(live):
    port, d = live
    app_id = _setup(port)
    sec = api(port, "POST", f"/api/v1/apps/{app_id}/cmp-secret")
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "k.pem", cwd=d)
    r = ossl("cmp", "-cmd", "ir", "-server", f"127.0.0.1:{port}", "-path", ".well-known/cmp", "-ref", sec["reference"],
             "-secret", f"pass:{sec['secret']}", "-newkey", "k.pem", "-subject", "/CN=evil.example.com",
             "-sans", "evil.example.com", "-certout", "c.pem", cwd=d, check=False)
    assert r.returncode != 0 and "san_scope" in r.stderr + r.stdout
    r = ossl("cmp", "-cmd", "ir", "-server", f"127.0.0.1:{port}", "-path", ".well-known/cmp", "-ref", sec["reference"],
             "-secret", "pass:wrong", "-newkey", "k.pem", "-subject", "/CN=a.plant.bank.internal",
             "-certout", "c.pem", "-unprotected_errors", cwd=d, check=False)
    assert r.returncode != 0


@needs_openssl
def test_polling_until_a_second_person_approves(live):
    port, d = live
    app_id = _setup(port, profile="code-signing", name="plc-firmware")
    sec = api(port, "POST", f"/api/v1/apps/{app_id}/cmp-secret")
    ossl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "fw.pem", cwd=d)
    proc = subprocess.Popen(["openssl", "cmp", "-cmd", "ir", "-server", f"127.0.0.1:{port}", "-path", ".well-known/cmp",
                             "-ref", sec["reference"], "-secret", f"pass:{sec['secret']}", "-newkey", "fw.pem",
                             "-subject", "/CN=fw.plant.bank.internal", "-certout", "fw.crt", "-total_timeout", "90"],
                            cwd=d, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env={"PATH": "/usr/bin:/bin", "NO_PROXY": "*"})
    for _ in range(100):
        pending = api(port, "GET", "/api/v1/approvals?status=pending")
        if pending:
            break
        time.sleep(0.1)
    api(port, "POST", f"/api/v1/approvals/{pending[0]['id']}/approve", {}, key="approver-key")
    out, _ = proc.communicate(timeout=120)
    assert proc.returncode == 0, out
    assert "POLLREP" in out
    cert = x509.load_pem_x509_certificate((d / "fw.crt").read_bytes())
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value[0].dotted_string == "1.3.6.1.5.5.7.3.3"


def test_garbage_gets_a_cmp_error(client):
    from pyasn1.codec.der import decoder
    from pyasn1_modules import rfc4210

    r = client.post("/.well-known/cmp", content=b"\x30\x03\x02\x01\x00", headers={"Content-Type": "application/pkixcmp"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pkixcmp"
    msg, _ = decoder.decode(r.content, asn1Spec=rfc4210.PKIMessage())
    assert msg["body"].getName() == "error"


def test_helpers():
    assert fail_info(2) == b"\x03\x02\x05\x20"   # badRequest
    assert fail_info(1, 9) == b"\x03\x03\x06\x40\x40"
    assert len(pbm_key(b"s", b"salt", __import__("hashlib").sha256, 500)) == 32
    assert callable(handle)
