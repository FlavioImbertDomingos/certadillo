"""Code-signing service and RFC 3161 time-stamping, verified with openssl."""
from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess

import pytest
from asn1crypto import cms, tsp
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from conftest import ADMIN, APPROVER, make_settings, onboard

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


def _setup(c, purpose, name):
    app_id, h = onboard(c, f"build-{name}", domains=(f"*.{name}.bank.internal",))
    r = c.post("/api/v1/signing/keys", json={"name": name, "app_id": app_id, "purpose": purpose}, headers=ADMIN)
    assert r.status_code == 202, r.text
    # the requester cannot approve their own key; an approver can
    assert c.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=ADMIN).status_code == 403
    r = c.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER)
    assert r.status_code == 200, r.text
    return app_id, h


def _verify(tmp_path, c, key, data: bytes, sig_der: bytes, name="artifact.bin"):
    (tmp_path / name).write_bytes(data)
    (tmp_path / f"{name}.p7s").write_bytes(sig_der)
    (tmp_path / "chain.pem").write_text(c.get(f"/api/v1/signing/keys/{key}/chain", headers=ADMIN).text)
    return subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(tmp_path / f"{name}.p7s"),
                           "-content", str(tmp_path / name), "-CAfile", str(tmp_path / "chain.pem"), "-purpose", "any",
                           "-out", "/dev/null"], capture_output=True, text=True)


def test_test_key_signs_at_once_and_openssl_verifies(tmp_path, client):
    _, h = _setup(client, "test", "ci-snapshots")
    keys = client.get("/api/v1/signing/keys", headers=h).json()
    assert [k["name"] for k in keys] == ["ci-snapshots"] and keys[0]["signer"] == "software"
    data = b"payments-api-2.4.1.tar.gz contents"
    r = client.post("/api/v1/signing/sign", headers=h, json={
        "key": "ci-snapshots", "digest_alg": "sha256", "digest": hashlib.sha256(data).hexdigest(),
        "artifact": {"name": "payments-api-2.4.1.tar.gz", "version": "2.4.1", "commit": "8a925e3"}})
    assert r.status_code == 200, r.text
    sig = base64.b64decode(r.json()["signature_cms"])
    v = _verify(tmp_path, client, "ci-snapshots", data, sig)
    assert v.returncode == 0, v.stderr
    # a changed artifact does not verify
    assert _verify(tmp_path, client, "ci-snapshots", data + b"x", sig).returncode != 0

    # the signature carries an RFC 3161 token over the signature value
    info = cms.ContentInfo.load(sig)
    si = info["content"]["signer_infos"][0]
    token = [a for a in si["unsigned_attrs"] if a["type"].native == "signature_time_stamp_token"][0]["values"][0]
    tst = tsp.TSTInfo.load(token["content"]["encap_content_info"]["content"].parsed.dump())
    assert tst["message_imprint"]["hashed_message"].native == hashlib.sha256(si["signature"].native).digest()
    # and openssl accepts the embedded token for the signature value
    (tmp_path / "token.der").write_bytes(token.dump())
    (tmp_path / "sigvalue.bin").write_bytes(si["signature"].native)
    v = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", str(tmp_path / "token.der"), "-data",
                        str(tmp_path / "sigvalue.bin"), "-CAfile", str(tmp_path / "chain.pem")],
                       capture_output=True, text=True)
    assert "Verification: OK" in v.stdout, v.stdout + v.stderr

    audit = [(e["action"], e["details"].get("version")) for e in client.get("/api/v1/audit?limit=100",
                                                                             headers=ADMIN).json()]
    assert ("codesign.sign", "2.4.1") in audit


def test_release_key_needs_a_second_person_for_every_signature(tmp_path, client):
    _, h = _setup(client, "release", "payments-release")
    data = b"release build"
    body = {"key": "payments-release", "digest_alg": "sha384", "digest": hashlib.sha384(data).hexdigest(),
            "artifact": {"name": "payments-api-3.0.0.tar.gz", "version": "3.0.0"}}
    r = client.post("/api/v1/signing/sign", headers=h, json=body)
    assert r.status_code == 202 and r.json()["status"] == "pending" and "signature_cms" not in r.json()
    req_id, approval = r.json()["id"], r.json()["approval_id"]
    assert client.get(f"/api/v1/signing/requests/{req_id}", headers=h).json()["status"] == "pending"
    # the app that asked cannot approve (it is not an approver)
    assert client.post(f"/api/v1/approvals/{approval}/approve", headers=h).status_code == 403
    assert client.post(f"/api/v1/approvals/{approval}/approve", headers=APPROVER).status_code == 200
    done = client.get(f"/api/v1/signing/requests/{req_id}", headers=h).json()
    assert done["status"] == "signed"
    v = _verify(tmp_path, client, "payments-release", data, base64.b64decode(done["signature_cms"]))
    assert v.returncode == 0, v.stderr

    # a rejected request never gets a signature
    r = client.post("/api/v1/signing/sign", headers=h, json={**body, "artifact": {"name": "suspicious.bin"}})
    client.post(f"/api/v1/approvals/{r.json()['approval_id']}/reject", headers=APPROVER, json={"comment": "no ticket"})
    assert client.get(f"/api/v1/signing/requests/{r.json()['id']}", headers=h).json()["status"] == "rejected"


def test_only_the_owning_app_can_use_a_key(client):
    _setup(client, "test", "team-a-key")
    _, other = onboard(client, "other-app", domains=("*.other.bank.internal",))
    body = {"key": "team-a-key", "digest_alg": "sha256", "digest": "00" * 32, "artifact": {"name": "x"}}
    assert client.post("/api/v1/signing/sign", headers=other, json=body).status_code == 403
    assert client.get("/api/v1/signing/keys", headers=other).json() == []
    # malformed digests and missing artifact names are refused
    _, h = onboard(client, "build-team-a-key2", domains=("*.a2.bank.internal",))
    assert client.post("/api/v1/signing/sign", headers=ADMIN,
                       json={**body, "digest": "zz" * 32}).status_code == 400
    assert client.post("/api/v1/signing/sign", headers=ADMIN,
                       json={**body, "digest_alg": "md5"}).status_code == 400
    assert client.post("/api/v1/signing/sign", headers=ADMIN, json={**body, "artifact": {}}).status_code == 400


def test_tsa_answers_openssl_ts(tmp_path, client):
    (tmp_path / "doc.txt").write_bytes(b"contract v7")
    subprocess.run(["openssl", "ts", "-query", "-data", str(tmp_path / "doc.txt"), "-sha256", "-cert",
                    "-out", str(tmp_path / "q.tsq")], check=True, capture_output=True)
    r = client.post("/tsa", content=(tmp_path / "q.tsq").read_bytes(),
                    headers={"Content-Type": "application/timestamp-query"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/timestamp-reply"
    (tmp_path / "r.tsr").write_bytes(r.content)
    chain = client.get("/pki/ca/issuing-ca-1.pem").text + client.get("/pki/ca/root-ca.pem").text
    (tmp_path / "chain.pem").write_text(chain)
    v = subprocess.run(["openssl", "ts", "-verify", "-in", str(tmp_path / "r.tsr"), "-queryfile",
                        str(tmp_path / "q.tsq"), "-CAfile", str(tmp_path / "chain.pem")], capture_output=True, text=True)
    assert v.returncode == 0 and "Verification: OK" in v.stdout, v.stdout + v.stderr
    # garbage gets a rejection response, not a server error
    r = client.post("/tsa", content=b"\x30\x03\x02\x01\x01")
    assert r.status_code == 200
    (tmp_path / "bad.tsr").write_bytes(r.content)
    out = subprocess.run(["openssl", "ts", "-reply", "-in", str(tmp_path / "bad.tsr"), "-text"],
                         capture_output=True, text=True).stdout
    assert "Status: Rejected" in out and "wrong format" in out


def test_signing_key_in_an_hsm(tmp_path, softhsm):
    # SoftHSM reads its token directory once per process and other tests put
    # root-ca there, so this hierarchy uses its own labels
    from certadillo.runtime import get_runtime

    s = make_settings(tmp_path / "data", signer="pkcs11", pkcs11_lib=softhsm, pkcs11_pin="1234", auto_init_ca=False)
    with TestClient(create_app(s, background=False)) as c:
        with get_runtime().platform() as p:
            root = p.ca.create_root("root-cs")
            p.ca.create_subordinate(root, "issuing-cs")
            p.commit()
        _setup(c, "test", "hsm-signing")
        assert c.get("/api/v1/signing/keys", headers=ADMIN).json()[0]["signer"] == "pkcs11"
        _, h = onboard(c, "hsm-caller", domains=("*.hsmc.bank.internal",))
        data = b"firmware.bin"
        r = c.post("/api/v1/signing/sign", headers=ADMIN, json={
            "key": "hsm-signing", "digest_alg": "sha384", "digest": hashlib.sha384(data).hexdigest(),
            "artifact": {"name": "firmware.bin"}})
        assert r.status_code == 200, r.text
        v = _verify(tmp_path, c, "hsm-signing", data, base64.b64decode(r.json()["signature_cms"]))
        assert v.returncode == 0, v.stderr


def test_cli_sign_against_a_live_server(tmp_path):
    """`certadillo sign` hashes locally, sends only the digest, writes FILE.p7s."""
    import socket
    import threading
    import time

    import httpx
    import uvicorn
    from click.testing import CliRunner

    from certadillo.cli import main

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    s = make_settings(tmp_path / "srv")
    s.base_url = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(uvicorn.Config(create_app(s, background=False), host="127.0.0.1", port=port,
                                           log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        base = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=base) as c:
            app_id = c.post("/api/v1/teams", json={"name": "team-rel", "contact_email": "t@example.com"},
                            headers=ADMIN).json()["id"]
            app_id = c.post("/api/v1/apps", json={"team_id": app_id, "name": "release-bot", "environment": "dev",
                                                  "profile": "tls-server", "allowed_domains": ["*.rel.bank.internal"]},
                            headers=ADMIN).json()["id"]
            key = c.post(f"/api/v1/apps/{app_id}/credentials", headers=ADMIN).json()["api_key"]
            a = c.post("/api/v1/signing/keys", json={"name": "rel-test", "app_id": app_id, "purpose": "test"},
                       headers=ADMIN).json()
            c.post(f"/api/v1/approvals/{a['approval_id']}/approve", headers=APPROVER)
            chain = c.get("/api/v1/signing/keys/rel-test/chain", headers=ADMIN).text
        art = tmp_path / "payments-api.whl"
        art.write_bytes(b"\x00wheel bytes" * 1000)
        (tmp_path / "key.txt").write_text(key)
        r = CliRunner().invoke(main, ["sign", str(art), "--key", "rel-test", "--server", base,
                                      "--api-key-file", str(tmp_path / "key.txt"), "--version", "1.2.3"])
        assert r.exit_code == 0, r.output
        (tmp_path / "chain.pem").write_text(chain)
        v = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", f"{art}.p7s",
                            "-content", str(art), "-CAfile", str(tmp_path / "chain.pem"), "-purpose", "any",
                            "-out", "/dev/null"], capture_output=True, text=True)
        assert v.returncode == 0, v.stderr
    finally:
        server.should_exit = True
        t.join(5)
