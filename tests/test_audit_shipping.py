"""Audit shipping: every event leaves the host in order, with its chain hashes
and a MAC, and a receiver can prove nothing was changed, dropped or forged."""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient
from sqlalchemy import text

from certadillo.api.app import create_app, run_audit_shipping, run_housekeeping
from certadillo.audit import shipping
from certadillo.db import get_session
from conftest import ADMIN, issue, make_settings, onboard


def _records(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _verify(path: Path, *extra) -> tuple[int, dict]:
    from certadillo.cli import main

    r = CliRunner().invoke(main, ["audit", "verify-export", str(path), *extra])
    return r.exit_code, json.loads(r.output[r.output.index("{"):])


def test_file_sink_ships_everything_and_an_export_verifies(tmp_path, monkeypatch):
    out = tmp_path / "audit.jsonl"
    s = make_settings(tmp_path, audit_ship=[f"file:{out}"])
    with TestClient(create_app(s, background=False)) as c:
        _, h = onboard(c)
        issue(c, h)
        sent = run_audit_shipping()
        assert sent[f"file:{out}"] > 5
        assert run_audit_shipping()[f"file:{out}"] == 0  # nothing new, nothing resent
        recs = _records(out)
        events = c.get("/api/v1/audit?limit=1000", headers=ADMIN).json()
        assert len(recs) == len(events) and recs[0]["prev_hash"] == "0" * 64
        assert all(r["mac"] for r in recs)
        # the verifier runs with the same key material (same data dir)
        monkeypatch.setenv("CERTADILLO_DATA_DIR", str(tmp_path))
        code, res = _verify(out)
        assert code == 0 and res["valid"] and res["from_genesis"]

        # edit one shipped record: caught
        bad = [dict(r) for r in recs]
        bad[3]["details"] = {**bad[3]["details"], "note": "edited"}
        (tmp_path / "edited.jsonl").write_text("".join(json.dumps(r) + "\n" for r in bad))
        code, res = _verify(tmp_path / "edited.jsonl")
        assert code == 1 and "changed" in res["problems"][0]["problem"]
        # drop one record: caught
        (tmp_path / "gap.jsonl").write_text("".join(json.dumps(r) + "\n" for i, r in enumerate(recs) if i != 4))
        code, res = _verify(tmp_path / "gap.jsonl")
        assert code == 1 and "gap" in res["problems"][0]["problem"]
        # a record forged by someone without the seal key: caught
        forged = [dict(r) for r in recs]
        forged[-1]["mac"] = "0" * 64
        (tmp_path / "forged.jsonl").write_text("".join(json.dumps(r) + "\n" for r in forged))
        code, res = _verify(tmp_path / "forged.jsonl")
        assert code == 1 and "MAC" in res["problems"][0]["problem"]
        # a duplicate from at-least-once delivery is fine
        (tmp_path / "dup.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs + recs[-3:]))
        assert _verify(tmp_path / "dup.jsonl")[0] == 0


def test_history_changed_after_shipping_stops_the_shipper_and_alerts(tmp_path):
    out = tmp_path / "audit.jsonl"
    s = make_settings(tmp_path, audit_ship=[f"file:{out}"])
    with TestClient(create_app(s, background=False)) as c:
        onboard(c)
        run_audit_shipping()
        shipped = len(_records(out))
        with get_session() as db:
            # someone with database owner rights drops the guard and rewrites the last event
            db.execute(text("DROP TRIGGER IF EXISTS audit_events_no_update"))
            db.execute(text("UPDATE audit_events SET hash = :h WHERE id = (SELECT MAX(id) FROM audit_events)"),
                       {"h": "f" * 64})
            db.commit()
        _, h = onboard(c, "second", domains=["*.second.bank.internal"])
        result = run_audit_shipping()[f"file:{out}"]
        assert "chain break" in result
        assert len(_records(out)) == shipped  # nothing after the break was sent as if it were fine
        run_housekeeping()
        alerts = {a["rule"]: a for a in c.get("/api/v1/alerts", headers=ADMIN).json()}
        assert alerts["AuditShippingFailing"]["severity"] == "critical"


def test_syslog_over_tls(tmp_path):
    # a TLS syslog receiver on loopback, with its own CA
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", key, "-out", crt, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-days", "1"], check=True, capture_output=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = bytearray()

    def serve():
        conn, _ = srv.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            while True:
                try:
                    chunk = tls.recv(65536)
                except (ssl.SSLError, OSError):
                    break  # the sender closed the connection
                if not chunk:
                    break
                received.extend(chunk)
            try:
                tls.unwrap()  # answer the sender's close_notify
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    s = make_settings(tmp_path, audit_ship=[f"syslog+tls://localhost:{port}"], audit_ship_cacert=str(crt))
    with TestClient(create_app(s, background=False)) as c:
        onboard(c)
        n = run_audit_shipping()[f"syslog+tls://localhost:{port}"]
    t.join(timeout=5)
    # octet-counted RFC 5424 frames, each carrying a JSON record
    frames, buf = [], bytes(received)
    while buf:
        length, _, rest = buf.partition(b" ")
        frames.append(rest[:int(length)])
        buf = rest[int(length):]
    assert len(frames) == n > 0
    assert frames[0].startswith(b"<109>1 ")
    first = json.loads(frames[0][frames[0].index(b"{"):])
    assert first["prev_hash"] == "0" * 64 and first["mac"]


def test_splunk_hec(tmp_path, monkeypatch):
    seen = []

    def hec(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/collector/event"
        assert request.headers["authorization"] == "Splunk hec-token"
        seen.extend(json.loads(line) for line in request.content.decode().splitlines())
        return httpx.Response(200, json={"text": "Success", "code": 0})

    monkeypatch.setitem(shipping.test_transport, "http", httpx.MockTransport(hec))
    monkeypatch.setenv("CERTADILLO_TEST_HEC", "hec-token")
    s = make_settings(tmp_path, audit_ship=["splunk+https://splunk.bank.internal:8088"],
                      audit_ship_token_ref="env:CERTADILLO_TEST_HEC", audit_ship_splunk_index="pki_audit")
    with TestClient(create_app(s, background=False)):
        run_audit_shipping()
    assert seen and all(e["sourcetype"] == "certadillo:audit" and e["index"] == "pki_audit" for e in seen)
    assert seen[0]["event"]["prev_hash"] == "0" * 64


def test_s3_object_lock(tmp_path, monkeypatch):
    moto = pytest.importorskip("moto")
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        import boto3

        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="pki-audit", ObjectLockEnabledForBucket=True)
        s = make_settings(tmp_path, audit_ship=["s3://pki-audit/certadillo/prod"], audit_ship_s3_retention_days=30)
        with TestClient(create_app(s, background=False)) as c:
            onboard(c)
            run_audit_shipping()
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket="pki-audit")["Contents"]]
        assert len(keys) == 1 and keys[0].startswith("certadillo/prod/000000000001-")
        head = s3.head_object(Bucket="pki-audit", Key=keys[0])
        assert head["ObjectLockMode"] == "COMPLIANCE" and head["ObjectLockRetainUntilDate"]
        body = s3.get_object(Bucket="pki-audit", Key=keys[0])["Body"].read().decode()
        assert shipping.verify_records([json.loads(ln) for ln in body.splitlines()], check_mac=False)["valid"]


def test_a_mistyped_sink_stops_startup(tmp_path):
    with pytest.raises(ValueError):
        create_app(make_settings(tmp_path, audit_ship=["ftp://nowhere"]), background=False)


def test_shipping_status_and_lag_alert(tmp_path, monkeypatch):
    monkeypatch.setitem(shipping.test_transport, "http",
                        httpx.MockTransport(lambda r: httpx.Response(503, json={})))
    s = make_settings(tmp_path, audit_ship=["https://collector.bank.internal/audit"])
    with TestClient(create_app(s, background=False)) as c:
        onboard(c)
        res = run_audit_shipping()["https://collector.bank.internal/audit"]
        assert "503" in res
        status = c.get("/api/v1/audit/shipping", headers=ADMIN).json()[0]
        assert status["behind"] > 0 and status["failures"] == 1 and "token" not in json.dumps(status)
        run_housekeeping()
        assert "AuditShippingFailing" in [a["rule"] for a in c.get("/api/v1/alerts", headers=ADMIN).json()]


def test_records_are_signed_and_a_receiver_needs_only_the_public_key(tmp_path, monkeypatch):
    """The receiver holds the public key, not the seal key: it can check every
    record and cannot forge one, even by recomputing the whole chain."""
    from certadillo.audit.log import _digest
    from datetime import datetime

    out = tmp_path / "audit.jsonl"
    s = make_settings(tmp_path, audit_ship=[f"file:{out}"])
    with TestClient(create_app(s, background=False)) as c:
        onboard(c)
        run_audit_shipping()
        key = c.get("/api/v1/audit/signing-key", headers=ADMIN).json()
    assert key["algorithm"] == "Ed25519"
    pub = tmp_path / "audit-signing.pub"
    pub.write_text(key["public_key_pem"])
    recs = _records(out)
    assert all(r["sig"] and r["kid"] == key["key_id"] for r in recs)
    assert (tmp_path / "audit-signing.key.pem").stat().st_mode & 0o077 == 0
    assert b"ENCRYPTED" in (tmp_path / "audit-signing.key.pem").read_bytes()

    # a verifier somewhere else: no data dir, no seal key, only the public key
    monkeypatch.setenv("CERTADILLO_DATA_DIR", str(tmp_path / "elsewhere"))
    code, res = _verify(out, "--public-key", str(pub), "--no-mac")
    assert code == 0 and res["signatures_checked"] and not res["macs_checked"]

    # without the public key or the seal key, origin is unchecked: not valid
    code, res = _verify(out, "--no-mac")
    assert code == 1 and "origin not checked" in res["problems"][0]["problem"]

    # rewrite the last record and re-hash it so the chain still links: the hash
    # checks pass, the signature does not
    forged = [dict(r) for r in recs]
    last = forged[-1]
    last["details"] = {**last["details"], "note": "rewritten"}
    last["hash"] = _digest(last["prev_hash"], datetime.fromisoformat(last["ts"]), last["actor"], last["action"],
                           last["target"], last["details"])
    (tmp_path / "rewritten.jsonl").write_text("".join(json.dumps(r) + "\n" for r in forged))
    code, res = _verify(tmp_path / "rewritten.jsonl", "--public-key", str(pub), "--no-mac")
    assert code == 1 and [p["problem"] for p in res["problems"]] == \
        ["signature does not verify (not from this Certadillo)"]
    # stripping the signatures does not help either
    stripped = [{k: v for k, v in r.items() if k != "sig"} for r in recs]
    (tmp_path / "stripped.jsonl").write_text("".join(json.dumps(r) + "\n" for r in stripped))
    assert _verify(tmp_path / "stripped.jsonl", "--public-key", str(pub), "--no-mac")[0] == 1
