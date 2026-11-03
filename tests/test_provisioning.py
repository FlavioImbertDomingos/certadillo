"""Push provisioning: issue, install, check the endpoint, renew.

The SSH tests run a real sshd and a real nginx on loopback ports and check
what nginx serves over TLS. Kubernetes and F5 run against small fakes of
their REST APIs; AWS ACM runs against moto."""
from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from cryptography import x509

from certadillo.provisioning import engine as prov
from certadillo.provisioning.validation import served_fingerprint
from conftest import ADMIN, onboard

HAVE_SSH_NGINX = bool(shutil.which("sshd") or Path("/usr/sbin/sshd").exists()) and bool(
    shutil.which("nginx") or Path("/usr/sbin/nginx").exists())
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 8.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} never opened")


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A loopback 'web server host': sshd for Certadillo to log in to, nginx serving TLS."""
    if not HAVE_SSH_NGINX:
        pytest.skip("sshd and nginx are needed")
    d = tmp_path / "host"
    www = d / "www"
    www.mkdir(parents=True)
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("ssh-keygen", "-q", "-t", "ed25519", "-f", str(d / "hostkey"), "-N", "")
    run("ssh-keygen", "-q", "-t", "ed25519", "-f", str(d / "client"), "-N", "")
    shutil.copy(d / "client.pub", d / "authorized_keys")
    ssh_port, tls_port = _free_port(), _free_port()
    (d / "sshd_config").write_text(
        f"Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nAuthorizedKeysFile {d}/authorized_keys\n"
        f"PidFile {d}/sshd.pid\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
        "PermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n")
    # nginx needs something to serve before the first push
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", str(www / "tls.key"), "-out", str(www / "tls.crt"), "-subj", "/CN=placeholder", "-days", "1")
    conf = d / "nginx.conf"
    conf.write_text(
        f"pid {d}/nginx.pid;\nerror_log {d}/nginx-error.log;\nevents {{}}\nhttp {{\n"
        f"  access_log off;\n  client_body_temp_path {d}/tmp1; proxy_temp_path {d}/tmp2;\n"
        f"  fastcgi_temp_path {d}/tmp3; uwsgi_temp_path {d}/tmp4; scgi_temp_path {d}/tmp5;\n"
        f"  server {{ listen 127.0.0.1:{tls_port} ssl; server_name _;\n"
        f"    ssl_certificate {www}/tls.crt; ssl_certificate_key {www}/tls.key; return 200 ok; }}\n}}\n")
    try:
        Path("/run/sshd").mkdir(exist_ok=True)  # privilege separation dir when running as root
    except OSError:
        pass
    subprocess.run([SSHD, "-f", str(d / "sshd_config"), "-E", str(d / "sshd.log")], check=True)
    subprocess.run([NGINX, "-e", str(d / "nginx-error.log"), "-c", str(conf), "-p", str(d)], check=True,
                   capture_output=True)
    _wait_port(ssh_port)
    _wait_port(tls_port)
    monkeypatch.setenv("CERTADILLO_TEST_SSH_KEY", (d / "client").read_text())
    prov.validation_attempts.update(attempts=4, delay=0.3)
    info = {"dir": d, "www": www, "ssh_port": ssh_port, "tls_port": tls_port,
            "host_key": " ".join((d / "hostkey.pub").read_text().split()[:2]),
            "reload": f"{NGINX} -e {d}/nginx-error.log -c {conf} -p {d} -s reload"}
    yield info
    for pidfile in ("sshd.pid", "nginx.pid"):
        try:
            os.kill(int((d / pidfile).read_text().strip()), 15)
        except (OSError, ValueError):
            pass


def _team_of(client, app_id) -> int:
    return next(a for a in client.get("/api/v1/apps", headers=ADMIN).json() if a["id"] == app_id)["team_id"]


def _ssh_target(client, host, team_id, **over):
    cfg = {"host": "127.0.0.1", "port": host["ssh_port"], "username": getpass.getuser(),
           "host_key": host["host_key"], "allowed_dirs": [str(host["www"])], "reload_command": host["reload"]}
    cfg.update(over)
    r = client.post("/api/v1/targets", json={"name": f"web-{len(over)}-{time.time_ns()}", "kind": "ssh",
                                             "team_id": team_id, "config": cfg,
                                             "credential_ref": "env:CERTADILLO_TEST_SSH_KEY"}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _installation(client, app_id, target_id, host, **over):
    body = {"app_id": app_id, "target_id": target_id, "common_name": "web.pay.bank.internal",
            "params": {"cert_path": str(host["www"] / "tls.crt"), "key_path": str(host["www"] / "tls.key")},
            "validate_endpoint": f"127.0.0.1:{host['tls_port']}"}
    body.update(over)
    r = client.post("/api/v1/installations", json=body, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _cert(client, cert_id):
    return client.get(f"/api/v1/certificates/{cert_id}", headers=ADMIN).json()


# ------------------------------------------------------------------ SSH + nginx, end to end
def test_push_to_nginx_over_ssh_and_renew(client, host):
    app_id, _ = onboard(client)
    target = _ssh_target(client, host, _team_of(client, app_id))
    inst = _installation(client, app_id, target, host)

    r = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN)
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["status"] == "validated"
    cert = _cert(client, first["certificate_id"])
    assert served_fingerprint(f"127.0.0.1:{host['tls_port']}", "web.pay.bank.internal") == cert["fingerprint_sha256"]
    assert stat.S_IMODE((host["www"] / "tls.key").stat().st_mode) == 0o600
    assert "generated a ec-p256 key in memory" in first["runs"][0]["steps"]

    # renewal: a new certificate goes in, the old one is retired only after the endpoint serves the new one
    second = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert second["status"] == "validated" and second["certificate_id"] != first["certificate_id"]
    assert _cert(client, first["certificate_id"])["status"] == "superseded"
    assert served_fingerprint(f"127.0.0.1:{host['tls_port']}", "x") == _cert(client, second["certificate_id"])["fingerprint_sha256"]
    audit = [e for e in client.get("/api/v1/audit?limit=100", headers=ADMIN).json() if e["action"] == "provisioning.run"]
    assert len(audit) == 2 and all(e["details"]["status"] == "ok" for e in audit)
    # nothing in the audit trail or the API looks like a private key
    assert "PRIVATE KEY" not in json.dumps(audit) + json.dumps(second)


def test_key_generated_on_the_host_never_leaves_it(client, host):
    app_id, _ = onboard(client)
    target = _ssh_target(client, host, _team_of(client, app_id))
    inst = _installation(client, app_id, target, host, key_location="device")
    r = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "validated"
    assert "the target generated a ec-p256 key and returned a CSR" in body["runs"][0]["steps"]
    cert = x509.load_pem_x509_certificate(_cert(client, body["certificate_id"])["pem"].encode())
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    host_key = load_pem_private_key((host["www"] / "tls.key").read_bytes(), None)
    assert host_key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_validation_catches_a_server_that_was_not_reloaded(client, host):
    app_id, _ = onboard(client)
    target = _ssh_target(client, host, _team_of(client, app_id), reload_command=None)
    inst = _installation(client, app_id, target, host)
    r = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN)
    assert r.status_code == 502
    body = r.json()
    assert body["status"] == "failed" and "does not serve the new certificate" in body["last_error"]
    from certadillo.api.app import run_housekeeping

    run_housekeeping()  # backing off, so it does not retry; it evaluates alerts
    alerts = {a["rule"]: a for a in client.get("/api/v1/alerts", headers=ADMIN).json()}
    assert alerts["ProvisioningFailed"]["severity"] == "warning"


def test_wrong_host_key_fails_and_the_undelivered_certificate_is_revoked(client, host):
    app_id, _ = onboard(client)
    other = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(host["dir"] / "other"), "-N", ""],
                           check=True)
    assert other.returncode == 0
    impostor = " ".join((host["dir"] / "other.pub").read_text().split()[:2])
    target = _ssh_target(client, host, _team_of(client, app_id), host_key=impostor)
    inst = _installation(client, app_id, target, host)
    body = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert body["status"] == "failed" and "host key" in body["last_error"]
    run = body["runs"][0]
    assert run["certificate_id"] and _cert(client, run["certificate_id"])["status"] == "revoked"
    assert body["next_attempt_at"] is not None


def test_paths_outside_allowed_dirs_are_refused(client, host):
    app_id, _ = onboard(client)
    target = _ssh_target(client, host, _team_of(client, app_id))
    for bad in ("/etc/shadow", str(host["www"] / ".." / "escape.key"), "relative/tls.key"):
        r = client.post("/api/v1/installations", json={
            "app_id": app_id, "target_id": target, "common_name": "web.pay.bank.internal",
            "params": {"cert_path": str(host["www"] / "tls.crt"), "key_path": bad}}, headers=ADMIN)
        assert r.status_code == 400, bad


# ------------------------------------------------------------------ rules that need no host
def test_secrets_never_go_into_target_config(client):
    app_id, _ = onboard(client)
    team = _team_of(client, app_id)
    base = {"host": "h", "username": "u", "host_key": "ssh-ed25519 AAAA", "allowed_dirs": ["/srv"]}
    r = client.post("/api/v1/targets", json={"name": "t1", "kind": "ssh", "team_id": team,
                                             "config": {**base, "password": "hunter2"}}, headers=ADMIN)
    assert r.status_code == 400 and "credential_ref" in r.text
    r = client.post("/api/v1/targets", json={"name": "t2", "kind": "ssh", "team_id": team, "config": base,
                                             "credential_ref": "hunter2"}, headers=ADMIN)
    assert r.status_code == 400


def test_a_target_serves_only_its_own_team(client):
    app_a, _ = onboard(client, "app-a", domains=["*.a.bank.internal"])
    app_b, _ = onboard(client, "app-b", domains=["*.b.bank.internal"])
    t = client.post("/api/v1/targets", json={
        "name": "k8s-a", "kind": "kubernetes", "team_id": _team_of(client, app_a),
        "config": {"api_server": "https://k8s.a.bank.internal", "namespaces": ["web"]}}, headers=ADMIN).json()
    r = client.post("/api/v1/installations", json={"app_id": app_b, "target_id": t["id"],
                                                   "common_name": "x.b.bank.internal",
                                                   "params": {"namespace": "web", "secret_name": "x"}}, headers=ADMIN)
    assert r.status_code == 403


def test_only_admins_create_targets(client):
    app_id, h = onboard(client)
    r = client.post("/api/v1/targets", json={"name": "k8s-x", "kind": "kubernetes", "team_id": _team_of(client, app_id),
                                             "config": {"api_server": "https://k", "namespaces": ["a"]}}, headers=h)
    assert r.status_code == 403


# ------------------------------------------------------------------ Kubernetes (fake API server)
class FakeK8s:
    def __init__(self):
        self.secrets: dict[tuple[str, str], dict] = {}
        self.auth: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.auth.append(request.headers.get("authorization", ""))
        parts = request.url.path.strip("/").split("/")  # api v1 namespaces ns secrets [name]
        ns = parts[3]
        if request.method == "GET":
            s = self.secrets.get((ns, parts[5]))
            return httpx.Response(200, json=s) if s else httpx.Response(404, json={})
        body = json.loads(request.content)
        name = body["metadata"]["name"]
        if request.method == "POST":
            if (ns, name) in self.secrets:
                return httpx.Response(409, json={})
            body["metadata"]["resourceVersion"] = "1"
        else:
            body["metadata"]["resourceVersion"] = str(int(self.secrets[(ns, name)]["metadata"]["resourceVersion"]) + 1)
        self.secrets[(ns, name)] = body
        return httpx.Response(201 if request.method == "POST" else 200, json=body)


def test_kubernetes_secret_is_created_then_updated_and_foreign_secrets_are_left_alone(client, monkeypatch):
    import base64

    fake = FakeK8s()
    monkeypatch.setitem(prov.test_transports, "kubernetes", httpx.MockTransport(fake.handler))
    monkeypatch.setenv("CERTADILLO_TEST_K8S_TOKEN", "sa-token")
    app_id, _ = onboard(client)
    t = client.post("/api/v1/targets", json={
        "name": "k8s", "kind": "kubernetes", "team_id": _team_of(client, app_id),
        "config": {"api_server": "https://k8s.bank.internal:6443", "namespaces": ["payments"]},
        "credential_ref": "env:CERTADILLO_TEST_K8S_TOKEN"}, headers=ADMIN).json()
    inst = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "api.pay.bank.internal",
        "params": {"namespace": "payments", "secret_name": "api-tls"}}, headers=ADMIN).json()["id"]
    first = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert first["status"] == "installed", first
    secret = fake.secrets[("payments", "api-tls")]
    assert secret["type"] == "kubernetes.io/tls"
    leaf = x509.load_pem_x509_certificate(base64.b64decode(secret["data"]["tls.crt"]))
    assert leaf.subject.rfc4514_string().startswith("CN=api.pay.bank.internal")
    assert fake.auth[0] == "Bearer sa-token"
    second = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert second["status"] == "installed" and fake.secrets[("payments", "api-tls")]["metadata"]["resourceVersion"] == "2"

    fake.secrets[("payments", "someone-else")] = {"metadata": {"name": "someone-else", "resourceVersion": "9"}}
    other = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "b.pay.bank.internal",
        "params": {"namespace": "payments", "secret_name": "someone-else"}}, headers=ADMIN).json()["id"]
    body = client.post(f"/api/v1/installations/{other}/provision", headers=ADMIN).json()
    assert body["status"] == "failed" and "not created by Certadillo" in body["last_error"]
    r = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "c.pay.bank.internal",
        "params": {"namespace": "kube-system", "secret_name": "x"}}, headers=ADMIN)
    assert r.status_code == 400


# ------------------------------------------------------------------ F5 BIG-IP (fake iControl REST)
class FakeBigIP:
    def __init__(self):
        self.uploads: dict[str, bytes] = {}
        self.installed: list[tuple[str, str]] = []
        self.profiles: dict[str, dict] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/mgmt/shared/authn/login":
            creds = json.loads(request.content)
            ok = creds["password"] == "f5-secret"
            return httpx.Response(200 if ok else 401, json={"token": {"token": "tok"}})
        if request.headers.get("x-f5-auth-token") != "tok":
            return httpx.Response(401)
        if path.startswith("/mgmt/shared/file-transfer/uploads/"):
            self.uploads[path.rsplit("/", 1)[1]] = request.content
            return httpx.Response(200, json={})
        if path.startswith("/mgmt/tm/sys/crypto/"):
            body = json.loads(request.content)
            self.installed.append((path.rsplit("/", 1)[1], body["name"]))
            return httpx.Response(200, json={})
        if path.startswith("/mgmt/tm/ltm/profile/client-ssl/"):
            self.profiles[path.rsplit("~", 1)[1]] = json.loads(request.content)
            return httpx.Response(200, json={})
        return httpx.Response(404)


def test_f5_installs_new_objects_then_switches_the_profile(client, monkeypatch):
    fake = FakeBigIP()
    monkeypatch.setitem(prov.test_transports, "f5", httpx.MockTransport(fake.handler))
    monkeypatch.setenv("CERTADILLO_TEST_F5", "f5-secret")
    app_id, _ = onboard(client)
    t = client.post("/api/v1/targets", json={
        "name": "bigip-dc1", "kind": "f5", "team_id": _team_of(client, app_id),
        "config": {"host": "https://bigip.dc1.bank.internal", "username": "certadillo", "partition": "Payments"},
        "credential_ref": "env:CERTADILLO_TEST_F5"}, headers=ADMIN).json()
    inst = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "www.pay.bank.internal",
        "params": {"profile": "www_clientssl"}}, headers=ADMIN).json()["id"]
    body = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert body["status"] == "installed", body
    serial = _cert(client, body["certificate_id"])["serial"]
    obj = f"www_clientssl_{serial[:12]}"
    assert [n for _, n in fake.installed] == [f"{obj}.key", f"{obj}.crt", f"{obj}-chain.crt"]
    assert b"PRIVATE KEY" in fake.uploads[f"{obj}.key"]
    chain = fake.profiles["www_clientssl"]["certKeyChain"][0]
    assert chain["cert"] == f"/Payments/{obj}.crt" and chain["key"] == f"/Payments/{obj}.key"

    monkeypatch.setenv("CERTADILLO_TEST_F5", "wrong")
    failed = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert failed["status"] == "failed" and "login failed" in failed["last_error"]
    # the certificate that could not be delivered is revoked; the one on the F5 stays active
    assert _cert(client, failed["runs"][0]["certificate_id"])["status"] == "revoked"
    assert _cert(client, body["certificate_id"])["status"] == "active"


# ------------------------------------------------------------------ AWS ACM (moto)
def test_acm_import_then_reimport_into_the_same_arn(client, monkeypatch):
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        import boto3

        app_id, _ = onboard(client)
        t = client.post("/api/v1/targets", json={"name": "acm-use1", "kind": "aws-acm",
                                                 "team_id": _team_of(client, app_id),
                                                 "config": {"region": "us-east-1"}}, headers=ADMIN).json()
        inst = client.post("/api/v1/installations", json={
            "app_id": app_id, "target_id": t["id"], "common_name": "edge.pay.bank.internal"}, headers=ADMIN).json()["id"]
        first = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
        assert first["status"] == "installed", first
        arn = first["params"]["certificate_arn"]
        second = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
        assert second["params"]["certificate_arn"] == arn
        acm = boto3.client("acm", region_name="us-east-1")
        assert len(acm.list_certificates()["CertificateSummaryList"]) == 1
        served = x509.load_pem_x509_certificate(acm.get_certificate(CertificateArn=arn)["Certificate"].encode())
        assert format(served.serial_number, "x") == _cert(client, second["certificate_id"])["serial"]


# ------------------------------------------------------------------ scheduler
def test_scheduler_picks_up_new_failed_and_campaign_installations(client, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from certadillo.db import Installation, RenewalAdvice, RenewalCampaign
    from certadillo.runtime import get_runtime

    fake = FakeK8s()
    monkeypatch.setitem(prov.test_transports, "kubernetes", httpx.MockTransport(fake.handler))
    app_id, _ = onboard(client)
    t = client.post("/api/v1/targets", json={
        "name": "k8s", "kind": "kubernetes", "team_id": _team_of(client, app_id),
        "config": {"api_server": "https://k8s.bank.internal", "namespaces": ["web"]}}, headers=ADMIN).json()
    inst_id = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "s.pay.bank.internal",
        "params": {"namespace": "web", "secret_name": "s"}}, headers=ADMIN).json()["id"]
    with get_runtime().platform() as p:
        assert [i.id for i in prov.due(p)] == [inst_id]          # never provisioned
        prov.renew_due(p)
        assert prov.due(p) == []                                  # current certificate, nothing to do
        inst = p.s.get(Installation, inst_id)
        now = datetime.now(timezone.utc)
        camp = RenewalCampaign(name="ca-rollover", reason="test", criteria={}, window_start=now - timedelta(hours=1),
                               window_end=now + timedelta(days=1), created_by="t")
        p.s.add(camp)
        p.s.flush()
        p.s.add(RenewalAdvice(certificate_id=inst.certificate_id, campaign_id=camp.id,
                              window_start=now - timedelta(hours=1), window_end=now + timedelta(days=1)))
        p.commit()
        assert [i.id for i in prov.due(p)] == [inst_id]           # a renewal campaign covers it
        inst.status, inst.next_attempt_at = "failed", now + timedelta(hours=1)
        p.commit()
        assert prov.due(p) == []                                  # failed, but backing off


def test_a_target_changed_in_sql_pushes_nothing(client, monkeypatch):
    """A database write that repoints a target or adds a reload command must not
    reach any host: the target's seal breaks and the run stops before connecting."""
    from sqlalchemy import text

    from certadillo.db import get_session

    fake = FakeK8s()
    monkeypatch.setitem(prov.test_transports, "kubernetes", httpx.MockTransport(fake.handler))
    app_id, _ = onboard(client)
    t = client.post("/api/v1/targets", json={
        "name": "k8s", "kind": "kubernetes", "team_id": _team_of(client, app_id),
        "config": {"api_server": "https://k8s.bank.internal", "namespaces": ["web"]}}, headers=ADMIN).json()
    inst = client.post("/api/v1/installations", json={
        "app_id": app_id, "target_id": t["id"], "common_name": "s.pay.bank.internal",
        "params": {"namespace": "web", "secret_name": "s"}}, headers=ADMIN).json()["id"]
    evil = json.dumps({"api_server": "https://attacker.example", "namespaces": ["web"]})
    with get_session() as s:
        s.execute(text("UPDATE provisioning_targets SET config = :c WHERE id = :i"), {"c": evil, "i": t["id"]})
        s.commit()
    body = client.post(f"/api/v1/installations/{inst}/provision", headers=ADMIN).json()
    assert body["status"] == "failed" and "integrity" in body["last_error"]
    assert fake.secrets == {} and body["runs"][0]["certificate_id"] is None
    problems = client.get("/api/v1/integrity", headers=ADMIN).json()["problems"]
    assert any(p["kind"] == "provisioning_target" for p in problems)
