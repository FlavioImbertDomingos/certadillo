"""Fixes from the AI code review: EST certificate login uses the sealed status,
LDAP is TLS-only, no public default key passphrase, and the CLI keeps the API
key and private key to itself."""
from __future__ import annotations

import os
import ssl
import stat
import subprocess
import time

import pytest
from sqlalchemy import text

from certadillo.config import Settings
from certadillo.db import get_session
from conftest import ADMIN, onboard
from test_est_phase2 import _basic, _csr, _leaf, _via_lb, lb_client  # noqa: F401 - fixture


# ------------------------------------------------------------------ EST
def test_est_login_uses_the_sealed_status(lb_client):  # noqa: F811
    _, h = onboard(lb_client, "atm-fleet", profile="tls-client", domains=["*.atm.bank.internal"])
    _, body = _csr("atm-7.atm.bank.internal")
    cert = _leaf(lb_client.post("/.well-known/est/simpleenroll", content=body, headers=_basic(h["X-API-Key"])))
    row = next(c for c in lb_client.get("/api/v1/certificates", headers=ADMIN).json()
               if c["serial"] == format(cert.serial_number, "x"))
    assert lb_client.post(f"/api/v1/certificates/{row['id']}/revoke", json={"reason": "key_compromise"},
                          headers=h).status_code == 200
    with get_session() as s:  # an attacker with database access flips it back
        s.execute(text("UPDATE certificates SET status = 'active', revoked_at = NULL WHERE id = :i"), {"i": row["id"]})
        s.commit()
    _, again = _csr("atm-7.atm.bank.internal")
    r = lb_client.post("/.well-known/est/simplereenroll", content=again, headers=_via_lb(cert))
    assert r.status_code == 401


# ------------------------------------------------------------------ LDAP transport
class _Recorder:
    def __init__(self):
        self.server = self.conn = None

    def server_factory(self, url, **kw):
        self.server = (url, kw)
        return "server"

    def connection_factory(self, server, **kw):
        self.conn = kw
        return "conn"


def test_ldap_url_is_upgraded_with_starttls_and_validated(monkeypatch):
    import ldap3

    from certadillo.adcs.ldaptls import open_connection

    monkeypatch.delenv("CERTADILLO_ADCS_LDAP_ALLOW_PLAIN", raising=False)
    r = _Recorder()
    open_connection(ldap3, "ldap://dc1.bank.internal", "u", "p",
                    server_factory=r.server_factory, connection_factory=r.connection_factory)
    assert r.conn["auto_bind"] == ldap3.AUTO_BIND_TLS_BEFORE_BIND
    assert r.server[1]["tls"].validate == ssl.CERT_REQUIRED
    r = _Recorder()
    open_connection(ldap3, "ldaps://dc1.bank.internal", "u", "p",
                    server_factory=r.server_factory, connection_factory=r.connection_factory)
    assert r.server[1]["use_ssl"] is True and r.server[1]["tls"].validate == ssl.CERT_REQUIRED


def test_ldaps_to_an_untrusted_certificate_fails_closed(tmp_path, monkeypatch):
    """A real TLS listener with a self-signed certificate: the resolver must refuse it."""
    from certadillo.adcs.directory import DirectoryError, DirectoryResolver

    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", key, "-out", crt, "-subj", "/CN=localhost", "-days", "1"], check=True,
                   capture_output=True)
    port = 18636
    srv = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", str(port), "-cert", crt, "-key", key],
                           stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.6)
        monkeypatch.delenv("CERTADILLO_ADCS_LDAP_CACERT", raising=False)
        with pytest.raises(DirectoryError, match="CERTIFICATE_VERIFY_FAILED"):
            DirectoryResolver(f"ldaps://localhost:{port}", "u", "p", "DC=x").resolve_upn("a@bank.internal")
    finally:
        srv.kill()


# ------------------------------------------------------------------ key passphrase
def test_no_public_default_passphrase(tmp_path, monkeypatch):
    monkeypatch.delenv("CERTADILLO_KEY_PASSPHRASE", raising=False)
    s = Settings(data_dir=tmp_path)
    f = tmp_path / "key-passphrase"
    assert len(s.key_passphrase) >= 32 and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert Settings(data_dir=tmp_path).key_passphrase == s.key_passphrase
    for bad in ("change-me-dev-only", "replace-me", "short"):
        with pytest.raises(ValueError):
            Settings(data_dir=tmp_path / bad, key_passphrase=bad)


def test_old_data_dir_with_keys_but_no_passphrase_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("CERTADILLO_KEY_PASSPHRASE", raising=False)
    (tmp_path / "keys").mkdir()
    with pytest.raises(ValueError, match="old public"):
        Settings(data_dir=tmp_path)


# ------------------------------------------------------------------ CLI
def test_cli_refuses_to_send_the_key_without_tls(monkeypatch):
    from click.testing import CliRunner

    from certadillo.cli import main

    monkeypatch.delenv("CERTADILLO_ALLOW_HTTP", raising=False)
    env = {"CERTADILLO_API_KEY": "cdl_x"}
    r = CliRunner().invoke(main, ["cert", "request", "--server", "http://pki.bank.internal", "--cn", "a"], env=env)
    assert r.exit_code != 0 and "without TLS" in r.output


def test_cli_warns_when_the_key_is_on_the_command_line():
    from click.testing import CliRunner

    from certadillo.cli import main

    r = CliRunner().invoke(main, ["cert", "request", "--server", "http://pki.bank.internal", "--api-key", "cdl_x",
                                  "--cn", "a"])
    assert "process list" in r.output


def test_private_key_file_is_never_world_readable(tmp_path, monkeypatch):
    from certadillo import cli

    seen = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *a, **kw):
        fd = real_open(path, flags, mode, *a, **kw)
        if str(path).endswith(".key.tmp"):
            seen.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return fd

    monkeypatch.setattr(cli.os, "open", spy)
    old = os.umask(0o022)
    try:
        cli._write(tmp_path, b"-----BEGIN PRIVATE KEY-----\n", {"pem": "", "id": 1, "serial": "1",
                                                                 "not_before": "", "not_after": ""})
    finally:
        os.umask(old)
    assert seen == [0o600]
    assert stat.S_IMODE((tmp_path / "tls.key").stat().st_mode) == 0o600
