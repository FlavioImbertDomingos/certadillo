"""deploy/server/backup.sh and restore.sh, with docker stubbed out and the real
age: backups are encrypted to the recipients, plaintext never stays on disk,
and a restore refuses a backup whose contents do not match its manifest."""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("age") is None, reason="age not installed")

DOCKER_STUB = r"""#!/usr/bin/env bash
# records every call; plays pg_dump, tar and pg_restore with canned data
echo "$*" >> "$STUB_LOG"
case "$*" in
  *pg_dump*) printf 'PGDMP fake dump\n' ;;
  *"tar -C /var/lib/certadillo -cf -"*) tar -C "$STUB_DATA" -cf - . ;;
  *pg_restore*) cat > "$STUB_DIR/restored.dump" ;;
  *"tar -C /data -xf -"*) cat > "$STUB_DIR/restored-data.tar" ;;
esac
"""


@pytest.fixture
def env(tmp_path):
    app = tmp_path / "opt"
    (app / "releases" / "abc1234").mkdir(parents=True)
    (app / "app").symlink_to(app / "releases" / "abc1234")
    data = tmp_path / "volume"
    (data / "keys").mkdir(parents=True)
    (data / "keys" / "issuing-ca-1.key.pem").write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\n...\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(DOCKER_STUB)
    (bin_dir / "docker").chmod(0o755)
    for name in ("curl",):  # restore waits for /healthz
        (bin_dir / name).write_text("#!/bin/sh\necho ok\n")
        (bin_dir / name).chmod(0o755)
    ids = []
    for i in range(2):
        key = tmp_path / f"id{i}.txt"
        subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
        ids.append((key, next(ln.split(": ")[1] for ln in key.read_text().splitlines() if "public key" in ln)))
    (app / ".env").write_text(f"POSTGRES_PASSWORD=x\nBACKUP_AGE_RECIPIENTS={ids[0][1]}, {ids[1][1]}\nBACKUP_KEEP=2\n")
    e = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "APP_DIR": str(app), "STUB_LOG": str(tmp_path / "log"),
         "STUB_DATA": str(data), "STUB_DIR": str(tmp_path), "TMPDIR": str(tmp_path / "tmp")}
    (tmp_path / "tmp").mkdir()
    return {"app": app, "ids": ids, "env": e, "tmp": tmp_path}


def _backup(env):
    r = subprocess.run(["bash", str(ROOT / "deploy/server/backup.sh")], env=env["env"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return sorted((env["app"] / "backups").glob("certadillo-*.tar.age"))


def test_backup_is_encrypted_to_every_recipient(env):
    out = _backup(env)[-1]
    assert out.read_bytes().startswith(b"age-encryption.org/v1")
    assert b"PGDMP" not in out.read_bytes() and b"PRIVATE KEY" not in out.read_bytes()
    assert (env["app"] / "backups").stat().st_mode & 0o077 == 0
    assert not any((env["tmp"] / "tmp").iterdir())  # the plaintext staging directory is gone
    for key, _ in env["ids"]:  # either private key opens it
        plain = env["tmp"] / f"plain-{key.stem}.tar"
        subprocess.run(["age", "-d", "-i", str(key), "-o", str(plain), str(out)], check=True)
        with tarfile.open(plain) as t:
            assert sorted(t.getnames()) == ["MANIFEST", "data.tar", "db.dump"]
            manifest = t.extractfile("MANIFEST").read().decode()
        assert "revision=abc1234" in manifest and "db.dump" in manifest


def test_retention_and_copy_off_host(env):
    env["env"]["BACKUP_COPY_CMD"] = f"cp {{}} {env['tmp']}/offsite/"
    (env["tmp"] / "offsite").mkdir()
    for _ in range(3):
        _backup(env)
        subprocess.run(["sleep", "1.1"])
    assert len(list((env["app"] / "backups").glob("*.tar.age"))) == 2  # BACKUP_KEEP=2
    assert len(list((env["tmp"] / "offsite").glob("*.tar.age"))) == 3


def test_refuses_without_recipients_or_with_a_bad_key(env):
    (env["app"] / ".env").write_text("POSTGRES_PASSWORD=x\n")
    r = subprocess.run(["bash", str(ROOT / "deploy/server/backup.sh")], env=env["env"], capture_output=True, text=True)
    assert r.returncode != 0 and "BACKUP_AGE_RECIPIENTS" in r.stderr
    env["env"]["BACKUP_AGE_RECIPIENTS"] = "ssh-rsa AAAA"
    r = subprocess.run(["bash", str(ROOT / "deploy/server/backup.sh")], env=env["env"], capture_output=True, text=True)
    assert r.returncode != 0 and "not an age public key" in r.stderr


def test_restore_checks_the_manifest(env):
    out = _backup(env)[-1]
    key = env["ids"][0][0]
    plain = subprocess.run(["age", "-d", "-i", str(key), str(out)], check=True, capture_output=True).stdout
    restore = str(ROOT / "deploy/server/restore.sh")
    (env["app"] / ".env").write_text("POSTGRES_PASSWORD=x\n")
    r = subprocess.run(["bash", restore], input=plain, env=env["env"], capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    assert (env["tmp"] / "restored.dump").read_bytes() == b"PGDMP fake dump\n"
    log = (env["tmp"] / "log").read_text()
    assert "stop certadillo" in log and "start certadillo" in log

    # a backup whose database dump was swapped does not match its manifest
    src = env["tmp"] / "x"
    src.mkdir()
    with tarfile.open(fileobj=__import__("io").BytesIO(plain)) as t:
        t.extractall(src, filter="data")
    (src / "db.dump").write_bytes(b"PGDMP something else\n")
    bad = env["tmp"] / "bad.tar"
    with tarfile.open(bad, "w") as t:
        for n in ("MANIFEST", "db.dump", "data.tar"):
            t.add(src / n, arcname=n)
    (env["tmp"] / "restored.dump").unlink()
    r = subprocess.run(["bash", restore], input=bad.read_bytes(), env=env["env"], capture_output=True)
    assert r.returncode != 0 and b"manifest hashes do not match" in r.stderr
    assert not (env["tmp"] / "restored.dump").exists()
