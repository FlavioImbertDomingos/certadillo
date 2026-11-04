"""SSH key management: the agent finds static keys, the server tracks where
each one opens a door, who owns it, and which need action."""
from __future__ import annotations

import os
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fastapi.testclient import TestClient

from certadillo.api.app import create_app, run_housekeeping
from certadillo.discovery.agent import parse_ssh_key_line, scan_ssh
from conftest import ADMIN, make_settings


def _pub(key, comment):
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode() + f" {comment}\n"


def _tree(tmp_path):
    shared = ed25519.Ed25519PrivateKey.generate()
    weak = rsa.generate_private_key(65537, 1024)
    homes = {u: tmp_path / "home" / u for u in ("alice", "deploy", "root")}
    for h in homes.values():
        (h / ".ssh").mkdir(parents=True)
    (homes["alice"] / ".ssh/authorized_keys").write_text(
        "# alice's laptop\n" + _pub(shared, "alice@laptop") + _pub(weak, "old-jenkins"))
    (homes["deploy"] / ".ssh/authorized_keys").write_text(_pub(shared, "alice@laptop"))
    root_ak = homes["root"] / ".ssh/authorized_keys"
    root_ak.write_text(_pub(ec.generate_private_key(ec.SECP256R1()), "break-glass")
                       + 'from="10.1.0.0/16",command="/usr/local/bin/backup --token s3cr3t",no-pty '
                       + _pub(ed25519.Ed25519PrivateKey.generate(), "backup"))
    old = time.time() - 400 * 86400
    os.utime(root_ak, (old, old))
    etc = tmp_path / "etc/ssh"
    (etc / "authorized_keys").mkdir(parents=True)
    (etc / "authorized_keys/ghost").write_text(_pub(ed25519.Ed25519PrivateKey.generate(), "left-the-bank"))
    (etc / "ssh_host_ed25519_key.pub").write_text(_pub(ed25519.Ed25519PrivateKey.generate(), "root@web1"))
    return {u: str(h) for u, h in homes.items()}, str(etc), weak


def test_agent_parses_keys_like_ssh_keygen(tmp_path):
    for t, bits in (("rsa", "3072"), ("ed25519", None), ("ecdsa", "521")):
        f = tmp_path / t
        subprocess.run(["ssh-keygen", "-q", "-t", t, "-N", "", "-f", str(f), "-C", "c"] + (["-b", bits] if bits else []),
                       check=True)
        size, fp = subprocess.run(["ssh-keygen", "-lf", f"{f}.pub"], capture_output=True, text=True,
                                  check=True).stdout.split()[:2]
        k = parse_ssh_key_line(open(f"{f}.pub").read())
        assert k["fingerprint"] == fp and k["bits"] == int(size)
    # a blob that claims a different type, and garbage, are skipped
    good = open(f"{tmp_path / 'ed25519'}.pub").read().split()
    assert parse_ssh_key_line(f"ssh-rsa {good[1]}") is None
    assert parse_ssh_key_line("ssh-ed25519 not-base64!!") is None


def test_inventory_findings_alerts_and_ownership(tmp_path):
    homes, etc, weak = _tree(tmp_path)
    keys = scan_ssh(homes, etc)
    # the command= value is not reported (it can carry secrets); the from= restriction is
    backup = next(k for k in keys if k["comment"] == "backup")
    assert backup["options"]["from"] == "10.1.0.0/16" and backup["options"]["command"] is True
    assert "s3cr3t" not in str(keys)

    with TestClient(create_app(make_settings(tmp_path / "srv"), background=False)) as c:
        agent_key = c.post("/api/v1/principals", json={"name": "agent-web1", "role": "agent"},
                           headers=ADMIN).json()["api_key"]
        agent = {"X-API-Key": agent_key}
        r = c.post("/api/v1/discovery/agent-report", headers=agent,
                   json={"host": "web1", "certificates": [], "key_files": [], "ssh_keys": keys})
        assert r.status_code == 200 and r.json()["ssh_keys"] == 7 and r.json()["new"] == 7
        assert c.get("/api/v1/ssh-keys", headers=agent).status_code == 403  # agents report, never read

        inv = c.get("/api/v1/ssh-keys", headers=ADMIN).json()
        assert {(k["account"], k["kind"]) for k in inv} >= {("alice", "authorized"), ("ghost", "authorized"),
                                                            (None, "host")}
        found = {}
        for f in c.get("/api/v1/discovery/findings", headers=ADMIN).json():
            found.setdefault(f["kind"], []).append(f)
        assert [f["detail"]["comment"] for f in found["ssh_weak_key"]] == ["old-jenkins"]
        assert found["ssh_shared_key"][0]["detail"]["authorized_for"] == ["alice@web1", "deploy@web1"]
        assert [f["detail"]["comment"] for f in found["ssh_root_unrestricted"]] == ["break-glass"]
        assert [f["detail"]["account"] for f in found["ssh_orphaned_key"]] == ["ghost"]
        assert sorted(f["detail"]["comment"] for f in found["ssh_rotation_due"]) == ["backup", "break-glass"]

        run_housekeeping()
        rules = {a["rule"] for a in c.get("/api/v1/alerts", headers=ADMIN).json()}
        assert {"SshKeyWeak", "SshKeyShared", "SshRootKeyUnrestricted", "SshKeyOrphaned",
                "SshKeyRotationDue"} <= rules

        # claiming a key claims it everywhere it appears
        shared_id = next(k["id"] for k in inv if k["account"] == "alice" and k["comment"] == "alice@laptop")
        r = c.put(f"/api/v1/ssh-keys/{shared_id}/owner", json={"owner": "team-payments", "note": "CHG0042"},
                  headers=ADMIN)
        assert r.status_code == 200
        owned = c.get("/api/v1/ssh-keys?owner=team-payments", headers=ADMIN).json()
        assert {k["account"] for k in owned} == {"alice", "deploy"}
        assert all(k["owner"] is None for k in c.get("/api/v1/ssh-keys?owner=none", headers=ADMIN).json())

        # the weak key is removed from alice's file: it is marked removed and its finding closes
        ak = os.path.join(homes["alice"], ".ssh/authorized_keys")
        with open(ak) as fh:
            lines = [ln for ln in fh if "old-jenkins" not in ln]
        with open(ak, "w") as fh:
            fh.writelines(lines)
        r = c.post("/api/v1/discovery/agent-report", headers=agent,
                   json={"host": "web1", "certificates": [], "key_files": [], "ssh_keys": scan_ssh(homes, etc)})
        assert r.json()["removed"] == 1
        open_kinds = {f["kind"] for f in c.get("/api/v1/discovery/findings", headers=ADMIN).json()}
        assert "ssh_weak_key" not in open_kinds
        removed = c.get("/api/v1/ssh-keys?status=removed", headers=ADMIN).json()
        assert [k["comment"] for k in removed] == ["old-jenkins"]

        # an older agent that does not send ssh_keys leaves the SSH inventory alone
        c.post("/api/v1/discovery/agent-report", headers=agent, json={"host": "web1", "certificates": [],
                                                                      "key_files": []})
        assert len(c.get("/api/v1/ssh-keys", headers=ADMIN).json()) == 6

        audit = [e["action"] for e in c.get("/api/v1/audit?limit=200", headers=ADMIN).json()]
        assert "discovery.agent.ssh_keys" in audit and "ssh_key.owner" in audit
