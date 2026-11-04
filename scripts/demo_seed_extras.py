"""Demo data for the features added after the first demo seed: the policy tree,
code signing, static SSH keys, a keycensus import, push provisioning targets
and audit findings. Safe to run again: anything already there is skipped.

    python scripts/demo_seed_extras.py --server http://localhost:8080 \
        --admin-key $ADMIN --approver-key $APPROVER
"""
from __future__ import annotations

import argparse
import hashlib
import time
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://localhost:8080")
    ap.add_argument("--admin-key", required=True)
    ap.add_argument("--approver-key", required=True)
    a = ap.parse_args()
    admin = httpx.Client(base_url=a.server, headers={"X-API-Key": a.admin_key}, timeout=60)
    approver = httpx.Client(base_url=a.server, headers={"X-API-Key": a.approver_key}, timeout=60)

    def ok(r, allow=()):
        if r.status_code >= 400 and r.status_code not in allow:
            raise SystemExit(f"{r.request.method} {r.request.url}: {r.status_code} {r.text}")
        return r.json() if r.content else {}

    def approve(approval_id, comment):
        ok(approver.post(f"/api/v1/approvals/{approval_id}/approve", json={"comment": comment}))

    apps = {x["name"]: x for x in ok(admin.get("/api/v1/apps"))}
    teams = {x["name"]: x["id"] for x in ok(admin.get("/api/v1/teams"))}

    # ---- the policy tree
    folders = {f["path"]: f for f in ok(admin.get("/api/v1/folders"))}

    def folder(name, parent_path, settings):
        path = (parent_path + "\\" if parent_path else "\\") + name
        if path in folders:
            return folders[path]["id"]
        body = {"name": name, "settings": settings}
        if parent_path:
            body["parent_id"] = folders[parent_path]["id"]
        r = ok(admin.post("/api/v1/folders", json=body))
        if r.get("approval_id"):
            approve(r["approval_id"], "Policy board PB-114")
        folders.update({f["path"]: f for f in ok(admin.get("/api/v1/folders"))})
        return folders[path]["id"]

    folder("Bank", None, {"allowed_zones": {"value": ["bank.internal"], "locked": True},
                          "rsa_min_bits": {"value": 3072, "locked": True},
                          "max_validity_days": {"value": 200}})
    pay = folder("Payments", "\\Bank", {"max_validity_days": {"value": 90}})
    folder("Cards", "\\Bank\\Payments", {"max_validity_days": {"value": 30, "locked": True},
                                         "dual_control": {"value": True, "locked": True}})
    digital = folder("Digital", "\\Bank", {"ec_curves": {"value": ["secp256r1", "secp384r1"]}})
    for app_name, fid in (("ledger-core", pay), ("online-banking-web", digital)):
        app = apps.get(app_name)
        if app and app.get("folder_id") != fid:
            r = ok(admin.post(f"/api/v1/apps/{app['id']}/move", json={"folder_id": fid}), allow=(400,))
            if r.get("approval_id"):
                approve(r["approval_id"], "Moved under the policy tree")

    # ---- code signing
    if "release-bot" not in apps and "platform-security" in teams:
        r = ok(admin.post("/api/v1/apps", json={"team_id": teams["platform-security"], "name": "release-bot",
                                                "environment": "test", "profile": "tls-client",
                                                "allowed_domains": ["*.ci.bank.internal"]}))
        if r.get("approval_id"):
            approve(r["approval_id"], "CI signing pipeline")
        apps["release-bot"] = r
    bot_id = apps["release-bot"]["id"]
    keys = {k["name"] for k in ok(admin.get("/api/v1/signing/keys"))}
    for name, purpose in (("payments-release", "release"), ("ci-snapshots", "test")):
        if name not in keys:
            r = ok(admin.post("/api/v1/signing/keys", json={"name": name, "app_id": bot_id, "purpose": purpose}))
            approve(r["approval_id"], "Signing key ceremony SK-7")
    if not ok(admin.get("/api/v1/signing/requests")):
        bot_key = ok(admin.post(f"/api/v1/apps/{bot_id}/credentials"))["api_key"]
        bot = httpx.Client(base_url=a.server, headers={"X-API-Key": bot_key}, timeout=60)
        for v in ("2.4.0", "2.4.1"):
            data = f"payments-api-{v}.tar.gz".encode() * 100
            ok(bot.post("/api/v1/signing/sign", json={"key": "ci-snapshots", "digest": hashlib.sha256(data).hexdigest(),
                                                      "artifact": {"name": f"payments-api-{v}.tar.gz", "version": v}}))
        r = ok(bot.post("/api/v1/signing/sign", json={
            "key": "payments-release", "digest_alg": "sha384", "digest": hashlib.sha384(b"3.0.0").hexdigest(),
            "artifact": {"name": "payments-api-3.0.0.tar.gz", "version": "3.0.0", "commit": "8a925e3"}}))
        approve(r["approval_id"], "Release 3.0.0, CHG0087")
        ok(bot.post("/api/v1/signing/sign", json={
            "key": "payments-release", "digest_alg": "sha384", "digest": hashlib.sha384(b"3.0.1").hexdigest(),
            "artifact": {"name": "payments-api-3.0.1.tar.gz", "version": "3.0.1"}}))  # left waiting

    # ---- static SSH keys from a host agent
    if not ok(admin.get("/api/v1/ssh-keys")):
        def k(key, comment):
            pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                serialization.PublicFormat.OpenSSH).decode().split()
            raw = __import__("base64").b64decode(pub[1])
            fp = "SHA256:" + __import__("base64").b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            bits = key.key_size if isinstance(key, rsa.RSAPrivateKey) else (256 if pub[0] == "ssh-ed25519" else 256)
            return {"key_type": pub[0], "bits": bits, "fingerprint": fp, "comment": comment}

        shared = k(ed25519.Ed25519PrivateKey.generate(), "deploy@jenkins-01")
        old = int(time.time() - 500 * 86400)
        for host in ("app01.pay.bank.internal", "app02.pay.bank.internal"):
            report = [
                {**shared, "kind": "authorized", "path": "/home/deploy/.ssh/authorized_keys", "user": "deploy",
                 "user_exists": True, "options": {}, "file_mtime": old},
                {**k(rsa.generate_private_key(65537, 1024), "legacy-backup"), "kind": "authorized",
                 "path": "/root/.ssh/authorized_keys", "user": "root", "user_exists": True, "options": {},
                 "file_mtime": old},
                {**k(ed25519.Ed25519PrivateKey.generate(), "ansible@ctrl"), "kind": "authorized",
                 "path": "/home/ansible/.ssh/authorized_keys", "user": "ansible", "user_exists": True,
                 "options": {"from": "10.20.0.0/16"}, "file_mtime": int(time.time() - 30 * 86400)},
                {**k(ed25519.Ed25519PrivateKey.generate(), f"root@{host.split('.')[0]}"), "kind": "host",
                 "path": "/etc/ssh/ssh_host_ed25519_key.pub", "user": None, "user_exists": True, "options": {},
                 "file_mtime": int(time.time() - 200 * 86400)},
            ]
            if host.startswith("app02"):
                report.append({**k(ed25519.Ed25519PrivateKey.generate(), "jsmith@laptop"), "kind": "authorized",
                               "path": "/etc/ssh/authorized_keys/jsmith", "user": "jsmith", "user_exists": False,
                               "options": {}, "file_mtime": old})
            ok(admin.post("/api/v1/discovery/agent-report", json={"host": host, "certificates": [], "key_files": [
                {"path": "/opt/legacy/server.key", "mode": "0o644", "owner": "root", "world_readable": True}]
                if host.startswith("app02") else [], "ssh_keys": report}))
        ansible = [x for x in ok(admin.get("/api/v1/ssh-keys")) if x["comment"] == "ansible@ctrl"]
        if ansible:
            ok(admin.put(f"/api/v1/ssh-keys/{ansible[0]['id']}/owner", json={"owner": "platform-automation"}))

    # ---- keycensus: HSM and KMS keys and the applications that use them
    if not ok(admin.get("/api/v1/inventory/external")):
        now = datetime.now(timezone.utc)
        shadow_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "payments-partner.bank.internal")])
        shadow = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(shadow_key.public_key())
                  .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=10))
                  .not_valid_after(now + timedelta(days=355)).sign(shadow_key, hashes.SHA256()))
        doc = {"tool": "keycensus", "generated_at": now.isoformat(), "assets": [
            {"id": "kc-3f1a9c02b7d1", "kind": "key", "name": "pin-translation-zmk", "source": "prod-hsm",
             "source_type": "pkcs11", "algorithm": "AES", "key_size": 256, "location": "Luna slot 2 / payments",
             "state": "active", "hardware_backed": True, "exportable": False, "applications": ["card-auth-api"]},
            {"id": "kc-8b02e7a14c55", "kind": "key", "name": "alias/ledger-db-cmk", "source": "aws-prod",
             "source_type": "aws-kms", "algorithm": "AES", "key_size": 256, "location": "us-east-1",
             "state": "active", "hardware_backed": True, "applications": ["ledger-core"],
             "used_by": [{"type": "principal", "id": "arn:aws:iam::111122223333:role/ledger", "via": "iam-policy"}]},
            {"id": "kc-c41d0e9f3a77", "kind": "key", "name": "transit/payments-token", "source": "vault",
             "source_type": "vault", "algorithm": "RSA", "key_size": 2048, "location": "transit/",
             "state": "active", "applications": ["card-auth-api", "payments-mesh"]},
            {"id": "kc-5e7790aa0b13", "kind": "certificate", "name": "payments-partner.bank.internal",
             "source": "dmz-files", "source_type": "pem", "location": "/opt/partner/tls/partner.pem",
             "fingerprint_sha256": shadow.fingerprint(hashes.SHA256()).hex(), "expires": shadow.not_valid_after_utc.isoformat(),
             "applications": ["online-banking-web"]},
        ]}
        ok(admin.post("/api/v1/inventory/keycensus", content=__import__("json").dumps(doc)))

    # ---- push provisioning targets (left unrun: the demo hosts do not exist)
    if not ok(admin.get("/api/v1/targets")) and "payments-platform" in teams:
        hk = "ssh-ed25519 " + __import__("base64").b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"\x11" * 32).decode()
        t = ok(admin.post("/api/v1/targets", json={
            "name": "web1-nginx", "kind": "ssh", "team_id": teams["payments-platform"],
            "config": {"host": "web1.pay.bank.internal", "username": "certadillo", "host_key": hk,
                       "allowed_dirs": ["/etc/nginx/tls"], "reload_command": "sudo systemctl reload nginx"},
            "credential_ref": "vault:secret/data/certadillo/web1#ssh_key"}))
        ok(admin.post("/api/v1/targets", json={
            "name": "bigip-dc1", "kind": "f5", "team_id": teams["payments-platform"],
            "config": {"host": "https://bigip-dc1.bank.internal", "username": "certadillo", "partition": "Payments"},
            "credential_ref": "vault:secret/data/certadillo/bigip-dc1#password"}))
        ledger = apps.get("ledger-core")
        if ledger:
            ok(admin.post("/api/v1/installations", json={
                "app_id": ledger["id"], "target_id": t["id"], "common_name": "ledger.bank.internal",
                "key_location": "device", "params": {"cert_path": "/etc/nginx/tls/ledger.crt",
                                                     "key_path": "/etc/nginx/tls/ledger.key"},
                "validate_endpoint": "web1.pay.bank.internal:443", "auto_renew": False}), allow=(400, 403))

    print(ok(admin.post("/api/v1/alerts/evaluate")))


if __name__ == "__main__":
    main()
