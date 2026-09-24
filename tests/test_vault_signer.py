"""CA keys in HashiCorp Vault Transit, tested against a real Vault.

The fixture starts `vault server -dev` when the vault binary is installed (CI
installs it) and skips otherwise. A fake would only test our own assumptions;
the details that break a Transit signer (PSS vs PKCS#1 v1.5, DER vs raw ECDSA
signatures, key versions, policy paths) are Vault's.
"""
from __future__ import annotations

import datetime as dt
import shutil
import socket
import subprocess
import time
import uuid

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fastapi.testclient import TestClient

from conftest import ADMIN, APPROVER, issue, make_settings, onboard

pytestmark = pytest.mark.skipif(shutil.which("vault") is None, reason="vault binary not installed")

ROOT_TOKEN = "certadillo-test-root"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vault():
    port = _free_port()
    addr = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(["vault", "server", "-dev", f"-dev-root-token-id={ROOT_TOKEN}",
                             f"-dev-listen-address=127.0.0.1:{port}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    h = {"X-Vault-Token": ROOT_TOKEN}
    for _ in range(100):
        try:
            if httpx.get(f"{addr}/v1/sys/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("vault dev server did not start")
    httpx.post(f"{addr}/v1/sys/mounts/transit", json={"type": "transit"}, headers=h).raise_for_status()
    yield addr
    proc.terminate()
    proc.wait(timeout=10)


def admin(vault, method, path, **kw):
    r = httpx.request(method, f"{vault}/v1/{path}", headers={"X-Vault-Token": ROOT_TOKEN}, **kw)
    r.raise_for_status()
    return r.json() if r.content else {}


def shipped_policy(filename, prefix):
    """The policy file we ship in deploy/vault, with the test's key prefix."""
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "deploy" / "vault" / filename).read_text()
    return text.replace("certadillo-", prefix)


def token_for(vault, prefix, filename):
    name = f"{prefix}{filename.split('.')[0]}"
    admin(vault, "PUT", f"sys/policies/acl/{name}", json={"policy": shipped_policy(filename, prefix)})
    return admin(vault, "POST", "auth/token/create", json={"policies": [name]})["auth"]["client_token"]


def vault_settings(tmp_path, vault, prefix, token=ROOT_TOKEN, **kw):
    return make_settings(tmp_path, signer="vault-transit", vault_addr=vault, vault_token=token,
                         vault_key_prefix=prefix, **kw)


def ca_pem(client, name):
    return x509.load_pem_x509_certificate(client.get(f"/pki/ca/{name}.pem").text.encode())


def verify_chain(leaf, issuer, root):
    leaf.verify_directly_issued_by(issuer)
    issuer.verify_directly_issued_by(root)


@pytest.fixture
def prefix():
    return f"t{uuid.uuid4().hex[:8]}-"


# --------------------------------------------------------------------------- fresh deployment
def test_ca_keys_live_in_vault_and_sign(tmp_path, vault, prefix):
    from certadillo.api.app import create_app
    from certadillo.db import CertificateAuthority, get_session

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False)) as c:
        root, sub = ca_pem(c, "root-ca"), ca_pem(c, "issuing-ca-1")
        for name, cert in (("root-ca", root), ("issuing-ca-1", sub)):
            info = admin(vault, "GET", f"transit/keys/{prefix}{name}")["data"]
            assert info["exportable"] is False and info["allow_plaintext_backup"] is False
            vault_pub = serialization.load_pem_public_key(info["keys"]["1"]["public_key"].encode())
            assert vault_pub.public_numbers() == cert.public_key().public_numbers()
        with get_session() as db:
            refs = {ca.name: (ca.key_ref, ca.signer_type) for ca in db.query(CertificateAuthority)}
        assert refs["issuing-ca-1"] == (f"vault-transit:{prefix}issuing-ca-1:1", "vault-transit")
        assert refs["root-ca"] == (f"vault-transit:{prefix}root-ca:1", "vault-transit")
        # no CA private key was ever written to disk
        assert not (tmp_path / "keys").exists() or not any((tmp_path / "keys").iterdir())

        _, h = onboard(c)
        _, cert = issue(c, h)
        verify_chain(x509.load_pem_x509_certificate(cert["pem"].encode()), sub, root)
        crl = x509.load_der_x509_crl(c.get("/pki/crl/issuing-ca-1.crl").content)
        assert crl.is_signature_valid(sub.public_key())


@pytest.mark.parametrize("alg", ["rsa-3072", "ec-p256", "ec-p384"])
def test_every_key_type_produces_valid_x509(vault, prefix, alg):
    from certadillo.crypto.signers import sign_x509
    from certadillo.crypto.vault import VaultClient
    from certadillo.crypto.vault_signer import VaultTransitKeyStore

    store = VaultTransitKeyStore(VaultClient(vault, token=ROOT_TOKEN), prefix=prefix)
    signer = store.generate(f"k-{alg}", alg)
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, alg)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(signer.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    cert = sign_x509(b, signer, hashes.SHA384())
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        assert cert.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSA_WITH_SHA384
    else:
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


# --------------------------------------------------------------------------- key lifecycle
def test_rotating_the_vault_key_does_not_break_the_ca(tmp_path, vault, prefix):
    from certadillo.api.app import create_app

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False)) as c:
        admin(vault, "POST", f"transit/keys/{prefix}issuing-ca-1/rotate")
        assert admin(vault, "GET", f"transit/keys/{prefix}issuing-ca-1")["data"]["latest_version"] == 2
        _, h = onboard(c)
        _, cert = issue(c, h)  # still signs with the pinned version 1
        x509.load_pem_x509_certificate(cert["pem"].encode()).verify_directly_issued_by(ca_pem(c, "issuing-ca-1"))


def test_a_replaced_vault_key_is_refused(tmp_path, vault, prefix):
    from certadillo.api.app import create_app

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False),
                    raise_server_exceptions=False) as c:
        _, h = onboard(c)
        # someone with Vault admin rights deletes the key and creates a new one under the same name
        key = f"{prefix}issuing-ca-1"
        admin(vault, "POST", f"transit/keys/{key}/config", json={"deletion_allowed": True})
        admin(vault, "DELETE", f"transit/keys/{key}")
        admin(vault, "POST", f"transit/keys/{key}", json={"type": "ecdsa-p384"})
        from certadillo.runtime import get_runtime

        get_runtime().keystore.store_for(f"vault-transit:{key}:1")._pubs.clear()  # as after a restart
        from conftest import make_csr

        _, csr = make_csr("api.pay.bank.internal", dns=["api.pay.bank.internal"])
        r = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
        assert r.status_code >= 500
        assert c.get("/api/v1/certificates?source=issued", headers=ADMIN).json() == []


def test_existing_key_name_is_not_adopted(vault, prefix):
    from certadillo.crypto.vault import VaultClient, VaultError
    from certadillo.crypto.vault_signer import VaultTransitKeyStore

    admin(vault, "POST", f"transit/keys/{prefix}planted", json={"type": "ecdsa-p384"})
    store = VaultTransitKeyStore(VaultClient(vault, token=ROOT_TOKEN), prefix=prefix)
    with pytest.raises(VaultError, match="already exists"):
        store.generate("planted")


# --------------------------------------------------------------------------- tokens and outages
def test_token_file_is_reread_on_every_call(tmp_path, vault, prefix):
    from certadillo.crypto.vault import VaultClient, VaultError
    from certadillo.crypto.vault_signer import VaultTransitKeyStore

    tok = tmp_path / "vault-token"
    tok.write_text(ROOT_TOKEN + "\n")
    store = VaultTransitKeyStore(VaultClient(vault, token_file=str(tok)), prefix=prefix)
    signer = store.generate("rotating-token")
    signer.sign(b"tbs", hashes.SHA384())
    tok.write_text("revoked-or-expired")  # Vault Agent would write a fresh one here
    with pytest.raises(VaultError) as e:
        signer.sign(b"tbs", hashes.SHA384())
    assert e.value.status == 403
    tok.write_text(ROOT_TOKEN)
    signer.sign(b"tbs", hashes.SHA384())


def test_vault_down_means_no_certificate(tmp_path, vault, prefix):
    from certadillo.api.app import create_app
    from certadillo.runtime import get_runtime

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False),
                    raise_server_exceptions=False) as c:
        _, h = onboard(c)
        store = get_runtime().keystore.store_for(f"vault-transit:{prefix}issuing-ca-1:1")
        store.client.addr = "http://127.0.0.1:9"  # nothing listens here
        from conftest import make_csr

        _, csr = make_csr("api.pay.bank.internal", dns=["api.pay.bank.internal"])
        assert c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).status_code >= 500
        store.client.addr = vault
        assert c.get("/api/v1/certificates?source=issued", headers=ADMIN).json() == []


# --------------------------------------------------------------------------- least privilege
def test_least_privilege_token_cannot_use_the_root_key(tmp_path, vault, prefix):
    """After a ceremony token creates the hierarchy, the application runs with a
    token that may sign only with issuing CA keys: the root is unusable from the
    application, so a compromised server cannot mint a new intermediate."""
    from certadillo.api.app import create_app
    from certadillo.crypto.vault import VaultError
    from certadillo.db import CertificateAuthority
    from certadillo.runtime import get_runtime

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False)):
        pass  # ceremony: root and issuing CA created with the admin token

    admin(vault, "PUT", f"sys/policies/acl/{prefix}app", json={"policy": shipped_policy("certadillo-app.hcl", prefix)})
    app_token = admin(vault, "POST", "auth/token/create", json={"policies": [f"{prefix}app"]})["auth"]["client_token"]

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix, token=app_token), background=False)) as c:
        _, h = onboard(c)
        _, cert = issue(c, h)  # issuing CA: allowed
        x509.load_pem_x509_certificate(cert["pem"].encode()).verify_directly_issued_by(ca_pem(c, "issuing-ca-1"))
        with get_runtime().platform() as p:
            root = p.s.query(CertificateAuthority).filter_by(name="root-ca").one()
            with pytest.raises(VaultError) as e:
                p.ca.create_subordinate(root, "rogue-intermediate")
            assert e.value.status == 403
            p.s.rollback()
        # nor can it rotate, reconfigure or export any key
        for path in (f"transit/keys/{prefix}issuing-ca-1/rotate", f"transit/keys/{prefix}issuing-ca-1/config"):
            r = httpx.post(f"{vault}/v1/{path}", headers={"X-Vault-Token": app_token}, json={"exportable": True})
            assert r.status_code == 403


# --------------------------------------------------------------------------- migration
def test_moving_a_software_deployment_to_vault(tmp_path, vault, prefix):
    """Old issuing CA keeps working from its file key; a new issuing CA created
    after the switch lives in Vault and takes over new issuance."""
    from certadillo.api.app import create_app

    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        _, h = onboard(c)
        _, old_cert = issue(c, h)

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False)) as c:
        r = c.post("/api/v1/cas", json={"name": "issuing-ca-2", "parent": "root-ca"}, headers=ADMIN)
        assert r.status_code == 202, r.text
        assert c.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
        info = admin(vault, "GET", f"transit/keys/{prefix}issuing-ca-2")["data"]
        assert info["exportable"] is False

        key = c.post("/api/v1/apps/1/credentials", headers=ADMIN).json()["api_key"]
        _, new_cert = issue(c, {"X-API-Key": key}, "web.pay.bank.internal")
        root, old_ca, new_ca = ca_pem(c, "root-ca"), ca_pem(c, "issuing-ca-1"), ca_pem(c, "issuing-ca-2")
        verify_chain(x509.load_pem_x509_certificate(new_cert["pem"].encode()), new_ca, root)
        verify_chain(x509.load_pem_x509_certificate(old_cert["pem"].encode()), old_ca, root)
        # the old CA still signs its CRL from the file key
        from certadillo.db import CertificateAuthority
        from certadillo.runtime import get_runtime

        with get_runtime().platform() as p:
            p.ca.generate_crl(p.s.query(CertificateAuthority).filter_by(name="issuing-ca-1").one())
            p.commit()
        assert x509.load_der_x509_crl(c.get("/pki/crl/issuing-ca-1.crl").content).is_signature_valid(
            old_ca.public_key())


# --------------------------------------------------------------------------- a misbehaving Vault
@pytest.mark.parametrize("reply", ["garbage-signature", "wrong-version"])
def test_signatures_are_checked_before_use(vault, prefix, reply):
    """A proxy or a compromised Vault that returns a signature from another key
    or version must not produce a certificate."""
    import base64

    from certadillo.crypto.vault import VaultClient, VaultError
    from certadillo.crypto.vault_signer import VaultTransitKeyStore

    store = VaultTransitKeyStore(VaultClient(vault, token=ROOT_TOKEN), prefix=prefix)
    signer = store.generate("checked")
    if reply == "garbage-signature":  # a well-formed signature from some other key
        other = ec.generate_private_key(ec.SECP384R1()).sign(b"tbs", ec.ECDSA(hashes.SHA384()))
        sig = f"vault:v1:{base64.b64encode(other).decode()}"
    else:  # a genuine signature that says it came from another key version
        real = admin(vault, "POST", f"transit/sign/{prefix}checked", json={
            "input": base64.b64encode(b"tbs").decode(), "hash_algorithm": "sha2-384",
            "marshaling_algorithm": "asn1", "key_version": 1})["data"]["signature"]
        sig = real.replace("vault:v1:", "vault:v2:")
    fake = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"data": {"signature": sig}})))
    store.client._http = fake
    with pytest.raises(VaultError, match="does not verify|expected v1"):
        signer.sign(b"tbs", hashes.SHA384())


# --------------------------------------------------------------------------- operator visibility
def _alert_rules(c):
    c.post("/api/v1/alerts/evaluate", headers=ADMIN)
    return {a["rule"]: a for a in c.get("/api/v1/alerts", headers=ADMIN).json()}


def test_key_made_exportable_raises_an_alert(tmp_path, vault, prefix):
    from certadillo.api.app import create_app

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix), background=False)) as c:
        assert all(r["ok"] for r in c.get("/api/v1/cas/keys", headers=ADMIN).json())
        assert "CAKeyUnhealthy" not in _alert_rules(c)
        admin(vault, "POST", f"transit/keys/{prefix}issuing-ca-1/config", json={"exportable": True})
        rows = {r["ca"]: r for r in c.get("/api/v1/cas/keys", headers=ADMIN).json()}
        assert "made exportable" in "; ".join(rows["issuing-ca-1"]["problems"])
        assert "exportable" in _alert_rules(c)["CAKeyUnhealthy"]["summary"]


def test_revoked_token_raises_an_alert(tmp_path, vault, prefix):
    from certadillo.api.app import create_app

    tok = admin(vault, "POST", "auth/token/create", json={"policies": ["root"]})["auth"]["client_token"]
    with TestClient(create_app(vault_settings(tmp_path, vault, prefix, token=tok), background=False)) as c:
        admin(vault, "POST", "auth/token/revoke", json={"token": tok})
        alert = _alert_rules(c)["CAKeyUnhealthy"]
        assert "403" in alert["summary"]


def test_software_deployment_reports_file_keys(client):
    rows = client.get("/api/v1/cas/keys", headers=ADMIN).json()
    assert {r["backend"] for r in rows} == {"file"} and all(r["ok"] for r in rows)


# --------------------------------------------------------------------------- key ceremony
def test_ceremony_creates_an_issuing_ca_the_app_could_not(tmp_path, vault, prefix, monkeypatch):
    from click.testing import CliRunner

    from certadillo.api.app import create_app
    from certadillo.cli import main
    from certadillo.config import reset_settings

    from certadillo.cli import ceremony_policy_hcl

    def policy_token(name, hcl):
        admin(vault, "PUT", f"sys/policies/acl/{prefix}{name}", json={"policy": hcl})
        return admin(vault, "POST", "auth/token/create", json={"policies": [f"{prefix}{name}"]})["auth"]["client_token"]

    init_keys = ["root-ca", "issuing-ca-1"]
    init_token = policy_token("init", ceremony_policy_hcl("transit", prefix, init_keys, init_keys))
    ceremony = policy_token("ceremony", ceremony_policy_hcl("transit", prefix, ["issuing-ca-2"],
                                                            ["root-ca", "issuing-ca-2"]))
    app_token = token_for(vault, prefix, "certadillo-app.hcl")
    with TestClient(create_app(vault_settings(tmp_path, vault, prefix, token=init_token), background=False)):
        pass  # the first hierarchy is created in a ceremony

    env = {"CERTADILLO_DATA_DIR": str(tmp_path), "CERTADILLO_SIGNER": "vault-transit",
           "CERTADILLO_VAULT_ADDR": vault, "CERTADILLO_VAULT_KEY_PREFIX": prefix,
           "CERTADILLO_BOOTSTRAP_ADMIN_KEY": "admin-key", "CERTADILLO_BASE_URL": "http://testserver"}
    args = ["ca", "create-issuing", "--name", "issuing-ca-2", "--operator", "alice", "--witness", "bob"]

    def run(token):
        for k, v in {**env, "CERTADILLO_VAULT_TOKEN": token}.items():
            monkeypatch.setenv(k, v)
        reset_settings()
        return CliRunner().invoke(main, args)

    denied = run(app_token)
    assert denied.exit_code != 0 and "403" in str(denied.exception)
    ok = run(ceremony)
    assert ok.exit_code == 0, ok.output
    reset_settings()
    # even the ceremony token cannot weaken any CA key
    for key in ("root-ca", "issuing-ca-1", "issuing-ca-2"):
        for op, body in (("rotate", None), ("config", {"exportable": True}), ("trim", {"min_available_version": 1})):
            r = httpx.post(f"{vault}/v1/transit/keys/{prefix}{key}/{op}", json=body,
                           headers={"X-Vault-Token": ceremony})
            assert r.status_code == 403, (key, op, r.status_code)

    with TestClient(create_app(vault_settings(tmp_path, vault, prefix, token=app_token), background=False)) as c:
        audit = c.get("/api/v1/audit?limit=50", headers=ADMIN).json()
        ev = next(e for e in audit if e["action"] == "ca.create" and e["target"] == "issuing-ca-2")
        assert ev["details"]["operator"] == "alice" and ev["details"]["witness"] == "bob"
        _, h = onboard(c)
        _, cert = issue(c, h)  # the application's own token signs with the new issuing key
        verify_chain(x509.load_pem_x509_certificate(cert["pem"].encode()), ca_pem(c, "issuing-ca-2"),
                     ca_pem(c, "root-ca"))


def test_witness_must_be_someone_else():
    from click.testing import CliRunner

    from certadillo.cli import main

    r = CliRunner().invoke(main, ["ca", "create-issuing", "--name", "x", "--operator", "Alice", "--witness", "alice"])
    assert r.exit_code != 0 and "different person" in r.output


# --------------------------------------------------------------------------- the shipped Vault Agent config
def test_shipped_agent_config_logs_in_and_gets_only_app_rights(tmp_path, vault, prefix):
    """Run the real deploy/vault/agent.hcl (paths pointed at a temp dir) with
    AppRole, and check the token it writes has exactly the app policy's rights."""
    from pathlib import Path

    try:
        admin(vault, "POST", "sys/auth/approle", json={"type": "approle"})
    except httpx.HTTPStatusError:
        pass  # enabled by an earlier test in this module
    policy = f"{prefix}certadillo-app"
    admin(vault, "PUT", f"sys/policies/acl/{policy}", json={"policy": shipped_policy("certadillo-app.hcl", prefix)})
    role = f"{prefix}role"
    admin(vault, "POST", f"auth/approle/role/{role}", json={"token_policies": [policy], "token_ttl": "10m"})
    role_id = admin(vault, "GET", f"auth/approle/role/{role}/role-id")["data"]["role_id"]
    secret_id = admin(vault, "POST", f"auth/approle/role/{role}/secret-id")["data"]["secret_id"]
    (tmp_path / "role-id").write_text(role_id)
    (tmp_path / "secret-id").write_text(secret_id)

    cfg = (Path(__file__).resolve().parent.parent / "deploy" / "vault" / "agent.hcl").read_text()
    cfg = (cfg.replace("https://vault.bank.internal:8200", vault)
              .replace("/etc/certadillo/vault-role-id", str(tmp_path / "role-id"))
              .replace("/etc/certadillo/vault-secret-id", str(tmp_path / "secret-id"))
              .replace("/run/certadillo/vault-token", str(tmp_path / "token")))
    (tmp_path / "agent.hcl").write_text(cfg)
    agent = subprocess.Popen(["vault", "agent", f"-config={tmp_path / 'agent.hcl'}"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if (tmp_path / "token").exists() and (tmp_path / "token").read_text().strip():
                break
            time.sleep(0.1)
        token = (tmp_path / "token").read_text().strip()
    finally:
        agent.terminate()
        agent.wait(timeout=10)
    assert token and not (tmp_path / "secret-id").exists()  # remove_secret_id_file_after_reading

    for name in ("issuing-ca-9", "root-ca-9"):
        admin(vault, "POST", f"transit/keys/{prefix}{name}", json={"type": "ecdsa-p384"})

    def call(method, path, **kw):
        return httpx.request(method, f"{vault}/v1/{path}", headers={"X-Vault-Token": token}, **kw).status_code

    body = {"input": "dGJz", "hash_algorithm": "sha2-384", "marshaling_algorithm": "asn1"}
    assert call("POST", f"transit/sign/{prefix}issuing-ca-9", json=body) == 200
    assert call("POST", f"transit/sign/{prefix}root-ca-9", json=body) == 403
    assert call("GET", f"transit/keys/{prefix}root-ca-9") == 200
    assert call("POST", f"transit/keys/{prefix}issuing-ca-9/rotate") == 403
    assert call("POST", f"transit/keys/{prefix}new-key", json={"type": "ecdsa-p384"}) == 403
