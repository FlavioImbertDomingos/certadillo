"""P1 hardening from docs/THREAT_MODEL.md.

Each test plays a database-only attacker: someone who can run SQL against the
Certadillo database but cannot run code inside the application. The attack is
done with raw SQL, the way that attacker would do it, and the test checks the
control that stops or exposes it.
"""
from __future__ import annotations

import json

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from conftest import ADMIN, APPROVER, issue, make_csr, make_settings, onboard
from certadillo.db import get_session
from certadillo.services import hash_key


def sql(stmt, **params):
    with get_session() as s:
        s.execute(text(stmt), params)
        s.commit()


def cas(client):
    return x509.load_pem_x509_certificate(client.get("/pki/ca/issuing-ca-1.pem").text.encode())


def ocsp_status(client, leaf, issuer):
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    r = client.post("/pki/ocsp", content=req.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"})
    return ocsp.load_der_ocsp_response(r.content).certificate_status


def regenerate_crl(client):
    from certadillo.db import CertificateAuthority
    from certadillo.runtime import get_runtime

    with get_runtime().platform() as p:
        p.ca.generate_crl(p.s.query(CertificateAuthority).filter_by(name="issuing-ca-1").one())
        p.commit()
    return x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)


def rules(client):
    client.post("/api/v1/alerts/evaluate", headers=ADMIN)
    return {a["rule"] for a in client.get("/api/v1/alerts", headers=ADMIN).json()}


# =========================================================================== seals: principals
def test_rogue_admin_inserted_in_sql_cannot_log_in(client):
    raw = "cdl_attacker-chosen-key"
    sql("INSERT INTO principals (name, role, key_hash, active, created_by, created_at) "
        "VALUES ('backdoor', 'admin', :h, 1, 'system', CURRENT_TIMESTAMP)", h=hash_key(raw))
    assert client.get("/api/v1/teams", headers={"X-API-Key": raw}).status_code == 401
    scan = client.get("/api/v1/integrity", headers=ADMIN).json()
    assert not scan["ok"] and any(p["label"] == "backdoor" for p in scan["problems"])
    assert "IntegritySealBroken" in rules(client)


def test_role_escalation_in_sql_locks_the_principal_out(client):
    key = client.post("/api/v1/principals", json={"name": "viewer", "role": "auditor"}, headers=ADMIN).json()["api_key"]
    assert client.get("/api/v1/teams", headers={"X-API-Key": key}).status_code == 200
    sql("UPDATE principals SET role = 'admin' WHERE name = 'viewer'")
    assert client.get("/api/v1/teams", headers={"X-API-Key": key}).status_code == 401


# =========================================================================== seals: certificate status
def test_unrevoke_in_sql_still_reads_revoked(client):
    _, h = onboard(client)
    _, cert = issue(client, h)
    leaf, sub = x509.load_pem_x509_certificate(cert["pem"].encode()), cas(client)
    client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
    sql("UPDATE certificates SET status = 'active', revoked_at = NULL, revocation_reason = NULL WHERE id = :i",
        i=cert["id"])
    assert ocsp_status(client, leaf, sub) == ocsp.OCSPCertStatus.REVOKED
    assert regenerate_crl(client).get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
    assert "IntegritySealBroken" in rules(client)


def test_restoring_an_old_sealed_copy_is_caught_by_the_audit_trail(client):
    """Rollback: the attacker saved the row (and its valid seal) before the
    revocation and puts that copy back. The seal verifies; the audit trail does not agree."""
    _, h = onboard(client)
    _, cert = issue(client, h)
    leaf, sub = x509.load_pem_x509_certificate(cert["pem"].encode()), cas(client)
    with get_session() as s:
        old = s.execute(text("SELECT status, seal FROM certificates WHERE id = :i"), {"i": cert["id"]}).one()
    client.post(f"/api/v1/certificates/{cert['id']}/revoke", json={"reason": "key_compromise"}, headers=h)
    sql("UPDATE certificates SET status = :st, seal = :se, revoked_at = NULL, revocation_reason = NULL "
        "WHERE id = :i", st=old.status, se=old.seal, i=cert["id"])
    assert ocsp_status(client, leaf, sub) == ocsp.OCSPCertStatus.REVOKED
    assert regenerate_crl(client).get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
    problems = [p for p in client.get("/api/v1/integrity", headers=ADMIN).json()["problems"]
                if p["kind"] == "certificate" and p["id"] == cert["id"]]
    # the restored seal is genuine; only the audit cross-check catches the rollback
    assert [p["problem"] for p in problems] == ["status is active but the audit trail records its revocation"]


def test_a_later_update_does_not_launder_a_tampered_row(client):
    _, h = onboard(client)
    other_app, _ = onboard(client, "other-app", domains=["*.other.bank.internal"])
    _, cert = issue(client, h)
    # the attacker quietly moves an active certificate to another app (nothing
    # in the audit trail contradicts this, so only the seal can catch it)
    sql("UPDATE certificates SET app_id = :a WHERE id = :i", a=other_app, i=cert["id"])
    # an ordinary application write to the same row afterwards
    from certadillo.db import Certificate
    from certadillo.runtime import get_runtime

    with get_runtime().platform() as p:
        p.s.get(Certificate, cert["id"]).location = "lb-01"
        p.commit()
    problems = client.get("/api/v1/integrity", headers=ADMIN).json()["problems"]
    assert any(p["kind"] == "certificate" and p["id"] == cert["id"] for p in problems)


def test_normal_operations_leave_every_seal_valid(client):
    _, h = onboard(client)
    _, cert = issue(client, h)
    _, csr = make_csr("api.pay.bank.internal", dns=["api.pay.bank.internal"])
    client.post(f"/api/v1/certificates/{cert['id']}/renew", json={"csr_pem": csr}, headers=h)
    _, c2 = issue(client, h, "web.pay.bank.internal")
    client.post(f"/api/v1/certificates/{c2['id']}/revoke", json={"reason": "superseded"}, headers=h)
    assert client.get("/api/v1/integrity", headers=ADMIN).json() == {"ok": True, "problems": []}


# =========================================================================== seals: approvals
def test_tampered_approval_cannot_be_decided(client):
    _, h = onboard(client, "signer", profile="code-signing", domains=["signer.bank.internal"])
    key = ec.generate_private_key(ec.SECP384R1())
    _, csr = make_csr("release-signer", key=key)
    appr = client.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).json()["approval_id"]
    # the attacker swaps the CSR in the pending request for one of their own
    _, evil = make_csr("attacker-signer", key=ec.generate_private_key(ec.SECP384R1()))
    with get_session() as s:
        payload = json.loads(s.execute(text("SELECT payload FROM approvals WHERE id = :i"), {"i": appr}).scalar())
    payload["csr_pem"] = evil
    sql("UPDATE approvals SET payload = :p WHERE id = :i", p=json.dumps(payload), i=appr)
    r = client.post(f"/api/v1/approvals/{appr}/approve", headers=APPROVER)
    assert r.status_code == 403 and "integrity" in r.text


# =========================================================================== seal backfill and key rotation
def test_backfill_seals_legacy_rows_then_enforces(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo import integrity
    from certadillo.api.app import create_app

    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, background=False)) as c:
        onboard(c)
    # simulate a database from before sealing existed: no seals, no marker
    sql("UPDATE principals SET seal = NULL")
    (tmp_path / integrity.MARKER).unlink()
    integrity.reset()
    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        assert c.get("/api/v1/integrity", headers=ADMIN).json()["ok"]
        assert c.get("/api/v1/teams", headers=ADMIN).status_code == 200
        # after the one-time backfill, a missing seal counts as tampering
        sql("UPDATE principals SET seal = NULL WHERE name = 'bootstrap-admin'")
        assert c.get("/api/v1/teams", headers=ADMIN).status_code == 401


def test_seal_key_rotation(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo.api.app import create_app

    old, new = "11" * 32, "22" * 32
    with TestClient(create_app(make_settings(tmp_path, seal_key=old), background=False)) as c:
        onboard(c)
    with TestClient(create_app(make_settings(tmp_path, seal_key=new, seal_key_previous=old),
                               background=False)) as c:
        from certadillo import integrity
        from certadillo.runtime import get_runtime

        with get_runtime().platform() as p:
            res = integrity.reseal_all(p.s)
            p.commit()
        assert res["broken"] == 0 and res["resealed"] > 0
    with TestClient(create_app(make_settings(tmp_path, seal_key=new), background=False)) as c:
        assert c.get("/api/v1/integrity", headers=ADMIN).json()["ok"]


# =========================================================================== append-only audit and anchors
def test_audit_rows_cannot_be_updated_or_deleted(client):
    onboard(client)
    with pytest.raises(IntegrityError):
        sql("UPDATE audit_events SET actor = 'nobody'")
    with pytest.raises(IntegrityError):
        sql("DELETE FROM audit_events")


def test_rewritten_history_fails_against_saved_anchors(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo.api.app import create_app
    from certadillo.audit.log import GENESIS, _digest, load_anchors, verify_against_anchors
    from certadillo.db import AuditEvent

    anchors = tmp_path / "anchors.jsonl"
    with TestClient(create_app(make_settings(tmp_path, audit_anchor_file=str(anchors)), background=False)) as c:
        onboard(c)
        r = c.post("/api/v1/audit/anchor", headers=ADMIN)
        assert r.status_code == 200 and r.json()["sinks"] == ["file"]
        with get_session() as s:
            assert verify_against_anchors(s, load_anchors(str(anchors)))["valid"]

        # a DB owner drops the guard, edits an old event and recomputes every hash
        sql("DROP TRIGGER audit_events_no_update")
        with get_session() as s:
            prev = GENESIS
            for ev in s.query(AuditEvent).order_by(AuditEvent.id):
                if ev.id == 2:
                    ev.details = {**ev.details, "rewritten": True}
                ev.prev_hash = prev
                ev.hash = _digest(prev, ev.ts, ev.actor, ev.action, ev.target, ev.details)
                prev = ev.hash
            s.commit()
        assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["valid"]  # the chain alone is fooled
        with get_session() as s:
            res = verify_against_anchors(s, load_anchors(str(anchors)))
        assert not res["valid"] and res["mismatches"]
        assert "AuditAnchorMismatch" in rules(c)


def test_forged_anchor_is_rejected(client, tmp_path):
    from certadillo.audit.log import verify_against_anchors

    onboard(client)
    head = client.get("/api/v1/audit/head", headers=ADMIN).json()
    forged = {**head, "hash": "0" * 64}
    with get_session() as s:
        assert verify_against_anchors(s, [head])["valid"]
        assert verify_against_anchors(s, [forged])["mismatches"][0]["problem"] == "anchor MAC does not verify"


def test_anchor_posts_to_url(tmp_path):
    from certadillo.audit import log as audit_log
    from certadillo.runtime import get_runtime

    from fastapi.testclient import TestClient
    from certadillo.api.app import create_app

    got = []
    transport = httpx.MockTransport(lambda req: (got.append(json.loads(req.content)), httpx.Response(204))[1])
    settings = make_settings(tmp_path, audit_anchor_url="https://anchors.example/in")
    with TestClient(create_app(settings, background=False)) as c:
        onboard(c)
        audit_log._last_anchor["at"] = None
        with get_runtime().platform() as p:
            a = audit_log.maybe_anchor(p.s, settings, http=httpx.Client(transport=transport))
            p.commit()
    assert a is not None and got and got[0]["hash"] == a["hash"] and got[0]["mac"]


# =========================================================================== field encryption
def test_secret_columns_are_encrypted_at_rest(client):
    app_id, _ = onboard(client)
    client.post(f"/api/v1/apps/{app_id}/acme-eab", headers=ADMIN)
    client.post(f"/api/v1/apps/{app_id}/cmp-secret", headers=ADMIN)
    client.post("/api/v1/teams", json={"name": "t-hook", "contact_email": "t@e.com",
                                       "webhook_url": "https://hooks.slack.com/services/T0/B0/secret"}, headers=ADMIN)
    with get_session() as s:
        eab = s.execute(text("SELECT hmac_key_b64, hmac_key_enc FROM acme_eab")).one()
        cmp_ = s.execute(text("SELECT secret_enc FROM cmp_secrets")).scalar()
        team = s.execute(text("SELECT webhook_url, webhook_enc FROM teams WHERE name = 't-hook'")).one()
    assert eab.hmac_key_b64 == "" and eab.hmac_key_enc.startswith("enc:v1:local:")
    assert cmp_.startswith("enc:v1:local:")
    assert team.webhook_url is None and "secret" not in team.webhook_enc


def test_legacy_plaintext_secrets_are_encrypted_at_startup(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo.api.app import create_app

    with TestClient(create_app(make_settings(tmp_path), background=False)) as c:
        app_id, _ = onboard(c)
        team = c.post("/api/v1/teams", json={"name": "legacy", "contact_email": "l@e.com"}, headers=ADMIN).json()["id"]
    sql("INSERT INTO acme_eab (kid, hmac_key_b64, app_id, used, created_at) "
        "VALUES ('eab_legacy', 'bGVnYWN5LWtleQ', :a, 0, CURRENT_TIMESTAMP)", a=app_id)
    sql("UPDATE teams SET webhook_url = 'https://hooks.example/legacy' WHERE id = :t", t=team)
    with TestClient(create_app(make_settings(tmp_path), background=False)):
        with get_session() as s:
            eab = s.execute(text("SELECT hmac_key_b64, hmac_key_enc FROM acme_eab WHERE kid='eab_legacy'")).one()
            t = s.execute(text("SELECT webhook_url, webhook_enc FROM teams WHERE id = :t"), {"t": team}).one()
        assert eab.hmac_key_b64 == "" and eab.hmac_key_enc.startswith("enc:v1:")
        assert t.webhook_url is None and t.webhook_enc.startswith("enc:v1:")
        from certadillo.crypto.fieldcipher import get_cipher
        from certadillo.runtime import get_runtime

        assert get_cipher(get_runtime().settings).decrypt_str(eab.hmac_key_enc) == "bGVnYWN5LWtleQ"


def _fake_vault():
    """Vault Transit stand-in: 'encrypts' by base64-wrapping, and records calls."""
    calls = []

    def handler(req):
        body = json.loads(req.content)
        calls.append((req.url.path, req.headers.get("X-Vault-Token")))
        if req.url.path.endswith("/encrypt/certadillo-fields"):
            return httpx.Response(200, json={"data": {"ciphertext": "vault:v1:" + body["plaintext"]}})
        if req.url.path.endswith("/decrypt/certadillo-fields"):
            return httpx.Response(200, json={"data": {"plaintext": body["ciphertext"].split(":", 2)[2]}})
        return httpx.Response(403, json={"errors": ["permission denied"]})
    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_vault_transit_cipher_roundtrip(tmp_path):
    from certadillo.crypto.fieldcipher import FieldCipher

    http, calls = _fake_vault()
    settings = make_settings(tmp_path, field_cipher="vault", vault_addr="https://vault.bank.internal:8200",
                             vault_token="s.test")
    c = FieldCipher(settings, http=http)
    ct = c.encrypt("hmac-key-material")
    assert ct.startswith("enc:v1:vault:certadillo-fields:vault:v1:")
    assert c.decrypt_str(ct) == "hmac-key-material"
    assert calls[0] == ("/v1/transit/encrypt/certadillo-fields", "s.test")


def test_vault_errors_fail_closed(tmp_path):
    from certadillo.crypto.fieldcipher import CipherError, FieldCipher

    http = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(503)))
    settings = make_settings(tmp_path, field_cipher="vault", vault_addr="https://vault.bank.internal:8200",
                             vault_token="s.test")
    with pytest.raises(CipherError):
        FieldCipher(settings, http=http).encrypt("x")
    with pytest.raises(CipherError):
        FieldCipher(make_settings(tmp_path, field_cipher="vault"))  # no address or token


# =========================================================================== name constraints
def test_issuing_ca_name_constraints_limit_a_stolen_key(tmp_path):
    from fastapi.testclient import TestClient

    from certadillo.api.app import create_app
    from certadillo.db import CertificateAuthority
    from certadillo.runtime import get_runtime

    settings = make_settings(tmp_path, ca_permitted_dns=["bank.internal"])
    with TestClient(create_app(settings, background=False)) as c:
        root = x509.load_pem_x509_certificate(c.get("/pki/ca/root-ca.pem").text.encode())
        sub = cas(c)
        nc = sub.extensions.get_extension_for_class(x509.NameConstraints)
        assert nc.critical and nc.value.permitted_subtrees == [x509.DNSName("bank.internal")]

        # sign two leaves straight with the issuing CA key, as someone who stole it would
        with get_runtime().platform() as p:
            signer = p.ca.signer_for(p.s.query(CertificateAuthority).filter_by(name="issuing-ca-1").one())
            key = signer.private_key if hasattr(signer, "private_key") else None
        assert key is not None

        def leaf(name):
            k = ec.generate_private_key(ec.SECP256R1())
            import datetime as dt
            now = dt.datetime.now(dt.timezone.utc)
            return (x509.CertificateBuilder().subject_name(x509.Name([]))
                    .issuer_name(sub.subject).public_key(k.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(sub.public_key()),
                                   critical=False)
                    .sign(key, hashes.SHA384()))

        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

        verifier = PolicyBuilder().store(Store([root])).build_server_verifier(x509.DNSName("api.bank.internal"))
        verifier.verify(leaf("api.bank.internal"), [sub])  # inside the constraint: accepted
        evil = PolicyBuilder().store(Store([root])).build_server_verifier(x509.DNSName("login.evil.example"))
        with pytest.raises(VerificationError, match="(?i)name constraint|excluded|permitted"):
            evil.verify(leaf("login.evil.example"), [sub])


# =========================================================================== alerts
def test_new_privileged_principal_alerts(client):
    client.post("/api/v1/principals", json={"name": "second-admin", "role": "admin"}, headers=ADMIN)
    assert "PrivilegedPrincipalCreated" in rules(client)


def test_integrity_scan_endpoint_requires_staff(client):
    _, h = onboard(client)
    assert client.get("/api/v1/integrity", headers=h).status_code == 403
