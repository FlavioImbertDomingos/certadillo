"""Populate a running Certadillo with a realistic demo estate.

    python scripts/demo_seed.py --server http://localhost:8080 \
        --admin-key $ADMIN --approver-key $APPROVER

Creates teams and apps (one prod app goes through maker-checker), issues
certificates over REST and EST, an SSH user certificate, a code-signing
request waiting for approval, and imports a few legacy certificates
(expired, expiring, weak) so alerts and the mascot have something to say."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def csr_for(cn=None, dns=(), uris=(), key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    names = [x509.DNSName(d) for d in dns] + [x509.UniformResourceIdentifier(u) for u in uris]
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)] if cn else []))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), False)
    return b.sign(key, hashes.SHA256())


def legacy(cn, days_valid, days_ago, key=None, algo=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Legacy Enterprise CA G1")])
    return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=days_ago))
            .not_valid_after(now - timedelta(days=days_ago) + timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
            .sign(key, algo or hashes.SHA256())).public_bytes(serialization.Encoding.PEM).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://localhost:8080")
    ap.add_argument("--admin-key", required=True)
    ap.add_argument("--approver-key", required=True)
    a = ap.parse_args()
    admin = httpx.Client(base_url=a.server, headers={"X-API-Key": a.admin_key}, timeout=30)
    approver = httpx.Client(base_url=a.server, headers={"X-API-Key": a.approver_key}, timeout=30)

    def ok(r):
        if r.status_code >= 400:
            raise SystemExit(f"{r.request.method} {r.request.url}: {r.status_code} {r.text}")
        return r.json()

    teams = {}
    for name, email, hook in (("payments-platform", "payments-sre@bank.example", None),
                              ("digital-banking", "dbank-sre@bank.example", None),
                              ("platform-security", "pki-ops@bank.example", None)):
        teams[name] = ok(admin.post("/api/v1/teams", json={"name": name, "contact_email": email, "webhook_url": hook,
                                                           "cost_center": "CC-" + str(4000 + len(teams))}))["id"]

    def app(name, team, env, profile, domains, cls="internal"):
        body = ok(admin.post("/api/v1/apps", json={"team_id": teams[team], "name": name, "environment": env,
                                                   "profile": profile, "allowed_domains": domains,
                                                   "data_classification": cls}))
        if body.get("approval_id"):
            ok(approver.post(f"/api/v1/approvals/{body['approval_id']}/approve", json={"comment": "CAB-2291 approved"}))
        key = ok(admin.post(f"/api/v1/apps/{body['id']}/credentials"))["api_key"]
        return body["id"], httpx.Client(base_url=a.server, headers={"X-API-Key": key}, timeout=30), key

    _, card, _ = app("card-auth-api", "payments-platform", "prod", "mtls-service", ["*.cards.bank.internal"], "pci")
    _, ledger, _ = app("ledger-core", "payments-platform", "prod", "tls-server", ["ledger.bank.internal"], "pci")
    _, web, _ = app("online-banking-web", "digital-banking", "test", "tls-server", ["*.obk.test.bank.internal"])
    _, mesh, _ = app("payments-mesh", "payments-platform", "prod", "spiffe-svid", ["spiffe://bank.internal/payments/*"], "pci")
    _, atm, atm_key = app("atm-fleet", "digital-banking", "prod", "tls-client", ["*.atm.bank.internal"], "pci")
    _, signing, _ = app("release-signing", "platform-security", "prod", "code-signing", ["release.bank.internal"])

    def pem(c):
        return c.public_bytes(serialization.Encoding.PEM).decode()

    for n in ("auth", "tokenize", "settle"):
        ok(card.post("/api/v1/certificates", json={"csr_pem": pem(csr_for(f"{n}.cards.bank.internal", [f"{n}.cards.bank.internal"]))}))
    ok(ledger.post("/api/v1/certificates", json={"csr_pem": pem(csr_for("ledger.bank.internal", ["ledger.bank.internal"]))}))
    for n in ("www", "api"):
        ok(web.post("/api/v1/certificates", json={"csr_pem": pem(csr_for(f"{n}.obk.test.bank.internal", [f"{n}.obk.test.bank.internal"])),
                                                  "validity_days": 47}))
    for svc in ("card-auth", "fraud-score", "settlement"):
        ok(mesh.post("/api/v1/certificates", json={"csr_pem": pem(csr_for(uris=[f"spiffe://bank.internal/payments/{svc}"]))}))
    basic = "Basic " + base64.b64encode(f"atm:{atm_key}".encode()).decode()
    for i in range(1, 4):
        der = csr_for(f"atm-{i:04d}.atm.bank.internal").public_bytes(serialization.Encoding.DER)
        r = httpx.post(f"{a.server}/.well-known/est/simpleenroll", content=base64.encodebytes(der),
                       headers={"Authorization": basic, "Content-Type": "application/pkcs10"})
        r.raise_for_status()
    ok(signing.post("/api/v1/certificates", json={"csr_pem": pem(csr_for("Release Signing 2026",
                                                                        key=ec.generate_private_key(ec.SECP384R1())))}))
    ssh_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    ok(admin.post("/api/v1/ssh/certificates", json={"public_key": ssh_pub, "cert_type": "user", "principals": ["oncall"],
                                                    "key_id": "oncall@bank.example", "validity_hours": 8}))

    bundle = "".join([
        legacy("payments-gw.bank.internal", 398, 395),
        legacy("hr-portal.bank.internal", 365, 380),
        legacy("mainframe-mq.bank.internal", 730, 700),
        legacy("old-vpn.bank.internal", 1095, 200, key=rsa.generate_private_key(65537, 1024)),
    ])
    ok(admin.post("/api/v1/inventory/import", json={"pem": bundle, "location": "f5-dmz-01"}))
    print(ok(admin.post("/api/v1/alerts/evaluate")))


if __name__ == "__main__":
    main()
