"""ACME dns-01 (split-horizon), wildcards, ARI renewal campaigns, key rollover,
deactivation and cleanup."""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
from datetime import datetime, timedelta, timezone

import dns.message
import dns.rcode
import dns.rrset
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from certadillo.api.app import create_app, run_housekeeping
from certadillo.enrollment import acme as acme_mod
from certadillo.enrollment import ari
from conftest import ADMIN, APPROVER, make_settings, onboard
from test_protocols import MiniAcme, b64u


# ------------------------------------------------------------------ a tiny authoritative DNS server
class TinyDns:
    """UDP DNS server answering from a dict, so dns-01 runs through dnspython's
    real resolver code instead of a monkeypatch."""

    def __init__(self, records: dict):
        self.records = records  # {"name": {"TXT": [...], "CNAME": "target"}}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries: list[str] = []
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _answer(self, resp, name: str, depth=0):
        rec = self.records.get(name)
        if rec is None:
            return False
        if "CNAME" in rec and depth < 5:
            resp.answer.append(dns.rrset.from_text(name + ".", 60, "IN", "CNAME", rec["CNAME"] + "."))
            self._answer(resp, rec["CNAME"], depth + 1)
            return True
        if "TXT" in rec:
            resp.answer.append(dns.rrset.from_text_list(name + ".", 60, "IN", "TXT", [f'"{v}"' for v in rec["TXT"]]))
        return True

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                continue
            q = dns.message.from_wire(data)
            resp = dns.message.make_response(q)
            name = q.question[0].name.to_text().rstrip(".").lower()
            self.queries.append(name)
            if not self._answer(resp, name):
                resp.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(resp.to_wire(), addr)

    def close(self):
        self._stop = True
        self.t.join(1)
        self.sock.close()


@pytest.fixture
def dns_views():
    internal = TinyDns({})
    public = TinyDns({})
    yield internal, public
    internal.close()
    public.close()


@pytest.fixture
def dns_client(tmp_path, dns_views):
    internal, public = dns_views
    s = make_settings(tmp_path, acme_dns_views=f"portal.bank.internal=127.0.0.1:{internal.port}",
                      acme_dns_resolvers=[f"127.0.0.1:{public.port}"], acme_dns_timeout=2)
    with TestClient(create_app(s, background=False)) as c:
        yield c


def _account(client, name="web-portal", profile="tls-server", domains=("*.portal.bank.internal",)):
    app_id, h = onboard(client, name, profile=profile, domains=domains)
    eab = client.post(f"/api/v1/apps/{app_id}/acme-eab", headers=ADMIN).json()
    a = MiniAcme(client)
    assert a.register(eab["kid"], eab["hmac_key"]).status_code == 201
    return a, app_id, h


def _csr(names, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
           .sign(key, hashes.SHA256()))
    return b64u(csr.public_bytes(serialization.Encoding.DER))


def _finalize(a, order, names):
    r = a.post(order["finalize"], {"csr": _csr(names)})
    assert r.status_code == 200, r.text
    pem = a.post(r.json()["certificate"], None).content
    return x509.load_pem_x509_certificates(pem)[0]


def _txt(a, token):
    return base64.urlsafe_b64encode(hashlib.sha256(f"{token}.{a.thumbprint()}".encode()).digest()).rstrip(b"=").decode()


# ------------------------------------------------------------------ dns-01
def test_dns01_uses_the_internal_view(dns_client, dns_views):
    internal, public = dns_views
    a, _, _ = _account(dns_client)
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "www.portal.bank.internal"}]})
    order, order_url = r.json(), r.headers["Location"]
    authz = a.post(order["authorizations"][0], None).json()
    types = [c["type"] for c in authz["challenges"]]
    assert types == ["http-01", "dns-01"]
    ch = authz["challenges"][1]
    # the public view has a stale record; only the internal view has the right one
    public.records["_acme-challenge.www.portal.bank.internal"] = {"TXT": ["stale"]}
    internal.records["_acme-challenge.www.portal.bank.internal"] = {"TXT": ["unrelated", _txt(a, ch["token"])]}
    r = a.post(ch["url"], {})
    assert r.json()["status"] == "valid", r.text
    assert "_acme-challenge.www.portal.bank.internal" in internal.queries
    assert not public.queries
    # the other challenge of the same authorization stays pending
    authz = a.post(order["authorizations"][0], None).json()
    assert authz["status"] == "valid"
    assert [c["status"] for c in authz["challenges"]] == ["pending", "valid"]
    assert a.post(order_url, None).json()["status"] == "ready"
    cert = _finalize(a, order, ["www.portal.bank.internal"])
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "www.portal.bank.internal"


def test_dns01_follows_cname_delegation(dns_client, dns_views):
    internal, _ = dns_views
    a, _, _ = _account(dns_client)
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "api.portal.bank.internal"}]}).json()
    ch = a.post(order["authorizations"][0], None).json()["challenges"][1]
    internal.records["_acme-challenge.api.portal.bank.internal"] = {"CNAME": "api.acme-delegate.portal.bank.internal"}
    internal.records["api.acme-delegate.portal.bank.internal"] = {"TXT": [_txt(a, ch["token"])]}
    assert a.post(ch["url"], {}).json()["status"] == "valid"


def test_dns01_failure_is_explained(dns_client, dns_views):
    internal, _ = dns_views
    a, _, _ = _account(dns_client)
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "db.portal.bank.internal"}]}).json()
    ch = a.post(order["authorizations"][0], None).json()["challenges"][1]
    internal.records["_acme-challenge.db.portal.bank.internal"] = {"TXT": ["nope"]}
    body = a.post(ch["url"], {}).json()
    assert body["status"] == "invalid"
    assert "no TXT record" in body["error"]["detail"] and "portal.bank.internal view" in body["error"]["detail"]
    missing = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "gone.portal.bank.internal"}]}).json()
    ch = a.post(missing["authorizations"][0], None).json()["challenges"][1]
    assert "does not exist" in a.post(ch["url"], {}).json()["error"]["detail"]


def test_wildcards_need_the_profile_and_dns01(dns_client, dns_views):
    internal, _ = dns_views
    a, _, _ = _account(dns_client)
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "*.portal.bank.internal"}]})
    assert r.status_code == 403 and "wildcards not allowed" in r.json()["detail"]

    w, _, _ = _account(dns_client, "portal-edge", profile="tls-wildcard", domains=["*.portal.bank.internal"])
    order = w.post(w.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "*.edge.portal.bank.internal"}]}).json()
    authz = w.post(order["authorizations"][0], None).json()
    assert authz["identifier"]["value"] == "edge.portal.bank.internal" and authz["wildcard"] is True
    assert [c["type"] for c in authz["challenges"]] == ["dns-01"]
    token = authz["challenges"][0]["token"]
    # an http-01 attempt on a wildcard authorization does not exist
    assert w.post(authz["challenges"][0]["url"].replace("dns-01", "http-01"), {}).status_code == 404
    internal.records["_acme-challenge.edge.portal.bank.internal"] = {"TXT": [_txt(w, token)]}
    assert w.post(authz["challenges"][0]["url"], {}).json()["status"] == "valid"
    cert = _finalize(w, order, ["*.edge.portal.bank.internal"])
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["*.edge.portal.bank.internal"]
    r = w.post(w.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "api.*.portal.bank.internal"}]})
    assert r.status_code == 400


def test_resolver_views_pick_the_longest_zone():
    from certadillo.enrollment.acme_dns import parse_views, servers_for

    views = parse_views("bank.internal=10.0.0.53,10.0.0.54;pay.bank.internal=[fd00::53]:5353;example.com=1.1.1.1")
    assert servers_for("x.pay.bank.internal", views, [])[0] == "pay.bank.internal"
    assert servers_for("x.cards.bank.internal", views, [])[1][1].host == "10.0.0.54"
    assert servers_for("pay.bank.internal", views, [])[1][0].port == 5353
    assert servers_for("www.other.org", views, [])[0] == "default"


# ------------------------------------------------------------------ ARI and renewal campaigns
@pytest.fixture
def issued(client, monkeypatch):
    monkeypatch.setattr(acme_mod, "http01_fetch", lambda d, t: served[t])
    served: dict = {}
    a, app_id, h = _account(client)

    def order(names, replaces=None):
        payload = {"identifiers": [{"type": "dns", "value": n} for n in names]}
        if replaces:
            payload["replaces"] = replaces
        r = a.post(a.dir["newOrder"], payload)
        if r.status_code != 201:
            return r
        o = r.json()
        for url in o["authorizations"]:
            ch = a.post(url, None).json()["challenges"][0]
            served[ch["token"]] = f"{ch['token']}.{a.thumbprint()}"
            a.post(ch["url"], {})
        return _finalize(a, o, names)

    return a, app_id, h, order


def test_ari_window_and_campaign(client, issued):
    a, app_id, h, order = issued
    assert a.dir["renewalInfo"].endswith("/acme/renewal-info")
    old = order(["www.portal.bank.internal"])
    other = order(["api.portal.bank.internal"])
    cid = ari.cert_id(old)
    r = client.get(f"{a.dir['renewalInfo']}/{cid}")
    assert r.status_code == 200 and int(r.headers["Retry-After"]) == 21600
    win = r.json()["suggestedWindow"]
    start = datetime.fromisoformat(win["start"].replace("Z", "+00:00"))
    assert start > datetime.now(timezone.utc) + timedelta(days=10)  # 30-day cert: renew around day 15-18

    assert client.get(f"{a.dir['renewalInfo']}/AAAA.AQ").status_code == 404
    assert client.get(f"{a.dir['renewalInfo']}/not-a-cert-id").status_code == 400

    # a campaign pulls the window forward for the selected certificates only
    r = client.post("/api/v1/renewal-campaigns", headers=ADMIN, json={
        "name": "rotate issuing-ca-1 batch", "reason": "suspected key exposure on build host",
        "criteria": {"serials": [format(old.serial_number, "x")]}, "renew_within_hours": 12,
        "explanation_url": "https://status.bank.example/pki/2026-09"})
    assert r.status_code == 201, r.text
    camp = r.json()
    assert camp["counts"] == {"total": 1, "replaced": 0, "revoked": 0, "remaining": 1}
    r = client.get(f"{a.dir['renewalInfo']}/{cid}")
    end = datetime.fromisoformat(r.json()["suggestedWindow"]["end"].replace("Z", "+00:00"))
    assert end <= datetime.now(timezone.utc) + timedelta(hours=12, minutes=1)
    assert r.json()["explanationURL"].startswith("https://status.bank.example")
    assert int(r.headers["Retry-After"]) == 3600
    other_start = client.get(f"{a.dir['renewalInfo']}/{ari.cert_id(other)}").json()["suggestedWindow"]["start"]
    assert datetime.fromisoformat(other_start.replace("Z", "+00:00")) > datetime.now(timezone.utc) + timedelta(days=10)

    # the client renews with `replaces`; the old certificate is marked superseded
    new = order(["www.portal.bank.internal"], replaces=cid)
    assert isinstance(new, x509.Certificate)
    again = order(["www.portal.bank.internal"], replaces=cid)
    assert again.status_code == 409 and again.json()["type"].endswith("alreadyReplaced")
    camp = client.get(f"/api/v1/renewal-campaigns/{camp['id']}", headers=ADMIN).json()
    assert camp["counts"]["replaced"] == 1 and camp["certificates"][0]["team"] == "team-web-portal"

    # replaced certificates can be revoked without breaking anything
    r = client.post(f"/api/v1/renewal-campaigns/{camp['id']}/revoke-replaced", headers=ADMIN, json={"change_ref": "CHG0042"})
    assert r.json() == {"revoked": 1}
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
    assert crl.get_revoked_certificate_by_serial_number(old.serial_number) is not None
    assert crl.get_revoked_certificate_by_serial_number(new.serial_number) is None
    # a revoked certificate's window is in the past: renew now
    past = client.get(f"{a.dir['renewalInfo']}/{cid}").json()["suggestedWindow"]["end"]
    assert datetime.fromisoformat(past.replace("Z", "+00:00")) < datetime.now(timezone.utc)


def test_campaign_cutoff_needs_two_people_and_alerts_when_overdue(client, issued):
    from certadillo.db import RenewalCampaign
    from certadillo.runtime import get_runtime

    a, app_id, h, order = issued
    stale = order(["legacy.portal.bank.internal"])
    r = client.post("/api/v1/renewal-campaigns", headers=ADMIN, json={
        "name": "retire legacy", "reason": "mis-issued batch", "criteria": {"app_ids": [app_id]},
        "renew_within_hours": 1, "revocation_reason": "cessation_of_operation"})
    camp = r.json()
    assert client.post("/api/v1/renewal-campaigns", headers=ADMIN,
                       json={"name": "everything", "reason": "select all", "criteria": {}}).status_code == 400
    with get_runtime().platform() as p:
        c = p.s.get(RenewalCampaign, camp["id"])
        c.window_end = datetime.now(timezone.utc) - timedelta(minutes=1)
    run_housekeeping()
    alerts = client.get("/api/v1/alerts", headers=ADMIN).json()
    overdue = [x for x in alerts if x["rule"] == "RenewalCampaignOverdue"]
    assert overdue and "team-web-portal" in overdue[0]["summary"]

    r = client.post(f"/api/v1/renewal-campaigns/{camp['id']}/revoke-remaining", headers=ADMIN, json={"change_ref": "CHG1"})
    assert r.status_code == 202
    assert client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
    crl = x509.load_der_x509_crl(client.get("/pki/crl/issuing-ca-1.crl").content)
    assert crl.get_revoked_certificate_by_serial_number(stale.serial_number) is not None
    run_housekeeping()
    assert not [x for x in client.get("/api/v1/alerts", headers=ADMIN).json() if x["rule"] == "RenewalCampaignOverdue"]


def test_cert_id_encoding():
    assert ari.serial_bytes(0x7F) == b"\x7f"
    assert ari.serial_bytes(0x80) == b"\x00\x80"
    assert ari.parse_cert_id("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")[1] == 0x87654321
    with pytest.raises(ValueError):
        ari.parse_cert_id("aYhba4dGQEHhs3uEe6CuLN4ByNQ.h2VDIQ")  # negative serial


# ------------------------------------------------------------------ key rollover and deactivation
def _jws(key, jwk, prot_extra, payload):
    prot = {"alg": "ES256", **prot_extra}
    p64 = b64u(json.dumps(prot).encode())
    pay64 = b64u(json.dumps(payload).encode())
    der = key.sign(f"{p64}.{pay64}".encode(), ec.ECDSA(hashes.SHA256()))
    r_, s_ = decode_dss_signature(der)
    return {"protected": p64, "payload": pay64, "signature": b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))}


def test_key_change(client):
    a, _, _ = _account(client)
    new_key = ec.generate_private_key(ec.SECP256R1())
    n = new_key.public_key().public_numbers()
    new_jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    url = a.dir["keyChange"]
    inner = _jws(new_key, new_jwk, {"jwk": new_jwk, "url": url}, {"account": a.kid, "oldKey": a.jwk})
    # the inner JWS must not be replayable with a nonce, and must match the outer url
    bad = _jws(new_key, new_jwk, {"jwk": new_jwk, "url": url, "nonce": "x"}, {"account": a.kid, "oldKey": a.jwk})
    assert a.post(url, bad).status_code == 400
    r = a.post(url, inner)
    assert r.status_code == 200, r.text
    old_key, a.key, a.jwk = a.key, new_key, new_jwk
    assert a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "k.portal.bank.internal"}]}).status_code == 201
    a.key = old_key  # the old key is no longer accepted
    assert a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "k.portal.bank.internal"}]}).status_code == 400
    a.key = new_key

    # rolling over to a key another account already uses is a conflict
    b, _, _ = _account(client, "second-portal", domains=["*.second.bank.internal"])
    inner = _jws(b.key, b.jwk, {"jwk": b.jwk, "url": url}, {"account": a.kid, "oldKey": a.jwk})
    r = a.post(url, inner)
    assert r.status_code == 409 and r.headers["Location"] == b.kid


def test_account_and_authz_deactivation(client):
    a, _, _ = _account(client)
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "d.portal.bank.internal"}]}).json()
    r = a.post(order["authorizations"][0], {"status": "deactivated"})
    assert r.json()["status"] == "deactivated"
    order2 = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "e.portal.bank.internal"}]}).json()
    assert a.post(a.kid, {"status": "deactivated"}).json()["status"] == "deactivated"
    r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "f.portal.bank.internal"}]})
    assert r.status_code == 401 and r.json()["type"].endswith("unauthorized")
    # the key cannot come back as a fresh account either
    assert a.post(a.dir["newAccount"], {"onlyReturnExisting": True}, use_jwk=True).status_code == 401
    audit = [e["action"] for e in client.get("/api/v1/audit", headers=ADMIN).json()]
    assert "acme.account.deactivate" in audit and "acme.authz.deactivate" in audit
    from certadillo.db import AcmeAuthz, AcmeOrder
    from certadillo.runtime import get_runtime

    with get_runtime().platform() as p:
        o2 = p.s.get(AcmeOrder, int(order2["finalize"].split("/")[-2]))
        assert o2.status == "invalid"
        assert {x.status for x in p.s.query(AcmeAuthz).filter_by(order_id=o2.id)} == {"deactivated"}


def test_revoke_with_certificate_key(client, monkeypatch):
    a, _, _ = _account(client)
    monkeypatch.setattr(acme_mod, "http01_fetch", lambda d, t: f"{t}.{a.thumbprint()}")
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "lost.portal.bank.internal"}]}).json()
    ch = a.post(order["authorizations"][0], None).json()["challenges"][0]
    a.post(ch["url"], {})
    cert_key = ec.generate_private_key(ec.SECP256R1())
    r = a.post(order["finalize"], {"csr": _csr(["lost.portal.bank.internal"], cert_key)})
    cert = x509.load_pem_x509_certificates(a.post(r.json()["certificate"], None).content)[0]
    # a different client holding only the certificate's private key
    holder = MiniAcme(client)
    holder.key = cert_key
    n = cert_key.public_key().public_numbers()
    holder.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    r = holder.post(holder.dir["revokeCert"], {"certificate": b64u(cert.public_bytes(serialization.Encoding.DER)),
                                               "reason": 1}, use_jwk=True)
    assert r.status_code == 200, r.text
    stranger = MiniAcme(client)
    r = stranger.post(stranger.dir["revokeCert"], {"certificate": b64u(cert.public_bytes(serialization.Encoding.DER))},
                      use_jwk=True)
    assert r.status_code == 403


def test_housekeeping_expires_orders_and_drops_nonces(client):
    from certadillo.db import AcmeNonce, AcmeOrder
    from certadillo.runtime import get_runtime

    a, _, _ = _account(client)
    order = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "h.portal.bank.internal"}]}).json()
    with get_runtime().platform() as p:
        for o in p.s.query(AcmeOrder).all():
            o.expires = datetime.now(timezone.utc) - timedelta(days=31)
        for n in p.s.query(AcmeNonce).all():
            n.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
    with get_runtime().platform() as p:
        first = acme_mod.housekeeping(p.s)
    # expired a month ago: closed and purged in the same pass
    assert first["orders_expired"] == 1 and first["orders_purged"] == 1 and first["nonces_dropped"] >= 1
    with get_runtime().platform() as p:
        assert p.s.get(AcmeOrder, int(order["finalize"].split("/")[-2])) is None
    a.nonce = client.head(a.dir["newNonce"]).headers["Replay-Nonce"]  # the old one was dropped
    fresh = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": "i.portal.bank.internal"}]}).json()
    with get_runtime().platform() as p:
        o = p.s.get(AcmeOrder, int(fresh["finalize"].split("/")[-2]))
        o.expires = datetime.now(timezone.utc) - timedelta(hours=1)
    with get_runtime().platform() as p:
        second = acme_mod.housekeeping(p.s)
        assert second["orders_expired"] == 1 and second["orders_purged"] == 0
        assert p.s.get(AcmeOrder, o.id).status == "invalid"


def test_old_database_gets_new_columns(tmp_path):
    import sqlite3

    from certadillo import db

    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE acme_authz (id INTEGER PRIMARY KEY, order_id INTEGER, identifier VARCHAR(255), "
                "status VARCHAR(16), token VARCHAR(64), challenge_status VARCHAR(16), validated_at DATETIME)")
    con.execute("INSERT INTO acme_authz VALUES (1, 1, 'x.bank.internal', 'valid', 't', 'valid', NULL)")
    con.commit()
    con.close()
    db.init_db(f"sqlite:///{path}")
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(acme_authz)")}
    assert {"wildcard", "challenge_type", "error"} <= cols
