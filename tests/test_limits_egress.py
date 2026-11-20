"""Per-principal rate limits and the outbound allow-list."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from certadillo import egress
from certadillo.api.app import create_app
from certadillo.ratelimit import Limiter, parse
from conftest import ADMIN, issue, make_csr, make_settings, onboard


def test_limit_specs():
    assert parse("600/m") == (600, 60) and parse("500/h") == (500, 3600) and parse("10/30s") == (10, 30)
    assert parse("0") is None and parse("") is None and parse("off") is None
    with pytest.raises(ValueError):
        parse("lots")


def test_token_bucket_allows_a_burst_then_refills():
    now = [0.0]
    lim = Limiter(clock=lambda: now[0])
    assert all(lim.hit("k", 3, 60) is None for _ in range(3))
    wait = lim.hit("k", 3, 60)
    assert wait == pytest.approx(20.0)  # one token every 20 seconds
    now[0] += 20
    assert lim.hit("k", 3, 60) is None
    assert lim.hit("other", 3, 60) is None  # keys are independent


def test_request_limit_per_principal(tmp_path):
    s = make_settings(tmp_path, rate_limits={"app": "3/m"})
    with TestClient(create_app(s, background=False)) as c:
        _, h = onboard(c)
        codes = [c.get("/api/v1/me", headers=h).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        r = c.get("/api/v1/me", headers=h)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
        assert r.json()["error"] == "rate_limited"
        assert c.get("/api/v1/me", headers=ADMIN).status_code == 200  # other principals are unaffected
        assert 'certadillo_rate_limited_total{limit="requests",role="app"}' in c.get("/metrics").text


def test_issuance_limit_per_app_across_protocols(tmp_path):
    s = make_settings(tmp_path, issuance_limit="2/h")
    with TestClient(create_app(s, background=False)) as c:
        _, h = onboard(c)
        issue(c, h, cn="a.pay.bank.internal")
        issue(c, h, cn="b.pay.bank.internal")
        _, csr = make_csr("c.pay.bank.internal", dns=["c.pay.bank.internal"])
        r = c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h)
        assert r.status_code == 429 and "app card-api" in r.json()["message"]
        _, h2 = onboard(c, "other-api", domains=("*.other.bank.internal",))
        issue(c, h2, cn="x.other.bank.internal")  # a different app has its own allowance


def test_bad_limit_fails_at_start(tmp_path):
    with pytest.raises(ValueError, match="must look like"):
        create_app(make_settings(tmp_path, issuance_limit="many"), background=False)


# ------------------------------------------------------------------ egress
@pytest.mark.parametrize("url,allowed", [
    ("https://hooks.slack.com/services/x", True),
    ("https://vault.corp.example:8200/v1/sys/health", True),
    ("https://vault.corp.example:8201/v1/sys/health", False),  # the port is part of the entry
    ("https://jira.bank.internal/rest", True),  # *.bank.internal
    ("https://bank.internal/", False),  # the wildcard does not cover the apex
    ("http://10.20.4.5/hook", True),  # CIDR
    ("http://10.21.0.1/hook", False),
    ("https://evil.example/exfil", False),
])
def test_allow_list_matching(url, allowed):
    rules = ["hooks.slack.com", "vault.corp.example:8200", "*.bank.internal", "10.20.0.0/16"]
    if allowed:
        egress.check(url, allow=rules)
    else:
        with pytest.raises(egress.EgressDenied):
            egress.check(url, allow=rules)


def test_cloud_metadata_is_refused_even_without_a_list():
    egress.check("https://hooks.slack.com/x", allow=[])
    with pytest.raises(egress.EgressDenied, match="instance-metadata"):
        egress.check("http://169.254.169.254/latest/meta-data/iam/", allow=[])
    egress.check("http://169.254.169.254/latest/", allow=["169.254.169.254"])  # only when listed


def test_clients_check_every_request_and_redirect(tmp_path):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.host == "hooks.bank.internal":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200)

    with TestClient(create_app(make_settings(tmp_path, egress_allow=["*.bank.internal"]), background=False)):
        c = egress.client("notifications", transport=httpx.MockTransport(handler), follow_redirects=True)
        with pytest.raises(egress.EgressDenied):
            c.post("https://outside.example/hook")
        with pytest.raises(egress.EgressDenied):  # the redirect target is checked too
            c.post("https://hooks.bank.internal/hook")
        assert seen == ["https://hooks.bank.internal/hook"]


def test_team_webhook_outside_the_list_is_not_called(tmp_path):
    from certadillo.alerting.notifiers import WebhookNotifier

    with TestClient(create_app(make_settings(tmp_path, egress_allow=["hooks.slack.com"]), background=False)):
        n = WebhookNotifier("https://attacker.example/collect")
        with pytest.raises(egress.EgressDenied):
            n.http.post(n.url, json={})


def test_acme_gets_a_rate_limited_problem_and_the_order_stays_ready(tmp_path, monkeypatch):
    """RFC 8555 section 6.6: urn:ietf:params:acme:error:rateLimited with Retry-After."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from certadillo.enrollment import acme as acme_mod
    from test_protocols import MiniAcme, b64u

    with TestClient(create_app(make_settings(tmp_path, issuance_limit="1/h"), background=False)) as c:
        app_id, h = onboard(c, "web-portal", domains=["*.portal.bank.internal"])
        issue(c, h, cn="first.portal.bank.internal")  # uses the app's one certificate this hour
        eab = c.post(f"/api/v1/apps/{app_id}/acme-eab", headers=ADMIN).json()
        a = MiniAcme(c)
        assert a.register(eab["kid"], eab["hmac_key"]).status_code == 201
        name = "www.portal.bank.internal"
        r = a.post(a.dir["newOrder"], {"identifiers": [{"type": "dns", "value": name}]})
        order_url, order = r.headers["Location"], r.json()
        served = {}
        monkeypatch.setattr(acme_mod, "http01_fetch", lambda domain, token: served[token])
        authz = a.post(order["authorizations"][0], None).json()
        ch = authz["challenges"][0]
        served[ch["token"]] = f"{ch['token']}.{a.thumbprint()}"
        a.post(ch["url"], {})
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
               .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()))
        r = a.post(order["finalize"], {"csr": b64u(csr.public_bytes(serialization.Encoding.DER))})
        assert r.status_code == 429 and r.json()["type"] == "urn:ietf:params:acme:error:rateLimited"
        assert int(r.headers["Retry-After"]) > 0
        assert a.post(order_url, None).json()["status"] == "ready"
