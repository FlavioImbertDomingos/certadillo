"""EST: client certificates forwarded by a load balancer, manufacturer (IDevID)
bootstrap, csrattrs and serverkeygen."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from urllib.parse import quote

import pytest
from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi.testclient import TestClient

from certadillo.api.app import create_app
from certadillo.enrollment.est import parse_forwarded_cert
from conftest import ADMIN, APPROVER, make_settings, onboard

SECRET = "lb-shared-secret"
HDR = "X-SSL-Client-Cert"


@pytest.fixture
def lb_client(tmp_path):
    s = make_settings(tmp_path, est_client_cert_header=HDR, est_proxy_secret=SECRET)
    with TestClient(create_app(s, background=False)) as c:
        yield c


def _csr(cn, key=None, dns=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
    if dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), False)
    return key, base64.encodebytes(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def _basic(key):
    return {"Authorization": "Basic " + base64.b64encode(f"dev:{key}".encode()).decode()}


def _via_lb(cert, secret=SECRET):
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    h = {HDR: quote(pem)}  # nginx $ssl_client_escaped_cert
    if secret:
        h["X-Certadillo-Proxy-Auth"] = secret
    return h


def _leaf(r):
    assert r.status_code == 200, r.text
    return pkcs7.load_der_pkcs7_certificates(base64.b64decode(r.content))[0]


def test_reenroll_with_forwarded_client_certificate(lb_client):
    _, h = onboard(lb_client, "atm-fleet", profile="tls-client", domains=["*.atm.bank.internal"])
    _, body = _csr("atm-7.atm.bank.internal")
    cert = _leaf(lb_client.post("/.well-known/est/simpleenroll", content=body, headers=_basic(h["X-API-Key"])))

    # re-enroll with only the certificate, as the load balancer forwards it
    _, body2 = _csr("atm-7.atm.bank.internal")
    new = _leaf(lb_client.post("/.well-known/est/simplereenroll", content=body2, headers=_via_lb(cert)))
    assert new.serial_number != cert.serial_number
    rows = {c["serial"]: c["status"] for c in lb_client.get("/api/v1/certificates", headers=ADMIN).json()}
    assert rows[format(cert.serial_number, "x")] == "superseded"
    audit = [e for e in lb_client.get("/api/v1/audit", headers=ADMIN).json() if e["action"] == "est.enroll"]
    assert audit[0]["details"] == {"auth": "certificate", "reenroll": True}

    # the superseded certificate no longer authenticates
    _, body3 = _csr("atm-7.atm.bank.internal")
    assert lb_client.post("/.well-known/est/simplereenroll", content=body3, headers=_via_lb(cert)).status_code == 401
    # a different subject is refused (RFC 7030 4.2.2)
    _, other = _csr("atm-8.atm.bank.internal")
    assert lb_client.post("/.well-known/est/simplereenroll", content=other, headers=_via_lb(new)).status_code == 400
    # without the load balancer's secret the header is ignored
    assert lb_client.post("/.well-known/est/simplereenroll", content=body3,
                          headers=_via_lb(new, secret="guess")).status_code == 401


def _manufacturer():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Acme Devices"),
                      x509.NameAttribute(x509.NameOID.COMMON_NAME, "Acme Devices IDevID CA")])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    dev_key = ec.generate_private_key(ec.SECP256R1())
    dev = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, "SN-000451")]))
           .issuer_name(name).public_key(dev_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
           .sign(ca_key, hashes.SHA256()))
    return ca, dev


def test_idevid_bootstrap(lb_client):
    app_id, _ = onboard(lb_client, "branch-routers", profile="tls-client", domains=["*.routers.bank.internal"])
    ca, dev = _manufacturer()
    _, body = _csr("rtr-451.routers.bank.internal")
    assert lb_client.post("/.well-known/est/simpleenroll", content=body, headers=_via_lb(dev)).status_code == 401
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    r = lb_client.post(f"/api/v1/apps/{app_id}/est-trust-anchors", headers=ADMIN, json={"name": "acme", "cert_pem": ca_pem})
    assert r.status_code == 201, r.text
    leaf = _leaf(lb_client.post("/.well-known/est/simpleenroll", content=body, headers=_via_lb(dev)))
    assert leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "rtr-451.routers.bank.internal"
    # the device then re-enrolls with its new certificate, not the manufacturer one
    _, again = _csr("rtr-451.routers.bank.internal")
    assert lb_client.post("/.well-known/est/simplereenroll", content=again, headers=_via_lb(dev)).status_code == 403
    _leaf(lb_client.post("/.well-known/est/simplereenroll", content=again, headers=_via_lb(leaf)))
    # scope still applies to bootstrapped devices
    _, outside = _csr("evil.example.com")
    assert lb_client.post("/.well-known/est/simpleenroll", content=outside, headers=_via_lb(dev)).status_code == 400

    # for a production app, trusting a manufacturer CA takes a second person
    prod_id, _ = onboard(lb_client, "prod-routers", env="prod", profile="tls-client", domains=["*.prod.bank.internal"])
    r = lb_client.post(f"/api/v1/apps/{prod_id}/est-trust-anchors", headers=ADMIN, json={"name": "acme", "cert_pem": ca_pem})
    assert r.status_code == 202
    assert lb_client.post(f"/api/v1/approvals/{r.json()['approval_id']}/approve", headers=APPROVER).status_code == 200
    assert len(lb_client.get(f"/api/v1/apps/{prod_id}/est-trust-anchors", headers=ADMIN).json()) == 1
    leafcert = dev  # not a CA: refused
    r = lb_client.post(f"/api/v1/apps/{app_id}/est-trust-anchors", headers=ADMIN,
                       json={"name": "leaf", "cert_pem": leafcert.public_bytes(serialization.Encoding.PEM).decode()})
    assert r.status_code == 400


def test_forwarded_header_formats():
    _, dev = _manufacturer()
    pem = dev.public_bytes(serialization.Encoding.PEM).decode()
    der_b64 = base64.b64encode(dev.public_bytes(serialization.Encoding.DER)).decode()
    for value in (
        quote(pem),                                                   # nginx $ssl_client_escaped_cert, AWS ALB
        pem.replace("\n", " "),                                       # PEM folded onto one line
        f'By=spiffe://bank.internal/est;Hash=abc;Cert="{quote(pem)}";Subject="CN=x"',  # Envoy XFCC
        quote(der_b64),                                               # Traefik passTLSClientCert
    ):
        assert parse_forwarded_cert(value) == dev
    assert parse_forwarded_cert("garbage") is None


def test_trusted_proxy_cidrs():
    from types import SimpleNamespace

    from certadillo.enrollment.est import _from_trusted_proxy

    settings = SimpleNamespace(est_proxy_secret=None, est_trusted_proxies=["10.20.0.0/24"])
    req = lambda ip: SimpleNamespace(client=SimpleNamespace(host=ip), headers={})  # noqa: E731
    assert _from_trusted_proxy(req("10.20.0.7"), settings)
    assert not _from_trusted_proxy(req("10.21.0.7"), settings)
    assert not _from_trusted_proxy(req("10.20.0.7"), SimpleNamespace(est_proxy_secret=None, est_trusted_proxies=[]))


class _Attr(core.Sequence):
    _fields = [("type", core.ObjectIdentifier), ("values", core.SetOf, {"spec": core.Any})]


class _AttrOrOID(core.Choice):
    _alternatives = [("oid", core.ObjectIdentifier), ("attribute", _Attr)]


class _CsrAttrs(core.SequenceOf):
    _child_spec = _AttrOrOID


def test_csrattrs(client):
    r = client.get("/.well-known/est/csrattrs")
    assert r.status_code == 200 and r.headers["content-type"] == "application/csrattrs"
    items = _CsrAttrs.load(base64.b64decode(r.content))
    attr = items[0].chosen
    assert attr["type"].dotted == "1.2.840.10045.2.1"
    assert attr["values"][0].parse(core.ObjectIdentifier).dotted == "1.2.840.10045.3.1.7"
    assert items[1].chosen.dotted == "1.2.840.10045.4.3.2"
    _, h = onboard(client, "web", domains=["*.web.bank.internal"])
    items = _CsrAttrs.load(base64.b64decode(client.get("/.well-known/est/csrattrs", headers=_basic(h["X-API-Key"])).content))
    assert items[-1].chosen["type"].dotted == "1.2.840.113549.1.9.14"  # tls-server wants a SAN
    _, cs = onboard(client, "signer", profile="code-signing", domains=["*.build.bank.internal"])
    items = _CsrAttrs.load(base64.b64decode(client.get("/.well-known/est/csrattrs", headers=_basic(cs["X-API-Key"])).content))
    assert items[0].chosen["values"][0].parse(core.ObjectIdentifier).dotted == "1.3.132.0.34"  # P-384 only


def test_serverkeygen(client):
    _, h = onboard(client, "sensors", profile="tls-client", domains=["*.iot.bank.internal"])
    _, body = _csr("sensor-12.iot.bank.internal")
    r = client.post("/.well-known/est/serverkeygen", content=body, headers=_basic(h["X-API-Key"]))
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("multipart/mixed; boundary=")
    msg = message_from_bytes(b"Content-Type: " + r.headers["content-type"].encode() + b"\r\n\r\n" + r.content)
    parts = {p.get_content_type(): base64.b64decode(p.get_payload()) for p in msg.get_payload()}
    key = serialization.load_der_private_key(parts["application/pkcs8"], None)
    cert = pkcs7.load_der_pkcs7_certificates(parts["application/pkcs7-mime"])[0]
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    ev = [e for e in client.get("/api/v1/audit", headers=ADMIN).json() if e["action"] == "est.serverkeygen"][0]
    assert ev["details"]["stored"] is False

    _, web = onboard(client, "web2", domains=["*.web.bank.internal"])
    _, body = _csr("x.web.bank.internal", dns=["x.web.bank.internal"])
    assert client.post("/.well-known/est/serverkeygen", content=body, headers=_basic(web["X-API-Key"])).status_code == 403
