"""Fuzzing the parsers that take bytes from unauthenticated clients.

Each protocol endpoint gets valid messages with random corruption (bit flips,
truncation, inserted and deleted bytes) and plain random bytes. Whatever comes
in, the answer must be a protocol error, never a server error: a 500 is a
parser path nobody thought about, which is where memory-safe languages still
have logic bugs. Hypothesis shrinks any failure to a minimal input and keeps it
in its database, so a crash found once is replayed on every run.

CERTADILLO_FUZZ_EXAMPLES raises the number of cases per target (default 120)
for a longer run, e.g. nightly.
"""
from __future__ import annotations

import base64
import json
import os

import pytest

hypothesis = pytest.importorskip("hypothesis")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from certadillo.adcs.sd import SecurityDescriptor  # noqa: E402
from certadillo.api.app import create_app  # noqa: E402
from conftest import ADMIN, make_csr, make_settings, onboard  # noqa: E402

N = int(os.environ.get("CERTADILLO_FUZZ_EXAMPLES", "120"))
FUZZ = settings(max_examples=N, deadline=None, derandomize=False,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large,
                                       HealthCheck.function_scoped_fixture])


@st.composite
def corrupted(draw, seed: bytes):
    """A valid message with a few random edits, or random bytes."""
    if draw(st.integers(0, 9)) == 0:
        return draw(st.binary(max_size=2048))
    data = bytearray(seed)
    for _ in range(draw(st.integers(1, 6))):
        if not data:
            break
        op = draw(st.sampled_from(["flip", "set", "truncate", "insert", "delete", "length"]))
        i = draw(st.integers(0, len(data) - 1))
        if op == "flip":
            data[i] ^= 1 << draw(st.integers(0, 7))
        elif op == "set":
            data[i] = draw(st.integers(0, 255))
        elif op == "truncate":
            del data[i:]
        elif op == "insert":
            data[i:i] = draw(st.binary(min_size=1, max_size=16))
        elif op == "delete":
            del data[i:i + draw(st.integers(1, 16))]
        else:  # an absurd DER length byte
            data[i] = draw(st.sampled_from([0x80, 0x84, 0x88, 0xFF, 0x00]))
    return bytes(data)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fuzz")
    app = create_app(make_settings(tmp), background=False)
    with TestClient(app, raise_server_exceptions=False) as c:
        _, app_headers = onboard(c, "fuzz-api", domains=("*.fuzz.bank.internal",))
        c.app_headers = app_headers
        yield c


def _ok(r, what):
    assert r.status_code < 500, f"{what}: {r.status_code} {r.text[:300]}"


def test_scep_pki_operation(server):
    from tests_seeds import scep_seed

    seed = scep_seed(server)

    @FUZZ
    @given(corrupted(seed))
    def run(body):
        _ok(server.post("/scep?operation=PKIOperation", content=body,
                        headers={"Content-Type": "application/x-pki-message"}), "SCEP")
    run()


def test_cmp(server):
    from tests_seeds import cmp_seed

    seed = cmp_seed()

    @FUZZ
    @given(corrupted(seed))
    def run(body):
        r = server.post("/.well-known/cmp", content=body, headers={"Content-Type": "application/pkixcmp"})
        _ok(r, "CMP")
        assert r.headers["content-type"] == "application/pkixcmp"
    run()


def test_est_simpleenroll(server):
    _, csr_pem = make_csr("dev.fuzz.bank.internal", dns=["dev.fuzz.bank.internal"])
    der = x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
    auth = server.app_headers

    @FUZZ
    @given(corrupted(der), st.booleans())
    def run(body, as_base64):
        payload = base64.b64encode(body) if as_base64 else body
        _ok(server.post("/.well-known/est/simpleenroll", content=payload,
                        headers={**auth, "Content-Type": "application/pkcs10"}), "EST")
    run()


def test_ocsp(server):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "x")])
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    seed = ocsp.OCSPRequestBuilder().add_certificate(cert, cert, hashes.SHA1()).build().public_bytes(
        serialization.Encoding.DER)

    @FUZZ
    @given(corrupted(seed))
    def run(body):
        _ok(server.post("/pki/ocsp", content=body, headers={"Content-Type": "application/ocsp-request"}), "OCSP")
        enc = base64.urlsafe_b64encode(body).decode()
        _ok(server.get(f"/pki/ocsp/{enc}"), "OCSP GET")
    run()


def test_acme_jws(server):
    nonce = server.head("/acme/new-nonce").headers.get("replay-nonce", "n")
    protected = base64.urlsafe_b64encode(json.dumps(
        {"alg": "ES256", "nonce": nonce, "url": "http://testserver/acme/new-account",
         "jwk": {"kty": "EC", "crv": "P-256", "x": "A" * 43, "y": "A" * 43}}).encode()).rstrip(b"=").decode()
    seed = json.dumps({"protected": protected, "payload": "e30", "signature": "A" * 86}).encode()

    @FUZZ
    @given(corrupted(seed))
    def run(body):
        _ok(server.post("/acme/new-account", content=body, headers={"Content-Type": "application/jose+json"}),
            "ACME")
    run()


def test_rest_csr(server):
    _, csr_pem = make_csr("api.fuzz.bank.internal", dns=["api.fuzz.bank.internal"])

    @FUZZ
    @given(corrupted(csr_pem.encode()))
    def run(body):
        text = body.decode("utf-8", "replace")
        _ok(server.post("/api/v1/certificates", json={"csr_pem": text}, headers=server.app_headers), "REST CSR")
    run()


def test_pem_import(server):
    _, csr_pem = make_csr("x.fuzz.bank.internal")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "imp.fuzz.bank.internal")])
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(9).not_valid_before(now).not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    seed = cert.public_bytes(serialization.Encoding.PEM)

    @settings(max_examples=max(20, N // 4), deadline=None, suppress_health_check=list(HealthCheck))
    @given(corrupted(seed))
    def run(body):
        _ok(server.post("/api/v1/inventory/import", json={"pem": body.decode("utf-8", "replace"), "location": "fuzz"},
                        headers=ADMIN), "PEM import")
    run()


@FUZZ
@given(st.binary(max_size=512))
def test_adcs_security_descriptor(data):
    # nTSecurityDescriptor comes from the directory or an offline export: only
    # ValueError (which the audit reports as an unreadable descriptor) may escape
    try:
        SecurityDescriptor.parse(data)
    except ValueError:
        pass
