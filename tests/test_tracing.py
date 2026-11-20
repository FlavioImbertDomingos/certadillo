"""OpenTelemetry traces across enrollment, policy and signing."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import ADMIN, issue, make_settings, onboard

pytest.importorskip("opentelemetry.sdk")
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from certadillo.observability import tracing  # noqa: E402


@pytest.fixture
def traced(tmp_path):
    from certadillo.api.app import create_app

    exporter = InMemorySpanExporter()
    app = create_app(make_settings(tmp_path), background=False)
    tracing.configure(None, exporter=exporter)
    with TestClient(app) as c:
        yield c, exporter
    tracing.configure(make_settings(tmp_path))  # off again for the next test


def _by_name(exporter):
    out = {}
    for s in exporter.get_finished_spans():
        out.setdefault(s.name, []).append(s)
    return out


def test_one_trace_from_request_to_signature(traced):
    c, exporter = traced
    _, h = onboard(c)
    exporter.clear()
    _, body = issue(c, h)
    spans = _by_name(exporter)
    server = spans["POST /api/v1/certificates"][0]
    enroll = spans["certadillo.enrollment.request"][0]
    policy = spans["certadillo.policy.evaluate"][0]
    sign = next(s for s in spans["certadillo.sign"] if s.attributes["certadillo.object"] == "Certificate")
    audit = next(s for s in spans["certadillo.audit.record"] if s.attributes["certadillo.action"] == "certificate.issue")
    trace_id = server.context.trace_id
    assert {s.context.trace_id for s in (enroll, policy, sign, audit)} == {trace_id}
    assert enroll.parent.span_id == server.context.span_id
    assert policy.parent.span_id == enroll.context.span_id and sign.parent.span_id == enroll.context.span_id
    assert server.attributes["http.route"] == "/api/v1/certificates"
    assert server.attributes["http.response.status_code"] == 201
    assert enroll.attributes["certadillo.protocol"] == "rest" and enroll.attributes["certadillo.outcome"] == "issued"
    assert sign.attributes["certadillo.signer"] == "software"
    # nothing secret in any span
    blob = repr([dict(s.attributes) for s in exporter.get_finished_spans()])
    assert "BEGIN" not in blob and h["X-API-Key"] not in blob


def test_caller_trace_continues_and_response_names_it(traced):
    c, exporter = traced
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    r = c.get("/api/v1/me", headers={**ADMIN, "traceparent": parent})
    assert r.headers["traceresponse"].startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    server = _by_name(exporter)["GET /api/v1/me"][0]
    assert format(server.context.trace_id, "032x") == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert format(server.parent.span_id, "016x") == "00f067aa0ba902b7"


def test_policy_refusal_is_an_error_span(traced):
    c, exporter = traced
    _, h = onboard(c)
    exporter.clear()
    from conftest import make_csr

    _, csr = make_csr("www.google.com", dns=["www.google.com"])
    assert c.post("/api/v1/certificates", json={"csr_pem": csr}, headers=h).status_code == 422
    policy = _by_name(exporter)["certadillo.policy.evaluate"][0]
    assert policy.status.status_code.name == "ERROR"
    assert any(e.name == "exception" for e in policy.events)


def test_outbound_calls_carry_the_trace(traced):
    from certadillo import egress

    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200)

    with tracing.span("certadillo.test") as sp:
        egress.client("notifications", transport=httpx.MockTransport(handler)).post("https://hooks.bank.internal/x")
        tid = format(sp.get_span_context().trace_id, "032x")
    assert seen["traceparent"].split("-")[1] == tid


def test_logs_carry_the_trace_id(traced, caplog):
    import json
    import logging

    from certadillo.observability.logging import JsonFormatter

    with tracing.span("certadillo.test") as sp:
        rec = logging.LogRecord("certadillo", logging.INFO, __file__, 1, "hello", (), None)
        doc = json.loads(JsonFormatter().format(rec))
    assert doc["trace_id"] == format(sp.get_span_context().trace_id, "032x")


def test_off_by_default_and_no_op(tmp_path):
    assert tracing.configure(make_settings(tmp_path)) == "off" and not tracing.enabled()
    with tracing.span("x") as s:
        assert s is None
    with pytest.raises(ValueError):
        tracing.configure(make_settings(tmp_path, tracing="zipkin"))
