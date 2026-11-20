"""OpenTelemetry traces.

Off unless CERTADILLO_TRACING is `otlp` (export to an OpenTelemetry collector
over OTLP/HTTP, configured with the standard OTEL_EXPORTER_OTLP_* variables)
or `console` (print spans, for debugging). The OpenTelemetry packages are the
optional `otel` extra; without them every span below is a no-op.

One trace covers a request from the HTTP front end through the protocol
handler, the policy engine, approval or signing (HSM, Vault or software) and
the audit record, and continues into outbound calls (the W3C traceparent
header is added to webhooks, upstream CAs and the like). Incoming traceparent
headers are honored, so a pipeline's trace continues into Certadillo.

Spans carry names and outcomes, never secrets: no CSRs, keys, tokens or
certificate bodies.
"""
from __future__ import annotations

import contextlib
import logging
import os

log = logging.getLogger("certadillo")

_tracer = None
_provider = None


def enabled() -> bool:
    return _tracer is not None


def configure(settings, exporter=None) -> str:
    """Set up tracing from settings. `exporter` (a SpanExporter) is for tests.
    Returns what was configured, for the start-up log."""
    global _tracer, _provider
    mode = (getattr(settings, "tracing", "off") or "off").lower()
    if exporter is None and mode == "off":
        _shutdown()
        return "off"
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    except ImportError:
        log.warning("CERTADILLO_TRACING=%s but the OpenTelemetry packages are missing; "
                    "install certadillo[otel]", mode)
        return "unavailable"
    from certadillo import __version__

    _shutdown()
    resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "certadillo"),
                                "service.version": __version__})
    provider = TracerProvider(resource=resource)
    if exporter is not None:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        mode = "test"
    elif mode == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    elif mode == "otlp":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    else:
        raise ValueError("CERTADILLO_TRACING must be off, otlp or console")
    _provider = provider
    _tracer = provider.get_tracer("certadillo", __version__)
    return mode


def _shutdown() -> None:
    global _tracer, _provider
    if _provider is not None:
        _provider.shutdown()
    _tracer = _provider = None


def _clean(attrs: dict) -> dict:
    return {f"certadillo.{k}" if "." not in k else k: v for k, v in attrs.items()
            if v is not None and isinstance(v, (str, bool, int, float))}


@contextlib.contextmanager
def span(name: str, **attrs):
    """A child span of whatever is current. Exceptions are recorded on it and
    re-raised; set more attributes with set(span, ...)."""
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name, attributes=_clean(attrs)) as s:
        yield s


def set_attrs(s, **attrs) -> None:
    if s is not None:
        s.set_attributes(_clean(attrs))


@contextlib.contextmanager
def server_span(method: str, route: str, headers):
    """The root span of an incoming HTTP request, continuing the caller's trace
    when it sent a traceparent header."""
    if _tracer is None:
        yield None
        return
    from opentelemetry import propagate
    from opentelemetry.trace import SpanKind

    ctx = propagate.extract(dict(headers))
    with _tracer.start_as_current_span(f"{method} {route}", context=ctx, kind=SpanKind.SERVER,
                                       attributes={"http.request.method": method, "http.route": route}) as s:
        yield s


def inject(headers) -> None:
    """Add traceparent (and tracestate) to an outbound request's headers."""
    if _tracer is None:
        return
    from opentelemetry import propagate

    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    for k, v in carrier.items():
        headers[k] = v


def current_trace_id() -> str | None:
    if _tracer is None:
        return None
    from opentelemetry import trace

    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None
