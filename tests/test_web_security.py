"""Browser-facing hardening: CSP with Trusted Types on the console and KB, deny-all CSP on the
API, and no inline script or HTML-string sinks outside the audited helpers."""
from __future__ import annotations

import re
from importlib import resources

STATIC = resources.files("certadillo").joinpath("web/static")


def csp(r):
    return {d.split()[0]: d.split()[1:] for d in r.headers["content-security-policy"].split("; ")}


def test_console_csp_enforces_trusted_types_and_same_origin_scripts(client):
    r = client.get("/")
    p = csp(r)
    assert p["script-src"] == ["'self'"] and p["style-src"] == ["'self'"]
    assert p["require-trusted-types-for"] == ["'script'"] and p["trusted-types"] == ["certadillo-console"]
    assert p["frame-ancestors"] == ["'none'"] and p["object-src"] == ["'none'"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "strict-transport-security" not in r.headers


def test_kb_csp_names_only_its_own_policies(client):
    p = csp(client.get("/kb/"))
    assert p["script-src"] == ["'self'"]
    assert p["trusted-types"] == ["kb-app", "kb-scene"]


def test_api_responses_cannot_render_as_documents(client):
    for path in ("/api/v1/me", "/healthz", "/pki/ca/root-ca.pem"):
        assert client.get(path).headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_hsts_only_behind_https(client):
    r = client.get("/healthz", headers={"x-forwarded-proto": "https"})
    assert r.headers["strict-transport-security"].startswith("max-age=")


def test_pages_have_no_inline_script():
    for page in ("index.html", "kb/index.html"):
        text = STATIC.joinpath(page).read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text), page
        assert not re.search(r"\son[a-z]+\s*=", text), page


def test_markup_sinks_only_in_audited_helpers():
    # console.js: one innerHTML, inside render(); the KB scripts: one each, inside setHTML().
    for name, fn in (("console.js", "function render("), ("kb/kb-app.js", "function setHTML("),
                     ("kb/scenes-engine.js", "function setHTML(")):
        lines = [ln for ln in STATIC.joinpath(name).read_text().splitlines()
                 if re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write", ln)]
        assert len(lines) == 1, (name, lines)
    console = STATIC.joinpath("console.js").read_text()
    assert "el.innerHTML = policy ? policy.createHTML(safe.s) : safe.s;" in console
    assert "if (!(safe instanceof SafeHtml)) throw" in console
