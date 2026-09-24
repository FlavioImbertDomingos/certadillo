"""Browser security headers.

The console and the knowledge base render data that can come from outside Certadillo (a
discovered certificate carries whatever subject its server chose), so both pages run under a
Content-Security-Policy that only loads same-origin scripts and turns on Trusted Types: the
browser refuses any innerHTML assignment that did not go through the page's named policy.
API, protocol and PKI responses get a deny-everything policy, since nothing there should ever
render as a document. The interactive API docs load Swagger UI from a CDN, so they are left out.
"""

from __future__ import annotations

COMMON = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}

_LOCKED = "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

CONSOLE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    f"{_LOCKED}; require-trusted-types-for 'script'; trusted-types certadillo-console"
)

# The KB pulls two web fonts from Google and its generated pages carry a few style attributes.
KB_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; "
    f"{_LOCKED}; require-trusted-types-for 'script'; trusted-types kb-app kb-scene"
)

API_CSP = "default-src 'none'; frame-ancestors 'none'"

_DOCS = ("/docs", "/redoc", "/openapi.json")


def csp_for(path: str) -> str | None:
    if path.startswith(_DOCS):
        return None
    if path.startswith(("/kb", "/static/kb/")):
        return KB_CSP
    if path == "/" or path.startswith("/static/"):
        return CONSOLE_CSP
    return API_CSP


def apply(path: str, headers, https: bool) -> None:
    for k, v in COMMON.items():
        headers.setdefault(k, v)
    csp = csp_for(path)
    if csp:
        headers.setdefault("Content-Security-Policy", csp)
    if https:
        headers.setdefault("Strict-Transport-Security", "max-age=31536000")
