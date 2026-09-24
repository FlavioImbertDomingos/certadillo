"""Build the knowledge base from docs/ and kb-src/.

    python scripts/build_kb.py            # -> src/certadillo/web/static/kb (served at /kb)
    python scripts/build_kb.py --artifact build/kb-artifact   # self-contained page for static hosting

Content is written once, in Markdown under docs/, and rendered here. The 3D
scenes live in kb-src/scenes-*.js.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import shutil
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SRC = ROOT / "kb-src"
THREE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/three.js/0.149.0/three.min.js"
FONTS = ("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&"
         "family=IBM+Plex+Sans+Condensed:wght@600&family=IBM+Plex+Sans:wght@400;500;600&display=swap")

# slug, source, group, nav label, scene
PAGES = [
    ("concepts", "guide/01-concepts.md", "Start", "Concepts", "platform"),
    ("getting-started", "guide/02-getting-started.md", "Start", "Getting started", None),
    ("onboarding", "guide/03-onboarding.md", "Start", "Onboarding", None),
    ("rest", "guide/04-rest-api.md", "Protocols", "REST API and CLI", None),
    ("acme", "guide/05-acme.md", "Protocols", "ACME", "acme"),
    ("est", "guide/06-est.md", "Protocols", "EST", "estlb"),
    ("scep", "guide/07-scep.md", "Protocols", "SCEP", "devices"),
    ("cmp", "guide/18-cmp.md", "Protocols", "CMP", "cmp"),
    ("ssh", "guide/08-ssh.md", "Protocols", "SSH certificates", None),
    ("spiffe", "guide/09-workload-identity.md", "Protocols", "Workload identity", None),
    ("code-signing", "guide/10-code-signing-smime.md", "Protocols", "Code signing and S/MIME", None),
    ("windows-adcs", "guide/20-windows-adcs.md", "Protocols", "Windows and AD CS", "adcs"),
    ("revocation", "guide/11-revocation.md", "Operate", "Revocation: OCSP and CRL", "revocation"),
    ("campaigns", "guide/19-renewal-campaigns.md", "Operate", "Renewal campaigns (ARI)", "ari"),
    ("discovery", "guide/12-discovery-inventory.md", "Operate", "Discovery and inventory", None),
    ("alerting", "guide/13-alerting-observability.md", "Operate", "Alerting and observability", None),
    ("automation", "guide/14-automation.md", "Operate", "Automation", None),
    ("zero-trust-auth", "guide/21-zero-trust-auth.md", "Operate", "Zero-trust access (IdP)", None),
    ("administration", "guide/15-administration.md", "Operate", "Administration", None),
    ("api", "guide/16-api-reference.md", "Operate", "API reference", None),
    ("troubleshooting", "guide/17-troubleshooting.md", "Operate", "Troubleshooting", None),
    ("tour-platform", None, "3D walkthroughs", "Platform tour", "platform"),
    ("tour-acme", None, "3D walkthroughs", "ACME end to end", "acme"),
    ("tour-ari", None, "3D walkthroughs", "dns-01 and a renewal campaign", "ari"),
    ("tour-devices", None, "3D walkthroughs", "EST and SCEP devices", "devices"),
    ("tour-estlb", None, "3D walkthroughs", "EST behind a load balancer", "estlb"),
    ("tour-cmp", None, "3D walkthroughs", "CMP for industrial devices", "cmp"),
    ("tour-adcs", None, "3D walkthroughs", "Windows and AD CS", "adcs"),
    ("tour-revocation", None, "3D walkthroughs", "OCSP and CRL", "revocation"),
    ("architecture", "ARCHITECTURE.md", "Reference", "Architecture", None),
    ("security", "SECURITY.md", "Reference", "Security model", None),
    ("threat-model", "THREAT_MODEL.md", "Reference", "Threat model", None),
    ("hsm", "HSM.md", "Reference", "Key custody (HSM, Vault)", None),
    ("standards", "STANDARDS.md", "Reference", "Standards map", None),
    ("runbook", "RUNBOOK.md", "Reference", "Runbook", None),
    ("roadmap", "ROADMAP.md", "Reference", "Roadmap", None),
]

TOURS = {
    "tour-platform": ("Platform tour",
                      "Follow one application from onboarding to its first certificate, then watch discovery find a "
                      "certificate nobody owned, the alert reach the right team, and automation replace it.",
                      "concepts"),
    "tour-acme": ("ACME end to end",
                  "certbot against Certadillo, from the EAB credential to the downloaded chain, including what an "
                  "out-of-scope order looks like. Every payload is what the real endpoints send.",
                  "acme"),
    "tour-ari": ("dns-01 and a renewal campaign",
                 "A wildcard proven through the internal DNS view, then a suspected key exposure: ARI moves every "
                 "renewal window forward, clients replace their certificates, and only then are the old ones revoked.",
                 "campaigns"),
    "tour-devices": ("EST and SCEP devices",
                     "An ATM enrolling over EST and a branch router over SCEP, with the one-time challenge, the "
                     "encrypted envelopes, a replay that fails, renewal and a request that waits for an approver.",
                     "scep"),
    "tour-estlb": ("EST behind a load balancer",
                   "A router bootstraps with its factory certificate through nginx, re-enrolls with the certificate "
                   "alone, and a forged header gets nowhere. Plus a sensor that has its key made for it.",
                   "est"),
    "tour-cmp": ("CMP for industrial devices",
                 "A PLC enrolls with a one-time secret, confirms, updates its key, waits for an approver for a "
                 "firmware-signing certificate, and revokes one of its own certificates.",
                 "cmp"),
    "tour-adcs": ("Windows and AD CS",
                  "The template audit flags an ESC1 template, a smart-card logon certificate is issued with the SID "
                  "resolved from the directory, and the gateway hands an approved request to a Microsoft CA.",
                  "windows-adcs"),
    "tour-revocation": ("OCSP and CRL",
                        "A key leaks, the certificate is revoked, and both revocation paths tell relying parties within "
                        "the same request. Then the housekeeping that keeps them fresh.",
                        "revocation"),
}

FILE_TO_SLUG = {src.split("/")[-1]: slug for slug, src, *_ in PAGES if src}


def rewrite_links(h: str) -> str:
    def link(m):
        target, anchor = m.group(1), m.group(2)
        name = target.split("/")[-1]
        slug = FILE_TO_SLUG.get(name)
        if slug is None:
            return m.group(0)
        extra = f' data-anchor="{anchor[1:]}"' if anchor else ""
        return f'href="#{slug}"{extra}'

    h = re.sub(r'href="((?:\.\./|\./)?(?:guide/)?[A-Za-z0-9_.-]+\.md)(#[A-Za-z0-9_-]+)?"', link, h)
    h = re.sub(r'src="(?:\.\./)?screenshots/([^"]+)"', r'src="img/\1"', h)
    return h


def render_md(path: Path) -> tuple[str, str]:
    text = path.read_text()
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc"], extension_configs={"toc": {"permalink": False}})
    body = md.convert(text)
    title = re.search(r"<h1[^>]*>(.*?)</h1>", body)
    return rewrite_links(body), html.unescape(re.sub("<[^>]+>", "", title.group(1))) if title else path.stem


def split_for_scene(h: str) -> tuple[str, str]:
    """Title and first paragraph above the scene, the rest below."""
    m = re.search(r"</p>", h)
    if not m:
        return h, ""
    return h[: m.end()], h[m.end():]


def home_html(pages: list[dict]) -> str:
    cards = []
    for slug, (title, lead, _) in TOURS.items():
        cards.append(f'<a class="kb-card" href="#{slug}"><img src="img/{slug}.png" alt="" loading="lazy">'
                     f"<div><b>{html.escape(title)}</b><small>{html.escape(lead[:118].rsplit(' ', 1)[0])}…</small></div></a>")
    quick = [("getting-started", "Getting started", "Run it locally or with Docker"),
             ("onboarding", "Onboard an app", "Team, scope, approval, credentials"),
             ("acme", "ACME", "certbot, cert-manager, lego"),
             ("scep", "SCEP", "Intune, routers, one-time challenges"),
             ("est", "EST", "ATMs, appliances, IDevID bootstrap"),
             ("cmp", "CMP", "Telecom and industrial gear"),
             ("windows-adcs", "Windows and AD CS", "Template audit, logon, gateway"),
             ("campaigns", "Renewal campaigns", "Replace first, revoke second"),
             ("ssh", "SSH certificates", "Short-lived access, no authorized_keys"),
             ("revocation", "Revocation", "OCSP and CRL"),
             ("troubleshooting", "Troubleshooting", "Every policy error explained")]
    q = "".join(f'<a href="#{s}"><b>{html.escape(t)}</b><small>{html.escape(d)}</small></a>' for s, t, d in quick)
    return (
        '<article class="kb-page"><div class="kb-hero"><img src="img/dilly.svg" alt="Dilly, the Certadillo armadillo">'
        '<div class="kb-prose"><div class="kb-eyebrow">Certadillo knowledge base</div>'
        "<h1>Certificates for every client, one set of rules</h1>"
        "<p>How to onboard an application, get certificates over REST, ACME, EST, SCEP, CMP and SSH, revoke them, and "
        "run the platform. The 3D walkthroughs show each protocol message by message, with the real payloads.</p>"
        "</div></div>"
        '<div class="kb-prose"><h2 style="border:0;margin-top:0">3D walkthroughs</h2></div>'
        f'<div class="kb-cards">{"".join(cards)}</div>'
        '<div class="kb-prose"><h2>Jump in</h2></div>'
        f'<div class="kb-quick">{q}</div></article>'
    )


def build_pages() -> list[dict]:
    out = [{"slug": "home", "title": "Certadillo knowledge base", "group": "Start", "nav": "Welcome", "html": ""}]
    for slug, src, group, nav, scene in PAGES:
        if src:
            body, title = render_md(DOCS / src)
        else:
            title, lead, guide = TOURS[slug]
            body = (f"<h1>{html.escape(title)}</h1><p>{html.escape(lead)}</p>"
                    "<h2>How to use it</h2><ul><li><b>Play</b> runs the steps with time to read each payload; "
                    "<b>Next</b> and <b>Back</b> move one step.</li><li>Drag the scene to look around; "
                    "double-click to reset the view.</li><li>Click any step in the list to jump to it. The stack "
                    "of blocks next to the database is the audit hash chain growing.</li></ul>"
                    f'<p>The written guide for this flow: <a href="#{guide}">{html.escape(dict((p[0], p[3]) for p in PAGES)[guide])}</a>.</p>')
        page = {"slug": slug, "title": title, "group": group, "nav": nav, "html": body}
        if scene:
            page["scene"] = scene
            page["pre"], page["post"] = split_for_scene(body)
        out.append(page)
    out[0]["html"] = home_html(out)
    return out


SHELL = """<header class="kb-top">
  <button id="kb-menu" class="kb-menu" type="button" aria-label="Open navigation">Menu</button>
  <a class="kb-brand" href="#home"><img src="img/dilly.svg" alt=""><div><b>Certadillo</b><span>Knowledge base</span></div></a>
  <div class="kb-search"><input id="kb-q" type="search" placeholder="Search the docs ( / )" aria-label="Search the docs" autocomplete="off">
  <div id="kb-results" class="kb-results" hidden></div></div>
</header>
<div class="kb-shell">
  <nav id="kb-nav" class="kb-nav" aria-label="Documentation"></nav>
  <main id="kb-main" class="kb-main"></main>
</div>"""

SCRIPTS = """<script src="scenes-engine.js"></script>
<script src="scenes-data.js"></script>
<script src="kb-content.js"></script>
<script src="kb-app.js"></script>"""


def sized_svg(src: Path, dst: Path) -> None:
    """Give the mascot SVGs explicit pixel sizes so WebGL textures load them sharp."""
    s = src.read_text().replace("<svg ", '<svg width="660" height="510" ', 1)
    dst.write_text(s)


def write_common(out: Path, pages: list[dict]) -> None:
    (out / "img").mkdir(parents=True, exist_ok=True)
    for f in ("scenes-engine.js", "scenes-data.js", "kb-app.js"):
        shutil.copy(SRC / f, out / f)
    (out / "kb-content.js").write_text("window.KB_PAGES = " + json.dumps(pages, ensure_ascii=False) + ";\n")
    for f in (DOCS / "brand").glob("dilly*.svg"):
        sized_svg(f, out / "img" / f.name)
    for f in (DOCS / "screenshots").glob("*.png"):
        shutil.copy(f, out / "img" / f.name)
    for f in (SRC / "thumbs").glob("*.png"):
        shutil.copy(f, out / "img" / f.name)


def build_repo(pages: list[dict]) -> Path:
    out = ROOT / "src/certadillo/web/static/kb"
    out.mkdir(parents=True, exist_ok=True)
    write_common(out, pages)
    shutil.copy(SRC / "kb.css", out / "kb.css")
    (out / "index.html").write_text(
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        "<title>Certadillo knowledge base</title>\n"
        '<link rel="icon" href="img/dilly-rolled.svg">\n'
        f'<link rel="stylesheet" href="{FONTS}">\n<link rel="stylesheet" href="kb.css">\n</head>\n<body>\n'
        f"{SHELL}\n<script src=\"vendor/three.min.js\"></script>\n{SCRIPTS}\n</body>\n</html>\n"
    )
    return out


def build_artifact(pages: list[dict], out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    write_common(out, pages)
    css = (SRC / "kb.css").read_text()
    (out / "index.html").write_text(
        "<title>Certadillo Knowledge Base</title>\n"
        f'<link rel="stylesheet" href="{FONTS}">\n<style>\n{css}\n</style>\n{SHELL}\n'
        f'<script src="{THREE_CDN}"></script>\n{SCRIPTS}\n'
    )
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", type=Path, help="also write a static-hosting build here")
    a = ap.parse_args()
    pages = build_pages()
    print("repo build:", build_repo(pages))
    if a.artifact:
        print("artifact build:", build_artifact(pages, a.artifact))
    print(f"{len(pages)} pages")


if __name__ == "__main__":
    main()
