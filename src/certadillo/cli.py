"""certadillo command line.

Server-side commands (serve, init, principal, scan, audit, alerts) work on the
local database. `certadillo cert ...` is a thin API client for app teams and
automation (cron, systemd timers, Ansible, CI pipelines)."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click


@click.group()
@click.version_option()
def main():
    """Certadillo: PKI and certificate lifecycle platform."""


# ---------------------------------------------------------------- server side
@main.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8080, type=int)
def serve(host, port):
    """Run the API, web console, EST and ACME endpoints."""
    import uvicorn

    uvicorn.run("certadillo.api.app:main_app", factory=True, host=host, port=port, proxy_headers=True,
                log_config=None)


@main.command()
def init():
    """Create the database and CA hierarchy if missing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from certadillo.db import CertificateAuthority
    from certadillo.runtime import init_runtime

    rt = init_runtime()
    with rt.platform() as p:
        for ca in p.s.query(CertificateAuthority).all():
            c = x509.load_pem_x509_certificate(ca.cert_pem.encode())
            click.echo(f"{ca.name:14} {ca.signer_type:9} {c.not_valid_after_utc:%Y-%m-%d}  SHA256 {c.fingerprint(hashes.SHA256()).hex()}")


@main.command()
@click.argument("name")
@click.option("--role", type=click.Choice(["admin", "approver", "operator", "auditor", "gateway", "agent"]),
              required=True)
def principal(name, role):
    """Create a human principal and print its API key once."""
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        key = p.create_principal(None, name, role)
    click.echo(key)


@main.command()
@click.argument("targets", nargs=-1, required=True)
def scan(targets):
    """Discover TLS certificates (host:port or CIDR:port) into inventory."""
    from certadillo.discovery.scanner import scan as do_scan
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        for r in do_scan(list(targets)):
            if r.cert is None:
                click.echo(f"{r.target:28} ERROR {r.error}")
                continue
            row, findings, new = p.ingest("cli", r.cert, "discovered", r.target)
            flag = "new " if new else "seen"
            click.echo(f"{r.target:28} {flag} {row.common_name:40} {row.not_after:%Y-%m-%d} {','.join(f[0] for f in findings)}")


@main.group()
def audit():
    """Audit trail tools."""


@audit.command("verify")
@click.option("--anchors", type=click.Path(exists=True), help="JSONL file of saved chain anchors to check against")
def audit_verify(anchors):
    """Verify the audit hash chain; exit 1 if broken.

    With --anchors, also check that every saved anchor is still in the chain,
    which catches a history rewritten by someone able to recompute the hashes."""
    from certadillo.audit.log import load_anchors, verify_against_anchors, verify_chain
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        res = verify_against_anchors(p.s, load_anchors(anchors)) if anchors else verify_chain(p.s)
    click.echo(json.dumps(res))
    sys.exit(0 if res["valid"] else 1)


@audit.command("anchor")
def audit_anchor():
    """Send the current chain head to CERTADILLO_AUDIT_ANCHOR_FILE / _URL now."""
    from certadillo.audit.log import make_anchor, publish_anchor, record
    from certadillo.runtime import init_runtime

    rt = init_runtime()
    with rt.platform() as p:
        a = make_anchor(p.s, rt.settings.base_url)
        if a is None:
            raise click.ClickException("the audit chain is empty or broken; nothing to anchor")
        sinks = publish_anchor(a, rt.settings)
        if not sinks:
            raise click.ClickException("set CERTADILLO_AUDIT_ANCHOR_FILE or CERTADILLO_AUDIT_ANCHOR_URL")
        record(p.s, "cli", "audit.anchor", f"event:{a['event_id']}", {"hash": a["hash"], "sinks": sinks})
        p.commit()
    click.echo(json.dumps({**a, "sinks": sinks}))


@audit.command("ship")
def audit_ship():
    """Send unshipped audit events to every configured sink now."""
    from certadillo.audit.shipping import ship
    from certadillo.runtime import init_runtime

    rt = init_runtime()
    with rt.platform() as p:
        click.echo(json.dumps(ship(p.s, rt.settings)))


@audit.command("verify-export")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--public-key", "public_key", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="the audit signing public key (from `certadillo audit signing-key`); checks every signature")
@click.option("--no-mac", is_flag=True, help="skip the MAC check (when the seal key is not available here)")
def audit_verify_export(path, public_key, no_mac):
    """Check a shipped JSONL copy of the audit trail on its own: every record's
    hash, the links between records, the signatures (with --public-key) and the
    MACs (needs the seal key). Exit 1 on any problem, or if neither the
    signatures nor the MACs could be checked."""
    from certadillo.audit.shipping import load_public_key, verify_records

    if not no_mac:
        from certadillo import integrity
        from certadillo.config import get_settings

        try:
            integrity.configure(get_settings())
        except Exception:  # noqa: BLE001 - no key material here; signatures can still be checked
            if public_key is None:
                raise
    pub = load_public_key(public_key.read_bytes()) if public_key else None
    records = [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
    res = verify_records(records, check_mac=not no_mac, public_key=pub)
    if not (res["signatures_checked"] or res["macs_checked"]):
        res["valid"] = False
        res["problems"].insert(0, {"id": None, "problem": "origin not checked: pass --public-key or run with the seal key"})
    click.echo(json.dumps(res, indent=2))
    sys.exit(0 if res["valid"] else 1)


@audit.command("signing-key")
def audit_signing_key():
    """Print the public key that verifies shipped audit records. Give it to the
    SIEM or storage team; it can check records but not forge them."""
    from certadillo.audit.shipping import SIGNING_KEY_FILE, key_id, load_public_key, public_key_pem
    from certadillo.config import get_settings

    settings = get_settings()
    if not (Path(settings.data_dir) / SIGNING_KEY_FILE).exists():
        raise click.ClickException("no audit signing key in this data directory yet; it is created when the "
                                   "server starts with CERTADILLO_AUDIT_SHIP set")
    pem = public_key_pem(settings)
    click.echo(f"# key id {key_id(load_public_key(pem.encode()))}")
    click.echo(pem, nl=False)


@main.group()
def integrity():
    """Integrity seals on principals, approvals and certificate status."""


@integrity.command("check")
def integrity_check():
    """List rows changed outside Certadillo; exit 1 if any."""
    from certadillo import integrity as seals
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        problems = seals.scan(p.s)
    click.echo(json.dumps({"ok": not problems, "problems": problems}, indent=2))
    sys.exit(1 if problems else 0)


@integrity.command("reseal")
def integrity_reseal():
    """After rotating CERTADILLO_SEAL_KEY: reseal rows that verify under the
    current or CERTADILLO_SEAL_KEY_PREVIOUS key. Broken rows stay broken."""
    from certadillo import integrity as seals
    from certadillo.audit.log import record
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        res = seals.reseal_all(p.s)
        record(p.s, "cli", "integrity.reseal", "seals", res)
        p.commit()
    click.echo(json.dumps(res))


@main.group()
def ca():
    """Certificate authorities and their keys."""


@ca.command("keys")
def ca_keys():
    """Where each CA key lives (file, pkcs11, vault-transit) and whether it is
    reachable and intact. It makes no test signatures. Exit 1 on any problem."""
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        rows = p.ca.key_health()
    click.echo(json.dumps(rows, indent=2))
    sys.exit(1 if any(not r["ok"] for r in rows) else 0)


def ceremony_policy_hcl(mount: str, prefix: str, new_keys: list[str], signing_keys: list[str]) -> str:
    """Vault policy for one key ceremony. Write access is granted on the exact
    key paths being created, never on a glob: creating a Transit key needs
    "update", and "update" on transit/keys/<prefix>* would also allow rotate,
    config (making a key exportable) and trim on every CA key."""
    lines = [
        "# Key ceremony policy generated by `certadillo ca ceremony-policy`.",
        "# Issue a short-lived token with it for this ceremony only, then revoke the token.",
        "",
    ]
    from certadillo.crypto.vault_signer import VAULT_TYPES

    types = ", ".join(f'"{t}"' for t in sorted(set(VAULT_TYPES.values())))
    for k in new_keys:
        # An allowlist, not a denylist: Vault compares values literally, so a deny on
        # exportable=true is bypassed by sending "true" as a string. Only these
        # parameters, with exactly these values, are accepted when the key is created.
        lines += [f'path "{mount}/keys/{prefix}{k}" {{', '  capabilities = ["create", "update", "read"]',
                  "  allowed_parameters = {", f"    \"type\" = [{types}]",
                  '    "exportable" = [false]', '    "allow_plaintext_backup" = [false]', "  }", "}", ""]
    lines += [f'path "{mount}/keys/{prefix}*" {{', '  capabilities = ["read"]', "}", ""]
    for k in signing_keys:
        lines += [f'path "{mount}/sign/{prefix}{k}" {{', '  capabilities = ["update"]', "}", ""]
    return "\n".join(lines)


@ca.command("ceremony-policy")
@click.option("--name", help="the issuing CA the ceremony will create, e.g. issuing-ca-2")
@click.option("--parent", default="root-ca", show_default=True)
@click.option("--init", "init_", is_flag=True, help="policy for `certadillo init` (root-ca and issuing-ca-1)")
def ca_ceremony_policy(name, parent, init_):
    """Print the Vault policy for a key ceremony, scoped to the exact keys it creates."""
    from certadillo.config import get_settings

    s = get_settings()
    if init_:
        keys = ["root-ca", "issuing-ca-1"]
        click.echo(ceremony_policy_hcl(s.vault_signer_mount, s.vault_key_prefix, keys, keys))
        return
    if not name:
        raise click.ClickException("give --name, or --init for the first hierarchy")
    click.echo(ceremony_policy_hcl(s.vault_signer_mount, s.vault_key_prefix, [name], [parent, name]))


@ca.command("create-issuing")
@click.option("--name", required=True, help="new CA name, e.g. issuing-ca-2")
@click.option("--parent", default="root-ca", show_default=True)
@click.option("--years", default=5, show_default=True, type=int)
@click.option("--operator", required=True, help="the person running the ceremony")
@click.option("--witness", required=True, help="the second person present")
def ca_create_issuing(name, parent, years, operator, witness):
    """Key ceremony: create a new issuing CA signed by PARENT.

    Run it from an admin workstation with a short-lived ceremony token
    (deploy/vault/certadillo-ceremony.hcl) in CERTADILLO_VAULT_TOKEN, not from
    the application, whose own token cannot sign with the root key. The new CA
    becomes the default for new certificates; move existing ones with a renewal
    campaign on the old CA. Both names go into the audit trail."""
    import re

    from certadillo.audit.log import record
    from certadillo.runtime import init_runtime

    if operator.strip().lower() == witness.strip().lower():
        raise click.ClickException("the witness must be a different person")
    if not re.fullmatch(r"[a-z0-9-]+", name):
        raise click.ClickException("CA names are lowercase letters, digits and hyphens")
    rt = init_runtime()
    with rt.platform() as p:
        parent_ca = p.ca.get(parent)
        new = p.ca.create_subordinate(parent_ca, name, years=years)
        p.ca.generate_crl(new)
        record(p.s, f"ceremony:{operator}", "ca.create", name,
               {"parent": parent, "operator": operator, "witness": witness, "key_ref": new.key_ref,
                "signer": new.signer_type})
        p.commit()
        out = {"created": name, "parent": parent, "key_ref": new.key_ref, "signer": new.signer_type}
    click.echo(json.dumps(out))


@main.group()
def provision():
    """Push provisioning: install certificates on targets."""


@provision.command("due")
def provision_due():
    """Run every installation that is due now (new, failed and past its backoff,
    in its renewal window, or covered by a renewal campaign). The server does
    this on its own timer; use this from cron when the API runs without it."""
    from certadillo.provisioning.engine import renew_due
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        click.echo(json.dumps(renew_due(p)))


@provision.command("run")
@click.argument("installation_id", type=int)
def provision_run(installation_id):
    """Provision one installation now."""
    from certadillo.provisioning.engine import installation_json, provision as run_one
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        run = run_one(p, installation_id, "cli", "manual")
        p.commit()
        from certadillo.db import Installation

        click.echo(json.dumps({**installation_json(p.s.get(Installation, installation_id)),
                               "run": {"status": run.status, "steps": run.steps, "error": run.error}}))
        sys.exit(0 if run.status == "ok" else 1)


@main.group()
def agent():
    """Host agent: find certificates and keystores on this machine."""


@agent.command("scan")
@click.option("--server", envvar="CERTADILLO_SERVER")
@click.option("--api-key", envvar="CERTADILLO_API_KEY", help="an agent-role key; prefer the variable")
@click.option("--api-key-file", envvar="CERTADILLO_API_KEY_FILE", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--path", "paths", multiple=True, help="directories to scan (default: the usual TLS locations)")
@click.option("--password-file", type=click.Path(path_type=Path, exists=True, dir_okay=False),
              help="keystore passwords to try, one per line")
@click.option("--dry-run", is_flag=True, help="print what would be reported and send nothing")
def agent_scan(server, api_key, api_key_file, paths, password_file, dry_run):
    """Scan, then report the public certificates and the permissions of private
    key files. Private keys are never read into the report."""
    import socket

    from certadillo.discovery.agent import DEFAULT_PATHS, scan

    passwords = [ln for ln in password_file.read_text().splitlines() if ln] if password_file else []
    found = scan(list(paths) or [p for p in DEFAULT_PATHS if Path(p).exists()], passwords)
    report = {"host": socket.getfqdn(), "certificates": found["certificates"], "key_files": found["key_files"]}
    if dry_run:
        click.echo(json.dumps({"host": report["host"], "certificates": [
            {"path": c["path"], "format": c["format"]} for c in report["certificates"]],
            "key_files": report["key_files"]}, indent=2))
        return
    if not server:
        raise click.UsageError("set CERTADILLO_SERVER, or use --dry-run")
    r = _client(server, _resolve_key(api_key, api_key_file)).post("/api/v1/discovery/agent-report", json=report)
    if r.status_code != 200:
        click.echo(r.text, err=True)
        sys.exit(1)
    click.echo(json.dumps(r.json()))


@main.group()
def db():
    """Database schema and hardening."""


@db.command("migrate")
def db_migrate():
    """Create missing tables and columns and install the audit guards. Run with
    the owner credential in CERTADILLO_DB_URL before starting a new version."""
    from certadillo import db as dbm
    from certadillo.config import get_settings

    engine = dbm.init_db(get_settings().db_url)
    click.echo(json.dumps({"migrated": True, "audit_guards": dbm.install_audit_guards(engine)}))


@db.command("harden")
@click.option("--app-role", required=True, help="the PostgreSQL role the application connects as")
def db_harden(app_role):
    """PostgreSQL: give the application role only the rights it needs, and no
    UPDATE, DELETE or TRUNCATE on audit_events. Run as the table owner (the
    migration role). The application then connects as --app-role, which cannot
    drop the audit triggers because it does not own the table."""
    import re

    from sqlalchemy import text

    from certadillo import db as dbm
    from certadillo.config import get_settings

    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", app_role):
        raise click.ClickException("role names are lowercase letters, digits and underscores")
    engine = dbm.init_db(get_settings().db_url)
    if engine.dialect.name != "postgresql":
        raise click.ClickException("db harden is for PostgreSQL")
    r = f'"{app_role}"'
    with engine.begin() as conn:
        if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": app_role}).first():
            raise click.ClickException(f"role {app_role} does not exist; create it first (CREATE ROLE {app_role} "
                                       "LOGIN PASSWORD '...'), then rerun")
        owner = conn.execute(text("SELECT tableowner FROM pg_tables WHERE tablename = 'audit_events'")).scalar()
        if owner == app_role:
            raise click.ClickException(f"{app_role} owns the tables; the application role must not be the owner. "
                                       "Run this as a separate owner role and point the app at the restricted role")
        for stmt in (
            f"GRANT USAGE ON SCHEMA public TO {r}",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {r}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {r}",
            f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {r}",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {r}",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {r}",
        ):
            conn.execute(text(stmt))
    click.echo(json.dumps({"hardened": True, "owner": owner, "app_role": app_role,
                           "audit_events": "SELECT, INSERT only for the app role"}))


@main.group()
def adcs():
    """Audit AD CS certificate templates for ESC misconfigurations (read-only)."""


@adcs.command("audit")
@click.option("--json", "json_file", type=click.Path(exists=True, path_type=Path),
              help="audit a Export-CertadilloAdcsTemplates export instead of live LDAP")
@click.option("--store/--no-store", default=True, help="save findings to the database")
def adcs_audit(json_file, store):
    """Run a template audit and print the findings.

    With --json, audits the file the PowerShell exporter produced. Otherwise
    reads the live directory over LDAP using CERTADILLO_ADCS_LDAP_* settings.
    """
    from certadillo.adcs.audit import audit_objects, store_findings
    from certadillo.adcs.collector import LdapCollector, from_json
    from certadillo.config import get_settings
    from certadillo.runtime import init_runtime

    if json_file:
        with open(json_file) as fh:
            templates, cas, ntauth = from_json(json.load(fh))
        source = "json"
    else:
        s = get_settings()
        if not (s.adcs_ldap_url and s.adcs_ldap_user and s.adcs_ldap_base):
            raise click.ClickException("set CERTADILLO_ADCS_LDAP_URL, _USER, _PASSWORD and _BASE, or pass --json")
        collector = LdapCollector(s.adcs_ldap_url, s.adcs_ldap_user, s.adcs_ldap_password or "", s.adcs_ldap_base)
        collector.connect()
        templates, cas, ntauth = collector.collect()
        source = "ldap"

    run_id, findings = audit_objects(templates, cas, source=source, ntauth=ntauth)
    if store:
        with init_runtime().platform() as p:
            store_findings(p.s, run_id, findings, "cli")
            p.commit()
    click.echo(json.dumps({"run_id": run_id, "templates": len(templates), "cas": len(cas),
                           "findings": findings}, indent=2))
    sys.exit(1 if any(f["severity"] in ("critical", "high") for f in findings) else 0)


@main.group()
def alerts():
    """Alert evaluation."""


@alerts.command("run")
def alerts_run():
    """Publish due CRLs and evaluate alerts once (for cron / Kubernetes CronJob)."""
    from certadillo.api.app import run_housekeeping
    from certadillo.runtime import init_runtime

    init_runtime()
    click.echo(json.dumps(run_housekeeping()))


# ---------------------------------------------------------------- client side
@main.group()
def cert():
    """Request and renew certificates through the API (app teams, automation)."""


_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def _resolve_key(api_key: str | None, api_key_file: Path | None) -> str:
    """The app credential, from CERTADILLO_API_KEY, a file, or (discouraged) the command line."""
    ctx = click.get_current_context()
    if api_key and ctx.get_parameter_source("api_key") == click.core.ParameterSource.COMMANDLINE:
        click.echo("warning: --api-key on the command line shows up in the process list and shell history; "
                   "use CERTADILLO_API_KEY or --api-key-file", err=True)
    if api_key_file is not None:
        return api_key_file.read_text().strip()
    if not api_key:
        raise click.UsageError("set CERTADILLO_API_KEY or pass --api-key-file")
    return api_key


def _client(server, key):
    """HTTP client that only sends the credential over TLS (or to this machine)."""
    from urllib.parse import urlsplit

    import httpx

    u = urlsplit(server)
    if u.scheme != "https" and not (u.scheme == "http" and (u.hostname or "") in _LOOPBACK):
        if (os.environ.get("CERTADILLO_ALLOW_HTTP", "") or "").lower() != "true":
            raise click.UsageError(f"refusing to send the API key to {server} without TLS; use https://")
    import ssl

    cafile = os.environ.get("CERTADILLO_CACERT")  # a private CA bundle for the server's certificate
    verify = ssl.create_default_context(cafile=cafile) if cafile else True
    return httpx.Client(base_url=server, headers={"X-API-Key": key}, timeout=30, verify=verify)


def _key_and_csr(cn, sans, spiffe_id, key_type):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    key = ec.generate_private_key(ec.SECP256R1()) if key_type == "ec" else rsa.generate_private_key(65537, 3072)
    names = [x509.DNSName(s) for s in sans]
    if spiffe_id:
        names.append(x509.UniformResourceIdentifier(spiffe_id))
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)] if cn else [])
    )
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    csr = b.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode()


def _write(out: Path, key_pem: bytes, data: dict):
    out.mkdir(parents=True, exist_ok=True)
    kp = out / "tls.key"
    tmp = kp.with_suffix(".key.tmp")
    tmp.unlink(missing_ok=True)
    # created 0600 from the first byte; writing then chmod-ing leaves a window
    # where the key is readable under the default umask
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem)
    tmp.replace(kp)
    (out / "tls.crt").write_text(data["pem"] + data.get("chain_pem", ""))
    (out / "meta.json").write_text(json.dumps({k: data[k] for k in ("id", "serial", "not_before", "not_after")}, indent=2))


@cert.command("request")
@click.option("--server", envvar="CERTADILLO_SERVER", required=True)
@click.option("--api-key", envvar="CERTADILLO_API_KEY", help="prefer the CERTADILLO_API_KEY variable")
@click.option("--api-key-file", envvar="CERTADILLO_API_KEY_FILE", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--cn")
@click.option("--san", multiple=True)
@click.option("--spiffe-id")
@click.option("--key-type", type=click.Choice(["ec", "rsa"]), default="ec")
@click.option("--days", type=int)
@click.option("--out", type=click.Path(path_type=Path), default=Path("."))
def cert_request(server, api_key, api_key_file, cn, san, spiffe_id, key_type, days, out):
    """Generate a key locally, submit a CSR, write tls.key / tls.crt."""
    api_key = _resolve_key(api_key, api_key_file)
    key_pem, csr = _key_and_csr(cn, list(san), spiffe_id, key_type)
    r = _client(server, api_key).post("/api/v1/certificates", json={"csr_pem": csr, "validity_days": days})
    if r.status_code == 202:
        click.echo(f"pending approval #{r.json()['approval_id']}")
        return
    if r.status_code != 201:
        click.echo(r.text, err=True)
        sys.exit(1)
    _write(out, key_pem, r.json())
    click.echo(f"issued serial {r.json()['serial']} valid until {r.json()['not_after']}")


@cert.command("renew-if-due")
@click.option("--server", envvar="CERTADILLO_SERVER", required=True)
@click.option("--api-key", envvar="CERTADILLO_API_KEY", help="prefer the CERTADILLO_API_KEY variable")
@click.option("--api-key-file", envvar="CERTADILLO_API_KEY_FILE", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--dir", "directory", type=click.Path(path_type=Path), default=Path("."))
@click.option("--fraction", default=0.33, help="renew when less than this share of lifetime remains")
@click.option("--force", is_flag=True)
def cert_renew(server, api_key, api_key_file, directory, fraction, force):
    """Renew with a new key once the certificate passes 2/3 of its lifetime,
    or earlier when the server's renewal window (ARI) says so, e.g. during a
    renewal campaign."""
    from cryptography import x509

    api_key = _resolve_key(api_key, api_key_file)

    meta = json.loads((directory / "meta.json").read_text())
    current = x509.load_pem_x509_certificate((directory / "tls.crt").read_bytes())
    now = datetime.now(timezone.utc)
    life = current.not_valid_after_utc - current.not_valid_before_utc
    left = current.not_valid_after_utc - now
    server_says = False
    try:
        info = _client(server, api_key).get(f"/api/v1/certificates/{meta['id']}/renewal-info")
        if info.status_code == 200 and info.json().get("renew_now"):
            server_says = True
            why = info.json().get("explanation_url")
            click.echo("the server asks for renewal now" + (f": {why}" if why else ""))
    except Exception:  # noqa: BLE001, S110 - an older server or a network blip: fall back to the lifetime rule
        pass
    if not force and not server_says and left > life * fraction:
        click.echo(f"not due: {left.days}d left of {life.days}d")
        return
    cn_attr = current.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    try:
        san = current.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        uris = [u for u in san.get_values_for_type(x509.UniformResourceIdentifier) if u.startswith("spiffe://")]
    except x509.ExtensionNotFound:
        dns, uris = [], []
    from cryptography.hazmat.primitives.asymmetric import ec

    key_type = "ec" if isinstance(current.public_key(), ec.EllipticCurvePublicKey) else "rsa"
    key_pem, csr = _key_and_csr(cn_attr[0].value if cn_attr else None, dns, uris[0] if uris else None, key_type)
    r = _client(server, api_key).post(f"/api/v1/certificates/{meta['id']}/renew", json={"csr_pem": csr})
    if r.status_code != 201:
        click.echo(r.text, err=True)
        sys.exit(1)
    _write(directory, key_pem, r.json())
    click.echo(f"renewed: serial {r.json()['serial']} valid until {r.json()['not_after']}")


if __name__ == "__main__":
    main()
