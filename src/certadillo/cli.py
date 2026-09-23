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
@click.option("--role", type=click.Choice(["admin", "approver", "operator", "auditor"]), required=True)
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
def audit_verify():
    """Verify the audit hash chain; exit 1 if broken."""
    from certadillo.audit.log import verify_chain
    from certadillo.runtime import init_runtime

    with init_runtime().platform() as p:
        res = verify_chain(p.s)
    click.echo(json.dumps(res))
    sys.exit(0 if res["valid"] else 1)


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


def _client(server, key):
    import httpx

    return httpx.Client(base_url=server, headers={"X-API-Key": key}, timeout=30)


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
    tmp.write_bytes(key_pem)
    os.chmod(tmp, 0o600)
    tmp.replace(kp)
    (out / "tls.crt").write_text(data["pem"] + data.get("chain_pem", ""))
    (out / "meta.json").write_text(json.dumps({k: data[k] for k in ("id", "serial", "not_before", "not_after")}, indent=2))


@cert.command("request")
@click.option("--server", envvar="CERTADILLO_SERVER", required=True)
@click.option("--api-key", envvar="CERTADILLO_API_KEY", required=True)
@click.option("--cn")
@click.option("--san", multiple=True)
@click.option("--spiffe-id")
@click.option("--key-type", type=click.Choice(["ec", "rsa"]), default="ec")
@click.option("--days", type=int)
@click.option("--out", type=click.Path(path_type=Path), default=Path("."))
def cert_request(server, api_key, cn, san, spiffe_id, key_type, days, out):
    """Generate a key locally, submit a CSR, write tls.key / tls.crt."""
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
@click.option("--api-key", envvar="CERTADILLO_API_KEY", required=True)
@click.option("--dir", "directory", type=click.Path(path_type=Path), default=Path("."))
@click.option("--fraction", default=0.33, help="renew when less than this share of lifetime remains")
@click.option("--force", is_flag=True)
def cert_renew(server, api_key, directory, fraction, force):
    """Renew with a new key once the certificate passes 2/3 of its lifetime."""
    from cryptography import x509

    meta = json.loads((directory / "meta.json").read_text())
    current = x509.load_pem_x509_certificate((directory / "tls.crt").read_bytes())
    now = datetime.now(timezone.utc)
    life = current.not_valid_after_utc - current.not_valid_before_utc
    left = current.not_valid_after_utc - now
    if not force and left > life * fraction:
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
