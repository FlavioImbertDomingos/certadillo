"""Network TLS discovery. Finds certificates nobody told us about."""
from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from cryptography import x509

from certadillo.observability.metrics import DISCOVERY_SCANS

MAX_HOSTS = 1024


@dataclass
class ScanResult:
    target: str
    cert: x509.Certificate | None = None
    error: str | None = None


def expand_targets(targets: list[str], default_port: int = 443) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for t in targets:
        t = t.strip()
        if t.startswith("["):  # [ipv6]:port
            host, _, rest = t[1:].partition("]")
            p = int(rest[1:]) if rest.startswith(":") else default_port
        elif t.count(":") == 1:
            host, port = t.split(":")
            p = int(port)
        else:
            host, p = t, default_port
        if "/" in host:
            net = ipaddress.ip_network(host, strict=False)
            if net.num_addresses > MAX_HOSTS:
                raise ValueError(f"{host} is larger than {MAX_HOSTS} addresses; split the range")
            out.extend((str(ip), p) for ip in (net.hosts() if net.num_addresses > 2 else net))
        else:
            out.append((host, p))
    return out


def fetch_certificate(host: str, port: int, timeout: float = 4.0) -> x509.Certificate:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we are collecting, not trusting
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sni = None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            sni = host
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def scan(targets: list[str], workers: int = 32, timeout: float = 4.0) -> list[ScanResult]:
    pairs = expand_targets(targets)

    def one(pair):
        host, port = pair
        label = f"{host}:{port}"
        try:
            cert = fetch_certificate(host, port, timeout)
            DISCOVERY_SCANS.labels(result="found").inc()
            return ScanResult(label, cert=cert)
        except Exception as e:  # noqa: BLE001 - every failure is a scan result
            DISCOVERY_SCANS.labels(result="error").inc()
            return ScanResult(label, error=f"{type(e).__name__}: {e}")

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(pairs)))) as pool:
        return list(pool.map(one, pairs))
