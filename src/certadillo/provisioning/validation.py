"""After an install, connect to the endpoint the way a client would and check
it serves the certificate that was just issued. Load balancers and web servers
can accept a new file and keep serving the old one until reloaded; this is how
that is caught."""
from __future__ import annotations

import socket
import ssl
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def served_fingerprint(endpoint: str, server_name: str, timeout: float = 5.0) -> str:
    host, _, port = endpoint.rpartition(":")
    host = host.strip("[]") or endpoint
    ctx = ssl.create_default_context()
    # We compare the exact certificate, so chain trust is not what is being checked here.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port or 443)), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()).hex()


def wait_until_served(endpoint: str, server_name: str, expected_fp: str, attempts: int = 5,
                      delay: float = 1.0, confirmations: int = 3) -> tuple[bool, str]:
    """True once `confirmations` connections in a row see the new certificate.
    One match is not enough: during a graceful reload old workers keep serving
    for a moment, and behind a load balancer each connection may hit another node."""
    last = ""
    streak = 0
    for i in range(attempts * confirmations):
        try:
            last = served_fingerprint(endpoint, server_name)
        except OSError as exc:
            last = f"connection failed: {exc}"
        if last == expected_fp:
            streak += 1
            if streak >= confirmations:
                return True, last
            time.sleep(min(delay, 0.5))
            continue
        streak = 0
        if i < attempts * confirmations - 1:
            time.sleep(delay)
    return False, last
