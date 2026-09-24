"""A stand-in for the domain-joined AD CS gateway worker.

Signs a claimed CSR with a throwaway CA (playing the Microsoft CA) so the
gateway round trip can be tested without a real AD CS. Mirrors what the
PowerShell gateway does: claim, submit, post the certificate back.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class FakeMicrosoftCA:
    def __init__(self):
        self.key = rsa.generate_private_key(65537, 2048)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Issuing CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Issuing CA")]))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def issue(self, csr_pem: str) -> tuple[str, str]:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(csr.subject if list(csr.subject) else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adcs")]))
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        chain = self.cert.public_bytes(serialization.Encoding.PEM).decode()
        return pem, chain


def run_once(client, headers, ca: FakeMicrosoftCA, limit: int = 10) -> list[dict]:
    """Claim pending jobs and complete them, like one poll of the worker."""
    claimed = client.post(f"/api/v1/adcs/gateway/jobs/claim?limit={limit}", headers=headers).json()["jobs"]
    done = []
    for job in claimed:
        if job["type"] == "issue":
            pem, chain = ca.issue(job["csr_pem"])
            r = client.post(f"/api/v1/adcs/gateway/jobs/{job['id']}/complete",
                            json={"certificate_pem": pem, "chain_pem": chain}, headers=headers)
        elif job["type"] == "revoke":
            r = client.post(f"/api/v1/adcs/gateway/jobs/{job['id']}/complete", json={}, headers=headers)
        else:
            r = client.post(f"/api/v1/adcs/gateway/jobs/{job['id']}/complete",
                            json={"certificates": []}, headers=headers)
        done.append(r.json())
    return done
