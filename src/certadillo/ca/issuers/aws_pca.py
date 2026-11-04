"""AWS Private CA (ACM PCA). IssueCertificate with the validity Certadillo's
policy decided, wait for the certificate, return it with its chain.
Credentials come from the standard AWS chain."""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization

PCA_REASONS = {"key_compromise": "KEY_COMPROMISE", "superseded": "SUPERSEDED", "affiliation_changed":
               "AFFILIATION_CHANGED", "cessation_of_operation": "CESSATION_OF_OPERATION",
               "privilege_withdrawn": "PRIVILEGE_WITHDRAWN"}


class AwsPcaIssuer:
    def __init__(self, name: str, cfg: dict, settings=None):
        for k in ("ca_arn", "region"):
            if not cfg.get(k):
                raise ValueError(f"issuer {name}: aws-pca needs {k}")
        self.name, self.cfg = name, cfg

    def _client(self):
        import boto3

        return boto3.client("acm-pca", region_name=self.cfg["region"])

    def sign(self, csr, decision):
        pca = self._client()
        alg = self.cfg.get("signing_algorithm", "SHA256WITHECDSA")
        kwargs = {"CertificateAuthorityArn": self.cfg["ca_arn"],
                  "Csr": csr.public_bytes(serialization.Encoding.PEM), "SigningAlgorithm": alg,
                  "Validity": {"Value": max(1, decision.validity.days), "Type": "DAYS"}}
        if self.cfg.get("template_arn"):
            kwargs["TemplateArn"] = self.cfg["template_arn"]
        arn = pca.issue_certificate(**kwargs)["CertificateArn"]
        pca.get_waiter("certificate_issued").wait(CertificateAuthorityArn=self.cfg["ca_arn"], CertificateArn=arn,
                                                  WaiterConfig={"Delay": 1, "MaxAttempts": 60})
        got = pca.get_certificate(CertificateAuthorityArn=self.cfg["ca_arn"], CertificateArn=arn)
        leaf = x509.load_pem_x509_certificate(got["Certificate"].encode())
        chain = x509.load_pem_x509_certificates(got["CertificateChain"].encode()) if got.get("CertificateChain") else []
        return leaf, chain, arn

    def revoke(self, serial_hex: str, reason: str, ref: str | None = None, cert_pem: str | None = None) -> None:
        s = serial_hex.rjust(len(serial_hex) + len(serial_hex) % 2, "0")
        self._client().revoke_certificate(CertificateAuthorityArn=self.cfg["ca_arn"],
                                          CertificateSerial=":".join(s[i:i + 2] for i in range(0, len(s), 2)),
                                          RevocationReason=PCA_REASONS.get(reason, "UNSPECIFIED"))
