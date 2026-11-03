"""AWS Certificate Manager: import, then re-import into the same ARN on every
renewal so load balancers and CloudFront that reference it pick it up without
a change. Credentials come from the standard AWS chain (instance role, IRSA,
environment); credential_ref is not used."""
from __future__ import annotations

import re

from certadillo.provisioning.drivers import register
from certadillo.provisioning.drivers.base import Driver, InstallBundle, ProvisioningError

ARN = re.compile(r"^arn:aws[a-z-]*:acm:[a-z0-9-]+:\d{12}:certificate/[0-9a-f-]+$")


@register
class AwsAcmDriver(Driver):
    kind = "aws-acm"

    @classmethod
    def check_config(cls, config: dict) -> dict:
        cls.require(config, "region")
        return config

    def check_params(self, params: dict) -> dict:
        arn = params.get("certificate_arn")
        if arn is not None and not ARN.match(arn):
            raise ValueError("certificate_arn is not an ACM certificate ARN")
        return {"certificate_arn": arn}

    def install(self, params: dict, bundle: InstallBundle) -> dict:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        if bundle.key_pem is None:
            raise ProvisioningError("ACM needs a centrally generated key")
        acm = boto3.client("acm", region_name=self.config["region"])
        kwargs = {"Certificate": bundle.cert_pem.encode(), "PrivateKey": bundle.key_pem,
                  "CertificateChain": bundle.chain_pem.encode()}
        if params.get("certificate_arn"):
            kwargs["CertificateArn"] = params["certificate_arn"]
        else:
            kwargs["Tags"] = [{"Key": "managed-by", "Value": "certadillo"}]
        try:
            arn = acm.import_certificate(**kwargs)["CertificateArn"]
        except (BotoCoreError, ClientError) as exc:
            raise ProvisioningError(f"ACM import failed: {exc}") from None
        bundle.steps.append(("re-imported into " if params.get("certificate_arn") else "imported as ") + arn)
        return {"certificate_arn": arn}
