# Certadillo on AWS (ECS Fargate)

A Terraform module that runs Certadillo the way the rest of this repository
assumes production looks:

| Piece | What the module creates |
| --- | --- |
| Compute | ECS Fargate service (two tasks by default) in private subnets; every container read-only, uid 10001, no Linux capabilities |
| Schema | a `migrate` container in each task runs `certadillo db migrate` to completion before the server starts; concurrent tasks wait on a PostgreSQL advisory lock, and the server runs with `CERTADILLO_DB_AUTO_MIGRATE=false` |
| Database | RDS PostgreSQL 16, encrypted, multi-AZ, TLS forced, 35-day backups, deletion protection |
| Data directory | EFS, encrypted at rest and in transit, mounted through an access point owned by uid 10001 (mode 0700), IAM-authorized. Tasks share it: it holds the OCSP responder keys, the audit-shipping key and, with software signing, the CA keys |
| Secrets | Secrets Manager: the database URL, the key passphrase, the first admin and approver API keys |
| Load balancer | ALB, internal by default, TLS 1.2+ on 443; on 80 only `/pki/*` (CRLs, CA certificates, OCSP) is served, everything else redirects |
| Logs | CloudWatch, optionally with your KMS key |

Background work (CRL signing, alerts, push renewals, audit shipping) runs on
one task at a time through leases, so two or more tasks are safe.

```hcl
module "certadillo" {
  source             = "github.com/FlavioImbertDomingos/certadillo//deploy/terraform/aws-ecs"
  vpc_id             = "vpc-..."
  private_subnet_ids = ["subnet-...", "subnet-..."]
  public_subnet_ids  = ["subnet-...", "subnet-..."]
  allowed_cidrs      = ["10.0.0.0/8"]
  certificate_arn    = "arn:aws:acm:..."
  base_url           = "https://pki.bank.example"
  image              = "ghcr.io/flavioimbertdomingos/certadillo@sha256:..."
  environment = {
    CERTADILLO_EGRESS_ALLOW = "*.bank.example,hooks.slack.com"
  }
}
```

Pin the image by digest and verify it first (`cosign verify`, see
[SECURITY.md](../../../docs/SECURITY.md#supply-chain)). After `apply`, read the
first admin key from the `bootstrap_keys_secret_arn` output, onboard people
through single sign-on, and then rotate or remove the bootstrap keys. Back up
the key passphrase secret: without it, software keys and integrity seals
cannot be recovered.

## CA keys in AWS CloudHSM

Set `cloudhsm_security_group_id` so the tasks can reach the cluster, and add
the CloudHSM settings to `environment`:

```hcl
environment = {
  CERTADILLO_SIGNER      = "pkcs11"
  CERTADILLO_PKCS11_LIB  = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
  CERTADILLO_PKCS11_TOKEN = "hsm1"
}
```

The PIN (`user:password`) belongs in Secrets Manager; add it to the task
definition's secrets as `CERTADILLO_PKCS11_PIN`. The published image does not
include the CloudHSM client: build a small image `FROM` it that installs
`cloudhsm-pkcs11` and the cluster's CA certificate, and pass that image here.

## Testing

`terraform test` applies the module against mocked providers (no AWS account)
and checks its security defaults: encryption, the internal load balancer, TLS
policy, read-only non-root containers, the migrate-then-serve order, and the
opt-in CloudHSM rule. CI runs it with `terraform fmt -check` and `validate`.
