# terraform init && terraform plan, with your own VPC and certificate.
provider "aws" {
  region = "us-east-1"
}

module "certadillo" {
  source = "../.."

  name               = "certadillo"
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0aaa", "subnet-0bbb"]
  public_subnet_ids  = ["subnet-0aaa", "subnet-0bbb"] # internal ALB in the private subnets
  internal_alb       = true
  allowed_cidrs      = ["10.0.0.0/8"]
  certificate_arn    = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  base_url           = "https://pki.bank.example"
  org_name           = "Example Bank"
  image              = "ghcr.io/flavioimbertdomingos/certadillo@sha256:0000000000000000000000000000000000000000000000000000000000000000"

  environment = {
    CERTADILLO_EGRESS_ALLOW     = "*.bank.example,hooks.slack.com"
    CERTADILLO_TRACING          = "otlp"
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector.bank.internal:4318"
  }
}

output "alb" {
  value = module.certadillo.url
}
