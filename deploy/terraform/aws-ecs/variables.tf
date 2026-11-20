variable "name" {
  description = "Prefix for every resource"
  type        = string
  default     = "certadillo"
}

variable "vpc_id" {
  description = "VPC to run in"
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets for the tasks, the database and EFS (at least two, in different AZs)"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Subnets for the load balancer (private ones too if the ALB is internal)"
  type        = list(string)
}

variable "internal_alb" {
  description = "Keep the load balancer off the internet (typical for an internal PKI)"
  type        = bool
  default     = true
}

variable "allowed_cidrs" {
  description = "Networks allowed to reach the load balancer on 443 (and 80 for OCSP/CRL over HTTP)"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate for the HTTPS listener"
  type        = string
}

variable "base_url" {
  description = "CERTADILLO_BASE_URL, e.g. https://pki.bank.example (published in AIA/CDP and ACME URLs)"
  type        = string
}

variable "org_name" {
  type    = string
  default = "Example Bank"
}

variable "image" {
  description = "Container image, pinned by digest (ghcr.io/flavioimbertdomingos/certadillo@sha256:...)"
  type        = string
}

variable "desired_count" {
  description = "Tasks; they share the database and an EFS data directory, and lease background work"
  type        = number
  default     = 2
}

variable "cpu" {
  type    = number
  default = 512
}

variable "memory" {
  type    = number
  default = 1024
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_engine_version" {
  type    = string
  default = "16"
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key for RDS, EFS, Secrets Manager and logs; empty uses AWS-managed keys"
  type        = string
  default     = ""
}

variable "cloudhsm_security_group_id" {
  description = "Security group of an AWS CloudHSM cluster; when set, tasks may reach it on 2223-2225. The image must include the CloudHSM PKCS#11 library (see the README)"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Extra CERTADILLO_* / OTEL_* settings for the server"
  type        = map(string)
  default     = {}
}

variable "log_retention_days" {
  type    = number
  default = 400
}

variable "tags" {
  type    = map(string)
  default = {}
}
