# terraform test: applies the module against mocked providers (no AWS account)
# and checks the security properties that matter.
mock_provider "aws" {
  # resources whose ARNs other resources validate
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/certadillo-mock" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/mock/1" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/mock/1" }
  }
  mock_resource "aws_lb_listener" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/mock/1/1" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:certadillo/mock" }
  }
  mock_resource "aws_efs_file_system" {
    defaults = { arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-mock", id = "fs-mock" }
  }
  mock_resource "aws_efs_access_point" {
    defaults = { arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-mock", id = "fsap-mock" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/certadillo:1" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/certadillo", id = "arn:aws:ecs:us-east-1:123456789012:cluster/certadillo" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}
mock_provider "random" {}

variables {
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-a", "subnet-b"]
  public_subnet_ids  = ["subnet-a", "subnet-b"]
  allowed_cidrs      = ["10.0.0.0/8"]
  certificate_arn    = "arn:aws:acm:us-east-1:123456789012:certificate/test"
  base_url           = "https://pki.bank.example"
  image              = "ghcr.io/flavioimbertdomingos/certadillo@sha256:abc"
}

run "secure_defaults" {
  command = apply

  assert {
    condition     = aws_db_instance.this.storage_encrypted && aws_db_instance.this.deletion_protection && aws_db_instance.this.multi_az
    error_message = "the database must be encrypted, protected from deletion and multi-AZ by default"
  }
  assert {
    condition     = aws_efs_file_system.data.encrypted
    error_message = "the data directory holds keys and must be encrypted"
  }
  assert {
    condition     = aws_efs_access_point.data.posix_user[0].uid == 10001 && aws_efs_access_point.data.root_directory[0].creation_info[0].permissions == "0700"
    error_message = "the data directory belongs to the image's user and nobody else"
  }
  assert {
    condition     = aws_lb.this.internal && aws_lb.this.drop_invalid_header_fields
    error_message = "the load balancer is internal and drops malformed headers by default"
  }
  assert {
    condition     = aws_lb_listener.https.ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "TLS 1.2 or later only"
  }
  assert {
    condition     = alltrue([for c in jsondecode(aws_ecs_task_definition.this.container_definitions) : c.readonlyRootFilesystem && c.user == "10001:10001" && contains(c.linuxParameters.capabilities.drop, "ALL")])
    error_message = "every container runs read-only, as uid 10001, with no capabilities"
  }
  assert {
    condition     = [for c in jsondecode(aws_ecs_task_definition.this.container_definitions) : c.name] == ["migrate", "certadillo"]
    error_message = "a migrate container runs before the server"
  }
  assert {
    condition = contains([for e in jsondecode(aws_ecs_task_definition.this.container_definitions)[1].environment : "${e.name}=${e.value}"],
    "CERTADILLO_DB_AUTO_MIGRATE=false")
    error_message = "the server must not run DDL; the migrate container does"
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.this.container_definitions)[1].dependsOn[0].condition == "SUCCESS"
    error_message = "the server starts only after the migration succeeded"
  }
  assert {
    condition     = aws_ecs_service.this.deployment_circuit_breaker[0].rollback
    error_message = "a failed deployment rolls back"
  }
}

run "cloudhsm_access_is_opt_in" {
  command = apply
  variables {
    cloudhsm_security_group_id = "sg-0hsm"
  }
  assert {
    condition     = length(aws_security_group_rule.cloudhsm) == 1 && aws_security_group_rule.cloudhsm[0].from_port == 2223
    error_message = "tasks reach CloudHSM on 2223-2225 only when a cluster is given"
  }
}
