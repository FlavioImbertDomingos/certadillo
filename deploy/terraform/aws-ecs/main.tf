# Certadillo on AWS: ECS Fargate behind an ALB, RDS PostgreSQL, an EFS data
# directory shared by the tasks, secrets in Secrets Manager, logs in
# CloudWatch. See README.md.

data "aws_region" "current" {}

locals {
  kms       = var.kms_key_arn != "" ? var.kms_key_arn : null
  tags      = merge({ "app" = "certadillo" }, var.tags)
  data_dir  = "/var/lib/certadillo"
  db_name   = "certadillo"
  db_user   = "certadillo_owner"
  log_group = "/ecs/${var.name}"
  base_env = merge({
    CERTADILLO_BASE_URL     = var.base_url
    CERTADILLO_ORG_NAME     = var.org_name
    CERTADILLO_DATA_DIR     = local.data_dir
    CERTADILLO_EGRESS_ALLOW = ""
  }, var.environment)
}

# ------------------------------------------------------------------ network
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Certadillo load balancer"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description = "HTTPS: API, console, ACME, EST, SCEP, CMP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  ingress {
    description = "HTTP: CRL and OCSP for relying parties (everything else redirects)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "Certadillo tasks"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description     = "from the load balancer"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  # Outbound HTTP is narrowed by CERTADILLO_EGRESS_ALLOW in the application;
  # tighten this too if your VPC routes the internet through a proxy.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  description = "Certadillo database"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "efs" {
  name_prefix = "${var.name}-efs-"
  description = "Certadillo data directory"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group_rule" "cloudhsm" {
  count                    = var.cloudhsm_security_group_id != "" ? 1 : 0
  description              = "Certadillo tasks to the CloudHSM cluster"
  type                     = "ingress"
  from_port                = 2223
  to_port                  = 2225
  protocol                 = "tcp"
  security_group_id        = var.cloudhsm_security_group_id
  source_security_group_id = aws_security_group.task.id
}

# ------------------------------------------------------------------ secrets
resource "random_password" "db" {
  length  = 40
  special = false
}

resource "random_password" "passphrase" {
  length  = 48
  special = false
}

resource "random_password" "admin_key" {
  length  = 48
  special = false
}

resource "random_password" "approver_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "db_url" {
  name_prefix = "${var.name}/db-url-"
  kms_key_id  = local.kms
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = "postgresql+psycopg://${local.db_user}:${random_password.db.result}@${aws_db_instance.this.address}:5432/${local.db_name}?sslmode=require"
}

resource "aws_secretsmanager_secret" "passphrase" {
  name_prefix = "${var.name}/key-passphrase-"
  description = "Encrypts software keys and derives the integrity seal key; losing it loses those keys"
  kms_key_id  = local.kms
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "passphrase" {
  secret_id     = aws_secretsmanager_secret.passphrase.id
  secret_string = random_password.passphrase.result
}

resource "aws_secretsmanager_secret" "bootstrap" {
  name_prefix = "${var.name}/bootstrap-keys-"
  description = "First admin and approver API keys; rotate after onboarding people through SSO"
  kms_key_id  = local.kms
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "bootstrap" {
  secret_id = aws_secretsmanager_secret.bootstrap.id
  secret_string = jsonencode({
    admin    = "cdl_${random_password.admin_key.result}"
    approver = "cdl_${random_password.approver_key.result}"
  })
}

# ------------------------------------------------------------------ database
resource "aws_db_subnet_group" "this" {
  name_prefix = "${var.name}-"
  subnet_ids  = var.private_subnet_ids
  tags        = local.tags
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg${var.db_engine_version}-"
  family      = "postgres${var.db_engine_version}"
  tags        = local.tags
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_db_instance" "this" {
  identifier_prefix               = "${var.name}-"
  engine                          = "postgres"
  engine_version                  = var.db_engine_version
  instance_class                  = var.db_instance_class
  allocated_storage               = var.db_allocated_storage
  max_allocated_storage           = var.db_allocated_storage * 4
  storage_type                    = "gp3"
  storage_encrypted               = true
  kms_key_id                      = local.kms
  db_name                         = local.db_name
  username                        = local.db_user
  password                        = random_password.db.result
  db_subnet_group_name            = aws_db_subnet_group.this.name
  parameter_group_name            = aws_db_parameter_group.this.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  multi_az                        = var.db_multi_az
  backup_retention_period         = 35
  deletion_protection             = var.db_deletion_protection
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.name}-final"
  copy_tags_to_snapshot           = true
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = true
  performance_insights_kms_key_id = local.kms
  enabled_cloudwatch_logs_exports = ["postgresql"]
  tags                            = local.tags
}

# ------------------------------------------------------------------ data directory
resource "aws_efs_file_system" "data" {
  creation_token = "${var.name}-data"
  encrypted      = true
  kms_key_id     = local.kms
  tags           = merge(local.tags, { Name = "${var.name}-data" })
}

resource "aws_efs_backup_policy" "data" {
  file_system_id = aws_efs_file_system.data.id
  backup_policy { status = "ENABLED" }
}

resource "aws_efs_mount_target" "data" {
  for_each        = toset(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.data.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "data" {
  file_system_id = aws_efs_file_system.data.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/certadillo"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0700"
    }
  }
  tags = local.tags
}

# ------------------------------------------------------------------ IAM
data "aws_iam_policy_document" "assume_tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.assume_tasks.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.db_url.arn, aws_secretsmanager_secret.passphrase.arn,
    aws_secretsmanager_secret.bootstrap.arn]
  }
  dynamic "statement" {
    for_each = local.kms == null ? [] : [1]
    content {
      actions   = ["kms:Decrypt"]
      resources = [local.kms]
    }
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  name_prefix = "secrets-"
  role        = aws_iam_role.execution.id
  policy      = data.aws_iam_policy_document.execution_secrets.json
}

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.assume_tasks.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task" {
  statement {
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
    resources = [aws_efs_file_system.data.arn]
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.data.arn]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name_prefix = "efs-"
  role        = aws_iam_role.task.id
  policy      = data.aws_iam_policy_document.task.json
}

# ------------------------------------------------------------------ ECS
resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms
  tags              = local.tags
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}

locals {
  secrets = [
    { name = "CERTADILLO_DB_URL", valueFrom = aws_secretsmanager_secret.db_url.arn },
    { name = "CERTADILLO_KEY_PASSPHRASE", valueFrom = aws_secretsmanager_secret.passphrase.arn },
  ]
  hardened = {
    readonlyRootFilesystem = true
    user                   = "10001:10001"
    linuxParameters        = { capabilities = { drop = ["ALL"] }, initProcessEnabled = true }
    mountPoints = [
      { sourceVolume = "data", containerPath = local.data_dir, readOnly = false },
      { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = "certadillo"
      }
    }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.data.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.data.id
        iam             = "ENABLED"
      }
    }
  }
  volume {
    name = "tmp"
  }
  container_definitions = jsonencode([
    merge(local.hardened, {
      # runs to completion before the server starts; concurrent tasks wait on
      # a PostgreSQL advisory lock, so only one migrates
      name        = "migrate"
      image       = var.image
      essential   = false
      command     = ["db", "migrate"]
      environment = [for k, v in local.base_env : { name = k, value = v } if v != ""]
      secrets     = local.secrets
    }),
    merge(local.hardened, {
      name         = "certadillo"
      image        = var.image
      essential    = true
      command      = ["serve", "--port", "8080"]
      dependsOn    = [{ containerName = "migrate", condition = "SUCCESS" }]
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      environment = [for k, v in merge(local.base_env, { CERTADILLO_DB_AUTO_MIGRATE = "false" }) :
      { name = k, value = v } if v != ""]
      secrets = concat(local.secrets, [
        { name = "CERTADILLO_BOOTSTRAP_ADMIN_KEY", valueFrom = "${aws_secretsmanager_secret.bootstrap.arn}:admin::" },
        { name = "CERTADILLO_BOOTSTRAP_APPROVER_KEY", valueFrom = "${aws_secretsmanager_secret.bootstrap.arn}:approver::" },
      ])
      healthCheck = {
        command     = ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }),
  ])
  tags = local.tags
}

resource "aws_lb" "this" {
  name_prefix                = substr(var.name, 0, 6)
  load_balancer_type         = "application"
  internal                   = var.internal_alb
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  tags                       = local.tags
}

resource "aws_lb_target_group" "this" {
  name_prefix = substr(var.name, 0, 6)
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path    = "/readyz"
    matcher = "200"
  }
  deregistration_delay = 20
  tags                 = local.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# CRLs, CA certificates and OCSP are fetched over plain HTTP by relying parties
# (RFC 5280, RFC 6960); they are signed, so TLS adds nothing and breaks loops.
resource "aws_lb_listener_rule" "pki_http" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
  condition {
    path_pattern { values = ["/pki/*"] }
  }
}

resource "aws_ecs_service" "this" {
  name                               = var.name
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  enable_execute_command             = false
  propagate_tags                     = "SERVICE"
  health_check_grace_period_seconds  = 90
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "certadillo"
    container_port   = 8080
  }
  depends_on = [aws_lb_listener.https, aws_efs_mount_target.data]
  tags       = local.tags
}
