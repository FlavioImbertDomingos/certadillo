output "url" {
  description = "The load balancer's DNS name; point var.base_url's host at it"
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "bootstrap_keys_secret_arn" {
  description = "First admin and approver API keys (JSON: admin, approver)"
  value       = aws_secretsmanager_secret.bootstrap.arn
}

output "key_passphrase_secret_arn" {
  description = "Back this up: it decrypts software keys and derives the integrity seal key"
  value       = aws_secretsmanager_secret.passphrase.arn
}

output "db_url_secret_arn" {
  value = aws_secretsmanager_secret.db_url.arn
}

output "task_security_group_id" {
  description = "Allow this group on anything Certadillo must reach (Vault, F5, CloudHSM, webhooks)"
  value       = aws_security_group.task.id
}

output "efs_file_system_id" {
  value = aws_efs_file_system.data.id
}

output "db_instance_identifier" {
  value = aws_db_instance.this.identifier
}
