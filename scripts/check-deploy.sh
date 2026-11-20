#!/usr/bin/env bash
# Validate the Helm chart and the Terraform module (needs helm, kubeconform, terraform).
#   bash scripts/check-deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
chart=deploy/helm/certadillo
k8s=1.31.0

helm lint "$chart"
validate() { helm template ci "$chart" "$@" | kubeconform -strict -summary -kubernetes-version "$k8s"; }
validate
validate --set replicaCount=3,persistence.accessMode=ReadWriteMany --set ingress.enabled=true,ingress.tlsSecret=tls \
  --set networkPolicy.enabled=true --set-string 'policies=profiles: {}' --set env.CERTADILLO_TRACING=otlp \
  --set database.migrationJob.ownerSecretKey=owner-db-url --set image.digest=sha256:0123
validate --set database.migrationJob.enabled=false --set persistence.enabled=false
# several replicas on a ReadWriteOnce volume must be refused, not deployed
if helm template ci "$chart" --set replicaCount=2 >/dev/null 2>&1; then
  echo "the chart accepted replicaCount=2 with a ReadWriteOnce volume" >&2; exit 1
fi
# the server never runs DDL when the migration job does
helm template ci "$chart" | grep -A1 'name: CERTADILLO_DB_AUTO_MIGRATE' | grep -q '"false"'

tf=deploy/terraform/aws-ecs
terraform -chdir="$tf" fmt -check -recursive
terraform -chdir="$tf" init -backend=false -input=false >/dev/null
terraform -chdir="$tf" validate
terraform -chdir="$tf" test
terraform -chdir="$tf/examples/basic" init -backend=false -input=false >/dev/null
terraform -chdir="$tf/examples/basic" validate
echo "deploy checks passed"
