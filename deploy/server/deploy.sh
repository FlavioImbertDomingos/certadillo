#!/usr/bin/env bash
# Deploy the committed tree to a Docker host over SSH.
#
#   deploy/server/deploy.sh root@154.53.47.199
#
# Optional environment:
#   BASE_URL   public URL written into certificates (AIA/CDP) and ACME links
#              default http://<host>:8080; set https://certadillo.com once the domain is live
#   SEED_DEMO  1 (default) loads demo data and a read-only viewer key on the first deploy
#   APP_DIR    install directory on the server, default /opt/certadillo
#   BIND       127.0.0.1 moves 8080 off the public interface once nginx fronts it
#              (also tells the app to trust nginx's X-Forwarded headers)
#   NO_BUILD   1 reuses the certadillo:server image already on the server
#   TRAEFIK_DOMAIN        serve through a Traefik that already runs on the server, e.g.
#                         TRAEFIK_DOMAIN=certadillo.com TRAEFIK_NETWORK=internal \
#                         TRAEFIK_CERTRESOLVER=traefikresolver deploy/server/deploy.sh root@host
#                         (sets BASE_URL=https://<domain> and BIND=127.0.0.1 unless given)
#
# Secrets are generated on the server into $APP_DIR/.env (mode 600) on the first
# run and never leave it, except the keys this script prints for you once.
# Re-run the script to ship a new commit; data and secrets are kept.
set -euo pipefail

TARGET=${1:?usage: deploy.sh user@host}
HOST=${TARGET#*@}
APP_DIR=${APP_DIR:-/opt/certadillo}
TRAEFIK_DOMAIN=${TRAEFIK_DOMAIN:-}
if [ -z "$TRAEFIK_DOMAIN" ]; then
  # later updates reuse the Traefik settings saved on the server
  while IFS='=' read -r k v; do
    case $k in
      CERTADILLO_DOMAIN) TRAEFIK_DOMAIN=$v ;;
      TRAEFIK_NETWORK) TRAEFIK_NETWORK=${TRAEFIK_NETWORK:-$v} ;;
      TRAEFIK_CERTRESOLVER) TRAEFIK_CERTRESOLVER=${TRAEFIK_CERTRESOLVER:-$v} ;;
    esac
  done < <(ssh "$TARGET" "grep -s -E '^(CERTADILLO_DOMAIN|TRAEFIK_NETWORK|TRAEFIK_CERTRESOLVER)=' '$APP_DIR/.env'" || true)
fi
if [ -n "$TRAEFIK_DOMAIN" ]; then
  : "${TRAEFIK_NETWORK:?set TRAEFIK_NETWORK to the Docker network Traefik uses}"
  : "${TRAEFIK_CERTRESOLVER:?set TRAEFIK_CERTRESOLVER to an ACME resolver defined in Traefik}"
  BASE_URL=${BASE_URL:-https://$TRAEFIK_DOMAIN}
  BIND=${BIND:-127.0.0.1}
fi
BASE_URL=${BASE_URL:-http://$HOST:8080}
SEED_DEMO=${SEED_DEMO:-1}

cd "$(git rev-parse --show-toplevel)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "You have uncommitted changes. Commit them first: the server gets the committed tree only." >&2
  exit 1
fi
REV=$(git rev-parse --short HEAD)

echo "==> Checking $TARGET"
ssh "$TARGET" 'command -v docker >/dev/null && docker compose version >/dev/null' || {
  echo "Docker with the compose plugin is required on the server." >&2; exit 1; }
ssh "$TARGET" "if ss -ltnp 2>/dev/null | grep -q ':8080 ' && ! docker ps --format '{{.Names}}' | grep -q '^certadillo-certadillo'; then
  echo 'Port 8080 is already used by another program on the server:' >&2; ss -ltnp | grep ':8080 ' >&2; exit 1; fi"

echo "==> Uploading $REV to $APP_DIR/releases/$REV"
git archive --format=tar HEAD | ssh "$TARGET" "set -e
  mkdir -p '$APP_DIR/releases/$REV'
  tar -x -C '$APP_DIR/releases/$REV'
  ln -sfn '$APP_DIR/releases/$REV' '$APP_DIR/app'"

echo "==> Building and starting (first build takes a few minutes)"
ssh "$TARGET" "APP_DIR='$APP_DIR' REV='$REV' BASE_URL='$BASE_URL' BIND='${BIND:-}' NO_BUILD='${NO_BUILD:-0}' \
  TRAEFIK_DOMAIN='$TRAEFIK_DOMAIN' TRAEFIK_NETWORK='${TRAEFIK_NETWORK:-}' TRAEFIK_CERTRESOLVER='${TRAEFIK_CERTRESOLVER:-}' bash -s" <<'REMOTE'
set -euo pipefail
cd "$APP_DIR"
umask 077
gen() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40; }
if [ ! -f .env ]; then
  cat > .env <<EOF
POSTGRES_PASSWORD=$(gen)
CERTADILLO_KEY_PASSPHRASE=$(gen)
CERTADILLO_BOOTSTRAP_ADMIN_KEY=cdl_$(gen)
CERTADILLO_BOOTSTRAP_APPROVER_KEY=cdl_$(gen)
CERTADILLO_BASE_URL=$BASE_URL
CERTADILLO_ORG_NAME="Example Bank"
EOF
  echo "created $APP_DIR/.env with new secrets"
fi
set_env() { if grep -q "^$1=" .env; then sed -i "s#^$1=.*#$1=$2#" .env; else echo "$1=$2" >> .env; fi; }
set_env CERTADILLO_BASE_URL "$BASE_URL"
if [ -n "$BIND" ]; then
  set_env CERTADILLO_BIND "$BIND"
  if [ "$BIND" = "127.0.0.1" ]; then set_env FORWARDED_ALLOW_IPS '*'; else set_env FORWARDED_ALLOW_IPS 127.0.0.1; fi
fi
if [ -n "$TRAEFIK_DOMAIN" ]; then
  docker network inspect "$TRAEFIK_NETWORK" >/dev/null || { echo "Docker network $TRAEFIK_NETWORK not found" >&2; exit 1; }
  set_env CERTADILLO_DOMAIN "$TRAEFIK_DOMAIN"
  set_env TRAEFIK_NETWORK "$TRAEFIK_NETWORK"
  set_env TRAEFIK_CERTRESOLVER "$TRAEFIK_CERTRESOLVER"
fi
F="-f app/deploy/server/docker-compose.yml"
grep -q '^CERTADILLO_DOMAIN=' .env && F="$F -f app/deploy/server/docker-compose.traefik.yml"
# back up the database before an upgrade; the five newest dumps are kept
if docker ps --format '{{.Names}}' | grep -q '^certadillo-postgres-1$'; then
  mkdir -p backups
  docker exec certadillo-postgres-1 pg_dump -U certadillo certadillo | gzip > "backups/pre-$REV.sql.gz"
  echo "database backed up to $APP_DIR/backups/pre-$REV.sql.gz"
  ls -1t backups/pre-*.sql.gz | tail -n +6 | xargs -r rm -f
fi
BUILD=--build; [ "$NO_BUILD" = "1" ] && BUILD=
docker compose $F --env-file .env -p certadillo up -d $BUILD
for _ in $(seq 90); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/healthz && echo
# keep the five newest releases
ls -1dt releases/* 2>/dev/null | tail -n +6 | xargs -r rm -rf
REMOTE

if [ "$SEED_DEMO" = "1" ]; then
  echo "==> Demo data"
  ssh "$TARGET" "APP_DIR='$APP_DIR' bash -s" <<'REMOTE'
set -euo pipefail
cd "$APP_DIR"
if [ -f .seeded ]; then echo "already loaded"; exit 0; fi
val() { grep "^$1=" .env | cut -d= -f2-; }
F="-f app/deploy/server/docker-compose.yml"
grep -q '^CERTADILLO_DOMAIN=' .env && F="$F -f app/deploy/server/docker-compose.traefik.yml"
C="docker compose $F --env-file .env -p certadillo"
$C exec -T certadillo python - --server http://127.0.0.1:8080 \
  --admin-key "$(val CERTADILLO_BOOTSTRAP_ADMIN_KEY)" --approver-key "$(val CERTADILLO_BOOTSTRAP_APPROVER_KEY)" \
  < app/scripts/demo_seed.py
VIEWER=$($C exec -T certadillo certadillo principal recruiter-viewer --role auditor </dev/null | tail -n 1)
umask 077
echo "CERTADILLO_VIEWER_KEY=$VIEWER" >> .env
touch .seeded
echo "loaded"
REMOTE
fi

echo "==> Keys (also stored in $APP_DIR/.env on the server)"
ssh "$TARGET" "grep -E '^CERTADILLO_(BOOTSTRAP_ADMIN|BOOTSTRAP_APPROVER|VIEWER)_KEY=' '$APP_DIR/.env'" || true

cat <<EOF

Done: $REV is live.
  Console         $BASE_URL/
  Knowledge base  $BASE_URL/kb/
  API docs        $BASE_URL/docs
Share the VIEWER key for read-only access (auditor role). Keep the admin and approver keys to yourself.
EOF
