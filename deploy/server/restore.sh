#!/usr/bin/env bash
# Restore a decrypted backup made by backup.sh. Reads the plaintext tar on
# stdin, so the age private key can stay on the workstation:
#
#   age -d -i backup-key.txt certadillo-<stamp>.tar.age | ssh root@host /opt/certadillo/app/deploy/server/restore.sh
#
# It checks the manifest hashes, stops the application, restores the data
# volume and the database, and starts it again. Run it on a server where
# deploy.sh has already set up the stack (same CERTADILLO_KEY_PASSPHRASE in
# .env, or the CA keys in the backup cannot be opened).
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/certadillo}
PROJECT=${COMPOSE_PROJECT:-certadillo}
cd "$APP_DIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
umask 077
tar -C "$WORK" -xf - MANIFEST db.dump data.tar
(cd "$WORK" && grep -E '^[0-9a-f]{64}  ' MANIFEST | sha256sum -c --quiet) || { echo "manifest hashes do not match" >&2; exit 1; }
grep -E '^(created|revision)=' "$WORK/MANIFEST"

F="-f app/deploy/server/docker-compose.yml"
grep -q '^CERTADILLO_DOMAIN=' .env && F="$F -f app/deploy/server/docker-compose.traefik.yml"
docker compose $F --env-file .env -p "$PROJECT" stop certadillo
# the data volume, through a throwaway container (the app's own root filesystem is read-only)
docker run --rm -i -v "${PROJECT}_cadata:/data" --entrypoint sh certadillo:server \
  -c 'find /data -mindepth 1 -delete && tar -C /data -xf -' < "$WORK/data.tar"
docker exec -i "$PROJECT-postgres-1" pg_restore -U certadillo -d certadillo --clean --if-exists --no-owner < "$WORK/db.dump"
docker compose $F --env-file .env -p "$PROJECT" start certadillo
for _ in $(seq 60); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/healthz && echo
echo "restored; run 'docker exec $PROJECT-certadillo-1 certadillo audit verify' and 'certadillo integrity check'"
