#!/usr/bin/env bash
# Encrypted backup of a Certadillo server: the database and the data volume
# (CA keys, which are already encrypted with the key passphrase, OCSP and audit
# signing keys, ceremony state), in one file encrypted to an age public key.
#
#   /opt/certadillo/app/deploy/server/backup.sh            # from cron or a systemd timer
#
# Settings come from /opt/certadillo/.env (or the environment):
#   BACKUP_AGE_RECIPIENTS  one or more age public keys (age1...), comma-separated. Required.
#                          The matching private keys stay off this server: keep one with the
#                          PKI team and one in the safe with the root key media.
#   BACKUP_KEEP            encrypted backups kept locally, default 14
#   BACKUP_COPY_CMD        optional command that ships the file off the host; {} is replaced by
#                          its path, e.g.  aws s3 cp {} s3://bank-pki-backups/certadillo/
#                          (a bucket with Object Lock), or  rclone copy {} offsite:certadillo
#
# Restore: decrypt on a workstation that holds a private key and stream the
# plaintext to the server, so the key never touches it:
#   age -d -i backup-key.txt certadillo-<stamp>.tar.age | ssh root@host /opt/certadillo/app/deploy/server/restore.sh
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/certadillo}
PROJECT=${COMPOSE_PROJECT:-certadillo}
cd "$APP_DIR"
if [ -f .env ]; then
  while IFS='=' read -r k v; do
    case $k in
      BACKUP_AGE_RECIPIENTS|BACKUP_KEEP|BACKUP_COPY_CMD) [ -z "${!k:-}" ] && export "$k=$v" ;;
    esac
  done < <(grep -E '^(BACKUP_AGE_RECIPIENTS|BACKUP_KEEP|BACKUP_COPY_CMD)=' .env || true)
fi
: "${BACKUP_AGE_RECIPIENTS:?set BACKUP_AGE_RECIPIENTS to the age public key(s) backups are encrypted to}"
KEEP=${BACKUP_KEEP:-14}
command -v age >/dev/null || { echo "age is not installed (apt-get install age)" >&2; exit 1; }

RECIPIENTS=()
IFS=',' read -ra keys <<< "$BACKUP_AGE_RECIPIENTS"
for r in "${keys[@]}"; do
  r=$(echo "$r" | tr -d '[:space:]')
  [[ $r == age1* ]] || { echo "not an age public key: $r" >&2; exit 1; }
  RECIPIENTS+=(-r "$r")
done

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
chmod 700 backups
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
umask 077

# plaintext only ever exists in a private temporary directory, and is removed on exit
docker exec "$PROJECT-postgres-1" pg_dump -U certadillo -Fc certadillo > "$WORK/db.dump"
docker exec "$PROJECT-certadillo-1" tar -C /var/lib/certadillo -cf - . > "$WORK/data.tar"
REV=$(basename "$(readlink -f app 2>/dev/null || echo unknown)")
{
  echo "created=$STAMP"
  echo "revision=$REV"
  (cd "$WORK" && sha256sum db.dump data.tar)
} > "$WORK/MANIFEST"
OUT="backups/certadillo-$STAMP.tar.age"
tar -C "$WORK" -cf - MANIFEST db.dump data.tar | age "${RECIPIENTS[@]}" -o "$OUT.partial"
mv "$OUT.partial" "$OUT"
echo "encrypted backup: $APP_DIR/$OUT ($(du -h "$OUT" | cut -f1))"

if [ -n "${BACKUP_COPY_CMD:-}" ]; then
  cmd=${BACKUP_COPY_CMD//\{\}/$APP_DIR/$OUT}
  bash -c "$cmd"
  echo "copied off the host"
fi
ls -1t backups/certadillo-*.tar.age 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f
