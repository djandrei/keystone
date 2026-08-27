#!/usr/bin/env bash
# Restore from a backup dir produced by backup.sh:  ./infra/restore.sh backups/<timestamp>
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?usage: restore.sh backups/<timestamp>}"
COMPOSE="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"

echo "==> Restore Postgres from $SRC/postgres.sql.gz"
gunzip -c "$SRC/postgres.sql.gz" | $COMPOSE exec -T postgres psql -U "${POSTGRES_USER:-keystone}" "${POSTGRES_DB:-keystone}"

echo "==> Restore MinIO from $SRC/minio"
$COMPOSE run --rm -v "$PWD/$SRC:/backup" minio-init /bin/sh -c \
  "mc alias set k http://minio:9000 \$MINIO_ROOT_USER \$MINIO_ROOT_PASSWORD && mc mirror --overwrite /backup/minio k/\${KEYSTONE_S3_BUCKET:-keystone}"

echo "restore complete"
