#!/usr/bin/env bash
# Restore from a backup dir produced by backup.sh:  ./infra/restore.sh backups/<timestamp>
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?usage: restore.sh backups/<timestamp>}"
COMPOSE="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"

echo "==> Restore Postgres from $SRC/postgres.sql.gz"
gunzip -c "$SRC/postgres.sql.gz" | $COMPOSE exec -T postgres psql -U "${POSTGRES_USER:-keystone}" "${POSTGRES_DB:-keystone}"

echo "==> Restore the S3 bucket from $SRC/s3"
$COMPOSE run --rm -v "$PWD/$SRC:/backup" aws s3 sync --only-show-errors /backup/s3 "s3://${KEYSTONE_S3_BUCKET:-keystone}"

echo "restore complete"
