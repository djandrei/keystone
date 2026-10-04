#!/usr/bin/env bash
# Back up Postgres (SQL dump) and the S3 bucket (object sync) to ./backups/<timestamp>/.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="backups/$STAMP"; mkdir -p "$OUT"

echo "==> Postgres dump"
$COMPOSE exec -T postgres pg_dump -U "${POSTGRES_USER:-keystone}" "${POSTGRES_DB:-keystone}" | gzip > "$OUT/postgres.sql.gz"

echo "==> S3 bucket sync"
$COMPOSE run --rm -v "$PWD/$OUT:/backup" aws s3 sync --only-show-errors "s3://${KEYSTONE_S3_BUCKET:-keystone}" /backup/s3

echo "backup complete: $OUT"
