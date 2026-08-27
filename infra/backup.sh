#!/usr/bin/env bash
# Back up Postgres (SQL dump) and MinIO (object mirror) to ./backups/<timestamp>/.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="backups/$STAMP"; mkdir -p "$OUT"

echo "==> Postgres dump"
$COMPOSE exec -T postgres pg_dump -U "${POSTGRES_USER:-keystone}" "${POSTGRES_DB:-keystone}" | gzip > "$OUT/postgres.sql.gz"

echo "==> MinIO mirror"
$COMPOSE run --rm -v "$PWD/$OUT:/backup" minio-init /bin/sh -c \
  "mc alias set k http://minio:9000 \$MINIO_ROOT_USER \$MINIO_ROOT_PASSWORD && mc mirror --overwrite k/\${KEYSTONE_S3_BUCKET:-keystone} /backup/minio"

echo "backup complete: $OUT"
