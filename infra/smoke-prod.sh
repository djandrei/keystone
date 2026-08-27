#!/usr/bin/env bash
# Fresh prod-compose bring-up + first-run bootstrap smoke.
#   ./infra/smoke-prod.sh
set -euo pipefail
cd "$(dirname "$0")/.."
C="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"

./infra/gen-certs.sh
$C up -d --build

echo "==> waiting for backend"
until $C exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" 2>/dev/null; do sleep 3; done

$C run --rm backend alembic upgrade head
$C run --rm backend python -m keystone_api.cli bootstrap

echo "==> TLS smoke"
test "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/api/healthz)" = "200"
test "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/)" = "200"
test "$(curl -s  -o /dev/null -w '%{http_code}' http://localhost/)" = "301"
curl -sk -X POST https://localhost/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"'"${KEYSTONE_ADMIN_PASSWORD:-change-me}"'"}' | grep -q access_token

echo "PROD SMOKE OK"
