#!/usr/bin/env bash
# M1.1 smoke: the core stack is up and the API answers through nginx.
set -euo pipefail
BASE="${1:-http://localhost:8080}"
echo "checking $BASE/api/healthz ..."
for i in $(seq 1 30); do
  code=$(curl -sS -m3 -o /dev/null -w "%{http_code}" "$BASE/api/healthz" || true)
  [ "$code" = "200" ] && { curl -sS "$BASE/api/healthz"; echo; echo "OK"; exit 0; }
  sleep 2
done
echo "FAILED: /api/healthz not 200"; exit 1
