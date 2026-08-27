#!/usr/bin/env bash
# Generate a self-signed TLS cert for the production edge (dev/testing only —
# use a real CA / Let's Encrypt in production).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"
if [[ -f "$DIR/privkey.pem" && "${1:-}" != "--force" ]]; then
  echo "certs already exist in $DIR (use --force to regenerate)"; exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$DIR/privkey.pem" -out "$DIR/fullchain.pem" \
  -subj "/CN=keystone.local"
echo "wrote $DIR/{fullchain,privkey}.pem"
