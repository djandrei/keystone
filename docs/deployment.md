# Keystone — Production Deployment

A one-command standalone deployment: built images, gunicorn (gevent, WebSocket-
capable), nginx + TLS at the edge, persistent Postgres + MinIO.

## 1. Prerequisites
- Docker + Docker Compose on the host.
- A DNS name pointing at the host (for real TLS).
- **ghidra-headless-mcp running on the same host** — its own repository and
  compose stack, set up first (§6). Keystone's worker joins its network and
  shares its samples directory.

## 2. Configure secrets
```bash
cp infra/.env.example infra/.env
```
Set strong values in `infra/.env` (never commit it):
- `KEYSTONE_JWT_SECRET` — long random string (signs access tokens).
- `POSTGRES_PASSWORD`, `MINIO_ROOT_PASSWORD`, `KEYSTONE_S3_SECRET_KEY`.
- `KEYSTONE_ADMIN_PASSWORD` — first-run admin password (change immediately after).
- `KEYSTONE_LLM_API_KEY` — the LLM endpoint key. **Deployment secret only** — never
  stored in the DB; the admin sets endpoint URL + default model at runtime.

## 3. TLS certificate
Drop a real cert at `infra/certs/{fullchain,privkey}.pem`, or for testing:
```bash
./infra/gen-certs.sh          # self-signed, CN=keystone.local
```

## 4. Bring it up
```bash
docker compose -f infra/docker-compose.prod.yml --env-file infra/.env up -d --build
```
Starts postgres, redis, minio (+ bucket init), backend (gunicorn), worker (celery)
and the nginx edge (TLS :443, HTTP→HTTPS on :80). Health-gated by `/readyz`.
ghidra-headless-mcp must already be up: the worker joins its network (§6).

## 5. First-run: migrate + bootstrap
```bash
C="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"
$C run --rm backend alembic upgrade head                    # migrations
$C run --rm backend python -m keystone_api.cli bootstrap    # settings + Default team + admin
```
Open `https://<host>/`, sign in as `admin` (password from `.env`), then **change the
admin password immediately**.

## 6. The analysis engine: ghidra-headless-mcp
Real RE/VR analyses run against **ghidra-headless-mcp**, a separate repository
with its own compose stack. Keystone does not start it; set it up first, on the
same host. The worker image already carries Semgrep for VR.

1. In `ghidra-headless-mcp` (checked out beside this repository): set
   `GHMCP_API_KEY` in its `.env`, keep `SAMPLES_DIR=./samples`, and
   `docker compose up -d`. Its compose network is named `ghidra-headless-mcp`.
2. Here, in `infra/.env`: `KEYSTONE_MCP_API_KEY` = that same key. If the two
   repositories are not side by side, also set `KEYSTONE_SAMPLES_DIR` (its
   samples directory, relative to `infra/`) and, if it renamed its network,
   `KEYSTONE_GHMCP_NETWORK`.
3. Bring Keystone up as in §4.

The worker calls it at the default `KEYSTONE_MCP_ENDPOINT`
(`http://ghidra-headless-mcp:1341`) over that network — never through a
published port. Uploaded binaries are written to its samples directory, which
both stacks mount at `/samples`, so the path the worker passes to
`analyze_binary` is the same file on both sides. Ghidra's projects are
ghidra-headless-mcp's to keep. For a demo without Ghidra/LLM,
`KEYSTONE_ENGINE_FAKE=1` on the worker drives the full path deterministically.

## 7. Backup & restore
```bash
./infra/backup.sh                       # -> backups/<timestamp>/ (pg dump + minio mirror)
./infra/restore.sh backups/<timestamp>  # restore both
```
Schedule `backup.sh` from cron. It covers the `pgdata` and `miniodata` volumes.
**Back up the shared samples directory too** (ghidra-headless-mcp's `samples/`):
every uploaded binary is also in MinIO, under `binaries/<sha256>`, but the worker
hands Ghidra the file in the samples directory and does not restore a missing one
from MinIO. Without that directory, existing binaries cannot be analysed until
they are uploaded again.

## 8. Upgrades
```bash
git pull
$C up -d --build
$C run --rm backend alembic upgrade head   # apply new migrations (never edit shipped ones)
```

## 9. Operations
- **Health:** `/api/healthz` (liveness), `/api/readyz` (DB/Redis/S3), `/api/metrics`
  (admin: analyses by status, durations).
- **Logs:** structured JSON to stdout — `docker compose ... logs -f backend worker`.
- **Errors:** set `KEYSTONE_SENTRY_DSN` for a Sentry-compatible tracker.
- **Rate limits:** login/token/upload throttled per IP; tune via `RATELIMIT_*`.
- **Scale:** raise worker `--concurrency`; add `backend` replicas behind nginx.
