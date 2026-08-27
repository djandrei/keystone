# Keystone — Production Deployment

A one-command standalone deployment: built images, gunicorn (gevent, WebSocket-
capable), nginx + TLS at the edge, persistent Postgres + MinIO.

## 1. Prerequisites
- Docker + Docker Compose on the host.
- A DNS name pointing at the host (for real TLS).

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

## 5. First-run: migrate + bootstrap
```bash
C="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"
$C run --rm backend alembic upgrade head                    # migrations
$C run --rm backend python -m keystone_api.cli bootstrap    # settings + Default team + admin
```
Open `https://<host>/`, sign in as `admin` (password from `.env`), then **change the
admin password immediately**.

## 6. The analysis engine (optional)
The RE/VR engine needs `ghidra-headless-mcp` (and Semgrep for VR); pin and run it,
then point `KEYSTONE_MCP_ENDPOINT` at it. Without it the app runs but analyses can't
start. For a demo without Ghidra/LLM, `KEYSTONE_ENGINE_FAKE=1` on the worker drives
the full path deterministically.

## 7. Backup & restore
```bash
./infra/backup.sh                       # -> backups/<timestamp>/ (pg dump + minio mirror)
./infra/restore.sh backups/<timestamp>  # restore both
```
Schedule `backup.sh` from cron. State lives in the `pgdata`, `miniodata`, `samples`
volumes.

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
