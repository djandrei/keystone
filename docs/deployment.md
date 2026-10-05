# Keystone — Production Deployment

A one-command standalone deployment: built images, gunicorn (gevent, WebSocket-
capable), nginx + TLS at the edge, persistent Postgres + S3 object storage
(VersityGW).

## 1. Prerequisites
- Docker + Docker Compose on the host.
- A DNS name pointing at the host (for real TLS).
- **ghidra-headless-mcp running and reachable** — a separate service, set up
  first (§6). Keystone's worker reaches it by URL and shares nothing else with it.

## 2. Configure secrets
```bash
cp infra/.env.example infra/.env
```
Set strong values in `infra/.env` (never commit it):
- `KEYSTONE_JWT_SECRET` — long random string, at least 32 characters (signs access
  tokens): `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.
- `POSTGRES_PASSWORD`, `KEYSTONE_S3_SECRET_KEY` (also the S3 store's root secret).
- `KEYSTONE_ADMIN_PASSWORD` — first-run admin password (change immediately after).
- `KEYSTONE_LLM_API_KEY` — the LLM endpoint key. **Deployment secret only** — never
  stored in the DB; the admin sets endpoint URL + default model at runtime.

The API and worker refuse to start in production while `KEYSTONE_JWT_SECRET` or
`KEYSTONE_ADMIN_PASSWORD` is empty or still a published default (the code's or
`.env.example`'s), or while the JWT secret is shorter than 32 characters; the error
names the variable, never its value.

## 3. TLS certificate
Drop a real cert at `infra/certs/{fullchain,privkey}.pem`, or for testing:
```bash
./infra/gen-certs.sh          # self-signed, CN=keystone.local
```

## 4. Bring it up
```bash
docker compose -f infra/docker-compose.prod.yml --env-file infra/.env up -d --build
```
Starts postgres, redis, s3 (+ bucket init), backend (gunicorn), worker (celery)
and the nginx edge (TLS :443, HTTP→HTTPS on :80). Health-gated by `/readyz`.
ghidra-headless-mcp should already be up (§6); the worker calls it per analysis.

## 5. First-run: migrate + bootstrap
```bash
C="docker compose -f infra/docker-compose.prod.yml --env-file infra/.env"
$C run --rm backend alembic upgrade head                    # migrations
$C run --rm backend python -m keystone_api.cli bootstrap    # settings + Default team + admin
```
Open `https://<host>/`, sign in as `admin` (password from `.env`), then **change the
admin password immediately**.

## 6. The analysis engine: ghidra-headless-mcp
Real RE/VR analyses run against **ghidra-headless-mcp**, a separate, standalone
service. Keystone does not start it and shares no files or network with it; set
it up first. The worker image already carries Semgrep for VR.

1. In `ghidra-headless-mcp`: set `GHMCP_API_KEY` and start it with
   `docker compose up -d`, which runs its `--http` service on 1351. Keep its
   `MAX_STREAM_UPLOAD_BYTES` (128 MiB by default) at least
   `KEYSTONE_UPLOAD_MAX_BYTES` (100 MiB by default).
2. Here, in `infra/.env`: `KEYSTONE_MCP_API_KEY` = that same key, and
   `KEYSTONE_MCP_ENDPOINT` = its URL as the worker container sees it. The
   default, `http://host.docker.internal:1351/api`, is its published `--http`
   port on this Docker host.
3. Bring Keystone up as in §4.

Per analysis, the worker reads the binary from Keystone's object store and sends
it as raw bytes to `POST /api/upload?analyze=true&keep=false`: one request that
imports it and discards the upload. The imported program stays in
ghidra-headless-mcp's project, which is its to keep. Client errors come back as
4xx and are not retried; a file over the server's limit fails with `too_large`. For a demo without Ghidra/LLM, `KEYSTONE_ENGINE_FAKE=1` on the
worker drives the full path deterministically.

## 7. Backup & restore
```bash
./infra/backup.sh                       # -> backups/<timestamp>/ (pg dump + s3 sync)
./infra/restore.sh backups/<timestamp>  # restore both
```
Schedule `backup.sh` from cron. It covers the `pgdata` and `s3data` volumes; the
S3 copy is taken with the `aws` CLI (`aws s3 sync`), so it works against any S3
store.
Every uploaded binary is in S3, under `binaries/<sha256>`, and the worker sends it
to ghidra-headless-mcp from there on each analysis, so these two volumes are all
Keystone needs restored.

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
