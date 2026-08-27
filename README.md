# Keystone

Multi-user, self-hostable web application for **AI-assisted reverse engineering &
vulnerability research**, built on `ghidra-headless-mcp`. See
[`../docs/design.md`](../docs/design.md) and
[`../docs/implementation-plan.md`](../docs/implementation-plan.md).

**Milestone status:** M1–M4 complete — multi-user app (JWT auth + API tokens,
users/teams/RBAC, admin system-settings, branded React shell), both analysis paths
end-to-end (RE: upload -> async analysis -> live Steps -> report; VR: Semgrep ->
interactive rule pick -> triage + reachability), and the review layer: searchable
team-scoped history, report export (MD/JSON/PDF), a team switcher, an admin audit
log, and in-app run notifications. Everything is test-gated and comes up with one
command.

## Quick start (everything in Docker Compose)

No host Python or Node is required — every service runs in a container, with
source bind-mounted for hot reload.

```bash
make up            # build + start the whole stack (Ctrl-C to stop; `make down` to remove)
```

Then open **http://localhost:8080** and sign in with the first-run admin:

| | |
|---|---|
| Username | `admin` |
| Password | `change-me` |

Change these before any real deployment (see **Configuration**). The admin, the
`Default` team, and the settings singleton are created automatically on first
boot (idempotent bootstrap); re-running never duplicates them.

### Services & ports (all behind nginx on :8080)

| URL / port | Service |
|---|---|
| http://localhost:8080 | Frontend (Vite dev server, proxied) |
| http://localhost:8080/api | Backend REST API (Flask) |
| http://localhost:8080/api/healthz | Liveness probe |
| postgres:5432 | PostgreSQL 16 (internal) |
| redis:6379 | Redis 7 (internal; jobs land in M2) |
| minio:9000 | MinIO / S3 object storage (internal) |
| ghidra-mcp:1341 | `ghidra-headless-mcp` (wired in M2) |

## Configuration

All config is environment-driven with the `KEYSTONE_` prefix (pydantic-settings).
Copy the template and edit:

```bash
cp infra/.env.example infra/.env
```

Secrets to change for production:

- `KEYSTONE_JWT_SECRET` — signs access tokens; use a long random value.
- `KEYSTONE_ADMIN_PASSWORD` — the first-run admin password.
- `POSTGRES_PASSWORD` / `MINIO_ROOT_PASSWORD` / `KEYSTONE_S3_SECRET_KEY`.
- `KEYSTONE_LLM_API_KEY` — the LLM endpoint key. It is a **deployment secret**:
  Keystone never stores it in the database. The admin sets the LLM *endpoint URL*
  and *default model* at runtime under **Settings**; the key stays in the
  environment and the UI only shows whether one is configured.

## Testing

```bash
make test          # backend (pytest) + frontend (vitest), both in-container
make test-be       # backend only  — 32 tests
make test-fe       # frontend only — 25 tests
make lint          # ruff/black/mypy + eslint/tsc
```

End-to-end (Playwright, against a running stack):

```bash
make up            # in one terminal
make e2e           # in another — drives the full M1 flow in a headless browser
```

The e2e proves M1–M4: M1 (login → provision analyst + team → settings), M2 (upload
→ run RE → Steps → report → history), M3 (run VR → pick a rule class → triage +
reachability) and M4 (cross-user collaboration → search → export → audit). M2–M4
need the worker running the deterministic fake engine (no Ghidra/LLM/Semgrep):

```bash
make up            # in one terminal
make engine-fake   # start the worker in fake-engine mode
make e2e           # runs both m1 and m2 specs
```

## Admin bootstrap & seeding

```bash
make bootstrap     # ensure settings + Default team + admin (idempotent)
make seed          # dev fixture: bootstrap + a demo analyst in a demo team
make migrate       # apply Alembic migrations to head
```

`make up` already applies migrations and bootstraps on start; these targets are
for re-running against an existing stack.

## Layout

```
backend/    Flask API (keystone_api) — app factory, SQLAlchemy models, Alembic
            migrations, auth (JWT + refresh + API tokens), RBAC, users/teams/
            settings APIs. pytest suite under tests/.
frontend/   React + TypeScript (Vite). Design system (Tailwind + Keystone tokens,
            Radix components), auth context + protected routing, admin/settings
            UI. Vitest + RTL unit tests; Playwright e2e under e2e/.
infra/      docker-compose.yml, nginx reverse proxy, .env.example, smoke.sh
```

Built stage-by-stage per the implementation plan; each stage is test-gated and
committed independently.
