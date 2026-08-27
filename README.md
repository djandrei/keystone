# Keystone

Multi-user, self-hostable web application for **AI-assisted reverse engineering &
vulnerability research**, built on `ghidra-headless-mcp`. See
[`../docs/design.md`](../docs/design.md) and
[`../docs/implementation-plan.md`](../docs/implementation-plan.md).

## Run (everything in Docker Compose)

```bash
make up            # build + start the whole stack (hot reload)
# API:      http://localhost:8080/api/healthz   (via nginx)
# Frontend: http://localhost:8080
```

## Test

```bash
make test          # backend (pytest) + frontend (vitest)
make lint          # ruff/black/mypy + eslint/tsc
make e2e           # Playwright smoke (added per milestone)
```

## Layout

```
backend/   Flask API (keystone_api) + analysis engine (keystone_engine, M2+) + worker
frontend/  React + TypeScript (Vite)
infra/     docker-compose + service configs
```

Built stage-by-stage per the implementation plan; each stage is test-gated.
