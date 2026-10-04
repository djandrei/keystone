#!/usr/bin/env bash
# Start Keystone in the development environment (Docker Compose).
#
# Brings up the core stack (postgres, redis, s3, backend, frontend, nginx),
# applies migrations, bootstraps the admin, and — unless --no-engine — starts the
# analysis worker in fake-engine mode so uploads can actually be analyzed without
# Ghidra/LLM/Semgrep. Everything runs in containers; no host Python or Node needed.
#
# Usage:
#   ./run-dev.sh              up + migrate + bootstrap + fake-engine worker
#   ./run-dev.sh --fresh      wipe the volumes first (clean DB + object store)
#   ./run-dev.sh --no-engine  skip the worker (browse/login/upload work; runs won't)
#   ./run-dev.sh --logs       follow logs after starting
#   ./run-dev.sh --down       stop the stack (keeps data)
#   ./run-dev.sh --help
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

COMPOSE="docker compose -f infra/docker-compose.yml"
COMPOSE_ENGINE="$COMPOSE -f infra/docker-compose.e2e.yml"  # overlays KEYSTONE_ENGINE_FAKE=1

ENGINE=1
REAL=0
FRESH=0
LOGS=0

for arg in "$@"; do
  case "$arg" in
    --no-engine)      ENGINE=0 ;;
    --real-engine)    REAL=1 ;;
    --fresh|--reset)  FRESH=1 ;;
    --logs)           LOGS=1 ;;
    --down|--stop)    echo "==> stopping"; $COMPOSE_ENGINE --profile engine down; exit 0 ;;
    -h|--help)
      cat <<'USAGE'
Start Keystone in the development environment (Docker Compose).

  ./run-dev.sh               up + migrate + bootstrap + fake-engine worker
  ./run-dev.sh --real-engine real Ghidra + a live LLM: a real worker against the
                             running ghidra-headless-mcp (needs KEYSTONE_MCP_API_KEY =
                             its GHMCP_API_KEY, KEYSTONE_LLM_API_KEY, and the LLM
                             endpoint/model in Settings)
  ./run-dev.sh --fresh       wipe the volumes first (clean DB + object store)
  ./run-dev.sh --no-engine   skip the worker (browse/login/upload work; runs won't)
  ./run-dev.sh --logs        follow logs after starting
  ./run-dev.sh --down        stop the stack (keeps data)
  ./run-dev.sh --help
USAGE
      exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# --- prerequisites -----------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "error: docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "error: Docker Compose v2 is required" >&2; exit 1; }

# --- env file ----------------------------------------------------------------
if [ ! -f infra/.env ]; then
  echo "==> creating infra/.env from infra/.env.example (set real secrets before deploying)"
  cp infra/.env.example infra/.env
fi

# --- ghidra-headless-mcp: set up first, in its own repository ----------------
# Keystone shares its samples directory (mounted at /samples by both stacks) and
# its worker joins its compose network. Read the two settings the way compose
# will: the shell environment, then infra/.env, then the side-by-side defaults.
env_value() { sed -nE "s/^$1=(.*)$/\1/p" infra/.env | tail -1; }
SAMPLES_DIR="${KEYSTONE_SAMPLES_DIR:-$(env_value KEYSTONE_SAMPLES_DIR)}"; SAMPLES_DIR="${SAMPLES_DIR:-../../ghidra-headless-mcp/samples}"
case "$SAMPLES_DIR" in /*) SAMPLES_PATH="$SAMPLES_DIR" ;; *) SAMPLES_PATH="infra/$SAMPLES_DIR" ;; esac
GHMCP_NETWORK="${KEYSTONE_GHMCP_NETWORK:-$(env_value KEYSTONE_GHMCP_NETWORK)}"; GHMCP_NETWORK="${GHMCP_NETWORK:-ghidra-headless-mcp}"
if [ ! -d "$SAMPLES_PATH" ]; then
  # Checked here because docker would otherwise create it, root-owned.
  echo "error: no samples directory at $SAMPLES_PATH — set up ghidra-headless-mcp first" >&2
  echo "       (clone it beside this repository, or set KEYSTONE_SAMPLES_DIR in infra/.env)" >&2
  exit 1
fi
if [ "$ENGINE" = 1 ] && ! docker network inspect "$GHMCP_NETWORK" >/dev/null 2>&1; then
  echo "error: no Docker network '$GHMCP_NETWORK' — start ghidra-headless-mcp first" >&2
  echo "       (docker compose up -d in its repository; or run with --no-engine)" >&2
  exit 1
fi

# --- optional clean slate ----------------------------------------------------
if [ "$FRESH" = 1 ]; then
  # The samples directory belongs to ghidra-headless-mcp and is left alone.
  echo "==> wiping volumes (postgres, s3)"
  $COMPOSE_ENGINE --profile engine down -v
fi

# --- build + start the core services -----------------------------------------
echo "==> building and starting the core stack"
$COMPOSE up -d --build

# nginx resolves its upstreams (backend/frontend) once at startup; if a rebuild
# gave them new container IPs, restart nginx so it re-resolves (else 502).
$COMPOSE restart nginx >/dev/null 2>&1 || true

# --- wait for the backend to answer ------------------------------------------
printf "==> waiting for the backend"
ready=0
for _ in $(seq 1 60); do
  if $COMPOSE exec -T backend python -c \
      "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)" \
      >/dev/null 2>&1; then
    ready=1; printf " — ready\n"; break
  fi
  printf "."; sleep 2
done
[ "$ready" = 1 ] || { printf "\nerror: backend did not become ready; check '$COMPOSE logs backend'\n" >&2; exit 1; }

# --- migrate + bootstrap (both idempotent) -----------------------------------
echo "==> applying database migrations"
$COMPOSE exec -T backend alembic upgrade head
echo "==> bootstrapping (system settings + Default team + admin)"
$COMPOSE exec -T backend python -m keystone_api.cli bootstrap

# --- analysis worker (fake engine) -------------------------------------------
if [ "$ENGINE" = 1 ] && [ "$REAL" = 1 ]; then
  # real engine: a worker that calls ghidra-headless-mcp and the LLM. The key is
  # ghidra-headless-mcp's, so it is copied from there, never generated here.
  if ! grep -q '^KEYSTONE_MCP_API_KEY=..' infra/.env; then
    echo "error: set KEYSTONE_MCP_API_KEY in infra/.env to ghidra-headless-mcp's GHMCP_API_KEY" >&2
    exit 1
  fi
  echo "==> starting the real-engine worker (ghidra-headless-mcp + live LLM)"
  $COMPOSE --profile engine up -d worker
elif [ "$ENGINE" = 1 ]; then
  echo "==> starting the analysis worker (fake engine — no Ghidra/LLM needed)"
  $COMPOSE_ENGINE --profile engine up -d worker
fi

# --- summary -----------------------------------------------------------------
admin_pw="$(grep -E '^KEYSTONE_ADMIN_PASSWORD=' infra/.env | cut -d= -f2-)"
cat <<EOF

Keystone is running.

  App        http://localhost:8080
  API        http://localhost:8080/api        (health: /api/healthz, ready: /api/readyz)
  Login      admin / ${admin_pw:-change-me}

  Analyses   $([ "$ENGINE" = 1 ] && echo "runnable now via the fake engine (upload a binary, then Run RE / Run VR)" \
                                 || echo "worker NOT started (--no-engine): uploads work, but runs won't")

  Logs       $COMPOSE logs -f
  Stop       ./run-dev.sh --down
EOF

[ "$LOGS" = 1 ] && exec $COMPOSE logs -f
exit 0
