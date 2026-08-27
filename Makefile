COMPOSE = docker compose -f infra/docker-compose.yml
COMPOSE_E2E = $(COMPOSE) -f infra/docker-compose.e2e.yml

.PHONY: up down logs ps build test test-be test-fe lint migrate seed bootstrap e2e engine-fake

up:        ; $(COMPOSE) up --build
down:      ; $(COMPOSE) down
logs:      ; $(COMPOSE) logs -f
ps:        ; $(COMPOSE) ps
build:     ; $(COMPOSE) build

test: test-be test-fe
test-be:   ; $(COMPOSE) run --rm backend pytest
test-fe:   ; $(COMPOSE) run --rm frontend npm test

lint:
	$(COMPOSE) run --rm backend sh -c "ruff check . && black --check . && mypy keystone_api"
	$(COMPOSE) run --rm frontend sh -c "npm run lint && npm run typecheck"

migrate:   ; $(COMPOSE) run --rm backend alembic upgrade head
seed:      ; $(COMPOSE) run --rm backend python -m keystone_api.cli seed
bootstrap: ; $(COMPOSE) run --rm backend python -m keystone_api.cli bootstrap

# Start the worker with the deterministic fake engine (needed for the M2 e2e).
engine-fake: ; $(COMPOSE_E2E) --profile engine up -d worker

# Playwright against the already-up stack (nginx on :8080). Bring it up first:
#   make up   (in another terminal)   then   make e2e
PW_IMAGE = mcr.microsoft.com/playwright:v1.62.1-noble
e2e:
	docker run --rm --network host -v "$(CURDIR)/frontend":/work -w /work \
	  -u "$$(id -u):$$(id -g)" -e HOME=/work $(PW_IMAGE) npx playwright test

smoke:     ; ./infra/smoke.sh
