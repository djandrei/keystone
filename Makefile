COMPOSE = docker compose -f infra/docker-compose.yml

.PHONY: up down logs ps build test test-be test-fe lint migrate seed bootstrap e2e

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
e2e:       ; $(COMPOSE) run --rm e2e npx playwright test

smoke:     ; ./infra/smoke.sh
