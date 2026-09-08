# Headwaters — developer entrypoints.
# Every target here works today. Targets are added as their phase lands, so a
# green `make` is always an honest signal.

SHELL := /bin/bash
.DEFAULT_GOAL := help

BACKEND := backend
FRONTEND := frontend
COMPOSE := docker compose

# Host ports. Overridable in the environment or a root .env consumed by
# compose. Defaults avoid the ports most likely to be already taken.
API_PORT ?= 8000
WEB_PORT ?= 3100
export API_PORT
export WEB_PORT

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- environment -----------------------------------------------------------
.PHONY: init
init: ## Create local .env files from the examples (never overwrites)
	@[ -f $(BACKEND)/.env ]  || cp $(BACKEND)/.env.example  $(BACKEND)/.env  && echo "  backend/.env ready"
	@[ -f $(FRONTEND)/.env ] || cp $(FRONTEND)/.env.example $(FRONTEND)/.env && echo "  frontend/.env ready"

# --- the stack -------------------------------------------------------------
.PHONY: up
up: init daemon ports ## Build and start the full local stack
	$(COMPOSE) up --build

.PHONY: down
down: ## Stop the stack (keeps the database volume)
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and DESTROY the database volume
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail all service logs
	$(COMPOSE) logs -f

.PHONY: sh
sh: ## Shell into the running api container
	$(COMPOSE) exec api bash

.PHONY: psql
psql: ## Open psql against the local database
	$(COMPOSE) exec db psql -U headwaters -d headwaters

# --- database --------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply migrations to the local database
	$(COMPOSE) exec api alembic upgrade head

.PHONY: migration
migration: ## Autogenerate a migration: make migration m="add widgets"
	@[ -n "$(m)" ] || { echo '  usage: make migration m="describe the change"'; exit 1; }
	$(COMPOSE) exec api alembic revision --autogenerate -m "$(m)"
	@echo "  → review backend/alembic/versions/ before committing; never trust the diff on an index or constraint"

.PHONY: migrate-down
migrate-down: ## Roll back one migration
	$(COMPOSE) exec api alembic downgrade -1

.PHONY: drift
drift: ## Fail if the models and the migrations have diverged
	$(COMPOSE) exec api alembic check

# --- verification ----------------------------------------------------------
.PHONY: daemon
daemon: ## Check the Docker daemon is reachable
	@docker info >/dev/null 2>&1 || { \
		echo "  ✗ Docker daemon is not running."; \
		echo "      macOS:  open -a Docker    (then wait ~20s and retry)"; \
		echo "      check:  docker info"; \
		exit 1; \
	}
	@echo "  ✓ docker daemon reachable"

.PHONY: ports
ports: ## Check the host ports we need are free
	@for p in $(API_PORT) $(WEB_PORT); do \
		if lsof -nP -iTCP:$$p -sTCP:LISTEN 2>/dev/null | grep -qv COMMAND; then \
			echo "  ✗ port $$p is already in use:"; \
			lsof -nP -iTCP:$$p -sTCP:LISTEN | tail -n +2 | awk '{print "      " $$1, "pid", $$2, $$9}'; \
			echo "      set API_PORT/WEB_PORT to something else, or stop that process"; \
		else echo "  ✓ port $$p free"; fi; \
	done

.PHONY: smoke
smoke: ## Verify the stack end to end (api -> db, web -> api)
	@echo "→ /healthz";  curl -fsS http://127.0.0.1:$(API_PORT)/healthz | python3 -m json.tool
	@echo "→ /readyz";   curl -fsS http://127.0.0.1:$(API_PORT)/readyz  | python3 -m json.tool
	@echo "→ dashboard"; curl -fsS -o /dev/null -w "  HTTP %{http_code}\n" http://127.0.0.1:$(WEB_PORT)/
	@echo "✓ stack healthy — dashboard http://127.0.0.1:$(WEB_PORT)  api http://127.0.0.1:$(API_PORT)"

.PHONY: test
test: ## Run the backend test suite inside the container
	$(COMPOSE) exec api pytest

.PHONY: lint
lint: ## Lint and type-check the backend
	$(COMPOSE) exec api sh -c "ruff check . && ruff format --check . && mypy app"

.PHONY: fmt
fmt: ## Auto-format the backend
	$(COMPOSE) exec api sh -c "ruff format . && ruff check --fix ."

.PHONY: audit
audit: ## Dependency CVEs and Python security lint
	$(COMPOSE) exec api sh -c "pip-audit && bandit -r app -ll"
