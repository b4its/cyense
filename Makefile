# Makefile — Cyense API Service (PRD v2.0)
# Install dependencies first: pip install -r requirements.txt pytest ruff
# Usage: make up / make down / make logs / make test / make shell

.PHONY: up down logs shell build clean ps help test lint ruff format fix docker-volumes cli demo

SHELL := /bin/bash
APP_DIR := dev/main
VENV := .venv
PYTHON := $(shell which python3 || echo "python")
DOCKER := docker
COMPOSE := docker compose

help: ## Show all available targets
	@echo "Cyense — Agentic IDOR Vulnerability Scanner"
	@echo ""
	@echo "Usage:"
	@echo "  make up         Start API + lab app containers"
	@echo "  make down       Stop and remove containers"
	@echo "  make logs       Follow logs from API container"
	@echo "  make logs-api   Logs from API only"
	@echo "  make logs-lab   Logs from Lab app only"
	@echo "  make shell      Open interactive shell in running API container"
	@echo "  make build      Build images (api + lab)"
	@echo "  make clean      Remove containers and volumes"
	@echo "  make ps         Show container status"
	@echo "  make test       Run pytest unit/integration tests"
	@echo "  make lint       Run ruff linter"
	@echo "  make ruff-fix   Apply auto-fixes with ruff"
	@echo "  make format     Format code with ruff"
	@echo "  make cli        Jalankan cyense CLI (lokal, service harus sudah up)"
	@echo "  make demo       Demo end-to-end: scan repo contoh + lihat laporan"
	@echo ""

up: build ## Start services (API + lab app profile)
	$(COMPOSE) --profile lab up -d --wait api vulnerable-app

down: ## Stop services
	$(COMPOSE) --profile lab down

build: ## Build images (api service + lab app)
	cd $(APP_DIR) && $(DOCKER) build -t cyense-api:latest .
	cd $(APP_DIR)/tests/fixtures && $(DOCKER) build -f lab_Dockerfile -t cyense-lab:latest .

logs: ## Follow logs from both API and lab
	$(COMPOSE) --profile lab logs -f --tail=50 api vulnerable-app

logs-api: ## Follow API logs only
	$(COMPOSE) --profile lab logs -f --tail=100 api

logs-lab: ## Follow lab app logs only
	$(COMPOSE) --profile lab logs -f --tail=100 vulnerable-app

shell: ## Interactive shell in API container
	docker exec -it cyense_api_1 /bin/bash

ps: ## Container status
	$(COMPOSE) --profile lab ps

clean: down ## Remove containers and data volumes
	$(COMPOSE) --profile lab down -v
	@rm -rf reports/ __pycache__ .pytest_cache */*/__pycache__ */*/__pycache__

test: ## Run pytest with coverage hints
	cd $(APP_DIR) && $(PYTHON) -m pytest tests -v --tb=short || (echo "Tests failed!" && exit 1)

lint: ## Run ruff linter
	cd $(APP_DIR) && $(PYTHON) -m ruff check app baseline tests --statistics

format: ## Auto-format code with ruff
	cd $(APP_DIR) && $(PYTHON) -m ruff format app baseline tests wordlists tests/fixtures

fix: ## Fix fixable issues with ruff
	cd $(APP_DIR) && $(PYTHON) -m ruff check --fix app baseline tests

docker-volumes: ## List Docker volumes used by Cyense
	$(DOCKER) volume ls | grep cyense

install-dev: ## Install Python dev dependencies locally
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -e "$(APP_DIR)[dev]"

check-python: ## Verify Python version >=3.11
	$(PYTHON) -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'"

start-venv: ## Activate virtualenv
	@echo "Activate manually: source $(VENV)/bin/activate"

# ---------------------------------------------------------------------------
# CLI targets (cli-experience.md §5.2)

cli: ## Jalankan cyense CLI (service harus sudah `make up`)
	cd $(APP_DIR) && $(PYTHON) -m app.cli.main $(ARGS)

demo: ## Demo end-to-end: scan repo publik contoh (butuh internet + service up)
	@echo "=== Cyense CLI Demo ==="
	@echo "Memastikan service berjalan..."
	@cd $(APP_DIR) && $(PYTHON) -m app.cli.main version || (echo "ERROR: jalankan 'make up' dulu" && exit 1)
	@echo ""
	@echo "Scan repo contoh (octocat/Hello-World)..."
	cd $(APP_DIR) && $(PYTHON) -m app.cli.main scan github \
		https://github.com/octocat/Hello-World \
		--i-have-permission \
		--lang auto \
		--fail-on none