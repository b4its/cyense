# Makefile — Cyense API Service (PRD v2.0)
# Install dependencies first: pip install -r requirements.txt pytest ruff
# Usage: make up / make down / make logs / make test / make shell

.PHONY: up down logs shell build clean ps help test lint ruff format fix docker-volumes cli cli-shell cli-help demo run recon

SHELL := /bin/bash
APP_DIR := dev/main
VENV := .venv
PYTHON := $(shell which python3 || echo "python")
DOCKER := docker
COMPOSE := docker compose
# Compose file lives in $(APP_DIR); all compose commands must run from there.
COMPOSE_IN_APP := cd $(APP_DIR) && $(COMPOSE)

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
	@echo ""
	@echo "CLI commands (run AFTER 'make up' — execute inside API container):"
	@echo "  make cli ARGS=\"list\"              List recent scans"
	@echo "  make cli ARGS=\"version\"           Show CLI + service version"
	@echo "  make cli ARGS=\"rules\"             List active detection rules"
	@echo "  make cli ARGS=\"history\"           Scan history with filters"
	@echo "  make cli ARGS=\"view <scan_id>\"    Open web viewer for a scan"
	@echo "  make cli ARGS=\"scan github URL --i-have-permission\""
	@echo "  make cli ARGS=\"scan program --i-have-permission\""
	@echo "  make cli ARGS=\"fix <scan_id>\"     Propose remediation patches"
	@echo "  make cli ARGS=\"crypt hash <text> --algo sha256\"   Hash string"
	@echo "  make cli ARGS=\"crypt aes encrypt <text> --key <k> -m gcm\"   AES encrypt"
	@echo "  make cli ARGS=\"crypt rsa generate --bits 2048\"       RSA keypair"
	@echo "  make cli ARGS=\"crypt ecc generate\"                   ECC keypair (P-256)"
	@echo "  make cli-shell                      Open bash shell in container (type CLI commands interactively)"
	@echo "  make cli-help                       Show full CLI help"
	@echo "  make demo                           Demo end-to-end: scan a public repo"
	@echo ""

up: build ## Start services (API + lab app profile)
	$(COMPOSE_IN_APP) --profile lab up -d --wait api vulnerable-app

down: ## Stop services
	$(COMPOSE_IN_APP) --profile lab down

build: ## Build images (api service + lab app)
	cd $(APP_DIR) && $(DOCKER) build -t cyense-api:latest .
	cd $(APP_DIR)/tests/fixtures && $(DOCKER) build -f lab_Dockerfile -t cyense-lab:latest .

logs: ## Follow logs from both API and lab
	$(COMPOSE_IN_APP) --profile lab logs -f --tail=50 api vulnerable-app

logs-api: ## Follow API logs only
	$(COMPOSE_IN_APP) --profile lab logs -f --tail=100 api

logs-lab: ## Follow lab app logs only
	$(COMPOSE_IN_APP) --profile lab logs -f --tail=100 vulnerable-app

shell: ## Interactive shell in API container
	$(COMPOSE_IN_APP) exec api /bin/bash

ps: ## Container status
	$(COMPOSE_IN_APP) --profile lab ps

clean: down ## Remove containers and data volumes
	$(COMPOSE_IN_APP) --profile lab down -v
	@rm -rf $(APP_DIR)/reports $(APP_DIR)/__pycache__ $(APP_DIR)/.pytest_cache
	@find $(APP_DIR) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

test: ## Run pytest with coverage hints
	cd $(APP_DIR) && $(PYTHON) -m pytest tests -v --tb=short || (echo "Tests failed!" && exit 1)

lint: ## Run ruff linter
	cd $(APP_DIR) && $(PYTHON) -m ruff check app baseline tests --statistics

format: ## Auto-format code with ruff
	cd $(APP_DIR) && $(PYTHON) -m ruff format app baseline tests wordlists tests/fixtures/vulnerable_app

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
# All CLI targets run INSIDE the API container — no local Python deps
# needed. Requires 'make up' to have been run first.

cli: ## Run cyense CLI inside API container (e.g. make cli ARGS="list")
	$(COMPOSE_IN_APP) exec api python -m app.cli.main $(ARGS)

cli-shell: ## Open interactive bash shell inside API container for CLI work
	@echo ""
	@echo "============================================================"
	@echo "  Cyense CLI — interactive shell (inside API container)"
	@echo "============================================================"
	@echo ""
	@echo "Run CLI commands with:"
	@echo "  python -m app.cli.main --help                   # show all commands"
	@echo "  python -m app.cli.main version                  # CLI + service version"
	@echo "  python -m app.cli.main list                     # list recent scans"
	@echo "  python -m app.cli.main rules                    # active detection rules"
	@echo "  python -m app.cli.scan github URL --i-have-permission"
	@echo ""
	@echo "Exit the shell with: exit"
	@echo ""
	$(COMPOSE_IN_APP) exec api /bin/bash

cli-help: ## Show cyense CLI help
	$(COMPOSE_IN_APP) exec api python -m app.cli.main --help

demo: ## Demo end-to-end: scan a public repo (requires internet + service up)
	@echo "=== Cyense CLI Demo ==="
	@echo "Memastikan service berjalan..."
	@$(COMPOSE_IN_APP) exec -T api python -m app.cli.main version \
		|| (echo "ERROR: jalankan 'make up' dulu" && exit 1)
	@echo ""
	@echo "Scan repo contoh (octocat/Hello-World)..."
	$(COMPOSE_IN_APP) exec api python -m app.cli.main scan github \
		https://github.com/octocat/Hello-World \
		--i-have-permission \
		--lang auto \
		--fail-on none

run: ## Jalankan Cyense — pilih mode Website atau CLI (launcher)
	cd $(APP_DIR) && $(PYTHON) -m app.cli.main launch

recon: ## Recon menyeluruh ke URL (adaptasi BBHT: semua tool recon dalam 1 scan)
	@if [ -z "$(URL)" ]; then echo "Pakai: make recon URL=https://target.example"; exit 1; fi
	cd $(APP_DIR) && $(PYTHON) -m app.cli.main cve "$(URL)" --i-have-permission