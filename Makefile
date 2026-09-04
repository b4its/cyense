# Makefile — Cyense API Service (PRD v2.0)
# Install dependencies first: pip install -r requirements.txt pytest ruff
#
# Two ways to run:
#   * Docker  : make up / make down / make logs / make test / make shell
#   * Lokal   : make local-install && make local-up   (tanpa Docker)
# Usage: make up / make down / make logs / make test / make shell

.PHONY: up down logs shell build clean ps help test lint ruff ruff-fix format fix docker-volumes cli cli-shell cli-help demo run recon \
        local-install local-checks api lab local-up local-restart local-down local-ps local-health local-logs-api local-logs-lab \
        local-cli local-cli-shell local-cli-help local-demo local-recon local-clean \
        web-install web-build web open restart local-web-open

SHELL := /bin/bash
APP_DIR := dev/main
APP_ABS := $(abspath $(APP_DIR))
# Prefer the project venv (dev/main/.venv) so dev targets (test/lint/format)
# use the installed deps instead of failing on a system Python that lacks
# pytest/ruff. Falls back to the system interpreter when no venv is present
# (e.g. on a fresh clone before 'make install-dev').
VENV := $(APP_DIR)/.venv
PYTHON := $(if $(wildcard $(VENV)/bin/python),$(abspath $(VENV)/bin/python),$(shell which python3 || echo "python"))
DOCKER := docker
COMPOSE := docker compose
# Compose file lives in $(APP_DIR); all compose commands must run from there.
COMPOSE_IN_APP := cd $(APP_DIR) && $(COMPOSE)

# ── Local (no-Docker) runtime config ───────────────────────────────────────
# All local targets run from the project venv (dev/main/.venv) with absolute
# paths so they work regardless of the current shell cwd.
LOCAL_HOST ?= 127.0.0.1
API_PORT ?= 8000
LAB_PORT ?= 8080            # note: lab_app.py hardcodes 8080 (see lab_Dockerfile)
LOCAL_WORKSPACE ?= $(APP_ABS)/target
LOCAL_API_URL := http://$(LOCAL_HOST):$(API_PORT)
API_PID := $(APP_ABS)/.api.pid
LAB_PID := $(APP_ABS)/.lab.pid
LOCAL_API_LOG := $(APP_ABS)/api.log
LOCAL_LAB_LOG := $(APP_ABS)/lab.log

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
	@echo "Local (NO Docker) — run everything from the project venv:"
	@echo "  make local-install                  Create venv + install runtime/dev/lab deps"
	@echo "  make local-up                       Start API + Lab in the background"
	@echo "  make api                            Run API in foreground (Ctrl+C to stop)"
	@echo "  make lab                            Run Lab app (Flask) in foreground"
	@echo "  make local-down                     Stop the local API + Lab"
	@echo "  make local-logs-api | local-logs-lab   Follow local logs"
	@echo "  make local-ps                       Show local process + health status"
	@echo "  make local-cli ARGS=\"list\"         Run CLI locally (API must be up)"
	@echo "  make local-cli-help                 Show full CLI help (local)"
	@echo "  make local-cli-shell                Interactive CLI shell (local)"
	@echo "  make local-demo                     Demo scan a public repo (local)"
	@echo "  make local-recon URL=...            Recon menyeluruh ke URL (local)"
	@echo "  make local-clean                    Remove local reports/brain/logs/pids"
	@echo ""
	@echo "Frontend Web UI (browser):"
	@echo "  make web-install                    Install frontend deps via npm (NOT pnpm)"
	@echo "  make web-build                      Rebuild the Svelte Web UI (npm run build)"
	@echo "  make web                            local-up + open the Web UI in a browser"
	@echo "  make open                           Open http://$(LOCAL_API_URL)/ui in a browser"
	@echo "  make restart                        Stop + start the service (down+up)"
	@echo "  make local-restart                  Stop + start the local (no-Docker) service"
	@echo "  make local-web-open                 Open Web UI for the local (no-Docker) service"
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

ruff-fix: fix ## Alias untuk 'make fix' (nama yang diiklankan di help)

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

# ---------------------------------------------------------------------------
# Local / no-Docker workflow (jalankan via venv dev/main/.venv)
# Pengganti lengkap untuk target Docker (up/down/build/logs/ps/...) kapan pun
# Docker tidak tersedia:  make local-install && make local-up
# ---------------------------------------------------------------------------

local-install: ## Buat venv & install semua dependensi (runtime + dev + lab)
	@mkdir -p $(VENV)
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -U pip
	$(VENV)/bin/pip install -q -e "$(APP_DIR)[dev]"
	@echo "OK — aktivasi venv: source $(VENV)/bin/activate"

local-checks: ## Periksa Python + dependensi lokal
	@$(MAKE) check-python
	@$(PYTHON) -c "import fastapi, uvicorn, typer, rich, cvss, reportlab, yaml, flask" 2>/dev/null \
		&& echo "Dependensi OK" \
		|| (echo "Dependensi belum lengkap — jalankan: make local-install" && exit 1)

api: ## Jalankan backend FastAPI di foreground (Ctrl+C untuk stop)
	@$(MAKE) local-checks
	@mkdir -p $(LOCAL_WORKSPACE)
	cd $(APP_ABS) && CYENSE_WORKSPACE_DIR=$(LOCAL_WORKSPACE) \
		$(PYTHON) -m uvicorn app.main:app --host $(LOCAL_HOST) --port $(API_PORT)

lab: ## Jalankan aplikasi lab (Flask) di foreground (Ctrl+C untuk stop)
	@$(PYTHON) -c "import flask" 2>/dev/null || (echo "Membutuhkan flask — jalankan: make local-install" && exit 1)
	cd $(APP_ABS)/tests/fixtures/vulnerable_app && $(PYTHON) lab_app.py

local-up: ## Jalankan API + Lab di background (pengganti 'make up', tanpa Docker)
	@$(MAKE) local-checks
	@mkdir -p $(LOCAL_WORKSPACE) $(APP_ABS)/reports $(APP_ABS)/brain
	@if [ -f $(API_PID) ] && kill -0 $$(cat $(API_PID)) 2>/dev/null; then \
		echo "  API sudah berjalan (pid $$(cat $(API_PID)))"; \
	else \
		cd $(APP_ABS); CYENSE_WORKSPACE_DIR=$(LOCAL_WORKSPACE) \
			nohup $(PYTHON) -m uvicorn app.main:app --host $(LOCAL_HOST) --port $(API_PORT) \
			>> $(LOCAL_API_LOG) 2>&1 < /dev/null & echo $$! > $(API_PID); \
		echo "  API  : $(LOCAL_API_URL)/ui  (pid $$(cat $(API_PID)))"; \
	fi
	@if [ -f $(LAB_PID) ] && kill -0 $$(cat $(LAB_PID)) 2>/dev/null; then \
		echo "  Lab  sudah berjalan (pid $$(cat $(LAB_PID)))"; \
	else \
		cd $(APP_ABS)/tests/fixtures/vulnerable_app; \
			nohup $(PYTHON) lab_app.py >> $(LOCAL_LAB_LOG) 2>&1 < /dev/null & echo $$! > $(LAB_PID); \
		echo "  Lab  : http://$(LOCAL_HOST):$(LAB_PORT)  (pid $$(cat $(LAB_PID)))"; \
	fi
	@ok=0; for i in $$(seq 1 40); do \
		if $(PYTHON) -c "import urllib.request as u; u.urlopen('$(LOCAL_API_URL)/api/v1/health', timeout=1)" 2>/dev/null; then ok=1; break; fi; \
		sleep 0.5; done; \
	if [ "$$ok" = "1" ]; then \
		echo "  ✓ API siap: $(LOCAL_API_URL)/ui  (Lab di http://$(LOCAL_HOST):$(LAB_PORT))"; \
	else \
		echo "  ✗ API tidak merespons — cek $(LOCAL_API_LOG)"; \
	fi

local-down: ## Stop API + Lab lokal (pengganti 'make down', tanpa Docker)
	@for f in $(API_PID) $(LAB_PID); do \
		if [ -f $$f ]; then \
			pid=$$(cat $$f); \
			if kill -0 $$pid 2>/dev/null; then kill $$pid 2>/dev/null && echo "  stopped (pid $$pid)"; \
			else echo "  $$f: pid $$pid tidak berjalan"; fi; \
			rm -f $$f; \
		fi; \
	done; true
	@echo "Selesai."

local-restart: ## Restart API + Lab lokal (pengganti 'make down && make up')
	@$(MAKE) local-down
	@$(MAKE) local-up

local-web-open: ## Buka Web UI lokal di browser
	@$(PYTHON) -c "import urllib.request as u; u.urlopen('$(LOCAL_API_URL)/api/v1/health', timeout=2)" 2>/dev/null \
		|| (echo "API offline — jalankan: make local-up" && exit 1)
	@echo "Buka Web UI: $(LOCAL_API_URL)/ui"
	@command -v xdg-open >/dev/null 2>&1 && xdg-open "$(LOCAL_API_URL)/ui" >/dev/null 2>&1 & \
	command -v open >/dev/null 2>&1 && open "$(LOCAL_API_URL)/ui" >/dev/null 2>&1 || true

local-ps: ## Status proses lokal + health API
	@echo "PID API : $$(cat $(API_PID) 2>/dev/null || echo '-')"
	@echo "PID Lab : $$(cat $(LAB_PID) 2>/dev/null || echo '-')"
	@$(MAKE) local-health

local-health: ## Cek health API lokal
	@$(PYTHON) -c "import urllib.request as u; print('API health:', u.urlopen('$(LOCAL_API_URL)/api/v1/health', timeout=2).status)" 2>/dev/null \
		|| echo "API offline di $(LOCAL_API_URL)"

local-logs-api: ## Ikuti log API lokal
	@[ -f $(LOCAL_API_LOG) ] || (echo "Log belum ada — jalankan make local-up" && exit 1)
	tail -f $(LOCAL_API_LOG)

local-logs-lab: ## Ikuti log lab lokal
	@[ -f $(LOCAL_LAB_LOG) ] || (echo "Log belum ada — jalankan make local-up" && exit 1)
	tail -f $(LOCAL_LAB_LOG)

local-cli: ## Jalankan CLI lokal (API harus berjalan). Contoh: make local-cli ARGS="list"
	cd $(APP_ABS) && CYENSE_API_URL=$(LOCAL_API_URL) $(PYTHON) -m app.cli.main $(ARGS)

local-cli-help: ## Tampilkan bantuan CLI lengkap (lokal)
	cd $(APP_ABS) && CYENSE_API_URL=$(LOCAL_API_URL) $(PYTHON) -m app.cli.main --help

local-cli-shell: ## Shell interaktif CLI (lokal)
	@echo ""
	@echo "============================================================"
	@echo "  Cyense CLI — local shell (no Docker). Ctrl+D / exit untuk keluar"
	@echo "============================================================"
	@echo ""
	@echo "Jalankan perintah seperti:"
	@echo "  python -m app.cli.main --help     # semua perintah"
	@echo "  python -m app.cli.main version    # versi CLI + service"
	@echo "  python -m app.cli.main list       # daftar scan terbaru"
	@echo "  python -m app.cli.main rules      # rules deteksi aktif"
	@echo "  python -m app.cli.main scan github URL --i-have-permission"
	@echo ""
	@cd $(APP_ABS) && CYENSE_API_URL=$(LOCAL_API_URL) \
		PATH="$(abspath $(VENV))/bin:$$PATH" /bin/bash -i

local-demo: local-up ## Demo end-to-end lokal: scan repo publik (mulai API bila belum)
	@echo "=== Cyense CLI Demo (lokal, no Docker) ==="
	cd $(APP_ABS) && CYENSE_API_URL=$(LOCAL_API_URL) $(PYTHON) -m app.cli.main scan github \
		https://github.com/octocat/Hello-World --i-have-permission --lang auto --fail-on none

local-recon: ## Recon menyeluruh ke URL (lokal). Pakai: make local-recon URL=https://target.example
	@if [ -z "$(URL)" ]; then echo "Pakai: make local-recon URL=https://target.example"; exit 1; fi
	cd $(APP_ABS) && CYENSE_API_URL=$(LOCAL_API_URL) $(PYTHON) -m app.cli.main cve "$(URL)" --i-have-permission

# ---------------------------------------------------------------------------
# Frontend (Svelte Web UI) — builder + browser launcher
# Repo memakai npm (package-lock.json di-track). JANGAN pakai pnpm:
# pnpm memblokir postinstall esbuild (ERR_PNPM_IGNORED_BUILDS), sehingga
# `vite build` gagal. Selalu gunakan npm di sini.
# ---------------------------------------------------------------------------

SVELTE_DIR := $(APP_ABS)/app/interface/svelte
WEB_NPM := npm

web-install: ## Install dependensi frontend (npm; jangan pnpm)
	cd $(SVELTE_DIR) && $(WEB_NPM) install

web-build: web-install ## Build ulang Web UI (npm ci) — output di $(SVELTE_DIR)/dist
	cd $(SVELTE_DIR) && $(WEB_NPM) run build
	@echo "✓ Web UI dibangun — disajikan di :8000/ui oleh API"

web: local-up ## Alias: pastikan service lokal hidup, lalu buka Web UI di browser
	@$(MAKE) open

open: ## Buka Web UI di browser (pakai service yang sudah berjalan)
	@$(PYTHON) -c "import urllib.request as u; u.urlopen('$(LOCAL_API_URL)/api/v1/health', timeout=2)" 2>/dev/null \
		|| (echo "API offline — jalankan: make up (Docker) atau make local-up" && exit 1)
	@echo "Buka Web UI: $(LOCAL_API_URL)/ui"
	@if command -v xdg-open >/dev/null 2>&1; then xdg-open "$(LOCAL_API_URL)/ui" >/dev/null 2>&1 & \
	elif command -v open >/dev/null 2>&1; then open "$(LOCAL_API_URL)/ui" >/dev/null 2>&1 & \
	else echo "  (browser tidak ditemukan — buka manual: $(LOCAL_API_URL)/ui)"; fi

restart: ## Hentikan lalu nyalakan kembali service (Docker: down+up)
	@$(MAKE) down
	@$(MAKE) up

local-clean: local-down ## Bersihkan data lokal (reports/brain/target/logs/pids)
	@rm -rf $(APP_ABS)/reports $(APP_ABS)/brain $(APP_ABS)/target $(LOCAL_API_LOG) $(LOCAL_LAB_LOG)
	@find $(APP_ABS) -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf $(APP_ABS)/.pytest_cache $(APP_ABS)/.ruff_cache $(VENV)
	@echo "Data lokal dibersihkan (venv ikut dihapus; ulangi make local-install untuk setup)."