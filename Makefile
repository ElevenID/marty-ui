# Marty UI Development Environment
# =================================

.PHONY: help dev up down restart logs clean status shell test infra setup-local run-api run-api-tunnel run-ui \
	services-up services-up-tunnel services-down services-logs services-build services-restart services-migrate \
	tunnel-start tunnel-stop tunnel-restart tunnel-status tunnel-logs tunnel-nginx-logs \
	tunnel-refresh-upstreams \
	tunnel-auth-restart tunnel-keycloak-restart tunnel-full-restart tunnel-use-prod tunnel-use-dev \
	setup-keycloak \
	dev-ui-tunnel prod-ui-tunnel prod-ui-tunnel-kill tunnel-prod-static tunnel-prod-restart \
	public-ui public-ui-dev check prod-ui-docker prod-ui-docker-rebuild prod-ui-docker-stop \
	obs-up obs-down \
	wallet-up wallet-down \
	proto-gen grpc-health \
	package-selfhost-bundle \
	selfhost-prod-license-init-keypair selfhost-prod-license-issue \
	selfhost-prod-openbao-up selfhost-prod-openbao-down selfhost-prod-openbao-ps selfhost-prod-openbao-logs \
	selfhost-prod-openbao-bootstrap selfhost-prod-openbao-export \
	selfhost-prod-ui-build selfhost-prod-config selfhost-prod-check selfhost-prod-bootstrap selfhost-prod-up \
	selfhost-prod-down selfhost-prod-restart selfhost-prod-ps selfhost-prod-logs \
	deploy-prod

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

ifeq ($(OS),Windows_NT)
ifneq ($(wildcard C:/PROGRA~1/Git/usr/bin/sh.exe),)
SHELL := C:/PROGRA~1/Git/usr/bin/sh.exe
export PATH := C:/PROGRA~1/Git/usr/bin;$(PATH)
else ifneq ($(wildcard C:/Program Files/Git/usr/bin/sh.exe),)
SHELL := C:/Program Files/Git/usr/bin/sh.exe
export PATH := C:/Program Files/Git/usr/bin;$(PATH)
else ifneq ($(wildcard C:/Program Files/Git/bin/sh.exe),)
SHELL := C:/Program Files/Git/bin/sh.exe
export PATH := C:/Program Files/Git/bin;$(PATH)
endif
endif

# Configuration
COMPOSE := docker compose
BASE_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml
TUNNEL_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.tunnel.yml
OBS_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.obs.yml
WALTID_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.waltid.yml
WALTID_SERVICES := waltid-wallet-api waltid-web-wallet waltid-nginx
WHEELS_SCRIPT := ./scripts/build-rust-wheels.sh
SETUP_LOCAL_SCRIPT := ./scripts/setup-local.sh
SELFHOST_ENV_FILE ?= .env.selfhost.production.local
-include $(SELFHOST_ENV_FILE)
SELFHOST_PROD_COMPOSE := $(COMPOSE) --env-file $(SELFHOST_ENV_FILE) -f docker-compose.selfhost.prod.yml
SELFHOST_OPENBAO_COMPOSE := $(COMPOSE) --env-file $(SELFHOST_ENV_FILE) -f docker-compose.selfhost.openbao.yml
SELFHOST_OPENBAO_LOG_SERVICES := openbao openbao-bootstrap
SELFHOST_PROD_LOG_SERVICES := edge cloudflared gateway keycloak
SELFHOST_ISSUER_TOOL := ../tools/selfhost-license-issuer/selfhost_license_issuer.py
ifeq ($(OS),Windows_NT)
SELFHOST_ISSUER_KEY_DIR ?= $(subst \\,/,$(LOCALAPPDATA))/MartyLicenseIssuer/keys
else
SELFHOST_ISSUER_KEY_DIR ?= $(HOME)/.local/share/MartyLicenseIssuer/keys
endif
SELFHOST_ISSUER_PRIVATE_KEY ?= $(SELFHOST_ISSUER_KEY_DIR)/private_key.pem
SELFHOST_ISSUER_PUBLIC_KEY ?= $(SELFHOST_ISSUER_KEY_DIR)/public_key.pem
SELFHOST_LICENSE_OUTPUT_FILE ?= ../marty-selfhost-prod/license-issuer/issued/selfhost-license.jwt
SELFHOST_LICENSE_ORG_NAME ?= Marty Self-Host Local
SELFHOST_SECRET_DIR ?=
SELFHOST_LICENSE_SUBJECT ?= $(MARTY_ORG_ID)

INFRA_SERVICES := postgres redis keycloak mailpit openbao
APP_SERVICES := event-stream issuance gateway auth organization credential-template trust-profile applicant notification compliance-profile presentation-policy deployment-profile flow revocation-profile verification envoy

.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(GREEN)Marty UI - Development Targets$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-24s$(NC) %s\n", $$1, $$2}'
	@echo ""

dev: up ## Start infrastructure + microservices stack
	@echo "$(GREEN)✓ Development environment started$(NC)"
	@echo "  Gateway:      http://localhost:8000/docs"
	@echo "  Auth:         http://localhost:8001/docs  (gRPC :9001)"
	@echo "  Organization: http://localhost:8002/docs  (gRPC :9002)"
	@echo "  Cred-Tmpl:    http://localhost:8003/docs  (gRPC :9003)"
	@echo "  Pres-Policy:  http://localhost:8009/docs  (gRPC :9009)"
	@echo "  Flow:         http://localhost:8011/docs  (gRPC :9011)"
	@echo "  Keycloak:     http://localhost:8180"

build-wheels: ## Build native Rust wheels for local Python development (optional)
	@echo "$(BLUE)Building native Rust wheels for local development...$(NC)"
	@bash $(WHEELS_SCRIPT)
	@echo "$(GREEN)✓ Native wheels built successfully$(NC)"

package-selfhost-bundle: ## Stage the image-based self-host customer bundle in dist/selfhost-bundle
	@echo "$(BLUE)Staging self-host customer bundle...$(NC)"
	@python scripts/package-selfhost-bundle.py
	@echo "$(GREEN)✓ Self-host customer bundle staged$(NC)"

selfhost-prod-license-init-keypair: ## Generate the operator-side self-host issuer keypair
	@echo "$(BLUE)Generating self-host issuer keypair...$(NC)"
	@mkdir -p "$(SELFHOST_ISSUER_KEY_DIR)"
	@python $(SELFHOST_ISSUER_TOOL) init-keypair \
		--private-key-file "$(SELFHOST_ISSUER_PRIVATE_KEY)" \
		--public-key-file "$(SELFHOST_ISSUER_PUBLIC_KEY)"
	@echo "$(GREEN)✓ Issuer keypair written$(NC)"
	@echo "  Private key: $(SELFHOST_ISSUER_PRIVATE_KEY)"
	@echo "  Public key:  $(SELFHOST_ISSUER_PUBLIC_KEY)"

selfhost-prod-license-issue: ## Issue and install a signed self-host license into SELFHOST_SECRET_DIR
	@if [ -z "$(SELFHOST_LICENSE_SUBJECT)" ]; then \
		echo "$(RED)❌ Error: MARTY_ORG_ID missing from $(SELFHOST_ENV_FILE) or SELFHOST_LICENSE_SUBJECT override$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(SELFHOST_SECRET_DIR)" ]; then \
		echo "$(RED)❌ Error: SELFHOST_SECRET_DIR missing from $(SELFHOST_ENV_FILE) or SELFHOST_SECRET_DIR override$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Issuing self-host production license...$(NC)"
	@mkdir -p "$(dir $(SELFHOST_LICENSE_OUTPUT_FILE))"
	@python $(SELFHOST_ISSUER_TOOL) issue-license \
		--env-file "$(SELFHOST_ENV_FILE)" \
		--private-key-file "$(SELFHOST_ISSUER_PRIVATE_KEY)" \
		--subject "$(SELFHOST_LICENSE_SUBJECT)" \
		--org-name "$(SELFHOST_LICENSE_ORG_NAME)" \
		--install-secret-dir "$(SELFHOST_SECRET_DIR)" \
		--license-output-file "$(SELFHOST_LICENSE_OUTPUT_FILE)"
	@echo "$(GREEN)✓ Self-host license installed$(NC)"

selfhost-prod-openbao-up: ## Start the standalone self-host OpenBao deployment
	@echo "$(BLUE)Starting self-host OpenBao...$(NC)"
	@$(SELFHOST_OPENBAO_COMPOSE) up -d
	@echo "$(GREEN)✓ Self-host OpenBao started$(NC)"

selfhost-prod-openbao-down: ## Stop the standalone self-host OpenBao deployment
	@echo "$(BLUE)Stopping self-host OpenBao...$(NC)"
	@$(SELFHOST_OPENBAO_COMPOSE) down
	@echo "$(GREEN)✓ Self-host OpenBao stopped$(NC)"

selfhost-prod-openbao-ps: ## Show the standalone self-host OpenBao container status
	@$(SELFHOST_OPENBAO_COMPOSE) ps

selfhost-prod-openbao-logs: ## Follow logs for the standalone self-host OpenBao deployment
	@$(SELFHOST_OPENBAO_COMPOSE) logs -f $(SELFHOST_OPENBAO_LOG_SERVICES)

selfhost-prod-openbao-bootstrap: ## Re-run the standalone OpenBao bootstrap helper
	@echo "$(BLUE)Running self-host OpenBao bootstrap...$(NC)"
	@$(SELFHOST_OPENBAO_COMPOSE) run --rm openbao-bootstrap
	@echo "$(GREEN)✓ Self-host OpenBao bootstrap completed$(NC)"

selfhost-prod-openbao-export: ## Export the standalone OpenBao state archive
	@echo "$(BLUE)Exporting self-host OpenBao state...$(NC)"
	@python scripts/export-selfhost-openbao.py --env-file "$(SELFHOST_ENV_FILE)"
	@echo "$(GREEN)✓ Self-host OpenBao export created$(NC)"

selfhost-prod-ui-build: ## Build the self-host UI bundle
	@echo "$(BLUE)Building self-host UI bundle...$(NC)"
	@cd ui && npm run build:selfhost
	@echo "$(GREEN)✓ Self-host UI bundle built$(NC)"

selfhost-prod-config: ## Validate the self-host production compose files
	@echo "$(BLUE)Validating self-host production compose files...$(NC)"
	@$(SELFHOST_OPENBAO_COMPOSE) config >/dev/null
	@$(SELFHOST_PROD_COMPOSE) config >/dev/null
	@echo "$(GREEN)✓ Self-host production compose is valid$(NC)"

selfhost-prod-check: ## Validate license, tunnel token, OpenBao state, and main self-host compose health
	@echo "$(BLUE)Checking self-host production deployment state...$(NC)"
	@python scripts/check-selfhost-production.py --env-file "$(SELFHOST_ENV_FILE)"

selfhost-prod-bootstrap: selfhost-prod-ui-build selfhost-prod-openbao-up selfhost-prod-up ## Build the self-host UI, start OpenBao, then start the main stack
	@echo "$(GREEN)✓ Self-host production bootstrap complete$(NC)"

selfhost-prod-up: selfhost-prod-config ## Start the self-host production stack with image rebuilds
	@echo "$(BLUE)Starting self-host production stack...$(NC)"
	@$(SELFHOST_PROD_COMPOSE) up -d --build
	@echo "$(GREEN)✓ Self-host production stack started$(NC)"

selfhost-prod-down: ## Stop the self-host production stack
	@echo "$(BLUE)Stopping self-host production stack...$(NC)"
	@$(SELFHOST_PROD_COMPOSE) down
	@echo "$(GREEN)✓ Self-host production stack stopped$(NC)"

selfhost-prod-restart: selfhost-prod-down selfhost-prod-up ## Restart the self-host production stack

selfhost-prod-ps: ## Show the self-host production stack status
	@$(SELFHOST_PROD_COMPOSE) ps

selfhost-prod-logs: ## Follow logs for the self-host production stack core services
	@$(SELFHOST_PROD_COMPOSE) logs -f $(SELFHOST_PROD_LOG_SERVICES)

setup-local: ## Setup native local development environment (venv + dependencies)
	@echo "$(BLUE)Setting up native local development environment...$(NC)"
	@bash $(SETUP_LOCAL_SCRIPT)

infra: ## Start only infrastructure services
	@echo "$(BLUE)Starting infrastructure services...$(NC)"
	@$(BASE_COMPOSE) up -d $(INFRA_SERVICES)
	@$(MAKE) --no-print-directory setup-keycloak
	@echo "$(GREEN)✓ Infrastructure started$(NC)"

run-api: infra services-up ## Start infra + API microservices
	@echo "$(GREEN)✓ Gateway API started at http://localhost:8000$(NC)"

run-api-tunnel: infra services-up-tunnel ## Start infra + API microservices with tunnel env vars (sets ISSUER_BASE_URL)
	@echo "$(GREEN)✓ Gateway API started (tunnel mode)$(NC)"

run-ui: ## Run UI natively (requires API stack)
	@echo "$(BLUE)Starting UI natively...$(NC)"
	@cd ui && npm run dev

public-ui: run-api-tunnel tunnel-keycloak-restart prod-ui-docker tunnel-start tunnel-use-prod ## Start all dependencies + Cloudflare tunnel/proxy + persistent Docker UI

public-ui-dev: run-api-tunnel tunnel-keycloak-restart tunnel-start tunnel-use-dev dev-ui-tunnel ## Start all dependencies + Cloudflare tunnel/proxy + UI dev server (public tunnel mode)

prod-ui-docker: ## Build UI and serve in Docker (persistent, survives terminal close)
	@echo "$(BLUE)🔨 Building production UI...$(NC)"
	@cp .env ui/.env
	@cd ui && npm run build
	@echo "$(BLUE)🚀 Starting UI container on :3002...$(NC)"
	@docker compose -f docker-compose.ui-prod.yml up -d --force-recreate
	@echo "$(GREEN)✅ UI running in Docker (restart: unless-stopped)$(NC)"
	@echo "  Local:  http://localhost:3002/"

prod-ui-docker-rebuild: ## Rebuild UI and restart Docker container
	@echo "$(BLUE)🔨 Rebuilding UI...$(NC)"
	@cp .env ui/.env
	@cd ui && npm run build
	@docker compose -f docker-compose.ui-prod.yml restart ui-prod
	@echo "$(GREEN)✅ UI rebuilt and restarted$(NC)"

prod-ui-docker-stop: ## Stop the Docker UI container
	@docker compose -f docker-compose.ui-prod.yml down
	@echo "$(GREEN)✅ UI container stopped$(NC)"

services-migrate: ## Run Alembic migrations using the migration runner
	@echo "$(BLUE)Running database migrations...$(NC)"
	@$(BASE_COMPOSE) up --build db-migrate
	@echo "$(GREEN)✓ Database migrations completed$(NC)"

services-up: ## Start all microservices (requires infra)
	@echo "$(BLUE)Starting Marty microservices stack...$(NC)"
	@$(BASE_COMPOSE) build db-migrate
	@$(BASE_COMPOSE) up -d db-migrate
	@$(BASE_COMPOSE) up -d --build $(APP_SERVICES)
	@$(MAKE) --no-print-directory tunnel-refresh-upstreams
	@echo "$(GREEN)✓ Microservices started$(NC)"

services-up-tunnel: ## Start all microservices with tunnel profile (sets ISSUER_BASE_URL for public wallet flows)
	@echo "$(BLUE)Starting Marty microservices stack (tunnel mode)...$(NC)"
	@$(TUNNEL_COMPOSE) build db-migrate
	@$(TUNNEL_COMPOSE) up -d db-migrate
	@$(TUNNEL_COMPOSE) up -d --build $(APP_SERVICES)
	@$(MAKE) --no-print-directory tunnel-refresh-upstreams
	@echo "$(GREEN)✓ Microservices started (tunnel mode)$(NC)"

services-down: ## Stop microservices only
	@echo "$(BLUE)Stopping Marty microservices...$(NC)"
	@$(BASE_COMPOSE) stop $(APP_SERVICES)
	@echo "$(GREEN)✓ Microservices stopped$(NC)"

services-logs: ## View microservices logs
	@$(BASE_COMPOSE) logs -f $(APP_SERVICES)

services-build: ## Build microservices images
	@echo "$(BLUE)Building microservices images...$(NC)"
	@$(BASE_COMPOSE) build $(APP_SERVICES)
	@echo "$(GREEN)✓ Images built$(NC)"

services-restart: services-down services-up ## Restart microservices

up: infra services-up ## Start infrastructure + microservices

down: ## Stop all services (base + tunnel profile services)
	@echo "$(BLUE)Stopping Marty stack...$(NC)"
	@$(TUNNEL_COMPOSE) down --remove-orphans
	@echo "$(GREEN)✓ Services stopped$(NC)"

restart: down up ## Restart full stack

logs: ## Follow logs from all base services
	@$(BASE_COMPOSE) logs -f

clean: ## Stop services and remove volumes
	@echo "$(RED)Cleaning up containers and volumes...$(NC)"
	@$(TUNNEL_COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

status: ## Show status of all base services
	@$(BASE_COMPOSE) ps

shell: ## Open shell in gateway container
	@$(BASE_COMPOSE) exec gateway bash

test: ## Run gRPC adapter and factory unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	@cd services && python -m pytest -v --tb=short
	@echo "$(GREEN)✓ Tests passed$(NC)"

proto-gen: ## Regenerate Python proto stubs from .proto definitions
	@echo "$(BLUE)Generating Python proto stubs...$(NC)"
	@python -m grpc_tools.protoc \
		-Iproto \
		--python_out=packages/marty_proto/v1 \
		--grpc_python_out=packages/marty_proto/v1 \
		proto/v1/*.proto
	@echo "$(GREEN)✓ Proto stubs generated$(NC)"

grpc-health: ## Check gRPC health status of all gRPC-enabled services
	@echo "$(BLUE)Checking gRPC service health...$(NC)"
	@for pair in "auth:9001" "organization:9002" "credential-template:9003" "presentation-policy:9009" "flow:9011"; do \
		service=$$(echo $$pair | cut -d: -f1); \
		port=$$(echo $$pair | cut -d: -f2); \
		if docker exec marty-$$service grpc_health_probe -addr=localhost:$$port 2>/dev/null; then \
			echo "  $(GREEN)✓ $$service (:$$port) healthy$(NC)"; \
		else \
			echo "  $(YELLOW)⚠ $$service (:$$port) — checking via grpcurl...$(NC)"; \
			docker exec marty-$$service python -c "import grpc; ch=grpc.insecure_channel('localhost:$$port'); grpc.channel_ready_future(ch).result(timeout=3); print('OK')" 2>/dev/null && \
				echo "  $(GREEN)✓ $$service (:$$port) reachable$(NC)" || \
				echo "  $(RED)✗ $$service (:$$port) unreachable$(NC)"; \
		fi; \
	done

tunnel-start: ## Start Cloudflare tunnel sidecars (uses .env)
	@if ! grep -q '^CLOUDFLARE_TUNNEL_TOKEN=eyJ' .env 2>/dev/null; then \
		echo "$(RED)❌ Error: CLOUDFLARE_TUNNEL_TOKEN missing in .env$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🚀 Starting Cloudflare Tunnel...$(NC)"
	@$(TUNNEL_COMPOSE) up -d cloudflared nginx-proxy
	@PUBLIC_DOMAIN=$$(grep '^PUBLIC_DOMAIN=' .env | cut -d'=' -f2); \
	echo "$(GREEN)✅ Tunnel started$(NC) at https://$${PUBLIC_DOMAIN}"

tunnel-stop: ## Stop Cloudflare tunnel sidecars
	@echo "$(BLUE)🛑 Stopping Cloudflare Tunnel...$(NC)"
	@$(TUNNEL_COMPOSE) stop cloudflared nginx-proxy
	@docker rm -f tunnel-nginx-proxy-prod >/dev/null 2>&1 || true
	@echo "$(GREEN)✅ Tunnel stopped$(NC)"

tunnel-restart: tunnel-stop tunnel-start ## Restart Cloudflare tunnel sidecars

tunnel-logs: ## View Cloudflare tunnel logs
	@docker logs -f cloudflared-tunnel

tunnel-nginx-logs: ## View tunnel nginx logs
	@docker logs -f tunnel-nginx-proxy

tunnel-status: ## Check tunnel and gateway/auth status
	@echo "$(BLUE)🔍 Checking tunnel status...$(NC)"
	@docker ps --filter name='cloudflared-tunnel|tunnel-nginx-proxy|marty-auth|marty-gateway|marty-organization' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

tunnel-refresh-upstreams: ## Refresh tunnel proxy upstreams after container IP changes
	@if docker ps --format '{{.Names}}' | grep -q '^tunnel-nginx-proxy$$'; then \
		echo "$(BLUE)♻️  Refreshing tunnel upstreams...$(NC)"; \
		$(TUNNEL_COMPOSE) restart nginx-proxy >/dev/null; \
		echo "$(GREEN)✅ Tunnel upstreams refreshed$(NC)"; \
	else \
		echo "$(YELLOW)ℹ️  tunnel-nginx-proxy not running; skipping upstream refresh$(NC)"; \
	fi

tunnel-auth-restart: ## Restart auth + gateway with tunnel overrides
	@echo "$(BLUE)🔄 Restarting auth and gateway with tunnel profile...$(NC)"
	@$(TUNNEL_COMPOSE) up -d auth gateway
	@$(MAKE) --no-print-directory tunnel-refresh-upstreams
	@echo "$(GREEN)✅ Auth and Gateway restarted$(NC)"

tunnel-keycloak-restart: ## Restart Keycloak with tunnel overrides (then runs setup-keycloak)
	@echo "$(BLUE)🔄 Restarting Keycloak with tunnel profile...$(NC)"
	@$(TUNNEL_COMPOSE) up -d keycloak
	@echo "$(GREEN)✅ Keycloak restarted$(NC)"
	@$(MAKE) --no-print-directory setup-keycloak

setup-keycloak: ## Patch Keycloak with env-var credentials (Google IdP, redirect URIs)
	@echo "$(BLUE)⚙️  Running Keycloak configurator...$(NC)"
	@docker run --rm \
		--entrypoint /bin/bash \
		--network marty-infra-network \
		--env-file .env \
		-e KC_URL=http://marty-keycloak:8080 \
		-e KCADM_PATH=/opt/keycloak/bin/kcadm.sh \
		-v "$(CURDIR)/scripts/setup-keycloak.sh:/scripts/setup-keycloak.sh:ro" \
		quay.io/keycloak/keycloak:25.0 \
		/scripts/setup-keycloak.sh 2>&1 | sed 's/^/  /'
	@echo "$(GREEN)✅ Keycloak configured$(NC)"

tunnel-full-restart: tunnel-keycloak-restart tunnel-auth-restart ## Restart all tunnel-sensitive services
	@echo "$(GREEN)✅ Tunnel-related services restarted$(NC)"

tunnel-use-prod: ## Route tunnel proxy to production preview UI (:3002)
	@echo "$(BLUE)🔧 Configuring tunnel for production preview server...$(NC)"
	@if ! grep -q '^UI_DEV_PORT=' .env 2>/dev/null; then \
		echo "UI_DEV_PORT=3002" >> .env; \
	else \
		sed -i.bak 's/^UI_DEV_PORT=.*/UI_DEV_PORT=3002/' .env && rm .env.bak; \
	fi
	@$(TUNNEL_COMPOSE) up -d --force-recreate nginx-proxy
	@echo "$(GREEN)✅ Tunnel now targets port 3002$(NC)"

tunnel-use-dev: ## Route tunnel proxy to Vite dev UI (:3000)
	@echo "$(BLUE)🔧 Configuring tunnel for dev server...$(NC)"
	@if ! grep -q '^UI_DEV_PORT=' .env 2>/dev/null; then \
		echo "UI_DEV_PORT=3000" >> .env; \
	else \
		sed -i.bak 's/^UI_DEV_PORT=.*/UI_DEV_PORT=3000/' .env && rm .env.bak; \
	fi
	@$(TUNNEL_COMPOSE) up -d --force-recreate nginx-proxy
	@echo "$(GREEN)✅ Tunnel now targets port 3000$(NC)"

dev-ui-tunnel: ## Start UI dev server for tunnel mode
	@echo "$(BLUE)🚀 Starting UI dev server for tunnel mode...$(NC)"
	@cp .env ui/.env
	@cd ui && npm run dev -- --host --mode tunnel

# Legacy compatibility aliases — intentionally hidden from `make help`.
prod-ui-tunnel:
	@echo "$(YELLOW)⚠ Deprecated: use prod-ui-docker$(NC)"
	@$(MAKE) --no-print-directory prod-ui-docker

prod-ui-tunnel-kill:
	@echo "$(YELLOW)⚠ Deprecated: use prod-ui-docker-stop$(NC)"
	@$(MAKE) --no-print-directory prod-ui-docker-stop

tunnel-prod-static:
	@echo "$(YELLOW)⚠ Deprecated: use public-ui$(NC)"
	@$(MAKE) --no-print-directory prod-ui-docker
	@$(MAKE) --no-print-directory tunnel-start
	@$(MAKE) --no-print-directory tunnel-use-prod

tunnel-prod-restart:
	@echo "$(YELLOW)⚠ Deprecated: use prod-ui-docker-rebuild$(NC)"
	@$(MAKE) --no-print-directory prod-ui-docker-rebuild

obs-up: ## Start observability profile
	@$(OBS_COMPOSE) up -d elasticsearch kibana fluentd prometheus grafana jaeger

obs-down: ## Stop observability profile
	@$(OBS_COMPOSE) stop elasticsearch kibana fluentd prometheus grafana jaeger

wallet-up: ## Start walt.id web wallet stack for Playwright testing (UI: :7101, API: :7001)
	@echo "$(BLUE)Starting walt.id wallet stack...$(NC)"
	@$(WALTID_COMPOSE) up -d $(WALTID_SERVICES)
	@echo "$(GREEN)✓ Walt.id wallet started$(NC)"
	@echo "  Demo Wallet: http://localhost:7101"
	@echo "  Wallet API:  http://localhost:7001/wallet-api"

wallet-down: ## Stop walt.id wallet stack
	@echo "$(BLUE)Stopping walt.id wallet stack...$(NC)"
	@$(WALTID_COMPOSE) stop $(WALTID_SERVICES)
	@echo "$(GREEN)✓ Walt.id wallet stopped$(NC)"

deploy-prod: ## Deploy with secrets from OCI Vault (no .env.production needed)
	@echo "$(BLUE)Fetching production secrets from OCI Vault...$(NC)"
	@bash -c 'source scripts/fetch-secrets.sh && $(BASE_COMPOSE) up -d'
	@echo "$(GREEN)✓ Production deployment started with vault secrets$(NC)"

check: ## Quick health check of all public-ui components
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(BLUE)  Public UI Health Check$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@UI_PORT=$$(grep '^UI_DEV_PORT=' .env 2>/dev/null | cut -d'=' -f2); \
	UI_PORT=$${UI_PORT:-3002}; \
	DOMAIN=$$(grep '^PUBLIC_DOMAIN=' .env 2>/dev/null | cut -d'=' -f2); \
	echo ""; \
	echo "  $(BLUE)Infrastructure$(NC)"; \
	for svc in postgres redis keycloak openbao mailpit; do \
		if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "marty-$$svc"; then \
			echo "    $(GREEN)✓$(NC) $$svc"; \
		else \
			echo "    $(RED)✗$(NC) $$svc"; \
		fi; \
	done; \
	echo ""; \
	echo "  $(BLUE)Microservices$(NC)"; \
	for svc in gateway auth organization issuance event-stream; do \
		if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "marty-$$svc"; then \
			echo "    $(GREEN)✓$(NC) $$svc"; \
		else \
			echo "    $(RED)✗$(NC) $$svc"; \
		fi; \
	done; \
	echo ""; \
	echo "  $(BLUE)Tunnel$(NC)"; \
	if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "cloudflared-tunnel"; then \
		echo "    $(GREEN)✓$(NC) cloudflared"; \
	else \
		echo "    $(RED)✗$(NC) cloudflared"; \
	fi; \
	if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "tunnel-nginx-proxy"; then \
		echo "    $(GREEN)✓$(NC) nginx-proxy"; \
	else \
		echo "    $(RED)✗$(NC) nginx-proxy"; \
	fi; \
	echo ""; \
	echo "  $(BLUE)Vite Dev Server$(NC) (port $$UI_PORT)"; \
	if curl -s -o /dev/null -w '%{http_code}' "http://localhost:$$UI_PORT/" 2>/dev/null | grep -q '200'; then \
		echo "    $(GREEN)✓$(NC) http://localhost:$$UI_PORT/"; \
	else \
		echo "    $(RED)✗$(NC) http://localhost:$$UI_PORT/ — not responding"; \
	fi; \
	echo ""; \
	echo "  $(BLUE)Public URL$(NC)"; \
	if [ -n "$$DOMAIN" ]; then \
		HTTP_CODE=$$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://$$DOMAIN/" 2>/dev/null); \
		if [ "$$HTTP_CODE" = "200" ]; then \
			echo "    $(GREEN)✓$(NC) https://$$DOMAIN/"; \
		else \
			echo "    $(RED)✗$(NC) https://$$DOMAIN/ — HTTP $$HTTP_CODE"; \
		fi; \
	else \
		echo "    $(YELLOW)⚠$(NC) PUBLIC_DOMAIN not set in .env"; \
	fi; \
	echo ""

