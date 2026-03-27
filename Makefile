# Marty UI Development Environment
# =================================

.PHONY: help dev up down restart logs clean status shell test infra setup-local run-api run-api-tunnel run-ui \
	services-up services-up-tunnel services-down services-logs services-build services-restart services-migrate \
	tunnel-start tunnel-stop tunnel-restart tunnel-status tunnel-logs tunnel-nginx-logs \
	tunnel-refresh-upstreams \
	tunnel-auth-restart tunnel-keycloak-restart tunnel-full-restart tunnel-use-prod tunnel-use-dev \
	setup-keycloak \
	dev-ui-tunnel prod-ui-tunnel prod-ui-tunnel-kill tunnel-prod-static tunnel-prod-restart \
	public-ui \
	obs-up obs-down \
	wallet-up wallet-down \
	proto-gen grpc-health \
	deploy-prod

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# Configuration
COMPOSE := docker compose
BASE_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml
TUNNEL_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.tunnel.yml
OBS_COMPOSE := $(COMPOSE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.obs.yml
WALTID_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.waltid.yml
WALTID_SERVICES := waltid-wallet-api waltid-web-wallet waltid-nginx
WHEELS_SCRIPT := ./scripts/build-rust-wheels.sh
SETUP_LOCAL_SCRIPT := ./scripts/setup-local.sh

INFRA_SERVICES := postgres redis keycloak mailhog
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
	@cd ui && bun run dev

public-ui: run-api-tunnel tunnel-keycloak-restart tunnel-start dev-ui-tunnel ## Start all dependencies + Cloudflare tunnel/proxy + UI dev server (public tunnel mode)

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
	@$(TUNNEL_COMPOSE) down
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
	@$(TUNNEL_COMPOSE) stop cloudflared nginx-proxy nginx-proxy-prod
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
	@cd ui && bun run vite --host --mode tunnel

prod-ui-tunnel: ## Build and run production preview UI on :3002
	@echo "$(BLUE)🚀 Building production UI...$(NC)"
	@cp .env ui/.env
	@cd ui && bunx vite build
	@lsof -ti :3002 | xargs kill 2>/dev/null || true
	@cd ui && bunx vite preview --host --port 3002 --strictPort

prod-ui-tunnel-kill: ## Kill process using port 3002
	@lsof -ti :3002 | xargs kill 2>/dev/null || true
	@echo "$(GREEN)✅ Port 3002 cleared$(NC)"

tunnel-prod-static: ## Serve static built UI through nginx-proxy-prod (9081)
	@echo "$(BLUE)📦 Building production bundle...$(NC)"
	@cd ui && bunx vite build
	@$(TUNNEL_COMPOSE) stop nginx-proxy || true
	@$(TUNNEL_COMPOSE) up -d cloudflared nginx-proxy-prod
	@echo "$(GREEN)✅ Static production tunnel proxy started on :9081$(NC)"

tunnel-prod-restart: ## Rebuild and restart static production proxy
	@cd ui && bunx vite build
	@$(TUNNEL_COMPOSE) restart nginx-proxy-prod

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

