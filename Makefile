# Marty UI Development Environment
# =================================
#
# QUICK START:
#   make dev         - Build wheels and start development environment
#   make build-wheels - Build Rust wheels from sibling repos
#   make up          - Start containers (assumes wheels exist)
#   make down        - Stop containers
#   make logs        - View container logs
#   make clean       - Stop and remove all containers and volumes

.PHONY: help dev build-wheels up down logs clean restart shell test infra setup-local run-api run-ui run-services services-up services-down services-logs tunnel-start tunnel-stop tunnel-logs tunnel-nginx-logs tunnel-restart tunnel-status dev-ui-tunnel

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# Configuration
COMPOSE := docker compose
INFRA_COMPOSE := $(COMPOSE) -f docker-compose.infra.yml
WHEELS_SCRIPT := ./scripts/build-rust-wheels.sh
SETUP_LOCAL_SCRIPT := ./scripts/setup-local.sh

.DEFAULT_GOAL := help

# =============================================================================
# Help
# =============================================================================
help: ## Show this help message
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(GREEN)Marty UI - Development Targets$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# =============================================================================
# Primary Development Workflow
# =============================================================================
dev: up ## Start development environment (5-7 min first time for Rust compilation)
	@echo "$(GREEN)✓ Development environment started!$(NC)"
	@echo "$(YELLOW)⏱️  First startup: 5-7 minutes (Rust compilation in Docker)$(NC)"
	@echo "$(YELLOW)⏱️  Subsequent starts: ~10 seconds (cached)$(NC)"
	@echo ""
	@echo "$(YELLOW)Services available at:$(NC)"
	@echo "  - API: http://localhost:8000"
	@echo "  - UI: http://localhost:3000"
	@echo ""
	@echo "$(YELLOW)View logs:$(NC) make logs"
	@echo "$(YELLOW)Stop:$(NC) make down"

build-wheels: ## Build native Rust wheels for local Python development (optional)
	@echo "$(BLUE)Building native Rust wheels for local development...$(NC)"
	@echo "$(YELLOW)Note: Docker dev mode builds Rust automatically - this is only needed for native Python setup$(NC)"
	@bash $(WHEELS_SCRIPT)
	@echo "$(GREEN)✓ Native wheels built successfully$(NC)"

infra: ## Start only infrastructure services (DB, Redis, Keycloak)
	@echo "$(BLUE)Starting infrastructure services...$(NC)"
	$(INFRA_COMPOSE) up -d
	@echo "$(GREEN)✓ Infrastructure started$(NC)"

setup-local: ## Setup native local development environment (venv + dependencies)
	@echo "$(BLUE)Setting up native local development environment...$(NC)"
	@bash $(SETUP_LOCAL_SCRIPT)

run-api: infra services-up ## Start infrastructure + microservices API stack
	@echo "$(GREEN)✓ Gateway API started at http://localhost:8000$(NC)"

run-ui: ## Run UI natively (uses gateway API at localhost:8000)
	@echo "$(BLUE)Starting UI natively...$(NC)"
	@echo "$(YELLOW)Note: Requires gateway API running (make run-api)$(NC)"
	@cd ui && bun run dev

gateway-dev: infra services-up run-ui ## Start full gateway-based development environment

# =============================================================================
# Microservices Operations
# =============================================================================
SERVICES_COMPOSE := $(COMPOSE) -f docker-compose.services-app.yml

run-services: services-up ## Start microservices stack (alias for services-up)

services-init-db: ## Initialize microservices database schemas
	@echo "$(BLUE)Initializing database schemas...$(NC)"
	@docker cp scripts/init-db.sql marty-ui-postgres-1:/tmp/init-db.sql
	@docker exec marty-ui-postgres-1 psql -U marty -f /tmp/init-db.sql
	@echo "$(GREEN)✓ Database schemas initialized$(NC)"

services-up: ## Start all microservices (requires infra)
	@echo "$(BLUE)Starting Marty microservices stack...$(NC)"
	$(SERVICES_COMPOSE) up -d --build
	@echo "$(GREEN)✓ Microservices started$(NC)"
	@echo ""
	@echo "$(YELLOW)Services available at:$(NC)"
	@echo "  - Gateway API:  http://localhost:8000/docs"
	@echo "  - Auth:         http://localhost:8001/docs"
	@echo "  - Organization: http://localhost:8002/docs"
	@echo "  - Keycloak:     http://localhost:8180 (admin/admin)"
	@echo "  - RabbitMQ:     http://localhost:15672 (marty/marty_dev_password)"
	@echo ""
	@echo "$(YELLOW)To start UI:$(NC) make run-ui (in separate terminal)"
	@echo "$(YELLOW)View logs:$(NC) make services-logs"
	@echo "$(YELLOW)Stop:$(NC) make services-down"

services-down: ## Stop all microservices
	@echo "$(BLUE)Stopping Marty microservices...$(NC)"
	$(SERVICES_COMPOSE) down
	@echo "$(GREEN)✓ Microservices stopped$(NC)"

services-logs: ## View microservices logs
	$(SERVICES_COMPOSE) logs -f

services-build: ## Build microservices images
	@echo "$(BLUE)Building microservices images...$(NC)"
	$(SERVICES_COMPOSE) build
	@echo "$(GREEN)✓ Images built$(NC)"

services-restart: services-down services-up ## Restart all microservices

# =============================================================================
# Docker Compose Operations
# =============================================================================
up: ## Start all containers with local development overrides
	@echo "$(BLUE)Starting marty-ui services...$(NC)"
	$(COMPOSE) --profile dev up -d
	@echo "$(GREEN)✓ Services started$(NC)"

down: ## Stop all containers
	@echo "$(BLUE)Stopping marty-ui services...$(NC)"
	$(COMPOSE) down
	@echo "$(GREEN)✓ Services stopped$(NC)"

restart: down up ## Restart all containers

logs: ## Follow logs from all containers
	$(COMPOSE) logs -f

clean: ## Stop containers and remove volumes
	@echo "$(RED)Cleaning up containers and volumes...$(NC)"
	$(COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

# =============================================================================
# Utility
# =============================================================================
shell: ## Open shell in api container
	$(COMPOSE) exec oid4vc-api bash

test: ## Run E2E tests
	$(COMPOSE) --profile test up --abort-on-container-exit --exit-code-from e2e-tests

status: ## Show status of all services
	$(COMPOSE) ps

# =============================================================================
# Cloudflare Tunnel (External Access)
# =============================================================================
TUNNEL_COMPOSE := $(COMPOSE) -f docker-compose.cloudflared.yml

tunnel-start: ## Start Cloudflare Tunnel for external access (requires .env.tunnel)
	@if [ ! -f .env.tunnel ]; then \
		echo "$(RED)❌ Error: .env.tunnel file not found$(NC)"; \
		echo ""; \
		echo "$(YELLOW)Setup:$(NC)"; \
		echo "  1. Copy template: cp .env.tunnel.example .env.tunnel"; \
		echo "  2. Add your CLOUDFLARE_TUNNEL_TOKEN"; \
		echo "  3. Set PUBLIC_DOMAIN to your domain"; \
		echo "  4. Configure public hostname in Cloudflare dashboard"; \
		exit 1; \
	fi
	@if ! grep -q '^CLOUDFLARE_TUNNEL_TOKEN=eyJ' .env.tunnel 2>/dev/null; then \
		echo "$(RED)❌ Error: CLOUDFLARE_TUNNEL_TOKEN not set in .env.tunnel$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🚀 Starting Cloudflare Tunnel...$(NC)"
	@$(TUNNEL_COMPOSE) --env-file .env.tunnel up -d
	@echo ""
	@echo "$(GREEN)✅ Cloudflare Tunnel started!$(NC)"
	@echo ""
	@PUBLIC_DOMAIN=$$(grep '^PUBLIC_DOMAIN=' .env.tunnel | cut -d'=' -f2); \
	echo "  🌐 Public URL:  $(YELLOW)https://$${PUBLIC_DOMAIN}$(NC)"; \
	echo "  🔗 Local UI:    http://localhost:9080"; \
	echo "  🔗 Gateway API: http://localhost:8000"
	@echo ""
	@echo "$(YELLOW)Important:$(NC) Configure auth service for external access:"
	@echo "  make tunnel-auth-restart"
	@echo ""
	@echo "$(YELLOW)Then start UI:$(NC)"
	@echo "  make dev-ui-tunnel"
	@echo ""
	@echo "$(YELLOW)Logs:$(NC)"
	@echo "  make tunnel-logs      # Tunnel logs"
	@echo "  make tunnel-nginx-logs # Nginx proxy logs"
	@echo ""
	@echo "$(YELLOW)Stop:$(NC) make tunnel-stop"

dev-ui-tunnel: ## Start UI dev server with external access (for tunnel)
	@echo "$(BLUE)🚀 Starting UI with external access...$(NC)"
	@echo "$(YELLOW)Note: UI will be accessible from Docker containers$(NC)"
	@if [ -f .env.tunnel ]; then \
		cp .env.tunnel ui/.env.tunnel; \
		echo "$(GREEN)✓ Synced .env.tunnel to ui/.env.tunnel$(NC)"; \
	fi
	@cd ui && bun run vite --host --mode tunnel

tunnel-stop: ## Stop Cloudflare Tunnel
	@echo "$(BLUE)🛑 Stopping Cloudflare Tunnel...$(NC)"
	@$(TUNNEL_COMPOSE) down
	@echo "$(GREEN)✅ Tunnel stopped$(NC)"

tunnel-restart: tunnel-stop tunnel-start ## Restart Cloudflare Tunnel

tunnel-logs: ## View Cloudflare Tunnel logs
	@echo "$(BLUE)📋 Cloudflare Tunnel logs:$(NC)"
	@echo ""
	@docker logs -f cloudflared-tunnel

tunnel-nginx-logs: ## View nginx proxy logs
	@echo "$(BLUE)📋 Nginx proxy logs:$(NC)"
	@echo ""
	@docker logs -f tunnel-nginx-proxy

tunnel-status: ## Check Cloudflare Tunnel status
	@echo "$(BLUE)🔍 Checking tunnel status...$(NC)"
	@echo ""
	@if docker ps --filter name=cloudflared-tunnel --format '{{.Names}}' | grep -q cloudflared-tunnel; then \
		echo "$(GREEN)✅ Tunnel container is running$(NC)"; \
		docker ps --filter name=tunnel --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"; \
		echo ""; \
		echo "$(BLUE)Recent tunnel logs:$(NC)"; \
		docker logs cloudflared-tunnel 2>&1 | tail -5; \
	else \
		echo "$(RED)❌ Tunnel container is not running$(NC)"; \
		echo "$(YELLOW)Start with: make tunnel-start$(NC)"; \
	fi
	@echo ""
	@echo "$(BLUE)💡 Check Cloudflare dashboard for detailed status:$(NC)"
	@echo "   https://one.dash.cloudflare.com/ → Access → Tunnels"

tunnel-auth-restart: ## Restart auth service with tunnel configuration (for external access)
	@if [ ! -f .env.tunnel ]; then \
		echo "$(RED)❌ Error: .env.tunnel file not found$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🔄 Restarting services with tunnel configuration...$(NC)"
	@PUBLIC_DOMAIN=$$(grep '^PUBLIC_DOMAIN=' .env.tunnel | cut -d'=' -f2); \
	echo "  Domain: $(YELLOW)$${PUBLIC_DOMAIN}$(NC)"; \
	docker-compose -f docker-compose.services-app.yml -f docker-compose.tunnel-override.yml --env-file .env.tunnel up -d auth gateway
	@echo "$(GREEN)✅ Services restarted with tunnel configuration$(NC)"
	@echo ""
	@echo "$(YELLOW)Note:$(NC) Auth and Gateway now configured for external access"

tunnel-keycloak-restart: ## Restart Keycloak with tunnel environment variables
	@if [ ! -f .env.tunnel ]; then \
		echo "$(RED)❌ Error: .env.tunnel file not found$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🔄 Restarting Keycloak with tunnel configuration...$(NC)"
	@PUBLIC_DOMAIN=$$(grep '^PUBLIC_DOMAIN=' .env.tunnel | cut -d'=' -f2); \
	echo "  Domain: $(YELLOW)$${PUBLIC_DOMAIN}$(NC)"; \
	docker-compose -f docker-compose.infra.yml -f docker-compose.infra-tunnel-override.yml --env-file .env.tunnel up -d keycloak
	@echo "$(GREEN)✅ Keycloak restarted with tunnel configuration$(NC)"
	@echo ""
	@echo "$(YELLOW)Note:$(NC) Keycloak realm now includes redirect URIs for $${PUBLIC_DOMAIN}"

tunnel-full-restart: tunnel-keycloak-restart tunnel-auth-restart ## Restart all services for tunnel mode
	@echo ""
	@echo "$(GREEN)✅ All services configured for tunnel access$(NC)"

