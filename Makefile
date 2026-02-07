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

.PHONY: help dev build-wheels up down logs clean restart shell test infra setup-local run-api run-ui run-services services-up services-down services-logs

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
