# Marty UI Development Environment
# =================================

.PHONY: help dev up down restart logs clean status shell test infra infra-tunnel setup-local run-api run-api-tunnel run-ui \
	services-up services-up-tunnel services-down services-logs services-build services-restart services-migrate \
	services-migrate-profile services-migrate-dev services-migrate-beta services-migrate-experiments services-migrate-test services-migrate-production \
	seed-demo-vendor-fixtures dev-db-reset beta-db-reset beta-experiments-db-reset test-db-reset \
	tunnel-start tunnel-stop tunnel-restart tunnel-status tunnel-logs tunnel-nginx-logs \
	tunnel-refresh-upstreams \
	tunnel-auth-restart tunnel-keycloak-restart tunnel-full-restart tunnel-use-prod tunnel-use-dev \
	beta-config beta-up beta-down beta-restart beta-status beta-logs beta-clean beta-public-ui beta-public-ui-dev \
	beta-public-ui-ghcr beta-public-ui-check beta-tunnel-start beta-tunnel-stop beta-tunnel-restart beta-tunnel-status \
	beta-tunnel-logs beta-tunnel-nginx-logs beta-tunnel-refresh-upstreams beta-tunnel-auth-restart \
	beta-tunnel-keycloak-restart beta-tunnel-full-restart beta-tunnel-use-prod beta-tunnel-use-dev beta-dev-ui-tunnel \
	beta-env-init beta-experiments-plan beta-experiments-config beta-experiments-up beta-experiments-down \
	beta-experiments-logs beta-canvas-experiments-bootstrap \
	beta-check \
	setup-keycloak \
	dev-ui-tunnel prod-ui-tunnel prod-ui-tunnel-kill tunnel-prod-static tunnel-prod-restart \
	public-ui public-ui-dev public-ui-ghcr public-ui-check check prod-ui-docker prod-ui-docker-rebuild prod-ui-docker-stop \
	obs-up obs-down \
	wallet-up wallet-down \
	canvas-sandbox-up canvas-sandbox-down canvas-sandbox-build canvas-sandbox-logs canvas-sandbox-status \
	canvas-real-up canvas-real-down canvas-real-logs canvas-real-status canvas-real-seed canvas-real-bootstrap \
	proto-gen grpc-health \
	package-selfhost-bundle \
	selfhost-images-ghcr-setup selfhost-images-build-dry-run selfhost-images-build selfhost-images-build-push \
	selfhost-images-artifacts-dry-run selfhost-images-release-artifacts selfhost-images-sbom selfhost-images-scan \
	selfhost-images-sign selfhost-images-verify-signatures \
	selfhost-prod-license-init-keypair selfhost-prod-license-issue \
	selfhost-prod-openbao-up selfhost-prod-openbao-down selfhost-prod-openbao-ps selfhost-prod-openbao-logs \
	selfhost-prod-openbao-bootstrap selfhost-prod-openbao-export \
	selfhost-prod-ui-build selfhost-prod-config selfhost-prod-check selfhost-prod-bootstrap selfhost-prod-up \
	selfhost-prod-down selfhost-prod-restart selfhost-prod-ps selfhost-prod-logs \
	selfhost-prod-beta-tunnel-up selfhost-prod-beta-tunnel-stop selfhost-prod-beta-tunnel-ps selfhost-prod-beta-tunnel-logs \
	deploy-catalog-validate deploy-stack-plan selfhost-prod-plan selfhost-prod-beta-tunnel-plan \
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
BETA_ENV_FILE ?= $(if $(wildcard .env.tunnel.beta.local),.env.tunnel.beta.local,.env)
BASE_COMPOSE := $(COMPOSE) --env-file $(BETA_ENV_FILE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml
TUNNEL_COMPOSE := $(COMPOSE) --env-file $(BETA_ENV_FILE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.tunnel.yml
GHCR_TUNNEL_COMPOSE := $(COMPOSE) --env-file $(BETA_ENV_FILE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.ghcr.yml -f docker-compose.profile.tunnel.yml
OBS_COMPOSE := $(COMPOSE) --env-file $(BETA_ENV_FILE) -f docker-compose.base.yml -f docker-compose.profile.dev.yml -f docker-compose.profile.obs.yml
WALTID_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.waltid.yml
CANVAS_SANDBOX_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.canvas-sandbox.yml
CANVAS_REAL_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.canvas-real.yml
CANVAS_EXPERIMENTS_COMPOSE := $(TUNNEL_COMPOSE) -f docker-compose.profile.canvas-real.yml -f docker-compose.profile.canvas-sandbox.yml
WALTID_SERVICES := waltid-wallet-api waltid-web-wallet waltid-nginx
WHEELS_SCRIPT := ./scripts/build-rust-wheels.sh
SETUP_LOCAL_SCRIPT := ./scripts/setup-local.sh
SELFHOST_ENV_FILE ?= .env.selfhost.production.local
-include $(SELFHOST_ENV_FILE)
SELFHOST_PROD_COMPOSE := $(COMPOSE) --env-file $(SELFHOST_ENV_FILE) -f docker-compose.selfhost.prod.yml
SELFHOST_PROD_BETA_COMPOSE := $(SELFHOST_PROD_COMPOSE) --profile beta-tunnel
SELFHOST_OPENBAO_COMPOSE := $(COMPOSE) --env-file $(SELFHOST_ENV_FILE) -f docker-compose.selfhost.openbao.yml
SELFHOST_OPENBAO_LOG_SERVICES := openbao openbao-bootstrap
SELFHOST_PROD_LOG_SERVICES := edge cloudflared gateway keycloak
SELFHOST_PROD_BETA_TUNNEL_SERVICES := tunnel-nginx-proxy cloudflared-beta
SELFHOST_ISSUER_TOOL := ../tools/selfhost-license-issuer/selfhost_license_issuer.py
SELFHOST_IMAGE_RELEASE_SCRIPT := ./scripts/build-selfhost-images-local.sh
SELFHOST_IMAGE_ARTIFACTS_SCRIPT := ./scripts/prepare-selfhost-release-artifacts.py
SELFHOST_GHCR_SETUP_SCRIPT := ./scripts/ghcr-setup.sh
SELFHOST_VERSION_FILE ?= VERSION
SELFHOST_DEFAULT_RELEASE_TAG := $(strip $(shell if [ -f "$(SELFHOST_VERSION_FILE)" ]; then tr -d '\r\n' < "$(SELFHOST_VERSION_FILE)"; fi))
SELFHOST_RELEASE_TAG ?= $(if $(TAG),$(TAG),$(SELFHOST_DEFAULT_RELEASE_TAG))
SELFHOST_RELEASE_SCAN_TOOL ?= auto
COSIGN_KEY ?=
COSIGN_PUBLIC_KEY ?=
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

beta-config: ## Validate the beta dev and tunnel compose files
	@echo "$(BLUE)Validating beta compose files...$(NC)"
	@$(BASE_COMPOSE) config >/dev/null
	@$(TUNNEL_COMPOSE) config >/dev/null
	@echo "$(GREEN)âœ“ Beta compose is valid$(NC)"

beta-env-init: ## Initialize the dedicated beta env file from .env when missing
	@if [ -f ".env.tunnel.beta.local" ]; then \
		echo "$(GREEN)âœ“ .env.tunnel.beta.local already exists$(NC)"; \
	elif [ -f ".env" ]; then \
		cp .env .env.tunnel.beta.local; \
		echo "$(GREEN)âœ“ Created .env.tunnel.beta.local from .env$(NC)"; \
	else \
		echo "$(RED)âŒ Error: .env not found; copy deploy-config/env/tunnel-beta/.env.template to .env.tunnel.beta.local first$(NC)"; \
		exit 1; \
	fi

beta-experiments-plan: ## Render the beta Canvas experiments deployment plan
	@python scripts/marty-deploy.py plan tunnel-beta-experiments

beta-experiments-config: ## Validate beta experiments compose files
	@echo "$(BLUE)Validating beta experiments compose files...$(NC)"
	@$(CANVAS_EXPERIMENTS_COMPOSE) config >/dev/null
	@echo "$(GREEN)Beta experiments compose is valid$(NC)"

beta-experiments-up: ## Start the beta experiments stack with real Canvas enabled
	@echo "$(BLUE)Starting beta experiments stack...$(NC)"
	@MARTY_MIGRATION_PROFILE=experiments $(CANVAS_EXPERIMENTS_COMPOSE) up -d --build
	@echo "$(GREEN)Beta experiments stack started$(NC)"

beta-experiments-down: ## Stop the beta experiments stack
	@echo "$(BLUE)Stopping beta experiments stack...$(NC)"
	@$(CANVAS_EXPERIMENTS_COMPOSE) down
	@echo "$(GREEN)Beta experiments stack stopped$(NC)"

beta-experiments-logs: ## Follow beta experiments logs
	@$(CANVAS_EXPERIMENTS_COMPOSE) logs -f

beta-canvas-experiments-bootstrap: beta-experiments-up canvas-real-seed ## Start beta experiments and seed Canvas platform/binding
	@echo "$(GREEN)Beta Canvas experiments bootstrap complete$(NC)"

beta-up: up ## Start the beta development stack

beta-down: down ## Stop the beta development stack

beta-restart: restart ## Restart the beta development stack

beta-status: status ## Show beta development stack status

beta-logs: logs ## Follow beta development stack logs

beta-clean: clean ## Stop the beta development stack and remove volumes

build-wheels: ## Build native Rust wheels for local Python development (optional)
	@echo "$(BLUE)Building native Rust wheels for local development...$(NC)"
	@bash $(WHEELS_SCRIPT)
	@echo "$(GREEN)✓ Native wheels built successfully$(NC)"

package-selfhost-bundle: ## Stage the image-based self-host customer bundle in dist/selfhost-bundle
	@echo "$(BLUE)Staging self-host customer bundle...$(NC)"
	@python scripts/package-selfhost-bundle.py
	@echo "$(GREEN)✓ Self-host customer bundle staged$(NC)"

selfhost-images-ghcr-setup: ## Authenticate Docker to GHCR for local self-host image publishing
	@bash $(SELFHOST_GHCR_SETUP_SCRIPT)

selfhost-images-build-dry-run: ## Print the local self-host image build plan (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" bash $(SELFHOST_IMAGE_RELEASE_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --dry-run

selfhost-images-build: ## Build self-host production images locally only (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" bash $(SELFHOST_IMAGE_RELEASE_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --skip-push

selfhost-images-build-push: ## Build self-host production images locally and push to GHCR (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" bash $(SELFHOST_IMAGE_RELEASE_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --push

selfhost-images-artifacts-dry-run: ## Print SBOM/scan/signing artifact commands (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --sbom --scan --inspect-digests --sign --verify-signatures --cosign-key "$(if $(COSIGN_KEY),$(COSIGN_KEY),dry-run-cosign.key)" --cosign-public-key "$(if $(COSIGN_PUBLIC_KEY),$(COSIGN_PUBLIC_KEY),dry-run-cosign.pub)" --dry-run

selfhost-images-release-artifacts: ## Generate SBOMs, scans, manifest, and checksums for built images (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --sbom --scan --scan-tool "$(SELFHOST_RELEASE_SCAN_TOOL)" --inspect-digests

selfhost-images-sbom: ## Generate Syft SBOMs for built self-host images (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --sbom

selfhost-images-scan: ## Run local Trivy/Grype scans for built self-host images (TAG=<version>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --scan --scan-tool "$(SELFHOST_RELEASE_SCAN_TOOL)"

selfhost-images-sign: ## Sign pushed self-host image digests with Cosign (TAG=<version> COSIGN_KEY=<path>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(COSIGN_KEY)" ]; then \
		echo "$(RED)❌ Error: COSIGN_KEY is required for signing$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --sign --cosign-key "$(COSIGN_KEY)"

selfhost-images-verify-signatures: ## Verify pushed self-host image digest signatures (TAG=<version> COSIGN_PUBLIC_KEY=<path>, defaults to VERSION)
	@if [ -z "$(SELFHOST_RELEASE_TAG)" ]; then \
		echo "$(RED)❌ Error: set TAG/SELFHOST_RELEASE_TAG or create VERSION (example: echo 2026.05.0 > VERSION)$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(COSIGN_PUBLIC_KEY)" ]; then \
		echo "$(RED)❌ Error: COSIGN_PUBLIC_KEY is required for verification$(NC)"; \
		exit 1; \
	fi
	@SELFHOST_IMAGE_PREFIX="$(SELFHOST_IMAGE_PREFIX)" python $(SELFHOST_IMAGE_ARTIFACTS_SCRIPT) --tag "$(SELFHOST_RELEASE_TAG)" --verify-signatures --cosign-public-key "$(COSIGN_PUBLIC_KEY)"

deploy-catalog-validate: ## Validate deployment metadata catalogs, stacks, and bundles
	@python scripts/marty-deploy.py validate

deploy-stack-plan: ## Render a redacted deployment plan (STACK=<name>)
	@if [ -z "$(STACK)" ]; then \
		echo "$(RED)❌ Error: STACK is required (example: make deploy-stack-plan STACK=selfhost-production)$(NC)"; \
		exit 1; \
	fi
	@python scripts/marty-deploy.py plan "$(STACK)"

selfhost-prod-plan: ## Render the self-host production deployment plan
	@python scripts/marty-deploy.py plan selfhost-production

selfhost-prod-beta-tunnel-plan: ## Render the self-host beta tunnel deployment plan
	@python scripts/marty-deploy.py plan selfhost-beta-tunnel

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
	@cd ui && SELFHOST_ENV_FILE="$(SELFHOST_ENV_FILE)" npm run build:selfhost
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

selfhost-prod-beta-tunnel-up: selfhost-prod-config ## Start the optional beta.elevenidllc.com tunnel against the self-host edge
	@if [ -z "$(SELFHOST_SECRET_DIR)" ]; then \
		echo "$(RED)❌ Error: SELFHOST_SECRET_DIR missing from $(SELFHOST_ENV_FILE)$(NC)"; \
		exit 1; \
	fi
	@if ! printf '%s' "$(UI_ADDITIONAL_BASE_URLS)" | tr ',' '\n' | grep -qx 'https://beta.elevenidllc.com'; then \
		echo "$(RED)❌ Error: beta.elevenidllc.com is not configured as a same-stack UI alias$(NC)"; \
		echo "Only run this target when beta should intentionally use the self-host production Keycloak."; \
		echo "For a separate beta stack/Keycloak, use the beta-tunnel targets instead."; \
		exit 1; \
	fi
	@if ! printf '%s' "$(CORS_ORIGINS)" | tr ',' '\n' | grep -qx 'https://beta.elevenidllc.com'; then \
		echo "$(RED)❌ Error: CORS_ORIGINS must include https://beta.elevenidllc.com for same-stack beta tunneling$(NC)"; \
		exit 1; \
	fi
	@if [ ! -s "$(SELFHOST_SECRET_DIR)/cloudflare_beta_tunnel_token" ]; then \
		echo "$(RED)❌ Error: cloudflare_beta_tunnel_token missing from SELFHOST_SECRET_DIR$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Starting self-host beta tunnel sidecars...$(NC)"
	@$(SELFHOST_PROD_BETA_COMPOSE) up -d --no-deps $(SELFHOST_PROD_BETA_TUNNEL_SERVICES)
	@echo "$(GREEN)✓ Self-host beta tunnel started$(NC)"

selfhost-prod-beta-tunnel-stop: ## Stop the optional beta tunnel sidecars
	@$(SELFHOST_PROD_BETA_COMPOSE) stop $(SELFHOST_PROD_BETA_TUNNEL_SERVICES)
	@echo "$(GREEN)✓ Self-host beta tunnel stopped$(NC)"

selfhost-prod-beta-tunnel-ps: ## Show optional beta tunnel sidecar status
	@$(SELFHOST_PROD_BETA_COMPOSE) ps $(SELFHOST_PROD_BETA_TUNNEL_SERVICES)

selfhost-prod-beta-tunnel-logs: ## Follow optional beta tunnel sidecar logs
	@$(SELFHOST_PROD_BETA_COMPOSE) logs -f $(SELFHOST_PROD_BETA_TUNNEL_SERVICES)

setup-local: ## Setup native local development environment (venv + dependencies)
	@echo "$(BLUE)Setting up native local development environment...$(NC)"
	@bash $(SETUP_LOCAL_SCRIPT)

infra: ## Start only infrastructure services
	@echo "$(BLUE)Starting infrastructure services...$(NC)"
	@$(BASE_COMPOSE) up -d $(INFRA_SERVICES)
	@$(MAKE) --no-print-directory setup-keycloak
	@echo "$(GREEN)✓ Infrastructure started$(NC)"

infra-tunnel: ## Start infrastructure services with tunnel overrides
	@echo "$(BLUE)Starting infrastructure services (tunnel mode)...$(NC)"
	@$(TUNNEL_COMPOSE) up -d $(INFRA_SERVICES)
	@$(MAKE) --no-print-directory setup-keycloak
	@echo "$(GREEN)âœ“ Infrastructure started (tunnel mode)$(NC)"

run-api: infra services-up ## Start infra + API microservices
	@echo "$(GREEN)✓ Gateway API started at http://localhost:8000$(NC)"

run-api-tunnel: infra-tunnel services-up-tunnel ## Start infra + API microservices with tunnel env vars (sets ISSUER_BASE_URL)
	@echo "$(GREEN)✓ Gateway API started (tunnel mode)$(NC)"

run-ui: ## Run UI natively (requires API stack)
	@echo "$(BLUE)Starting UI natively...$(NC)"
	@cd ui && npm run dev

public-ui: run-api-tunnel tunnel-keycloak-restart prod-ui-docker tunnel-start tunnel-use-prod ## Start all dependencies + Cloudflare tunnel/proxy + persistent Docker UI

public-ui-dev: run-api-tunnel tunnel-keycloak-restart tunnel-start tunnel-use-dev dev-ui-tunnel ## Start all dependencies + Cloudflare tunnel/proxy + UI dev server (public tunnel mode)

public-ui-ghcr: ## Start public UI using GHCR images + Cloudflare tunnel (no local backend image builds)
	@if [ -z "$(IMAGE_TAG)" ]; then \
		echo "$(RED)❌ Error: IMAGE_TAG is required (example: IMAGE_TAG=2026.04.14 make public-ui-ghcr)$(NC)"; \
		exit 1; \
	fi
	@if [ "$(IMAGE_TAG)" = "latest" ]; then \
		echo "$(RED)❌ Error: IMAGE_TAG=latest is not allowed for public beta startup; use a pinned tag$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🚀 Starting public UI via GHCR tag $(IMAGE_TAG)...$(NC)"
	@$(GHCR_TUNNEL_COMPOSE) pull db-migrate $(APP_SERVICES)
	@$(GHCR_TUNNEL_COMPOSE) up -d $(INFRA_SERVICES)
	@$(MAKE) --no-print-directory setup-keycloak
	@$(GHCR_TUNNEL_COMPOSE) up -d db-migrate
	@$(GHCR_TUNNEL_COMPOSE) up -d $(APP_SERVICES)
	@$(MAKE) --no-print-directory tunnel-refresh-upstreams
	@$(MAKE) --no-print-directory prod-ui-docker
	@$(MAKE) --no-print-directory tunnel-start
	@$(MAKE) --no-print-directory tunnel-use-prod
	@$(MAKE) --no-print-directory public-ui-check

public-ui-check: ## Run lightweight public UI readiness checks (local UI + public login/auth)
	@ENV_FILE="$(CURDIR)/$(BETA_ENV_FILE)" bash ./scripts/check-public-ui.sh

beta-public-ui: public-ui ## Start the beta public tunnel with the production-preview UI

beta-public-ui-dev: public-ui-dev ## Start the beta public tunnel with the Vite dev UI

beta-public-ui-ghcr: public-ui-ghcr ## Start the beta public tunnel using GHCR backend images

beta-public-ui-check: public-ui-check ## Run readiness checks for the beta public tunnel

prod-ui-docker: ## Build UI and serve in Docker (persistent, survives terminal close)
	@echo "$(BLUE)🔨 Building production UI...$(NC)"
	@cp "$(BETA_ENV_FILE)" ui/.env
	@cd ui && npm run build
	@echo "$(BLUE)🚀 Starting UI container on :3002...$(NC)"
	@docker compose -f docker-compose.ui-prod.yml up -d --force-recreate
	@echo "$(GREEN)✅ UI running in Docker (restart: unless-stopped)$(NC)"
	@echo "  Local:  http://localhost:3002/"

prod-ui-docker-rebuild: ## Rebuild UI and restart Docker container
	@echo "$(BLUE)🔨 Rebuilding UI...$(NC)"
	@cp "$(BETA_ENV_FILE)" ui/.env
	@cd ui && npm run build
	@docker compose -f docker-compose.ui-prod.yml restart ui-prod
	@echo "$(GREEN)✅ UI rebuilt and restarted$(NC)"

prod-ui-docker-stop: ## Stop the Docker UI container
	@docker compose -f docker-compose.ui-prod.yml down
	@echo "$(GREEN)✅ UI container stopped$(NC)"

services-migrate: ## Run Alembic migrations using the migration runner
	@echo "$(BLUE)Running database migrations...$(NC)"
	@$(BASE_COMPOSE) run --build --rm db-migrate
	@echo "$(GREEN)✓ Database migrations completed$(NC)"

services-migrate-profile: ## Run db-migrate with MIGRATION_PROFILE=<profile>
	@if [ -z "$(MIGRATION_PROFILE)" ]; then \
		echo "$(RED)❌ Error: MIGRATION_PROFILE is required (example: make services-migrate-profile MIGRATION_PROFILE=beta)$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Running database migrations with profile $(MIGRATION_PROFILE)...$(NC)"
	@MARTY_MIGRATION_PROFILE=$(MIGRATION_PROFILE) $(BASE_COMPOSE) run --build --rm db-migrate
	@echo "$(GREEN)✓ Database migrations completed for profile $(MIGRATION_PROFILE)$(NC)"

services-migrate-dev: ## Run db-migrate with the dev profile
	@$(MAKE) --no-print-directory services-migrate-profile MIGRATION_PROFILE=dev

services-migrate-beta: ## Run db-migrate with the beta profile
	@$(MAKE) --no-print-directory services-migrate-profile MIGRATION_PROFILE=beta

services-migrate-experiments: ## Run db-migrate with the experiments profile
	@$(MAKE) --no-print-directory services-migrate-profile MIGRATION_PROFILE=experiments

services-migrate-test: ## Run db-migrate with the test profile
	@$(MAKE) --no-print-directory services-migrate-profile MIGRATION_PROFILE=test

services-migrate-production: ## Run db-migrate with the production profile
	@$(MAKE) --no-print-directory services-migrate-profile MIGRATION_PROFILE=production

seed-demo-vendor-fixtures: ## Explicitly seed demo vendor org/catalog/template fixtures
	@echo "$(BLUE)Seeding demo vendor fixtures...$(NC)"
	@PYTHONIOENCODING=utf-8 MARTY_MIGRATION_PROFILE=$(if $(MARTY_MIGRATION_PROFILE),$(MARTY_MIGRATION_PROFILE),beta) python scripts/seed_demo_vendor_fixtures.py --env-file "$(BETA_ENV_FILE)"
	@echo "$(GREEN)✓ Demo vendor fixtures seeded$(NC)"

dev-db-reset: ## Drop local state volumes, rebuild infra, skip historical demo migrations, then apply explicit demo fixture seeds
	@echo "$(BLUE)Resetting development database and seed state...$(NC)"
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory infra
	@MARTY_USE_EXPLICIT_DEMO_SEED_PACK=1 $(MAKE) --no-print-directory services-migrate-dev
	@$(MAKE) --no-print-directory seed-demo-vendor-fixtures MARTY_MIGRATION_PROFILE=dev
	@echo "$(GREEN)✓ Development database reset complete$(NC)"

beta-db-reset: ## Drop beta/dev state volumes, rebuild infra, skip historical demo migrations, then apply explicit demo fixture seeds
	@echo "$(BLUE)Resetting beta database and seed state...$(NC)"
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory infra
	@MARTY_USE_EXPLICIT_DEMO_SEED_PACK=1 $(MAKE) --no-print-directory services-migrate-beta
	@$(MAKE) --no-print-directory seed-demo-vendor-fixtures MARTY_MIGRATION_PROFILE=beta
	@echo "$(GREEN)✓ Beta database reset complete$(NC)"

beta-experiments-db-reset: ## Reset beta using the experiments migration profile and explicit demo fixtures
	@echo "$(BLUE)Resetting beta experiments database and seed state...$(NC)"
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory infra
	@MARTY_USE_EXPLICIT_DEMO_SEED_PACK=1 $(MAKE) --no-print-directory services-migrate-experiments
	@$(MAKE) --no-print-directory seed-demo-vendor-fixtures MARTY_MIGRATION_PROFILE=experiments
	@echo "$(GREEN)✓ Beta experiments database reset complete$(NC)"

test-db-reset: ## Drop local state volumes, rebuild infra, and apply test-profile migrations
	@echo "$(BLUE)Resetting test database and seed state...$(NC)"
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory infra
	@$(MAKE) --no-print-directory services-migrate-test
	@echo "$(GREEN)✓ Test database reset complete$(NC)"

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

tunnel-start: ## Start Cloudflare tunnel sidecars for the beta stack
	@if ! grep -q '^CLOUDFLARE_TUNNEL_TOKEN=eyJ' "$(BETA_ENV_FILE)" 2>/dev/null; then \
		echo "$(RED)❌ Error: CLOUDFLARE_TUNNEL_TOKEN missing in $(BETA_ENV_FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🚀 Starting Cloudflare Tunnel...$(NC)"
	@$(TUNNEL_COMPOSE) up -d --no-deps docs nginx-proxy cloudflared
	@PUBLIC_DOMAIN=$$(grep '^PUBLIC_DOMAIN=' "$(BETA_ENV_FILE)" | cut -d'=' -f2); \
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
	@docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E '(^NAMES|cloudflared-tunnel|tunnel-nginx-proxy|marty-auth|marty-gateway|marty-organization)'

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
	@$(TUNNEL_COMPOSE) up -d --no-deps auth gateway
	@$(MAKE) --no-print-directory tunnel-refresh-upstreams
	@echo "$(GREEN)✅ Auth and Gateway restarted$(NC)"

tunnel-keycloak-restart: ## Restart Keycloak with tunnel overrides (then runs setup-keycloak)
	@echo "$(BLUE)🔄 Restarting Keycloak with tunnel profile...$(NC)"
	@$(TUNNEL_COMPOSE) up -d --no-deps --force-recreate keycloak
	@echo "$(GREEN)✅ Keycloak restarted$(NC)"
	@$(MAKE) --no-print-directory setup-keycloak

setup-keycloak: ## Patch Keycloak with env-var credentials (Google IdP, redirect URIs)
	@echo "$(BLUE)⚙️  Running Keycloak configurator...$(NC)"
	@set -o pipefail; MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
		--entrypoint bash \
		--network marty-infra-network \
		--env-file "$(BETA_ENV_FILE)" \
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
	@if ! grep -q '^UI_DEV_PORT=' "$(BETA_ENV_FILE)" 2>/dev/null; then \
		echo "UI_DEV_PORT=3002" >> "$(BETA_ENV_FILE)"; \
	else \
		sed -i.bak 's/^UI_DEV_PORT=.*/UI_DEV_PORT=3002/' "$(BETA_ENV_FILE)" && rm "$(BETA_ENV_FILE).bak"; \
	fi
	@docker rm -f tunnel-nginx-proxy >/dev/null 2>&1 || true
	@$(TUNNEL_COMPOSE) up -d --no-deps nginx-proxy
	@echo "$(GREEN)✅ Tunnel now targets port 3002$(NC)"

tunnel-use-dev: ## Route tunnel proxy to Vite dev UI (:3000)
	@echo "$(BLUE)🔧 Configuring tunnel for dev server...$(NC)"
	@if ! grep -q '^UI_DEV_PORT=' "$(BETA_ENV_FILE)" 2>/dev/null; then \
		echo "UI_DEV_PORT=3000" >> "$(BETA_ENV_FILE)"; \
	else \
		sed -i.bak 's/^UI_DEV_PORT=.*/UI_DEV_PORT=3000/' "$(BETA_ENV_FILE)" && rm "$(BETA_ENV_FILE).bak"; \
	fi
	@docker rm -f tunnel-nginx-proxy >/dev/null 2>&1 || true
	@$(TUNNEL_COMPOSE) up -d --no-deps nginx-proxy
	@echo "$(GREEN)✅ Tunnel now targets port 3000$(NC)"

dev-ui-tunnel: ## Start UI dev server for tunnel mode
	@echo "$(BLUE)🚀 Starting UI dev server for tunnel mode...$(NC)"
	@cp "$(BETA_ENV_FILE)" ui/.env
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

beta-tunnel-start: tunnel-start ## Start the beta Cloudflare tunnel sidecars

beta-tunnel-stop: tunnel-stop ## Stop the beta Cloudflare tunnel sidecars

beta-tunnel-restart: tunnel-restart ## Restart the beta Cloudflare tunnel sidecars

beta-tunnel-status: tunnel-status ## Show beta tunnel status

beta-tunnel-logs: tunnel-logs ## Follow beta cloudflared logs

beta-tunnel-nginx-logs: tunnel-nginx-logs ## Follow beta tunnel nginx logs

beta-tunnel-refresh-upstreams: tunnel-refresh-upstreams ## Refresh beta tunnel proxy upstreams

beta-tunnel-auth-restart: tunnel-auth-restart ## Restart beta auth and gateway with tunnel settings

beta-tunnel-keycloak-restart: tunnel-keycloak-restart ## Restart beta Keycloak with tunnel settings

beta-tunnel-full-restart: tunnel-full-restart ## Restart beta tunnel-sensitive services

beta-tunnel-use-prod: tunnel-use-prod ## Route the beta tunnel to the production-preview UI

beta-tunnel-use-dev: tunnel-use-dev ## Route the beta tunnel to the Vite dev UI

beta-dev-ui-tunnel: dev-ui-tunnel ## Start the beta UI dev server in tunnel mode

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

canvas-sandbox-up: ## Start Canvas Credentials Test Sandbox (requires tunnel profile)
	@echo "$(BLUE)Starting Canvas Credentials Test Sandbox...$(NC)"
	@$(CANVAS_SANDBOX_COMPOSE) up -d --build canvas-sandbox
	@echo "$(GREEN)✓ Canvas sandbox started$(NC)"
	@echo "  Internal:   http://canvas-sandbox:8017"
	@echo "  Tunnel:     https://canvas-sandbox.$$(grep '^PUBLIC_DOMAIN=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2)"
	@echo ""
	@echo "  Connector config:"
	@echo "    canvas_base_url:     https://canvas-sandbox.$$(grep '^PUBLIC_DOMAIN=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2)"
	@echo "    lti_client_id:       any-client-id"
	@echo "    lti_deployment_id:   test-deployment-sandbox"

canvas-sandbox-down: ## Stop Canvas sandbox
	@echo "$(BLUE)Stopping Canvas sandbox...$(NC)"
	@$(CANVAS_SANDBOX_COMPOSE) stop canvas-sandbox
	@$(CANVAS_SANDBOX_COMPOSE) rm -f canvas-sandbox
	@echo "$(GREEN)✓ Canvas sandbox stopped$(NC)"

canvas-sandbox-build: ## Rebuild the Canvas sandbox image
	@echo "$(BLUE)Rebuilding Canvas sandbox image...$(NC)"
	@$(CANVAS_SANDBOX_COMPOSE) build --no-cache canvas-sandbox
	@echo "$(GREEN)✓ Canvas sandbox image rebuilt$(NC)"

canvas-sandbox-logs: ## Follow Canvas sandbox logs
	@docker logs -f marty-canvas-sandbox

canvas-sandbox-status: ## Show Canvas sandbox status and platform setup guide
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(BLUE)  Canvas Sandbox Status$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E '(^NAMES|canvas-sandbox)' || echo "$(YELLOW)  Canvas sandbox not running$(NC)"
	@echo ""
	@echo "$(GREEN)To configure a Canvas platform against the sandbox:$(NC)"
	@echo ""
	@echo "  1. Start the sandbox:  make canvas-sandbox-up"
	@echo "  2. Create a Canvas platform via API or UI admin panel:"
	@echo ""
	@echo "     POST /v1/integrations/canvas/platforms"
	@echo "     {"
	@echo '       "organization_id": "<your-org-id>",'
	@echo '       "canvas_account_id": "sandbox-account-1",'
	@echo '       "canvas_base_url": "http://canvas-sandbox:8017",'
	@echo '       "lti_client_id": "any-client-id",'
	@echo '       "lti_deployment_id": "test-deployment-sandbox"'
	@echo "     }"
	@echo ""
	@echo "  3. Run sandbox probe:"
	@echo "     POST /v1/integrations/canvas/platforms/{platform_id}/sandbox-probe"
	@echo ""
	@echo "  4. Initiate LTI login:"
	@echo "     POST /v1/integrations/canvas/lti/platforms/{platform_id}/login"
	@echo "     { \"login_hint\": \"user@example.edu\", \"target_link_uri\": \"https://tool.example.edu/launch\" }"
	@echo ""

canvas-real-up: ## Start real Canvas LMS test environment
	@echo "$(BLUE)Starting real Canvas LMS test environment...$(NC)"
	@$(CANVAS_REAL_COMPOSE) up -d canvas-real
	@echo "$(GREEN)✓ Real Canvas started$(NC)"
	@echo "  Local:  http://localhost:$${CANVAS_REAL_HOST_PORT:-8088}"
	@CANVAS_HOST=$$(grep '^CANVAS_REAL_PUBLIC_HOST=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2); \
	DOMAIN=$$(grep '^PUBLIC_DOMAIN=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2); \
	CANVAS_HOST=$${CANVAS_HOST:-canvas-test.$$DOMAIN}; \
	echo "  Tunnel: https://$$CANVAS_HOST"
	@echo "  Note: first startup can take several minutes."

canvas-real-down: ## Stop real Canvas LMS test environment
	@echo "$(BLUE)Stopping real Canvas LMS...$(NC)"
	@$(CANVAS_REAL_COMPOSE) stop canvas-real
	@$(CANVAS_REAL_COMPOSE) rm -f canvas-real
	@echo "$(GREEN)✓ Real Canvas stopped$(NC)"

canvas-real-logs: ## Follow real Canvas LMS logs
	@docker logs -f marty-canvas-real

canvas-real-status: ## Show real Canvas LMS status
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(BLUE)  Real Canvas LMS Status$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E '(^NAMES|canvas-real)' || echo "$(YELLOW)  Canvas-real not running$(NC)"
	@echo ""
	@echo "$(GREEN)Platform setup tip:$(NC)"
	@echo "  Use a real Canvas base URL for production-like flows."
	@echo "  For beta experiments this profile exposes Canvas at http://canvas-real and CANVAS_REAL_PUBLIC_HOST."
	@echo ""

canvas-real-seed: ## Seed ElevenID Canvas platform/binding (and optional Canvas test course/user)
	@echo "$(BLUE)Seeding real Canvas LMS + ElevenID platform/binding...$(NC)"
	@PYTHONIOENCODING=utf-8 python scripts/seed_canvas_real.py --env-file "$(BETA_ENV_FILE)"
	@echo "$(GREEN)✓ Canvas seed completed$(NC)"

canvas-real-bootstrap: canvas-real-up canvas-real-seed ## Start real Canvas and run the seed script
	@echo "$(GREEN)✓ Canvas real bootstrap complete$(NC)"

deploy-prod: ## Deploy with secrets from OCI Vault (no .env.production needed)
	@echo "$(BLUE)Fetching production secrets from OCI Vault...$(NC)"
	@bash -c 'source scripts/fetch-secrets.sh && $(BASE_COMPOSE) up -d'
	@echo "$(GREEN)✓ Production deployment started with vault secrets$(NC)"

beta-check: check ## Quick health check of beta public-ui components

check: ## Quick health check of all public-ui components
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@echo "$(BLUE)  Public UI Health Check$(NC)"
	@echo "$(BLUE)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(NC)"
	@UI_PORT=$$(grep '^UI_DEV_PORT=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2); \
	UI_PORT=$${UI_PORT:-3002}; \
	DOMAIN=$$(grep '^PUBLIC_DOMAIN=' "$(BETA_ENV_FILE)" 2>/dev/null | cut -d'=' -f2); \
	CURL_TLS_ARGS=""; \
	if curl --help all 2>/dev/null | grep -q -- '--ssl-no-revoke'; then \
		CURL_TLS_ARGS="--ssl-no-revoke"; \
	fi; \
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
	if curl $$CURL_TLS_ARGS -s -o /dev/null -w '%{http_code}' "http://localhost:$$UI_PORT/" 2>/dev/null | grep -q '200'; then \
		echo "    $(GREEN)✓$(NC) http://localhost:$$UI_PORT/"; \
	else \
		echo "    $(RED)✗$(NC) http://localhost:$$UI_PORT/ — not responding"; \
	fi; \
	echo ""; \
	echo "  $(BLUE)Public URL$(NC)"; \
	if [ -n "$$DOMAIN" ]; then \
		HTTP_CODE=$$(curl $$CURL_TLS_ARGS -s -o /dev/null -w '%{http_code}' --max-time 5 "https://$$DOMAIN/" 2>/dev/null); \
		if [ "$$HTTP_CODE" = "200" ]; then \
			echo "    $(GREEN)✓$(NC) https://$$DOMAIN/"; \
		else \
			echo "    $(RED)✗$(NC) https://$$DOMAIN/ — HTTP $$HTTP_CODE"; \
		fi; \
	else \
		echo "    $(YELLOW)⚠$(NC) PUBLIC_DOMAIN not set in $(BETA_ENV_FILE)"; \
	fi; \
	echo ""

