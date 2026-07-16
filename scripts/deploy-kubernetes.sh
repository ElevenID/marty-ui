#!/bin/bash
# =============================================================================
# scripts/deploy-kubernetes.sh
# Deploy marty-ui to a Kubernetes cluster with a configurable image registry and
# optional Cloudflare Tunnel.
#
# Usage:
#   ./scripts/deploy-kubernetes.sh [--tag <tag>] [--env-file <path>]
#   ./scripts/deploy-kubernetes.sh setup-secrets
#   ./scripts/deploy-kubernetes.sh update-images
#   ./scripts/deploy-kubernetes.sh status
#   ./scripts/deploy-kubernetes.sh [uses VERSION when --tag and IMAGE_TAG are omitted]
#
# Notes:
#   - K8S_DIR defaults to k8s/oracle for backward compatibility with the current
#     manifest directory name. Override K8S_DIR or pass --k8s-dir as manifests are
#     moved to a provider-neutral path.
#   - The existing manifests still use OCIR_REGISTRY as the envsubst variable.
#     This script exports OCIR_REGISTRY from IMAGE_REGISTRY as a compatibility
#     bridge until the manifests are fully registry-neutral.
# =============================================================================
set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}ℹ  $*${NC}"; }
success() { echo -e "${GREEN}✓  $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
error()   { echo -e "${RED}✗  $*${NC}"; exit 1; }
step()    { echo -e "\n${YELLOW}━━━  $*  ━━━${NC}"; }

# ─── Defaults ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python}"
VERSION_FILE="${VERSION_FILE:-$REPO_ROOT/VERSION}"

K8S_STACK_NAME="${K8S_STACK_NAME:-kubernetes-production}"
K8S_DIR="${K8S_DIR:-${REPO_ROOT}/k8s/oracle}"
IMAGE_TAG="${IMAGE_TAG:-}"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env.production}"
NAMESPACE="${NAMESPACE:-marty-prod}"
SUBCOMMAND="${1:-deploy}"

IMAGE_REGISTRY="${IMAGE_REGISTRY:-${CONTAINER_REGISTRY:-${OCIR_REGISTRY:-}}}"
REGISTRY_HOST="${REGISTRY_HOST:-}"
REGISTRY_USERNAME="${REGISTRY_USERNAME:-}"
REGISTRY_AUTH_TOKEN="${REGISTRY_AUTH_TOKEN:-${OCIR_AUTH_TOKEN:-}}"
IMAGE_PULL_SECRET_NAME="${IMAGE_PULL_SECRET_NAME:-ocir-secret}"

OCI_REGION="${OCI_REGION:-}"
OCIR_TENANCY_NAMESPACE="${OCIR_TENANCY_NAMESPACE:-}"
OCI_USERNAME="${OCI_USERNAME:-}"

# ─── Parse flags ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    deploy|setup-secrets|update-images|status) SUBCOMMAND="$1"; shift ;;
    --tag)               IMAGE_TAG="$2"; shift 2 ;;
    --env-file)          ENV_FILE="$2"; shift 2 ;;
    --k8s-dir)           K8S_DIR="$2"; shift 2 ;;
    --namespace)         NAMESPACE="$2"; shift 2 ;;
    --version-file)      VERSION_FILE="$2"; shift 2 ;;
    --registry)          IMAGE_REGISTRY="$2"; shift 2 ;;
    --registry-host)     REGISTRY_HOST="$2"; shift 2 ;;
    --registry-username) REGISTRY_USERNAME="$2"; shift 2 ;;
    --image-pull-secret) IMAGE_PULL_SECRET_NAME="$2"; shift 2 ;;
    --region)            OCI_REGION="$2"; shift 2 ;;          # Legacy OCIR compatibility
    --oci-namespace)     OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;; # Legacy OCIR compatibility
    --registry-namespace) OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;; # Legacy OCIR compatibility
    *) error "Unknown argument: $1" ;;
  esac
done

# ─── Load env file ────────────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  info "Loading environment from ${ENV_FILE}"
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
else
  warn "Environment file not found at ${ENV_FILE}."
  warn "Copy the Kubernetes secret/config template values to an env file and fill them in."
  [[ "$SUBCOMMAND" != "status" ]] && error "Cannot continue without env file."
fi

IMAGE_REGISTRY="${IMAGE_REGISTRY:-${CONTAINER_REGISTRY:-${OCIR_REGISTRY:-}}}"
REGISTRY_AUTH_TOKEN="${REGISTRY_AUTH_TOKEN:-${OCIR_AUTH_TOKEN:-}}"
IMAGE_PULL_SECRET_NAME="${IMAGE_PULL_SECRET_NAME:-ocir-secret}"

resolve_release_tag() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || error "Required command not found: $PYTHON_BIN"

  local cmd=("$PYTHON_BIN" "$REPO_ROOT/scripts/release_version.py" resolve --repo-root "$REPO_ROOT" --version-file "$VERSION_FILE")
  if [[ -n "${IMAGE_TAG:-}" ]]; then
    cmd+=(--tag "$IMAGE_TAG")
  fi

  "${cmd[@]}"
}

case "$SUBCOMMAND" in
  deploy|update-images)
    IMAGE_TAG="$(resolve_release_tag)"
    ;;
esac

# ─── Registry compatibility ───────────────────────────────────────────────────
declare -A REGION_KEY=(
  [us-ashburn-1]=iad [us-phoenix-1]=phx [eu-frankfurt-1]=fra
  [uk-london-1]=lhr  [ap-tokyo-1]=nrt   [ap-sydney-1]=syd
  [ap-singapore-1]=sin [sa-saopaulo-1]=gru [ca-toronto-1]=yyz
  [me-jeddah-1]=jed
)
if [[ -z "$IMAGE_REGISTRY" && -n "$OCI_REGION" && -n "$OCIR_TENANCY_NAMESPACE" ]]; then
  REGION_SHORT="${REGION_KEY[$OCI_REGION]:-}"
  [[ -z "$REGION_SHORT" ]] && error "Unknown OCI region: $OCI_REGION"
  IMAGE_REGISTRY="${REGION_SHORT}.ocir.io/${OCIR_TENANCY_NAMESPACE}"
fi
[[ -z "${IMAGE_REGISTRY:-}" ]] && error "Set IMAGE_REGISTRY in the env file or pass --registry."

if [[ -z "$REGISTRY_HOST" ]]; then
  REGISTRY_HOST="${IMAGE_REGISTRY%%/*}"
fi
if [[ -z "$REGISTRY_USERNAME" && -n "$OCIR_TENANCY_NAMESPACE" && -n "$OCI_USERNAME" ]]; then
  REGISTRY_USERNAME="${OCIR_TENANCY_NAMESPACE}/${OCI_USERNAME}"
fi

# Existing manifests currently use OCIR_REGISTRY. Keep it as a compatibility alias.
OCIR_REGISTRY="$IMAGE_REGISTRY"
export IMAGE_REGISTRY OCIR_REGISTRY IMAGE_TAG NAMESPACE IMAGE_PULL_SECRET_NAME

# ─── Prerequisites ─────────────────────────────────────────────────────────────
check_prereqs() {
  command -v kubectl &>/dev/null || error "Required command not found: kubectl"
  kubectl cluster-info &>/dev/null || error "Cannot connect to Kubernetes. Configure kubectl for the target cluster first."
  info "Connected to cluster: $(kubectl config current-context)"
}

# ─── Helpers ──────────────────────────────────────────────────────────────────
apply_manifest() {
  local file="$1"
  info "Applying $(basename "$file")…"
  envsubst < "$file" | kubectl apply -f -
}

catalog_services() {
  "$PYTHON_BIN" "$REPO_ROOT/scripts/marty-deploy.py" services --group "$1" --field k8s_deployment
}

catalog_required_secret_envs() {
  "$PYTHON_BIN" "$REPO_ROOT/scripts/marty-deploy.py" secrets "$1" --field env
}

is_placeholder_secret() {
  case "$1" in
    ""|change-me*|CHANGE_ME*|replace-me*|REPLACE_ME*) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_secret_input() {
  local var_name="$1"
  local file_var_name="${var_name}_FILE"
  local current_value="${!var_name:-}"
  local file_path="${!file_var_name:-}"

  if [[ -n "$current_value" && -n "$file_path" ]]; then
    error "Both ${var_name} and ${file_var_name} are set; choose one."
  fi

  if [[ -n "$file_path" ]]; then
    [[ -r "$file_path" ]] || error "${file_var_name} is not readable: ${file_path}"
    tr -d '\r' < "$file_path"
    return 0
  fi

  printf '%s' "$current_value"
}

require_resolved_secret() {
  local var_name="$1"
  local value="$2"

  if is_placeholder_secret "$value"; then
    error "${var_name} must be set to a non-placeholder value before deployment."
  fi
}

require_catalog_required_secrets() {
  local stack_name="$1"
  local var_name value

  while IFS= read -r var_name; do
    [[ -z "$var_name" ]] && continue
    value="$(resolve_secret_input "$var_name")"
    require_resolved_secret "$var_name" "$value"
  done < <(catalog_required_secret_envs "$stack_name")
}

create_image_pull_secret() {
  if [[ -z "${REGISTRY_AUTH_TOKEN:-}" ]]; then
    warn "REGISTRY_AUTH_TOKEN/OCIR_AUTH_TOKEN not set. Create image pull secret '${IMAGE_PULL_SECRET_NAME}' manually if the registry is private."
    return 0
  fi

  [[ -n "$REGISTRY_USERNAME" ]] || error "REGISTRY_USERNAME is required when REGISTRY_AUTH_TOKEN is set."

  kubectl create secret docker-registry "$IMAGE_PULL_SECRET_NAME" \
    --docker-server="${REGISTRY_HOST}" \
    --docker-username="${REGISTRY_USERNAME}" \
    --docker-password="${REGISTRY_AUTH_TOKEN}" \
    -n "$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -
  success "Image pull secret created/updated"
}

# ─── Sub-command: setup-secrets ───────────────────────────────────────────────
cmd_setup_secrets() {
  step "Setting up Kubernetes Secrets and image pull secret"

  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  create_image_pull_secret

  local postgres_password keycloak_db_password marty_db_password keycloak_admin_password
  local marty_api_client_secret rabbitmq_password rabbitmq_erlang_cookie
  local google_client_id google_client_secret smtp_username smtp_password
  local issuance_api_key integration_secret_master_key canvas_credentials_shared_secret openbao_service_token license_key
  local session_secret_key square_access_token square_webhook_signature_key
  local cloudflare_tunnel_token

  postgres_password="$(resolve_secret_input POSTGRES_PASSWORD)"
  keycloak_db_password="$(resolve_secret_input KEYCLOAK_DB_PASSWORD)"
  marty_db_password="$(resolve_secret_input MARTY_DB_PASSWORD)"
  keycloak_admin_password="$(resolve_secret_input KEYCLOAK_ADMIN_PASSWORD)"
  marty_api_client_secret="$(resolve_secret_input MARTY_API_CLIENT_SECRET)"
  rabbitmq_password="$(resolve_secret_input RABBITMQ_PASSWORD)"
  rabbitmq_erlang_cookie="$(resolve_secret_input RABBITMQ_ERLANG_COOKIE)"
  session_secret_key="$(resolve_secret_input SESSION_SECRET_KEY)"
  google_client_id="$(resolve_secret_input GOOGLE_CLIENT_ID)"
  google_client_secret="$(resolve_secret_input GOOGLE_CLIENT_SECRET)"
  smtp_username="$(resolve_secret_input SMTP_USERNAME)"
  smtp_password="$(resolve_secret_input SMTP_PASSWORD)"
  issuance_api_key="$(resolve_secret_input ISSUANCE_API_KEY)"
  integration_secret_master_key="$(resolve_secret_input INTEGRATION_SECRET_MASTER_KEY)"
  canvas_credentials_shared_secret="$(resolve_secret_input CANVAS_CREDENTIALS_SHARED_SECRET)"
  openbao_service_token="$(resolve_secret_input OPENBAO_SERVICE_TOKEN)"
  license_key="$(resolve_secret_input LICENSE_KEY)"
  square_access_token="$(resolve_secret_input SQUARE_ACCESS_TOKEN)"
  square_webhook_signature_key="$(resolve_secret_input SQUARE_WEBHOOK_SIGNATURE_KEY)"
  cloudflare_tunnel_token="$(resolve_secret_input CLOUDFLARE_TUNNEL_TOKEN)"

  require_catalog_required_secrets "$K8S_STACK_NAME"

  kubectl create secret generic marty-secrets \
    --namespace="$NAMESPACE" \
    --from-literal=POSTGRES_PASSWORD="$postgres_password" \
    --from-literal=KEYCLOAK_DB_PASSWORD="$keycloak_db_password" \
    --from-literal=MARTY_DB_PASSWORD="$marty_db_password" \
    --from-literal=DATABASE_URL="postgresql+asyncpg://marty:${marty_db_password}@postgres:5432/marty" \
    --from-literal=DATABASE_SYNC_URL="postgresql://marty:${marty_db_password}@postgres:5432/marty" \
    --from-literal=KEYCLOAK_DB_URL="jdbc:postgresql://postgres:5432/keycloak" \
    --from-literal=KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}" \
    --from-literal=KEYCLOAK_ADMIN_PASSWORD="$keycloak_admin_password" \
    --from-literal=MARTY_API_CLIENT_SECRET="$marty_api_client_secret" \
    --from-literal=RABBITMQ_PASSWORD="$rabbitmq_password" \
    --from-literal=RABBITMQ_URL="amqp://marty:${rabbitmq_password}@rabbitmq:5672/" \
    --from-literal=RABBITMQ_ERLANG_COOKIE="$rabbitmq_erlang_cookie" \
    --from-literal=SESSION_SECRET_KEY="$session_secret_key" \
    --from-literal=GOOGLE_CLIENT_ID="$google_client_id" \
    --from-literal=GOOGLE_CLIENT_SECRET="$google_client_secret" \
    --from-literal=SMTP_USERNAME="$smtp_username" \
    --from-literal=SMTP_PASSWORD="$smtp_password" \
    --from-literal=ISSUANCE_API_KEY="$issuance_api_key" \
    --from-literal=SIGNING_KEYS_INTERNAL_API_KEY="$issuance_api_key" \
    --from-literal=INTEGRATION_SECRET_MASTER_KEY="$integration_secret_master_key" \
    --from-literal=CANVAS_CREDENTIALS_SHARED_SECRET="$canvas_credentials_shared_secret" \
    --from-literal=OPENBAO_SERVICE_TOKEN="$openbao_service_token" \
    --from-literal=LICENSE_KEY="$license_key" \
    --from-literal=SQUARE_ACCESS_TOKEN="$square_access_token" \
    --from-literal=SQUARE_WEBHOOK_SIGNATURE_KEY="$square_webhook_signature_key" \
    --dry-run=client -o yaml | kubectl apply -f -
  success "Application secrets created/updated"

  if ! is_placeholder_secret "$cloudflare_tunnel_token"; then
    kubectl create secret generic cloudflared-secret \
      --namespace="$NAMESPACE" \
      --from-literal=CLOUDFLARE_TUNNEL_TOKEN="$cloudflare_tunnel_token" \
      --dry-run=client -o yaml | kubectl apply -f -
    success "Cloudflare tunnel secret created/updated"
  else
    warn "CLOUDFLARE_TUNNEL_TOKEN is unset or placeholder — cloudflared will be skipped."
  fi
}

cmd_status() {
  step "Deployment Status — namespace: ${NAMESPACE}"
  echo ""
  kubectl get pods        -n "$NAMESPACE" -o wide 2>/dev/null || true
  echo ""
  kubectl get services    -n "$NAMESPACE"          2>/dev/null || true
  echo ""
  kubectl get statefulset -n "$NAMESPACE"          2>/dev/null || true
  echo ""
  kubectl get jobs        -n "$NAMESPACE"          2>/dev/null || true
}

cmd_update_images() {
  step "Rolling image update — tag: ${IMAGE_TAG}"
  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    kubectl set image deployment/"${svc}" "${svc}=${IMAGE_REGISTRY}/marty-ui/${svc}:${IMAGE_TAG}" \
      -n "$NAMESPACE" 2>/dev/null && success "Updated ${svc}" || warn "Deployment '${svc}' not found (skipped)"
  done < <(catalog_services app)
  kubectl set image deployment/canvas-sync-worker \
    "canvas-sync-worker=${IMAGE_REGISTRY}/marty-ui/issuance:${IMAGE_TAG}" \
    -n "$NAMESPACE" 2>/dev/null && success "Updated canvas-sync-worker" || warn "Deployment 'canvas-sync-worker' not found (skipped)"
  kubectl set image deployment/ui "ui=${IMAGE_REGISTRY}/marty-ui/ui-selfhost:${IMAGE_TAG}" \
    -n "$NAMESPACE" 2>/dev/null && success "Updated ui" || warn "Deployment 'ui' not found (skipped)"
  kubectl set image deployment/cloudflared "cloudflared=${IMAGE_REGISTRY}/marty-ui/cloudflared-wrapper:${IMAGE_TAG}" \
    -n "$NAMESPACE" 2>/dev/null && success "Updated cloudflared" || warn "Deployment 'cloudflared' not found (skipped)"
  kubectl rollout status deployment -n "$NAMESPACE" --timeout=300s || true
}

cmd_deploy() {
  step "Full Kubernetes Deploy"

  apply_manifest "${K8S_DIR}/00-namespace.yaml"
  cmd_setup_secrets
  apply_manifest "${K8S_DIR}/01-configmap.yaml"

  KC_REALM_DIR="${REPO_ROOT}/config/keycloak"
  if [[ -d "$KC_REALM_DIR" ]]; then
    info "Loading Keycloak realm config from ${KC_REALM_DIR}…"
    kubectl create configmap keycloak-realm-config \
      --from-file="$KC_REALM_DIR" \
      -n "$NAMESPACE" \
      --dry-run=client -o yaml | kubectl apply -f -

    KC_SETUP_SCRIPT_DIR="${REPO_ROOT}/scripts"
    if [[ -f "${KC_SETUP_SCRIPT_DIR}/setup-keycloak-selfhost-production.sh" && -f "${KC_SETUP_SCRIPT_DIR}/setup-keycloak.sh" && -f "${KC_SETUP_SCRIPT_DIR}/load-secrets-env.sh" ]]; then
      kubectl create configmap keycloak-setup-scripts \
        --from-file=setup-keycloak-selfhost-production.sh="${KC_SETUP_SCRIPT_DIR}/setup-keycloak-selfhost-production.sh" \
        --from-file=setup-keycloak.sh="${KC_SETUP_SCRIPT_DIR}/setup-keycloak.sh" \
        --from-file=load-secrets-env.sh="${KC_SETUP_SCRIPT_DIR}/load-secrets-env.sh" \
        -n "$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    fi

    if [[ -f "${KC_SETUP_SCRIPT_DIR}/load-openbao-token-and-start.sh" ]]; then
      kubectl create configmap marty-runtime-scripts \
        --from-file=load-openbao-token-and-start.sh="${KC_SETUP_SCRIPT_DIR}/load-openbao-token-and-start.sh" \
        -n "$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    fi

    success "Keycloak and runtime script ConfigMaps loaded"
  else
    warn "config/keycloak/ not found — skipping realm import ConfigMap"
  fi

  step "Deploying infrastructure…"
  apply_manifest "${K8S_DIR}/03-postgres.yaml"
  apply_manifest "${K8S_DIR}/04-redis-rabbitmq.yaml"

  info "Waiting for Postgres to be ready…"
  kubectl rollout status statefulset/postgres -n "$NAMESPACE" --timeout=300s

  info "Waiting for Redis to be ready…"
  kubectl rollout status statefulset/redis -n "$NAMESPACE" --timeout=120s

  info "Waiting for RabbitMQ to be ready…"
  kubectl rollout status statefulset/rabbitmq -n "$NAMESPACE" --timeout=180s

  step "Running database migrations…"
  kubectl delete job db-migrate -n "$NAMESPACE" --ignore-not-found=true
  apply_manifest "${K8S_DIR}/06-db-migrate.yaml"
  info "Waiting for migration job to complete…"
  kubectl wait --for=condition=complete job/db-migrate -n "$NAMESPACE" --timeout=300s \
    || { kubectl logs job/db-migrate -n "$NAMESPACE" --tail=50; error "Migration job failed"; }
  success "Database migrations completed"

  step "Deploying Keycloak…"
  apply_manifest "${K8S_DIR}/05-keycloak.yaml"
  info "Waiting for Keycloak (this can take ~2 minutes)…"
  kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=360s

  step "Deploying microservices…"
  apply_manifest "${K8S_DIR}/07-microservices.yaml"
  kubectl rollout status deployment/gateway  -n "$NAMESPACE" --timeout=180s || true
  kubectl rollout status deployment/auth     -n "$NAMESPACE" --timeout=180s || true

  step "Deploying UI…"
  apply_manifest "${K8S_DIR}/08-ui.yaml"
  kubectl rollout status deployment/ui -n "$NAMESPACE" --timeout=120s

  if ! is_placeholder_secret "$(resolve_secret_input CLOUDFLARE_TUNNEL_TOKEN)"; then
    step "Deploying Cloudflare Tunnel…"
    apply_manifest "${K8S_DIR}/09-cloudflared.yaml"
    kubectl rollout status deployment/cloudflared -n "$NAMESPACE" --timeout=60s || true
  else
    warn "Skipping cloudflared because CLOUDFLARE_TUNNEL_TOKEN is unset or placeholder."
  fi

  echo ""
  success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  success "  Deploy complete!"
  success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  info "  UI:      ${UI_BASE_URL}"
  info "  API:     ${PUBLIC_API_URL}/docs"
  info "  Auth:    ${OIDC_ISSUER_URL_EXTERNAL}"
  echo ""
  info "Useful commands:"
  info "  Status:      ./scripts/deploy-kubernetes.sh status"
  info "  Logs:        kubectl logs -f deployment/<svc> -n ${NAMESPACE}"
  info "  Port-fwd:    kubectl port-forward svc/gateway 8000:8000 -n ${NAMESPACE}"
  info "  Update imgs: IMAGE_TAG=2026.05.0 ./scripts/deploy-kubernetes.sh update-images"
}

check_prereqs

case "$SUBCOMMAND" in
  deploy)        cmd_deploy ;;
  setup-secrets) cmd_setup_secrets ;;
  update-images) cmd_update_images ;;
  status)        cmd_status ;;
  *) error "Unknown subcommand: $SUBCOMMAND. Use deploy | setup-secrets | update-images | status" ;;
esac
