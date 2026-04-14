#!/bin/bash
# =============================================================================
# scripts/deploy-oracle.sh
# Deploy marty-ui to Oracle Kubernetes Engine (OKE) with Cloudflare Tunnel.
#
# Usage:
#   ./scripts/deploy-oracle.sh [--tag <tag>] [--env-file <path>]
#   ./scripts/deploy-oracle.sh setup-secrets    # first-time secrets setup only
#   ./scripts/deploy-oracle.sh update-images    # rolling image update only
#   ./scripts/deploy-oracle.sh status           # check deployment status
#
# Prerequisites:
#   1. OKE cluster created and ~/.kube/config configured (oci ce cluster create-kubeconfig …)
#   2. Images pushed to OCIR (run scripts/build-push-ocir.sh first)
#   3. OCIR auth token available (for imagePullSecret)
#   4. k8s/oracle/02-secrets-template.yaml filled in (saved as .env.production)
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
K8S_DIR="${REPO_ROOT}/k8s/oracle"

IMAGE_TAG="${IMAGE_TAG:-prod}"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env.production}"
NAMESPACE="marty-prod"
SUBCOMMAND="${1:-deploy}"

OCI_REGION="${OCI_REGION:-}"
OCIR_TENANCY_NAMESPACE="${OCIR_TENANCY_NAMESPACE:-}"

# ─── Parse flags ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    deploy|setup-secrets|update-images|status) SUBCOMMAND="$1"; shift ;;
    --tag)      IMAGE_TAG="$2";              shift 2 ;;
    --env-file) ENV_FILE="$2";               shift 2 ;;
    --region)   OCI_REGION="$2";             shift 2 ;;
    --namespace) OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;;
    *) error "Unknown argument: $1" ;;
  esac
done

# ─── Load env file ────────────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  info "Loading environment from ${ENV_FILE}"
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
else
  warn ".env.production not found at ${ENV_FILE}."
  warn "Copy k8s/oracle/02-secrets-template.yaml values to .env.production and fill them in."
  [[ "$SUBCOMMAND" != "status" ]] && error "Cannot continue without env file."
fi

# ─── Derive OCIR registry ────────────────────────────────────────────────────
declare -A REGION_KEY=(
  [us-ashburn-1]=iad [us-phoenix-1]=phx [eu-frankfurt-1]=fra
  [uk-london-1]=lhr  [ap-tokyo-1]=nrt   [ap-sydney-1]=syd
  [ap-singapore-1]=sin [sa-saopaulo-1]=gru [ca-toronto-1]=yyz
  [me-jeddah-1]=jed
)
if [[ -n "$OCI_REGION" && -n "$OCIR_TENANCY_NAMESPACE" ]]; then
  REGION_SHORT="${REGION_KEY[$OCI_REGION]:-}"
  [[ -z "$REGION_SHORT" ]] && error "Unknown region: $OCI_REGION"
  OCIR_REGISTRY="${REGION_SHORT}.ocir.io/${OCIR_TENANCY_NAMESPACE}"
fi
[[ -z "${OCIR_REGISTRY:-}" ]] && error "Set OCIR_REGISTRY in .env.production or pass --region and --namespace flags."
export OCIR_REGISTRY IMAGE_TAG NAMESPACE

# ─── Prerequisites ─────────────────────────────────────────────────────────────
check_prereqs() {
  for cmd in kubectl; do
    command -v "$cmd" &>/dev/null || error "Required command not found: $cmd  (brew install kubectl)"
  done
  kubectl cluster-info &>/dev/null || error "Cannot connect to Kubernetes. Run: oci ce cluster create-kubeconfig --cluster-id <ocid> --file ~/.kube/config"
  info "Connected to cluster: $(kubectl config current-context)"
}

# ─── Apply a manifest with envsubst substitution ─────────────────────────────
apply_manifest() {
  local file="$1"
  info "Applying $(basename "$file")…"
  envsubst < "$file" | kubectl apply -f -
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

# ─── Sub-command: setup-secrets ───────────────────────────────────────────────
cmd_setup_secrets() {
  step "Setting up Kubernetes Secrets and OCIR pull secret"

  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

  # OCIR imagePullSecret
  if [[ -z "${OCIR_AUTH_TOKEN:-}" ]]; then
    warn "OCIR_AUTH_TOKEN not set. You'll need to create the OCIR pull secret manually:"
    warn "  kubectl create secret docker-registry ocir-secret \\"
    warn "    --docker-server=<region>.ocir.io \\"
    warn "    --docker-username='<tenancy-namespace>/<oci-username>' \\"
    warn "    --docker-password='<auth-token>' \\"
    warn "    -n marty-prod"
  else
    OCIR_HOST="$(echo "$OCIR_REGISTRY" | cut -d'/' -f1)"
    kubectl create secret docker-registry ocir-secret \
      --docker-server="${OCIR_HOST}" \
      --docker-username="${OCIR_TENANCY_NAMESPACE}/${OCI_USERNAME:-$(oci iam user list --query 'data[0].name' --raw-output 2>/dev/null)}" \
      --docker-password="${OCIR_AUTH_TOKEN}" \
      -n "$NAMESPACE" \
      --dry-run=client -o yaml | kubectl apply -f -
    success "OCIR pull secret created/updated"
  fi

  local postgres_password keycloak_db_password marty_db_password keycloak_admin_password
  local marty_api_client_secret rabbitmq_password rabbitmq_erlang_cookie
  local google_client_id google_client_secret smtp_username smtp_password
  local issuance_api_key openbao_service_token license_key license_public_key
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
  openbao_service_token="$(resolve_secret_input OPENBAO_SERVICE_TOKEN)"
  license_key="$(resolve_secret_input LICENSE_KEY)"
  license_public_key="$(resolve_secret_input LICENSE_PUBLIC_KEY)"
  square_access_token="$(resolve_secret_input SQUARE_ACCESS_TOKEN)"
  square_webhook_signature_key="$(resolve_secret_input SQUARE_WEBHOOK_SIGNATURE_KEY)"
  cloudflare_tunnel_token="$(resolve_secret_input CLOUDFLARE_TUNNEL_TOKEN)"

  require_resolved_secret POSTGRES_PASSWORD "$postgres_password"
  require_resolved_secret KEYCLOAK_DB_PASSWORD "$keycloak_db_password"
  require_resolved_secret MARTY_DB_PASSWORD "$marty_db_password"
  require_resolved_secret KEYCLOAK_ADMIN_PASSWORD "$keycloak_admin_password"
  require_resolved_secret MARTY_API_CLIENT_SECRET "$marty_api_client_secret"
  require_resolved_secret RABBITMQ_PASSWORD "$rabbitmq_password"
  require_resolved_secret RABBITMQ_ERLANG_COOKIE "$rabbitmq_erlang_cookie"
  require_resolved_secret SESSION_SECRET_KEY "$session_secret_key"
  require_resolved_secret ISSUANCE_API_KEY "$issuance_api_key"
  require_resolved_secret OPENBAO_SERVICE_TOKEN "$openbao_service_token"
  require_resolved_secret LICENSE_KEY "$license_key"
  require_resolved_secret LICENSE_PUBLIC_KEY "$license_public_key"

  # Application secrets from env vars or *_FILE inputs
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
    --from-literal=OPENBAO_SERVICE_TOKEN="$openbao_service_token" \
    --from-literal=LICENSE_KEY="$license_key" \
    --from-literal=LICENSE_PUBLIC_KEY="$license_public_key" \
    --from-literal=SQUARE_ACCESS_TOKEN="$square_access_token" \
    --from-literal=SQUARE_WEBHOOK_SIGNATURE_KEY="$square_webhook_signature_key" \
    --dry-run=client -o yaml | kubectl apply -f -
  success "Application secrets created/updated"

  # Cloudflare tunnel token secret
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

# ─── Sub-command: status ──────────────────────────────────────────────────────
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

# ─── Sub-command: update-images (rolling restart with new tag) ────────────────
cmd_update_images() {
  step "Rolling image update — tag: ${IMAGE_TAG}"
  for svc in gateway auth organization credential-template trust-profile issuance applicant notification compliance-profile presentation-policy deployment-profile flow verification revocation-profile device-registration event-stream billing ui; do
    kubectl set image deployment/"${svc}" "${svc}=${OCIR_REGISTRY}/marty-ui/${svc}:${IMAGE_TAG}" \
      -n "$NAMESPACE" 2>/dev/null && success "Updated ${svc}" || warn "Deployment '${svc}' not found (skipped)"
  done
  kubectl rollout status deployment -n "$NAMESPACE" --timeout=300s || true
}

# ─── Sub-command: deploy (full) ───────────────────────────────────────────────
cmd_deploy() {
  step "Full Deploy to OKE"

  # 1. Namespace first
  apply_manifest "${K8S_DIR}/00-namespace.yaml"

  # 2. Secrets (idempotent)
  cmd_setup_secrets

  # 3. ConfigMap
  apply_manifest "${K8S_DIR}/01-configmap.yaml"

  # 4. Keycloak realm ConfigMap (loaded from repo files)
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

  # 5. Infrastructure (Postgres, Redis, RabbitMQ)
  step "Deploying infrastructure…"
  apply_manifest "${K8S_DIR}/03-postgres.yaml"
  apply_manifest "${K8S_DIR}/04-redis-rabbitmq.yaml"

  info "Waiting for Postgres to be ready…"
  kubectl rollout status statefulset/postgres -n "$NAMESPACE" --timeout=300s

  info "Waiting for Redis to be ready…"
  kubectl rollout status statefulset/redis -n "$NAMESPACE" --timeout=120s

  info "Waiting for RabbitMQ to be ready…"
  kubectl rollout status statefulset/rabbitmq -n "$NAMESPACE" --timeout=180s

  # 6. Database migrations
  step "Running database migrations…"
  # Delete old job if it exists (Jobs are immutable)
  kubectl delete job db-migrate -n "$NAMESPACE" --ignore-not-found=true
  apply_manifest "${K8S_DIR}/06-db-migrate.yaml"
  info "Waiting for migration job to complete…"
  kubectl wait --for=condition=complete job/db-migrate -n "$NAMESPACE" --timeout=300s \
    || { kubectl logs job/db-migrate -n "$NAMESPACE" --tail=50; error "Migration job failed"; }
  success "Database migrations completed"

  # 7. Keycloak
  step "Deploying Keycloak…"
  apply_manifest "${K8S_DIR}/05-keycloak.yaml"
  info "Waiting for Keycloak (this can take ~2 minutes)…"
  kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=360s

  # 8. Microservices
  step "Deploying microservices…"
  apply_manifest "${K8S_DIR}/07-microservices.yaml"
  kubectl rollout status deployment/gateway  -n "$NAMESPACE" --timeout=180s || true
  kubectl rollout status deployment/auth     -n "$NAMESPACE" --timeout=180s || true

  # 9. UI
  step "Deploying UI…"
  apply_manifest "${K8S_DIR}/08-ui.yaml"
  kubectl rollout status deployment/ui -n "$NAMESPACE" --timeout=120s

  # 10. Cloudflare Tunnel
  if ! is_placeholder_secret "$(resolve_secret_input CLOUDFLARE_TUNNEL_TOKEN)"; then
    step "Deploying Cloudflare Tunnel…"
    apply_manifest "${K8S_DIR}/09-cloudflared.yaml"
    kubectl rollout status deployment/cloudflared -n "$NAMESPACE" --timeout=60s || true
  else
    warn "Skipping cloudflared because CLOUDFLARE_TUNNEL_TOKEN is unset or placeholder."
  fi

  # ─── Summary ────────────────────────────────────────────────────────────────
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
  info "  Status:      ./scripts/deploy-oracle.sh status"
  info "  Logs:        kubectl logs -f deployment/<svc> -n marty-prod"
  info "  Port-fwd:    kubectl port-forward svc/gateway 8000:8000 -n marty-prod"
  info "  Update imgs: IMAGE_TAG=v1.1 ./scripts/deploy-oracle.sh update-images"
}

# ─── Execute ──────────────────────────────────────────────────────────────────
check_prereqs

case "$SUBCOMMAND" in
  deploy)        cmd_deploy ;;
  setup-secrets) cmd_setup_secrets ;;
  update-images) cmd_update_images ;;
  status)        cmd_status ;;
  *) error "Unknown subcommand: $SUBCOMMAND. Use deploy | setup-secrets | update-images | status" ;;
esac
