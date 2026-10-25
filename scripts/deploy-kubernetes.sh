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

if [[ "$SUBCOMMAND" != status ]]; then
  [[ -n "${MARTY_DEPLOY_BIN:-}" ]] || error "Install and source a signed marty-deploy operator binary before deployment."
  "$REPO_ROOT/scripts/marty-deploy.sh" validate >/dev/null
fi

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
  if [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true && "$file" == "${K8S_DIR}/07-microservices.yaml" ]]; then
    [[ -n "${K8S_NATIVE_RENDERED_MODEL:-}" ]] || { error "Native issuance model was not preflighted."; return 1; }
    printf '%s\n' "$K8S_NATIVE_RENDERED_MODEL" | kubectl apply -f -
    return
  fi
  envsubst < "$file" | kubectl apply -f -
}

# No build or cluster mutation: authenticate the release and capture the exact
# full model before any deployment write. KMS-only deploy and update-images
# require the native owner and reject a disabled selector.
require_kubernetes_services_release() {
  [[ -n "${MARTY_STACK_MANIFEST:-}" ]] || { error "Set MARTY_STACK_MANIFEST to the signed Rust-only release manifest."; return 1; }
  [[ -n "${MARTY_KEYCLOAK_KMS_IMAGE:-}" ]] || { error "Set MARTY_KEYCLOAK_KMS_IMAGE to the signed Keycloak digest."; return 1; }
  [[ "${KEYCLOAK_KMS_ADDR:-}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || { error "KEYCLOAK_KMS_ADDR must identify a trusted HTTPS OpenBao origin."; return 1; }
  [[ "${KEYCLOAK_KMS_KEY_VERSION:-}" =~ ^[1-9][0-9]*$ ]] || { error "KEYCLOAK_KMS_KEY_VERSION must pin a positive remote key version."; return 1; }
  local source_sha checked_root checked_manifests relative_manifests manifest_file relative_file
  checked_root="$(git -C "$REPO_ROOT" rev-parse --show-toplevel)" || return 1
  [[ "$(cd "$checked_root" && pwd -P)" == "$REPO_ROOT" ]] || { error "Kubernetes release checkout identity changed."; return 1; }
  checked_manifests="$(cd "$K8S_DIR" && pwd -P)" || return 1
  case "$checked_manifests" in
    "$REPO_ROOT"/*) ;;
    *) error "Kubernetes manifests must be inside the reviewed checkout."; return 1 ;;
  esac
  relative_manifests="${checked_manifests#"$REPO_ROOT"/}"
  for manifest_file in \
    00-namespace.yaml 01-configmap.yaml 03-postgres.yaml \
    04-redis-rabbitmq.yaml 05-keycloak.yaml \
    05b-revocation-profile-migrations.yaml 06-db-migrate.yaml \
    06a-issuance-migrations.yaml 07-microservices.yaml \
    07a-issuance-native.yaml 07b-signing-keys.yaml \
    08-ui.yaml 09-cloudflared.yaml; do
    [[ -f "$checked_manifests/$manifest_file" && ! -L "$checked_manifests/$manifest_file" ]] || { error "Kubernetes manifest is missing or not a regular reviewed file."; return 1; }
    relative_file="$relative_manifests/$manifest_file"
    git -C "$REPO_ROOT" ls-files --error-unmatch -- "$relative_file" >/dev/null 2>&1 || { error "Kubernetes manifest is not tracked by the reviewed checkout."; return 1; }
  done
  [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]] || { error "Kubernetes release checkout must be clean."; return 1; }
  K8S_DIR="$checked_manifests"
  source_sha="$(git -C "$REPO_ROOT" rev-parse --verify HEAD^{commit})" || return 1
  "$PYTHON_BIN" "$REPO_ROOT/scripts/check_kubernetes_services_release.py" \
    --manifest "$MARTY_STACK_MANIFEST" --image "$MARTY_SERVICES_IMAGE" \
    --keycloak-image "$MARTY_KEYCLOAK_KMS_IMAGE" \
    --source-sha "$source_sha"
}

prepare_kubernetes_native_issuance() {
  K8S_NATIVE_RENDERED_MODEL=""
  K8S_ISSUANCE_NATIVE_ENABLED="${K8S_ISSUANCE_NATIVE_ENABLED-true}"
  case "$K8S_ISSUANCE_NATIVE_ENABLED" in
    false) error "KMS-only Kubernetes deployment requires native issuance."; return 1 ;;
    true) ;;
    *) error "Kubernetes native issuance selection must be true or false."; return 1 ;;
  esac
  K8S_NATIVE_ISSUANCE_BIN="${K8S_NATIVE_ISSUANCE_BIN:-${REPO_ROOT}/rust/target/release/kubernetes-native-issuance}"
  command -v "$K8S_NATIVE_ISSUANCE_BIN" >/dev/null 2>&1 || { error "Required native issuance deployment executable is unavailable."; return 1; }
  # Retain the reviewed issuance template variable while binding it to the
  # exact signed Rust services digest. No external issuance image is accepted.
  MARTY_ISSUANCE_IMAGE="$MARTY_SERVICES_IMAGE"
  export K8S_ISSUANCE_NATIVE_ENABLED MARTY_SERVICES_IMAGE MARTY_ISSUANCE_IMAGE
  "$K8S_NATIVE_ISSUANCE_BIN" validate || return 1
  require_kubernetes_services_release || return 1
  K8S_NATIVE_RENDERED_MODEL="$(envsubst < "${K8S_DIR}/07-microservices.yaml" | "$K8S_NATIVE_ISSUANCE_BIN" render --repo-root "$REPO_ROOT" --manifest-dir "$K8S_DIR")" || return 1
  [[ -n "$K8S_NATIVE_RENDERED_MODEL" ]] || { error "Native issuance deployment model is empty."; return 1; }
}

require_kubernetes_passport_selection() {
  local manifest="${K8S_DIR}/01-configmap.yaml"
  [[ -f "$manifest" ]] || { error "Kubernetes passport ConfigMap is missing."; return 1; }
  if ! envsubst < "$manifest" | "$K8S_NATIVE_ISSUANCE_BIN" check-selection --namespace "$NAMESPACE"; then
    error "Rust-only Kubernetes deploy requires selected passport routes and KMS custody in the reviewed ConfigMap."
    return 1
  fi
}

catalog_services() {
  "$REPO_ROOT/scripts/marty-deploy.sh" services --group "$1" --field k8s_deployment
}

catalog_required_secret_envs() {
  "$REPO_ROOT/scripts/marty-deploy.sh" secrets "$1" --field env
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
  local required_envs="${2-}"
  local var_name value

  if [[ $# -lt 2 ]]; then
    required_envs="$(catalog_required_secret_envs "$stack_name")" || return 1
  fi
  [[ -n "$required_envs" ]] || { error "Deployment catalog returned no required secrets."; return 1; }

  while IFS= read -r var_name; do
    [[ -z "$var_name" ]] && continue
    value="$(resolve_secret_input "$var_name")"
    require_resolved_secret "$var_name" "$value"
  done <<< "$required_envs"
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
  # Resolve and validate in Rust; credential values are sent to kubectl on stdin.
  # Namespace and registry provisioning retain their existing ordering.
  local required_envs="${1-}"
  if [[ $# -eq 0 ]]; then
    required_envs="$(catalog_required_secret_envs "$K8S_STACK_NAME")" || { error "Deployment catalog secret lookup failed."; return 1; }
  fi
  [[ -n "$required_envs" ]] || { error "Deployment catalog returned no required secrets."; return 1; }
  step "Setting up Kubernetes Secrets and image pull secret"
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  create_image_pull_secret
  "$REPO_ROOT/scripts/marty-deploy.sh" kubernetes-secrets "$K8S_STACK_NAME" "$NAMESPACE" "$required_envs" || return 1
  success "Application and workload identity secrets created/updated"
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
  [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true ]] || {
    error "Rust-only Kubernetes image updates require native issuance."
    return 1
  }
  prepare_kubernetes_native_issuance || return 1
  if [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true ]]; then
    # Read-only API snapshot, not a lock against concurrent operator changes.
    if ! kubectl get deployment/issuance-native deployment/gateway deployment/issuance deployment/signing-keys deployment/auth deployment/applicant deployment/presentation-policy deployment/flow service/issuance-native service/issuance service/signing-keys configmap/issuance-native-config configmap/marty-config -n "$NAMESPACE" -o json --request-timeout=10s \
      | "$K8S_NATIVE_ISSUANCE_BIN" check-update --repo-root "$REPO_ROOT" --manifest-dir "$K8S_DIR" --namespace "$NAMESPACE"; then
      error "Native issuance image update refused; apply the reviewed full-manifest selection first."
      return 1
    fi
  fi
  # Image-only updates cannot replace a legacy command or inherited selector.
  # This read-only snapshot is not a lock against concurrent operator changes.
  if ! kubectl get deployment canvas-sync-worker -n "$NAMESPACE" -o json --request-timeout=10s 2>/dev/null \
    | "$PYTHON_BIN" "$REPO_ROOT/scripts/check_canvas_worker_kubernetes_update.py" --namespace "$NAMESPACE"; then
    error "Canvas worker image update refused; apply the reviewed full-manifest cutover first."
    return 1
  fi
  if ! kubectl get deployment keycloak -n "$NAMESPACE" -o json --request-timeout=10s 2>/dev/null \
    | "$PYTHON_BIN" "$REPO_ROOT/scripts/check_kubernetes_keycloak_update.py" --namespace "$NAMESPACE"; then
    error "Keycloak image update refused; apply the reviewed KMS-only manifest first."
    return 1
  fi
  local app_services
  app_services="$(catalog_services app)" || { error "Deployment catalog service lookup failed."; return 1; }
  [[ -n "$app_services" ]] || { error "Deployment catalog returned no app services."; return 1; }
  kubectl set image deployment/keycloak "keycloak=${MARTY_KEYCLOAK_KMS_IMAGE}" -n "$NAMESPACE" || return 1
  kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=360s || return 1
  step "Rolling image update — tag: ${IMAGE_TAG}"
  if [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true ]]; then
    kubectl set image deployment/signing-keys "signing-keys=${MARTY_SERVICES_IMAGE}" -n "$NAMESPACE" || return 1
    kubectl rollout status deployment/signing-keys -n "$NAMESPACE" --timeout=180s || return 1
    kubectl set image deployment/issuance-native "issuance-native=${MARTY_SERVICES_IMAGE}" -n "$NAMESPACE" || return 1
    kubectl rollout status deployment/issuance-native -n "$NAMESPACE" --timeout=180s || return 1
    kubectl set image deployment/issuance "issuance=${MARTY_SERVICES_IMAGE}" -n "$NAMESPACE" || return 1
    kubectl rollout status deployment/issuance -n "$NAMESPACE" --timeout=180s || return 1
  fi
  while IFS= read -r svc; do
    # Issuance is updated with the shared Rust services image above.
    [[ -z "$svc" || "$svc" == "issuance" ]] && continue
    kubectl set image deployment/"${svc}" "${svc}=${IMAGE_REGISTRY}/marty-ui/${svc}:${IMAGE_TAG}" \
      -n "$NAMESPACE" 2>/dev/null && success "Updated ${svc}" || warn "Deployment '${svc}' not found (skipped)"
  done <<< "$app_services"
  kubectl set image deployment/ui "ui=${IMAGE_REGISTRY}/marty-ui/ui-selfhost:${IMAGE_TAG}" \
    -n "$NAMESPACE" 2>/dev/null && success "Updated ui" || warn "Deployment 'ui' not found (skipped)"
  kubectl set image deployment/cloudflared "cloudflared=${IMAGE_REGISTRY}/marty-ui/cloudflared-wrapper:${IMAGE_TAG}" \
    -n "$NAMESPACE" 2>/dev/null && success "Updated cloudflared" || warn "Deployment 'cloudflared' not found (skipped)"
  kubectl rollout status deployment -n "$NAMESPACE" --timeout=300s || true
}

cmd_deploy() {
  [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true ]] || {
    error "Rust-only Kubernetes deployment requires native issuance."
    return 1
  }
  prepare_kubernetes_native_issuance || return 1
  require_kubernetes_passport_selection || return 1
  local catalog_secret_envs
  catalog_secret_envs="$(catalog_required_secret_envs "$K8S_STACK_NAME")" || { error "Deployment catalog secret lookup failed."; return 1; }
  [[ -n "$catalog_secret_envs" ]] || { error "Deployment catalog returned no required secrets."; return 1; }
  step "Full Kubernetes Deploy"

  apply_manifest "${K8S_DIR}/00-namespace.yaml"
  cmd_setup_secrets "$catalog_secret_envs"
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
  kubectl delete job revocation-profile-migrations -n "$NAMESPACE" --ignore-not-found=true
  apply_manifest "${K8S_DIR}/05b-revocation-profile-migrations.yaml"
  info "Waiting for revocation-profile migrations to complete..."
  kubectl wait --for=condition=complete job/revocation-profile-migrations -n "$NAMESPACE" --timeout=300s \
    || { kubectl logs job/revocation-profile-migrations -n "$NAMESPACE" --tail=50; error "Revocation-profile migration job failed"; }
  success "Revocation-profile Rust migrations completed"

  kubectl delete job db-migrate -n "$NAMESPACE" --ignore-not-found=true
  apply_manifest "${K8S_DIR}/06-db-migrate.yaml"
  info "Waiting for migration job to complete…"
  kubectl wait --for=condition=complete job/db-migrate -n "$NAMESPACE" --timeout=300s \
    || { kubectl logs job/db-migrate -n "$NAMESPACE" --tail=50; error "Migration job failed"; }
  success "Marty UI database migrations completed"

  kubectl delete job issuance-migrations -n "$NAMESPACE" --ignore-not-found=true
  apply_manifest "${K8S_DIR}/06a-issuance-migrations.yaml"
  info "Waiting for credentials issuance migrations to completeâ€¦"
  kubectl wait --for=condition=complete job/issuance-migrations -n "$NAMESPACE" --timeout=300s \
    || { kubectl logs job/issuance-migrations -n "$NAMESPACE" --tail=50; error "Issuance migration job failed"; }
  success "All database migrations completed"

  step "Deploying Keycloak…"
  apply_manifest "${K8S_DIR}/05-keycloak.yaml"
  info "Waiting for Keycloak (this can take ~2 minutes)…"
  kubectl rollout status deployment/keycloak -n "$NAMESPACE" --timeout=360s

  step "Deploying microservices…"
  apply_manifest "${K8S_DIR}/07-microservices.yaml"
  if [[ "${K8S_ISSUANCE_NATIVE_ENABLED-true}" == true ]]; then
    kubectl rollout status deployment/signing-keys -n "$NAMESPACE" --timeout=180s || return 1
    kubectl rollout status deployment/issuance-native -n "$NAMESPACE" --timeout=180s || return 1
    kubectl rollout status deployment/issuance -n "$NAMESPACE" --timeout=180s || return 1
    kubectl rollout status deployment/gateway -n "$NAMESPACE" --timeout=180s || return 1
  fi
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
