#!/bin/bash
# =============================================================================
# scripts/build-push-ocir.sh
# Build all marty-ui Docker images and push them to Oracle Container Registry.
#
# Usage:
#   ./scripts/build-push-ocir.sh [--tag <tag>] [--region <oci-region>] [--push-only] [--build-only]
#
# Prerequisites:
#   - Docker (with buildx for multi-arch ARM64 recommended)
#   - OCI CLI configured (oci setup config)
#   - An OCIR auth token generated in OCI IAM
#   - OCIR_TENANCY_NAMESPACE and OCI_REGION set (or passed as flags)
# =============================================================================
set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}ℹ  $*${NC}"; }
success() { echo -e "${GREEN}✓  $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
error()   { echo -e "${RED}✗  $*${NC}"; exit 1; }

# ─── Defaults ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-prod}"
OCI_REGION="${OCI_REGION:-}"          # e.g. us-ashburn-1
OCIR_TENANCY_NAMESPACE="${OCIR_TENANCY_NAMESPACE:-}"  # e.g. axmpqrs12345
PUSH_ONLY=false
BUILD_ONLY=false
PLATFORM="${PLATFORM:-linux/arm64}"   # OCI Always-Free uses ARM A1.Flex; change to linux/amd64 if using x86 nodes

# ─── Parse flags ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --tag)        IMAGE_TAG="$2";              shift 2 ;;
    --region)     OCI_REGION="$2";             shift 2 ;;
    --namespace)  OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;;
    --platform)   PLATFORM="$2";               shift 2 ;;
    --push-only)  PUSH_ONLY=true;              shift ;;
    --build-only) BUILD_ONLY=true;             shift ;;
    *) error "Unknown flag: $1" ;;
  esac
done

# ─── Validate ─────────────────────────────────────────────────────────────────
[[ -z "$OCI_REGION" ]]             && error "Set OCI_REGION or pass --region  (e.g. us-ashburn-1)"
[[ -z "$OCIR_TENANCY_NAMESPACE" ]] && error "Set OCIR_TENANCY_NAMESPACE or pass --namespace  (find it in OCI Console → Tenancy Details → Object Storage Namespace)"

# Derive the OCIR hostname from the region (case statement — works on macOS bash 3.x)
case "$OCI_REGION" in
  us-ashburn-1)   REGION_SHORT=iad ;;
  us-phoenix-1)   REGION_SHORT=phx ;;
  eu-frankfurt-1) REGION_SHORT=fra ;;
  uk-london-1)    REGION_SHORT=lhr ;;
  ap-tokyo-1)     REGION_SHORT=nrt ;;
  ap-sydney-1)    REGION_SHORT=syd ;;
  ap-singapore-1) REGION_SHORT=sin ;;
  sa-saopaulo-1)  REGION_SHORT=gru ;;
  ca-toronto-1)   REGION_SHORT=yyz ;;
  me-jeddah-1)    REGION_SHORT=jed ;;
  *) error "Unknown region: $OCI_REGION. Add it to the case statement in this script." ;;
esac
OCIR_REGISTRY="${REGION_SHORT}.ocir.io/${OCIR_TENANCY_NAMESPACE}"

export OCIR_REGISTRY IMAGE_TAG

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "  Marty UI → OCIR Build & Push"
info "  Registry  : ${OCIR_REGISTRY}"
info "  Tag       : ${IMAGE_TAG}"
info "  Platform  : ${PLATFORM}"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Docker login to OCIR ─────────────────────────────────────────────────────
if [[ "$PUSH_ONLY" == false && "$BUILD_ONLY" == false ]] || [[ "$PUSH_ONLY" == true ]]; then
  info "Logging in to OCIR (${REGION_SHORT}.ocir.io)…"
  if [[ -n "${OCIR_AUTH_TOKEN:-}" ]]; then
    echo "${OCIR_AUTH_TOKEN}" | docker login "${REGION_SHORT}.ocir.io" \
      --username "${OCIR_TENANCY_NAMESPACE}/${OCI_USERNAME:-}" \
      --password-stdin \
    && success "Logged in to OCIR" || warn "OCIR login failed — using existing stored credentials"
  else
    warn "OCIR_AUTH_TOKEN not set — using existing stored Docker credentials"
  fi
fi

# ─── Set up buildx for multi-arch if needed ───────────────────────────────────
if [[ "$PLATFORM" == "linux/arm64" ]] && ! docker buildx inspect marty-builder &>/dev/null; then
  info "Creating Docker buildx builder for ARM64…"
  docker buildx create --name marty-builder --use
  docker buildx inspect --bootstrap
fi
BUILDER_CMD="docker buildx build --platform ${PLATFORM} --load"

# ─── Helper: build one image ──────────────────────────────────────────────────
build_and_push() {
  local service="$1"
  local dockerfile="$2"
  local context="$3"
  local build_args="${4:-}"

  local image="${OCIR_REGISTRY}/marty-ui/${service}:${IMAGE_TAG}"
  local image_latest="${OCIR_REGISTRY}/marty-ui/${service}:latest"

  if [[ "$PUSH_ONLY" == false ]]; then
    info "Building ${service}…"
    # shellcheck disable=SC2086
    $BUILDER_CMD \
      ${build_args} \
      -f "${dockerfile}" \
      -t "${image}" \
      -t "${image_latest}" \
      "${context}"
    success "Built ${image}"
  fi

  if [[ "$BUILD_ONLY" == false ]]; then
    info "Pushing ${service}…"
    docker push "${image}"
    docker push "${image_latest}"
    success "Pushed ${image}"
  fi
}

# Build context must be the monorepo parent directory (contains marty-ui/, marty-core/, marty-credentials/, etc.)
PARENT_DIR="$(cd "$REPO_ROOT/.." && pwd)"
cd "$PARENT_DIR"

# ─── Build each service ───────────────────────────────────────────────────────

# marty-ui/services uses a shared Dockerfile with SERVICE_NAME arg
for svc in gateway auth organization credential-template trust-profile applicant notification compliance-profile presentation-policy deployment-profile flow; do
  build_and_push \
    "$svc" \
    "marty-ui/services/Dockerfile" \
    "." \
    "--build-arg SERVICE_NAME=${svc}"
done

# Issuance — lives in marty-credentials
build_and_push \
  "issuance" \
  "marty-credentials/services/Dockerfile" \
  "."

# DB migrations runner
build_and_push \
  "db-migrate" \
  "marty-ui/services/Dockerfile.migrations" \
  "."

# UI — nginx + React SPA (context is the ui/ subdirectory)
build_and_push \
  "ui" \
  "marty-ui/ui/Dockerfile.prod" \
  "marty-ui/ui"

echo ""
success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
success "  All images built and pushed to OCIR"
success "  Registry: ${OCIR_REGISTRY}"
success "  Tag:      ${IMAGE_TAG}"
success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
info "Next: run ./scripts/deploy-oracle.sh to deploy to OKE."
