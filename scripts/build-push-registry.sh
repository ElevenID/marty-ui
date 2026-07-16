#!/bin/bash
# =============================================================================
# scripts/build-push-registry.sh
# Build all marty-ui Docker images and optionally push them to a configurable
# container registry.
#
# Usage:
#   ./scripts/build-push-registry.sh --registry <registry/repo-root> [--tag <tag>]
#   ./scripts/build-push-registry.sh --registry ghcr.io/elevenid [--push-only|--build-only]
#   ./scripts/build-push-registry.sh --registry ghcr.io/elevenid [uses VERSION when --tag is omitted]
#
# Compatibility:
#   OCIR_REGISTRY, OCI_REGION, OCIR_TENANCY_NAMESPACE, and OCIR_AUTH_TOKEN are
#   accepted as aliases while old OCIR-specific automation migrates.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}ℹ  $*${NC}"; }
success() { echo -e "${GREEN}✓  $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
error()   { echo -e "${RED}✗  $*${NC}"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python}"
VERSION_FILE="${VERSION_FILE:-$REPO_ROOT/VERSION}"

IMAGE_TAG="${IMAGE_TAG:-}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-${CONTAINER_REGISTRY:-${OCIR_REGISTRY:-}}}"
REGISTRY_HOST="${REGISTRY_HOST:-}"
REGISTRY_USERNAME="${REGISTRY_USERNAME:-}"
REGISTRY_AUTH_TOKEN="${REGISTRY_AUTH_TOKEN:-${OCIR_AUTH_TOKEN:-}}"
OCI_REGION="${OCI_REGION:-}"
OCIR_TENANCY_NAMESPACE="${OCIR_TENANCY_NAMESPACE:-}"
OCI_USERNAME="${OCI_USERNAME:-}"
PUSH_ONLY=false
BUILD_ONLY=false
TAG_LATEST=false
PLATFORM="${PLATFORM:-linux/arm64}"
MARTY_API_CORE_VERSION="${MARTY_API_CORE_VERSION:?Set the released @elevenid/marty-api-core version}"
MARTY_BLOG_VERSION="${MARTY_BLOG_VERSION:?Set the released @elevenid/marty-blog version}"
MARTY_COMMON_VERSION="${MARTY_COMMON_VERSION:?Set the released marty-common version}"
MARTY_RS_VERSION="${MARTY_RS_VERSION:?Set the released marty-credentials Python version}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --tag)               IMAGE_TAG="$2"; shift 2 ;;
    --registry)          IMAGE_REGISTRY="$2"; shift 2 ;;
    --registry-host)     REGISTRY_HOST="$2"; shift 2 ;;
    --registry-username) REGISTRY_USERNAME="$2"; shift 2 ;;
    --platform)          PLATFORM="$2"; shift 2 ;;
    --version-file)      VERSION_FILE="$2"; shift 2 ;;
    --tag-latest)        TAG_LATEST=true; shift ;;
    --push-only)         PUSH_ONLY=true; shift ;;
    --build-only)        BUILD_ONLY=true; shift ;;
    --region)            OCI_REGION="$2"; shift 2 ;;             # Legacy OCIR compatibility
    --namespace)         OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;; # Legacy OCIR compatibility
    --oci-namespace)     OCIR_TENANCY_NAMESPACE="$2"; shift 2 ;; # Legacy OCIR compatibility
    *) error "Unknown flag: $1" ;;
  esac
done

if [[ "$PUSH_ONLY" == true && "$BUILD_ONLY" == true ]]; then
  error "Choose only one of --push-only or --build-only."
fi

resolve_release_tag() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || error "Required command not found: $PYTHON_BIN"

  local cmd=("$PYTHON_BIN" "$REPO_ROOT/scripts/release_version.py" resolve --repo-root "$REPO_ROOT" --version-file "$VERSION_FILE")
  if [[ -n "${IMAGE_TAG:-}" ]]; then
    cmd+=(--tag "$IMAGE_TAG")
  fi

  "${cmd[@]}"
}

IMAGE_TAG="$(resolve_release_tag)"

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
[[ -z "$IMAGE_REGISTRY" ]] && error "Set IMAGE_REGISTRY or pass --registry."

if [[ -z "$REGISTRY_HOST" ]]; then
  REGISTRY_HOST="${IMAGE_REGISTRY%%/*}"
fi
if [[ -z "$REGISTRY_USERNAME" && -n "$OCIR_TENANCY_NAMESPACE" && -n "$OCI_USERNAME" ]]; then
  REGISTRY_USERNAME="${OCIR_TENANCY_NAMESPACE}/${OCI_USERNAME}"
fi

export IMAGE_REGISTRY IMAGE_TAG

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "  Marty UI → Registry Build & Push"
info "  Registry  : ${IMAGE_REGISTRY}"
info "  Tag       : ${IMAGE_TAG}"
info "  Platform  : ${PLATFORM}"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "$TAG_LATEST" == true ]]; then
  warn "Also tagging :latest. Do not use mutable tags for customer releases."
fi

if [[ "$BUILD_ONLY" == false ]]; then
  info "Preparing registry login for ${REGISTRY_HOST}…"
  if [[ -n "${REGISTRY_AUTH_TOKEN:-}" ]]; then
    [[ -n "$REGISTRY_USERNAME" ]] || error "REGISTRY_USERNAME is required when REGISTRY_AUTH_TOKEN is set."
    echo "${REGISTRY_AUTH_TOKEN}" | docker login "${REGISTRY_HOST}" \
      --username "${REGISTRY_USERNAME}" \
      --password-stdin \
    && success "Logged in to registry" || warn "Registry login failed — using existing stored credentials"
  else
    warn "REGISTRY_AUTH_TOKEN/OCIR_AUTH_TOKEN not set — using existing Docker credentials"
  fi
fi

if [[ "$PLATFORM" == "linux/arm64" ]] && ! docker buildx inspect marty-builder &>/dev/null; then
  info "Creating Docker buildx builder for ARM64…"
  docker buildx create --name marty-builder --use
  docker buildx inspect --bootstrap
fi
BUILDER_CMD="docker buildx build --platform ${PLATFORM} --load"

catalog_services() {
  "$PYTHON_BIN" "$REPO_ROOT/scripts/marty-deploy.py" services --group "$1" --field id
}

build_and_push() {
  local service="$1"
  local dockerfile="$2"
  local context="$3"
  local build_args="${4:-}"

  local image="${IMAGE_REGISTRY}/marty-ui/${service}:${IMAGE_TAG}"
  local image_latest="${IMAGE_REGISTRY}/marty-ui/${service}:latest"
  local tag_args=(-t "${image}")

  if [[ "$TAG_LATEST" == true ]]; then
    tag_args+=(-t "${image_latest}")
  fi

  if [[ "$PUSH_ONLY" == false ]]; then
    info "Building ${service}…"
    # shellcheck disable=SC2086
    $BUILDER_CMD \
      ${build_args} \
      -f "${dockerfile}" \
      "${tag_args[@]}" \
      "${context}"
    success "Built ${image}"
  fi

  if [[ "$BUILD_ONLY" == false ]]; then
    info "Pushing ${service}…"
    docker push "${image}"
    if [[ "$TAG_LATEST" == true ]]; then
      docker push "${image_latest}"
    fi
    success "Pushed ${image}"
  fi
}

cd "$REPO_ROOT"

while IFS= read -r svc; do
  [[ -z "$svc" || "$svc" == "issuance" ]] && continue
  build_and_push \
    "$svc" \
    "services/Dockerfile" \
    "." \
    "--build-arg SERVICE_NAME=${svc} --build-arg MARTY_RS_VERSION=${MARTY_RS_VERSION} --build-arg MARTY_COMMON_VERSION=${MARTY_COMMON_VERSION}"
done < <(catalog_services app)

build_and_push \
  "db-migrate" \
  "services/Dockerfile.migrations" \
  "." \
  "--build-arg MARTY_COMMON_VERSION=${MARTY_COMMON_VERSION}"

build_and_push \
  "ui-selfhost" \
  "docker/ui.Dockerfile" \
  "." \
  "--build-arg UI_VARIANT=selfhost --build-arg MARTY_API_CORE_VERSION=${MARTY_API_CORE_VERSION} --build-arg MARTY_BLOG_VERSION=${MARTY_BLOG_VERSION}"

build_and_push \
  "ui" \
  "docker/ui.Dockerfile" \
  "." \
  "--build-arg UI_VARIANT=public --build-arg MARTY_API_CORE_VERSION=${MARTY_API_CORE_VERSION} --build-arg MARTY_BLOG_VERSION=${MARTY_BLOG_VERSION}"

build_and_push \
  "cloudflared-wrapper" \
  "docker/cloudflared-wrapper.Dockerfile" \
  "."

echo ""
success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
success "  All images built/pushed"
success "  Registry: ${IMAGE_REGISTRY}"
success "  Tag:      ${IMAGE_TAG}"
success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
info "Next: run ./scripts/deploy-kubernetes.sh to deploy to Kubernetes."
