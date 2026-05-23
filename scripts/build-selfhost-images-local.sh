#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_section() {
  echo
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python}"
VERSION_FILE="${VERSION_FILE:-$REPO_ROOT/VERSION}"
IMAGE_PREFIX="${SELFHOST_IMAGE_PREFIX:-ghcr.io/elevenid/marty-ui}"
PLATFORM="${PLATFORM:-linux/amd64}"
TAG=""
PUSH=false
TAG_LATEST=false
INCLUDE_PUBLIC_UI=false
SKIP_CLOUDFLARED=false
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: scripts/build-selfhost-images-local.sh [--tag <version>] [options]

Builds Marty self-host production images locally and optionally pushes them to
GitHub Container Registry. This avoids GitHub Actions/cloud build costs.

Release version:
  --tag <version>          Immutable release tag, for example 2026.05.0
                           Defaults to VERSION in the repo root when omitted

Options:
  --push                   Push images to the registry after building
  --skip-push              Build locally only (default)
  --tag-latest             Also tag images as latest (not for customer docs)
  --include-public-ui      Also build ghcr.io/.../ui:<tag>
  --skip-cloudflared       Do not build cloudflared-wrapper
  --platform <platform>    Docker platform (default: linux/amd64)
  --image-prefix <prefix>  Registry prefix (default: ghcr.io/elevenid/marty-ui)
  --version-file <path>    Version file to use when --tag is omitted
  --dry-run                Print the build plan without running docker buildx
  -h, --help               Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --push)
      PUSH=true
      shift
      ;;
    --skip-push)
      PUSH=false
      shift
      ;;
    --tag-latest)
      TAG_LATEST=true
      shift
      ;;
    --include-public-ui)
      INCLUDE_PUBLIC_UI=true
      shift
      ;;
    --skip-cloudflared)
      SKIP_CLOUDFLARED=true
      shift
      ;;
    --platform)
      PLATFORM="${2:-}"
      shift 2
      ;;
    --image-prefix)
      IMAGE_PREFIX="${2:-}"
      shift 2
      ;;
    --version-file)
      VERSION_FILE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

resolve_release_tag() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    log_error "Missing required tool: $PYTHON_BIN"
    exit 1
  }

  local cmd=("$PYTHON_BIN" "$REPO_ROOT/scripts/release_version.py" resolve --repo-root "$REPO_ROOT" --version-file "$VERSION_FILE")
  if [ -n "$TAG" ]; then
    cmd+=(--tag "$TAG")
  fi

  "${cmd[@]}"
}

planned_image_names() {
  printf '%s\n' services db-migrate ui-selfhost
  if [ "$INCLUDE_PUBLIC_UI" = true ]; then
    printf '%s\n' ui
  fi
  if [ "$SKIP_CLOUDFLARED" = false ]; then
    printf '%s\n' cloudflared-wrapper
  fi
}

check_remote_release_tag_available() {
  if [ "$PUSH" != true ]; then
    return 0
  fi

  if [ "$DRY_RUN" = true ]; then
    log_warning "Dry run: skipping registry overwrite preflight"
    return 0
  fi

  log_section "Checking registry for existing immutable tag"
  local image_name image_ref
  local existing_refs=()

  while IFS= read -r image_name; do
    [ -n "$image_name" ] || continue
    image_ref="$IMAGE_PREFIX/$image_name:$TAG"
    if docker buildx imagetools inspect "$image_ref" >/dev/null 2>&1; then
      existing_refs+=("$image_ref")
    fi
  done < <(planned_image_names)

  if [ ${#existing_refs[@]} -ne 0 ]; then
    echo -e "${RED}✗ Refusing to overwrite existing immutable image tag in registry.${NC}"
    for image_ref in "${existing_refs[@]}"; do
      echo -e "${RED}  - $image_ref${NC}"
    done
    echo -e "${RED}Choose a new release tag instead of reusing an existing one.${NC}"
    exit 1
  fi

  log_success "Registry preflight passed; tag $TAG is available"
}

TAG="$(resolve_release_tag)"

check_prerequisites() {
  local missing=()
  command -v docker >/dev/null 2>&1 || missing+=("docker")
  command -v git >/dev/null 2>&1 || missing+=("git")

  if [ ${#missing[@]} -ne 0 ]; then
    log_error "Missing required tools: ${missing[*]}"
    exit 1
  fi

  if ! docker info >/dev/null 2>&1; then
    log_error "Docker is not running. Start Docker Desktop first."
    exit 1
  fi

  if ! docker buildx version >/dev/null 2>&1; then
    log_error "Docker Buildx is required."
    exit 1
  fi

  local required_paths=(
    "$WORKSPACE_ROOT/marty-core"
    "$WORKSPACE_ROOT/marty-credentials"
    "$WORKSPACE_ROOT/longfellow-zk/lib"
    "$WORKSPACE_ROOT/marty-microservices-framework"
    "$REPO_ROOT/services/Dockerfile"
    "$REPO_ROOT/services/Dockerfile.migrations"
    "$REPO_ROOT/docker/ui.Dockerfile"
  )

  for path in "${required_paths[@]}"; do
    if [ ! -e "$path" ]; then
      log_error "Required build input is missing: $path"
      exit 1
    fi
  done
}

repo_sha() {
  local repo="$1"
  git -C "$repo" rev-parse --short HEAD 2>/dev/null || printf 'unknown'
}

repo_full_sha() {
  local repo="$1"
  git -C "$repo" rev-parse HEAD 2>/dev/null || printf 'unknown'
}

BUILD_CREATED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MARTY_UI_SHA="$(repo_full_sha "$REPO_ROOT")"
MARTY_UI_SHORT_SHA="$(repo_sha "$REPO_ROOT")"
RELEASE_DIR="$REPO_ROOT/dist/releases/$TAG"
IMAGE_RECORDS=()

base_build_args() {
  printf '%s\0' \
    --platform "$PLATFORM" \
    --label "org.opencontainers.image.created=$BUILD_CREATED" \
    --label "org.opencontainers.image.version=$TAG" \
    --label "org.opencontainers.image.revision=$MARTY_UI_SHA" \
    --label "org.opencontainers.image.source=https://github.com/ElevenID/marty-ui" \
    --label "org.opencontainers.image.vendor=ElevenID" \
    --label "org.opencontainers.image.licenses=Commercial"
}

build_image() {
  local image_name="$1"
  local dockerfile="$2"
  local context="$3"
  shift 3

  local image_ref="$IMAGE_PREFIX/$image_name:$TAG"
  local cmd=(docker buildx build)
  local arg
  while IFS= read -r -d '' arg; do
    cmd+=("$arg")
  done < <(base_build_args)

  cmd+=(--file "$dockerfile" --tag "$image_ref")

  if [ "$TAG_LATEST" = true ]; then
    cmd+=(--tag "$IMAGE_PREFIX/$image_name:latest")
  fi

  while [ $# -gt 0 ]; do
    cmd+=("$1")
    shift
  done

  if [ "$PUSH" = true ]; then
    cmd+=(--push)
  else
    cmd+=(--load)
  fi

  cmd+=("$context")

  log_section "Building $image_name"
  log_info "Image: $image_ref"
  log_info "Dockerfile: $dockerfile"
  log_info "Context: $context"

  if [ "$DRY_RUN" = true ]; then
    printf 'DRY RUN:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
  else
    "${cmd[@]}"
  fi

  IMAGE_RECORDS+=("$image_name|$image_ref")
  log_success "$image_name complete"
}

write_manifest() {
  mkdir -p "$RELEASE_DIR"
  {
    echo "Marty self-host image release"
    echo "tag=$TAG"
    echo "image_prefix=$IMAGE_PREFIX"
    echo "platform=$PLATFORM"
    echo "created=$BUILD_CREATED"
    echo "marty_ui_sha=$MARTY_UI_SHA"
    echo "marty_core_sha=$(repo_full_sha "$WORKSPACE_ROOT/marty-core")"
    echo "marty_credentials_sha=$(repo_full_sha "$WORKSPACE_ROOT/marty-credentials")"
    echo "longfellow_zk_sha=$(repo_full_sha "$WORKSPACE_ROOT/longfellow-zk")"
    echo "marty_microservices_framework_sha=$(repo_full_sha "$WORKSPACE_ROOT/marty-microservices-framework")"
    echo
    echo "images:"
    for record in "${IMAGE_RECORDS[@]}"; do
      IFS='|' read -r name ref <<< "$record"
      echo "- $name $ref"
    done
  } > "$RELEASE_DIR/images.txt"

  log_success "Release manifest written: $RELEASE_DIR/images.txt"
}

main() {
  log_section "Marty self-host local image release"
  log_info "Repo: $REPO_ROOT"
  log_info "Workspace: $WORKSPACE_ROOT"
  log_info "Image prefix: $IMAGE_PREFIX"
  log_info "Tag: $TAG"
  log_info "Platform: $PLATFORM"

  check_prerequisites
  check_remote_release_tag_available

  build_image "services" "$REPO_ROOT/services/Dockerfile" "$WORKSPACE_ROOT"
  build_image "db-migrate" "$REPO_ROOT/services/Dockerfile.migrations" "$WORKSPACE_ROOT"
  build_image "ui-selfhost" "$REPO_ROOT/docker/ui.Dockerfile" "$REPO_ROOT" \
    --build-context "marty-cli=$WORKSPACE_ROOT/marty-cli" \
    --build-context "marty-blog=$WORKSPACE_ROOT/marty-blog" \
    --build-context "marty-subscriptions=$WORKSPACE_ROOT/marty-subscriptions" \
    --build-arg UI_VARIANT=selfhost

  if [ "$INCLUDE_PUBLIC_UI" = true ]; then
    build_image "ui" "$REPO_ROOT/docker/ui.Dockerfile" "$REPO_ROOT" \
      --build-context "marty-cli=$WORKSPACE_ROOT/marty-cli" \
      --build-context "marty-blog=$WORKSPACE_ROOT/marty-blog" \
      --build-context "marty-subscriptions=$WORKSPACE_ROOT/marty-subscriptions" \
      --build-arg UI_VARIANT=public
  fi

  if [ "$SKIP_CLOUDFLARED" = false ]; then
    build_image "cloudflared-wrapper" "$REPO_ROOT/docker/cloudflared-wrapper.Dockerfile" "$REPO_ROOT"
  fi

  if [ "$DRY_RUN" = true ]; then
    log_warning "Dry run only. No images were built, pushed, or recorded."
  else
    write_manifest
  fi

  if [ "$DRY_RUN" = true ]; then
    return 0
  elif [ "$PUSH" = true ]; then
    log_success "Images pushed to $IMAGE_PREFIX with tag $TAG"
  else
    log_warning "Images were built locally only. Re-run with --push to publish to GHCR."
  fi
}

main "$@"
