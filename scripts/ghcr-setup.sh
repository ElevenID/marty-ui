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

main() {
  log_info "Checking Docker before GHCR login"
  if ! docker info >/dev/null 2>&1; then
    log_error "Docker is not running. Start Docker Desktop first."
    exit 1
  fi

  if ! docker buildx version >/dev/null 2>&1; then
    log_error "Docker Buildx is required for Marty image releases."
    exit 1
  fi

  log_info "Enter your GitHub username:"
  read -r github_username
  if [ -z "$github_username" ]; then
    log_error "GitHub username is required."
    exit 1
  fi

  log_info "Enter a GitHub PAT with read:packages and write:packages scopes (input hidden):"
  read -rs github_token
  echo
  if [ -z "$github_token" ]; then
    log_error "GitHub token is required."
    exit 1
  fi

  log_info "Logging Docker into ghcr.io"
  if printf '%s' "$github_token" | docker login ghcr.io -u "$github_username" --password-stdin >/dev/null; then
    log_success "Docker is authenticated to GHCR."
  else
    log_error "GHCR authentication failed. Check the username and token scopes."
    exit 1
  fi

  log_warning "Keep the PAT out of repo files and rotate it if it was pasted anywhere unsafe."
}

main "$@"
