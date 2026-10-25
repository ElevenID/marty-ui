#!/usr/bin/env bash
# Source-identified read-only model policy for CI; this is not a release attestation.
set -euo pipefail
: "${GITHUB_ENV:?GitHub step environment file is required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_sha="$(git -C "$root" rev-parse HEAD)"
export MARTY_DEPLOY_SOURCE_SHA="$source_sha"
export MARTY_DEPLOY_RELEASE_TAG=v0.0.0
cargo +1.95.0 build --locked --manifest-path "$root/rust/Cargo.toml"   --target-dir "$root/rust/target" -p marty-deployment-catalog --bin marty-deploy
binary="$root/rust/target/debug/marty-deploy"
[[ "$("$binary" --build-identity)" == "$source_sha:v0.0.0" ]]
digest="$(sha256sum "$binary" | cut -d ' ' -f 1)"
{
  printf 'MARTY_DEPLOY_BIN=%s\n' "$binary"
  printf 'MARTY_DEPLOY_BIN_SHA256=%s\n' "$digest"
  printf 'MARTY_DEPLOY_SOURCE_SHA=%s\n' "$source_sha"
  printf 'MARTY_DEPLOY_RELEASE_TAG=v0.0.0\n'
} >> "$GITHUB_ENV"
