#!/usr/bin/env bash
# Source-identified read-only model policy for CI; this is not a release attestation.
set -euo pipefail
: "${GITHUB_ENV:?GitHub step environment file is required}"
: "${RUNNER_TEMP:?GitHub runner temporary directory is required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${1:-}" in
  model) package=marty-deployment-catalog; binary_name=marty-deploy; prefix=MARTY_DEPLOY ;;
  execution) package=marty-ci-execution; binary_name=marty-ci-execution; prefix=MARTY_CI_EXECUTION ;;
  *) echo "Expected model or execution native helper" >&2; exit 2 ;;
esac
source_sha="$(git -C "$root" rev-parse HEAD)"
export "${prefix}_SOURCE_SHA=$source_sha" "${prefix}_RELEASE_TAG=v0.0.0"
# Keep host-native policy tools out of the clean Bookworm artifact directory.
target="$RUNNER_TEMP/marty-native-tools"
cargo +1.95.0 build --locked --manifest-path "$root/rust/Cargo.toml" \
  --target-dir "$target" -p "$package" --bin "$binary_name"
binary="$target/debug/$binary_name"
[[ "$("$binary" --build-identity)" == "$source_sha:v0.0.0" ]]
digest="$(sha256sum "$binary" | cut -d ' ' -f 1)"
{
  printf '%s_BIN=%s\n' "$prefix" "$binary"
  printf '%s_BIN_SHA256=%s\n' "$prefix" "$digest"
  printf '%s_SOURCE_SHA=%s\n' "$prefix" "$source_sha"
  printf '%s_RELEASE_TAG=v0.0.0\n' "$prefix"
} >> "$GITHUB_ENV"
