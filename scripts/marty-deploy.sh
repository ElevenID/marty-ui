#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -n "${MARTY_DEPLOY_BIN:-}" ]; then
  [ -x "$MARTY_DEPLOY_BIN" ] || { echo "MARTY_DEPLOY_BIN is not executable" >&2; exit 1; }
  [ -n "${MARTY_DEPLOY_BIN_SHA256:-}" ] || { echo "MARTY_DEPLOY_BIN_SHA256 is required" >&2; exit 1; }
  [ -n "${MARTY_DEPLOY_SOURCE_SHA:-}" ] || { echo "MARTY_DEPLOY_SOURCE_SHA is required" >&2; exit 1; }
  [ -n "${MARTY_DEPLOY_RELEASE_TAG:-}" ] || { echo "MARTY_DEPLOY_RELEASE_TAG is required" >&2; exit 1; }
  printf '%s' "$MARTY_DEPLOY_BIN_SHA256" | grep -Eq '^[0-9a-f]{64}$' || { echo "MARTY_DEPLOY_BIN_SHA256 is invalid" >&2; exit 1; }
  printf '%s' "$MARTY_DEPLOY_SOURCE_SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "MARTY_DEPLOY_SOURCE_SHA is invalid" >&2; exit 1; }
  printf '%s' "$MARTY_DEPLOY_RELEASE_TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "MARTY_DEPLOY_RELEASE_TAG is invalid" >&2; exit 1; }
  actual_sha="$(sha256sum < "$MARTY_DEPLOY_BIN" | cut -d ' ' -f 1)"
  [ "$actual_sha" = "$MARTY_DEPLOY_BIN_SHA256" ] || { echo "MARTY_DEPLOY_BIN digest mismatch" >&2; exit 1; }
  actual_identity="$("$MARTY_DEPLOY_BIN" --build-identity)" || { echo "MARTY_DEPLOY_BIN identity unavailable" >&2; exit 1; }
  [ "$actual_identity" = "$MARTY_DEPLOY_SOURCE_SHA:$MARTY_DEPLOY_RELEASE_TAG" ] || { echo "MARTY_DEPLOY_BIN source or tag mismatch" >&2; exit 1; }
  exec "$MARTY_DEPLOY_BIN" --repo-root "$repo_root" "$@"
fi

# Source-checkout development path. Operator distributions set a pinned binary.
exec cargo +1.95.0 run --quiet --locked --manifest-path "$repo_root/rust/Cargo.toml" \
  -p marty-deployment-catalog --bin marty-deploy -- --repo-root "$repo_root" "$@"
