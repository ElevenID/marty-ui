#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -n "${MARTY_DEPLOY_BIN:-}" ]; then
  [ -x "$MARTY_DEPLOY_BIN" ] || { echo "MARTY_DEPLOY_BIN is not executable" >&2; exit 1; }
  [ -n "${MARTY_DEPLOY_BIN_SHA256:-}" ] || { echo "MARTY_DEPLOY_BIN_SHA256 is required" >&2; exit 1; }
  actual_sha="$(sha256sum < "$MARTY_DEPLOY_BIN" | cut -d ' ' -f 1)"
  [ "$actual_sha" = "$MARTY_DEPLOY_BIN_SHA256" ] || { echo "MARTY_DEPLOY_BIN digest mismatch" >&2; exit 1; }
  exec "$MARTY_DEPLOY_BIN" --repo-root "$repo_root" "$@"
fi

# Source-checkout development path. Operator distributions set a pinned binary.
exec cargo +1.95.0 run --quiet --locked --manifest-path "$repo_root/rust/Cargo.toml" \
  -p marty-deployment-catalog --bin marty-deploy -- --repo-root "$repo_root" "$@"
