#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
exec cargo +1.95.0 run --quiet --locked --manifest-path "$repo_root/rust/Cargo.toml" \
  -p marty-deployment-catalog --bin marty-deploy -- --repo-root "$repo_root" "$@"
