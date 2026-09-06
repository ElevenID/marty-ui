#!/bin/sh
# Trusted-main-only storage regression: read back a freshly written compiler
# result in a new read-only daemon, not just a successful backend startup.
set -eu
case "${1:-}" in
  ''|*[!0-9-]*) echo 'Expected a numeric workflow run/attempt nonce' >&2; exit 1 ;;
esac
test "$(cat /run/secrets/sccache_mode)" = READ_WRITE
export SCCACHE_GHA_ENABLED=true ACTIONS_CACHE_SERVICE_V2=true
export ACTIONS_RUNTIME_TOKEN="$(cat /run/secrets/sccache_token)"
export ACTIONS_RESULTS_URL="$(cat /run/secrets/sccache_url)"
export SCCACHE_GHA_RW_MODE=READ_WRITE
probe_dir=$(mktemp -d /tmp/marty-cache-probe.XXXXXXXX)
printf 'pub const NONCE: &str = "%s";\n' "$1" > "$probe_dir/probe.rs"
sccache rustc --crate-name marty_cache_probe --crate-type=rlib "$probe_dir/probe.rs" --out-dir "$probe_dir"
sccache --stop-server
rm "$probe_dir/libmarty_cache_probe.rlib"
export SCCACHE_GHA_RW_MODE=READ_ONLY
sccache rustc --crate-name marty_cache_probe --crate-type=rlib "$probe_dir/probe.rs" --out-dir "$probe_dir"
sccache --stop-server > "$probe_dir/stats"
cat "$probe_dir/stats"
awk '$1 == "Cache" && $2 == "hits" && $3 == "(Rust)" && $4 >= 1 { hit = 1 } END { exit !hit }' "$probe_dir/stats"
test -s "$probe_dir/libmarty_cache_probe.rlib"
rm "$probe_dir/probe.rs" "$probe_dir/libmarty_cache_probe.rlib" "$probe_dir/stats"
rmdir "$probe_dir"
