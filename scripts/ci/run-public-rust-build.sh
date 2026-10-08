#!/bin/sh
set -eu

# Local Docker builds work without GitHub cache credentials. CI supplies all
# three as ephemeral BuildKit secrets, never as ARG/ENV or image layers.
token=/run/secrets/sccache_token
url=/run/secrets/sccache_url
mode=/run/secrets/sccache_mode
if [ -s "$token" ] || [ -s "$url" ] || [ -s "$mode" ]; then
  if [ ! -s "$token" ] || [ ! -s "$url" ] || [ ! -s "$mode" ]; then
    echo "Incomplete sccache credentials" >&2
    exit 1
  fi
  export SCCACHE_GHA_ENABLED=true ACTIONS_CACHE_SERVICE_V2=true
  export ACTIONS_RUNTIME_TOKEN="$(cat "$token")"
  export ACTIONS_RESULTS_URL="$(cat "$url")"
  export SCCACHE_GHA_RW_MODE="$(cat "$mode")"
  case "$SCCACHE_GHA_RW_MODE" in
    READ_ONLY|READ_WRITE) ;;
    *) echo "Invalid sccache cache mode" >&2; exit 1 ;;
  esac
  export RUSTC_WRAPPER=sccache
  case "${1:-}" in
    build-rust-service-binaries) cache_phase=release_binaries ;;
    *) cache_phase=dependency_cook ;;
  esac
  report_cache_counters() {
    sccache --show-stats 2>/dev/null |
      awk -v phase="$cache_phase" -f /usr/local/bin/public-sccache-stats.awk || true
    sccache --stop-server >/dev/null 2>&1 || true
  }
  trap report_cache_counters EXIT
fi

"$@"
