#!/bin/sh
# Source inside the network-isolated compiler container, never on the host.
# Only the local disk backend is available; no Actions token is forwarded.
unset RUSTC_WRAPPER SCCACHE_GHA_ENABLED SCCACHE_GHA_CACHE_URL SCCACHE_GHA_RUNTIME_TOKEN
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RESULTS_URL SCCACHE_GHA_RW_MODE
RUSTC="$(rustup which rustc --toolchain 1.95.0)"
export RUSTC
"$RUSTC" --version | grep -Eq '^rustc 1[.]95[.]0 '
bookworm_sccache="${MARTY_BOOKWORM_SCCACHE:-/opt/marty-cache/sccache}"
if [ -x "$bookworm_sccache" ] && [ -d "${SCCACHE_DIR:-/nonexistent}" ]; then
  export SCCACHE_CACHE_SIZE=5G
  export SCCACHE_IGNORE_SERVER_IO_ERROR=1
  if timeout 30 "$bookworm_sccache" "$RUSTC" -vV >/dev/null 2>&1; then
    RUSTC_WRAPPER="$bookworm_sccache"
    export RUSTC_WRAPPER
  else
    echo 'Offline compiler cache unavailable; compiling directly.' >&2
  fi
fi
