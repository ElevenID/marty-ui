#!/usr/bin/env bash
# Rebuild only the native issuance binary when local Rust inputs change.
# This runs in the isolated disposable Compose project, never in production.
set -euo pipefail
cd /workspace/rust

child=''
stop_child() {
  if [[ -n "$child" ]] && kill -0 "$child" 2>/dev/null; then
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" || true
  fi
  child=''
}
trap 'stop_child; exit 0' INT TERM

snapshot() {
  find /workspace/rust /workspace/proto /workspace/contracts \
    -type d \( -name target -o -name .git \) -prune -o \
    -type f \
    -printf '%p:%T@:%s\n' | LC_ALL=C sort | sha256sum | cut -d ' ' -f 1
}

previous=''
while :; do
  current="$(snapshot)"
  if [[ "$current" != "$previous" ]]; then
    previous="$current"
    echo 'Passport Rust source changed; rebuilding issuance-native.'
    if cargo build --locked -p marty-issuance-service --bin marty-issuance-service; then
      stop_child
      (
        . /workspace/scripts/load-secrets-env.sh
        exec "$CARGO_TARGET_DIR/debug/marty-issuance-service"
      ) &
      child=$!
      echo "Issuance-native started with PID $child."
    else
      echo 'Issuance-native build failed; retaining the previous process.' >&2
    fi
  fi
  if [[ -n "$child" ]] && ! kill -0 "$child" 2>/dev/null; then
    wait "$child" || true
    child=''
    echo 'Issuance-native exited; waiting for another source change.' >&2
  fi
  sleep 3
done
