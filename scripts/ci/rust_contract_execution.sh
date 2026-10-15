#!/usr/bin/env bash
# Direct libtest executables can exit zero after selecting zero tests. Keep the
# existing streaming logs and timing rows, but require a positive test summary.
run_timed() (
  local name="$1"
  shift
  local started ended status log
  local -a pipeline_status
  log="$(mktemp)" || return 1
  trap 'rm -f -- "$log"' EXIT
  started=$(python3 -c 'import time; print(time.monotonic_ns())')
  set +e
  "$@" 2>&1 | tee "$log"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  status="${pipeline_status[0]}"
  if (( pipeline_status[1] != 0 && status == 0 )); then
    status="${pipeline_status[1]}"
  fi
  if (( status == 0 )) && ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; ' "$log"; then
    printf 'Rust contract %s exited successfully without a passing test summary.\n' "$name" >&2
    status=1
  fi
  ended=$(python3 -c 'import time; print(time.monotonic_ns())')
  printf 'MARTY_CI_PHASE_V1 {"phase":"contract","name":"%s","duration_ms":%s,"status":"%s"}\n' \
    "$name" "$(((ended - started) / 1000000))" "$([[ $status == 0 ]] && echo ok || echo failed)"
  return "$status"
)
