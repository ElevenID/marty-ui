#!/usr/bin/env bash
# Direct libtest executables can exit zero after selecting zero tests. Keep the
# existing streaming logs and timing rows, but require a positive test summary.
run_timed_rust_test() (
  local phase="$1" name="$2"
  shift 2
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
    printf 'Rust %s test %s exited successfully without a passing test summary.\n' "$phase" "$name" >&2
    status=1
  fi
  ended=$(python3 -c 'import time; print(time.monotonic_ns())')
  printf 'MARTY_CI_PHASE_V1 {"phase":"%s","name":"%s","duration_ms":%s,"status":"%s"}\n' \
    "$phase" "$name" "$(((ended - started) / 1000000))" "$([[ $status == 0 ]] && echo ok || echo failed)"
  return "$status"
)

run_timed() {
  run_timed_rust_test contract "$@"
}

# The contracts lane compiles these targets once and records Cargo's exact
# executable paths. Do not rediscover hashes in target/debug/deps: old local
# builds can leave extra executables there, and a successful libtest invocation
# alone does not identify which source revision was compiled.
resolve_issuance_canvas_contracts() {
  local artifacts="${RUNNER_TEMP:?RUNNER_TEMP must identify this run}/rust-test-artifacts.json"
  [[ -f "$artifacts" ]] || {
    echo "Missing recorded Rust test artifacts: $artifacts" >&2
    return 1
  }
  local rows name executable
  local -a executables=()
  local -A seen=()
  rows="$(jq -er '
    select(.reason == "compiler-artifact")
    | select(.package_id | contains("#marty-issuance-service@"))
    | select(.target.kind | index("test"))
    | select(
        ((.target.name | startswith("canvas_")) and
         (.target.name | endswith("_postgres_contract"))) or
        .target.name == "proof_nonce_postgres_contract"
      )
    | select(.executable != null)
    | [.target.name, .executable] | @tsv
  ' "$artifacts" | sort -u)" || return 1
  while IFS=$'\t' read -r name executable; do
    [[ -n "$name" && -n "$executable" && -z "${seen[$name]:-}" && -x "$executable" ]] || {
      printf 'Missing, duplicate, or non-executable Issuance PostgreSQL contract: %s\n' "$name" >&2
      return 1
    }
    seen[$name]=1
    executables+=("$executable")
  done <<< "$rows"
  if (( ${#executables[@]} != 11 )) || [[ -z "${seen[proof_nonce_postgres_contract]:-}" ]]; then
    printf 'Expected eleven issuance PostgreSQL contracts (ten Canvas plus proof nonce), found %s.\n' "${#executables[@]}" >&2
    return 1
  fi
  printf '%s\n' "${executables[@]}"
}
