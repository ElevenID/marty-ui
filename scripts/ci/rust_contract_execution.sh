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
  if (( status == 0 )) && ! python3 "$(dirname "${BASH_SOURCE[0]}")/native_execution_policy.py" positive-summary "$log"; then
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

# Select exactly one test executable from this job's Cargo compiler output.
# Target names alone are not unique across packages (e.g. migration_contract).
resolve_recorded_contract_executable() {
  local package="$1" target="$2"
  local artifacts="${RUNNER_TEMP:?RUNNER_TEMP must identify this run}/rust-test-artifacts.json"
  [[ -f "$artifacts" ]] || {
    printf 'Missing recorded Rust test artifacts: %s\n' "$artifacts" >&2
    return 1
  }
  local paths executable
  paths="$(jq -er --arg package "#$package@" --arg target "$target" '
    select(.reason == "compiler-artifact")
    | select(.package_id | contains($package))
    | select(.target.kind | index("test"))
    | select(.target.name == $target)
    | select(.executable != null)
    | .executable
  ' "$artifacts" | sort -u)" || return 1
  if [[ -z "$paths" || "$paths" == *$'\n'* || ! -x "$paths" ]]; then
    printf 'Expected one executable for %s/%s in this Cargo build.\n' "$package" "$target" >&2
    return 1
  fi
  executable="$paths"
  printf '%s\n' "$executable"
}

# The contracts lane compiles these targets once and records Cargo's exact
# executable paths. Do not rediscover hashes in target/debug/deps: old local
# builds can leave extra executables there, and a successful libtest invocation
# alone does not identify which source revision was compiled.
resolve_issuance_database_contracts() {
  resolve_recorded_contract_executable marty-issuance-service proof_nonce_postgres_contract
}
