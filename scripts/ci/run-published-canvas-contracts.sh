#!/usr/bin/env bash
set -euo pipefail
export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"
set -euo pipefail
# Reuse the frozen oracle pins, not mutable release tags. The test
# owns a separate tmpfs database; it never receives a deployment URL.
mapfile -t images < <(jq -er '.observed_postgres_image, .observed_image' ../contracts/canvas-worker-consumer-range-oracle.json)
[[ ${#images[@]} == 2 ]]
for image in "${images[@]}"; do
  [[ "$image" =~ ^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$ ]]
  docker pull "$image"
done
mapfile -t executables < <(jq -r '
  select(.reason == "compiler-artifact")
  | select(.package_id | contains("marty-issuance-service"))
  | select(.target.name == "canvas_published_schema_contract")
  | select(.executable != null) | .executable
' "$RUNNER_TEMP/rust-test-artifacts.json" | sort -u)
[[ ${#executables[@]} == 1 && -x "${executables[0]}" ]]
"${executables[0]}" --list | grep -Fx 'heartbeat_readiness_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_reads_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_inputs_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_jobs_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_jobs_are_atomic_and_concurrent: test'
"${executables[0]}" --list | grep -Fx 'enqueue_inputs_match_frozen_published_python: test'
"${executables[0]}" --nocapture --test-threads=1

