#!/usr/bin/env bash
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
"${executables[0]}" --list | grep -Fx 'worker_startup_matches_published_process_and_idle_heartbeat: test'
"${executables[0]}" --list | grep -Fx 'worker_rest_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_facts_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_after_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_signals_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_final_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_concurrent_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_reclaimers_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_reclaimers_retry_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_reclaimers_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_reclaimers_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_reclaimers_retry_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_reclaimers_retry_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_concurrent_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_concurrent_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_final_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_final_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_signals_match_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_signals_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_facts_match_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_rest_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_rest_native_child: test'
"${executables[0]}" --list | grep -Fx 'operations_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_reads_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_inputs_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_jobs_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_jobs_are_atomic_and_concurrent: test'
"${executables[0]}" --list | grep -Fx 'enqueue_inputs_match_frozen_published_python: test'
"${executables[0]}" --list | grep -Fx 'operations_resolution_matches_corrected_published_schema: test'
"${executables[0]}" --list | grep -Fx 'operations_resolution_fences_and_lifecycle_delegate: test'
"${executables[0]}" --list | grep -Fx 'review_inputs_match_published_python: test'
"${executables[0]}" --list | grep -Fx 'review_lifecycle_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_frozen_protocol: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_credential_and_delivery_effects: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_unicode_failures_and_recovery: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_charset_failures_and_recovery: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_iso2022_failures_and_recovery: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_ordinal_failures_and_recovery: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_utf7_label_failures_and_recovery: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_matches_utf7_full_credential_routes: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_json_consumer_reference: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_matches_json_full_credential_routes: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_json_depth_reference: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_matches_json_depth_full_credential_routes: test'
"${executables[0]}" --list | grep -Fx 'provider_configuration_matches_published_helpers: test'
"${executables[0]}" --list | grep -Fx 'validation_boundary_matches_published_http: test'
"${executables[0]}" --list | grep -Fx 'timeout_consumer_matches_published_socket_behavior: test'
"${executables[0]}" --list | grep -Fx 'utf7_consumer_diagnostic_matches_published_boundaries: test'
"${executables[0]}" --list | grep -Fx 'json_consumer_diagnostic_matches_published_boundaries: test'
"${executables[0]}" --list | grep -Fx 'json_depth_diagnostic_matches_published_boundaries: test'
"${executables[0]}" --list | grep -Fx 'cancelled_pool_release_does_not_wait_for_blocked_query: test'
"${executables[0]}" --nocapture --test-threads=1
