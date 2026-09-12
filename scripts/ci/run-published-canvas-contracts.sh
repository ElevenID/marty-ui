#!/usr/bin/env bash
export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"
set -euo pipefail
# A narrow early diagnostic gate supplements, never replaces, the full suite.
# Validate before any image/network work; arbitrary test filters are forbidden.
mode="${1-full}"
if (( $# > 1 )) || [[ "$mode" != full && "$mode" != mixed-roster-preflight && "$mode" != timeout-preflight && "$mode" != body-timeout-preflight && "$mode" != lease-expiry-preflight ]]; then
  echo "Usage: run-published-canvas-contracts.sh [full|timeout-preflight|lease-expiry-preflight|body-timeout-preflight|mixed-roster-preflight]" >&2
  exit 2
fi
preflight_target=""
case "$mode" in
  timeout-preflight) preflight_target=worker_timeout_matches_frozen_published_process ;;
  lease-expiry-preflight) preflight_target=worker_lease_expiry_matches_frozen_published_process ;;
  body-timeout-preflight) preflight_target=worker_body_timeout_matches_frozen_published_process ;;
  mixed-roster-preflight) preflight_target=worker_mixed_roster_matches_frozen_published_process ;;
esac
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
if [[ -n "$preflight_target" ]]; then
  "${executables[0]}" --list | grep -Fx "$preflight_target: test"
  "${executables[0]}" "$preflight_target" --exact --nocapture --test-threads=1
  exit 0
fi
"${executables[0]}" --list | grep -Fx 'heartbeat_readiness_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'worker_startup_matches_published_process_and_idle_heartbeat: test'
"${executables[0]}" --list | grep -Fx 'worker_rest_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_facts_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_after_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_fence_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_fence_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_patch_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_patch_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_retry_after_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_retry_after_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_backoff_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_backoff_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_queue_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_queue_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_repository_selection_matches_published_order: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_lease_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_lease_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_selection_reference_matches_published_repository: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_selection_repository_matches_published: test'
"${executables[0]}" --list | grep -Fx 'worker_validation_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_validation_repository_matches_frozen_errors: test'
"${executables[0]}" --list | grep -Fx 'worker_validation_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_roster_failure_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_roster_failure_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_resource_race_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_resources_unavailable_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_resources_unavailable_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_resource_race_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_resource_race_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_resource_race_repository_preserves_stale_write_fences: test'
"${executables[0]}" --list | grep -Fx 'worker_effect_transaction_obeys_real_database_lease_expiry: test'
"${executables[0]}" --list | grep -Fx 'worker_roster_metadata_reconciliation_preserves_current_fields_and_fences: test'
"${executables[0]}" --list | grep -Fx 'worker_mixed_roster_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_dispatch_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_mixed_roster_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_mixed_roster_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_retry_after_matches_frozen_published_process: test'
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
"${executables[0]}" --list | grep -Fx 'operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes: test'
"${executables[0]}" --list | grep -Fx 'operations_gateway_candidate_preserves_review_lifecycle: test'
"${executables[0]}" --list | grep -Fx 'review_inputs_match_published_python: test'
"${executables[0]}" --list | grep -Fx 'review_lifecycle_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_published_python: test'
"${executables[0]}" --list | grep -Fx 'status_provider_matches_frozen_protocol: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_preserves_credential_and_delivery_effects: test'
"${executables[0]}" --list | grep -Fx 'status_runtime_composes_review_resolution_with_configured_http: test'
"${executables[0]}" --list | grep -Fx 'didcomm_native_composes_crypto_https_and_published_durability: test'
"${executables[0]}" --list | grep -Fx 'didcomm_fresh_http_admission_composes_reservation_and_delivery: test'
"${executables[0]}" --list | grep -Fx 'didcomm_gateway_candidate_preserves_real_delivery_without_legacy_fallback: test'
"${executables[0]}" --list | grep -Fx 'didcomm_transport_reloads_valid_ca_bundles_without_disabling_tls: test'
"${executables[0]}" --list | grep -Fx 'status_main_process_resolves_reviews_with_real_http_publication_and_mirror: test'
"${executables[0]}" --list | grep -Fx 'worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings: test'
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
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_counters_reference_matches_published_cycle: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_counters_matches_frozen_published_cycle: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_secrets_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_secrets_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_secret_reference_constraints_match_published_schema: test'
"${executables[0]}" --list | grep -Fx 'worker_oauth_revocation_empty_token_is_not_dispatched: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_generation_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_generation_preserves_stronger_recovery_fence: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_generation_native_child: test'
"${executables[0]}" --list | grep -Fx 'canvas_worker_provider_recovery_replay::newer_generation_check_rejects_any_target_mutation: test'
"${executables[0]}" --list | grep -Fx 'worker_final_completion_race_has_one_repository_winner: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_completion_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_completion_preserves_atomic_terminal_winner: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_completion_native_child: test'
"${executables[0]}" --list | grep -Fx 'canvas_worker_provider_completion_replay::completion_atomicity_check_rejects_reference_or_target_drift: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_first_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_first_preserves_terminal_winner: test'
"${executables[0]}" --list | grep -Fx 'worker_provider_recovery_first_native_child: test'
"${executables[0]}" --list | grep -Fx 'canvas_worker_provider_completion_replay::rejected_owner_check_rejects_unrelated_or_reference_drift: test'
"${executables[0]}" --list | grep -Fx 'worker_deadline_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_deadline_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_deadline_native_child: test'
"${executables[0]}" --list | grep -Fx 'canvas_published_borrowed_database::outer_database_owner_survives_forced_borrower_exit: test'
"${executables[0]}" --list | grep -Fx 'canvas_published_borrowed_database::borrower_child: test'
"${executables[0]}" --list | grep -Fx 'worker_timeout_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_body_timeout_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_lease_expiry_reference_matches_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_lease_expiry_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_lease_expiry_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_body_timeout_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_body_timeout_native_child: test'
"${executables[0]}" --list | grep -Fx 'worker_timeout_matches_frozen_published_process: test'
"${executables[0]}" --list | grep -Fx 'worker_timeout_native_child: test'
"${executables[0]}" --nocapture --test-threads=1
