#!/usr/bin/env bash
export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"
set -euo pipefail
timed() {
  local phase="$1" name="$2"
  shift 2
  local started ended status=0
  started=$(python3 -c 'import time; print(time.monotonic_ns())')
  "$@" || status=$?
  ended=$(python3 -c 'import time; print(time.monotonic_ns())')
  printf 'MARTY_CI_PHASE_V1 {"phase":"%s","name":"%s","duration_ms":%s,"status":"%s"}\n' \
    "$phase" "$name" "$(((ended - started) / 1000000))" "$([[ $status == 0 ]] && echo ok || echo failed)"
  return "$status"
}
# A narrow early diagnostic gate precedes the full suite. The two retained
# exact native preflights are omitted later only with same-run evidence for
# this compiled executable. The long mixed-roster/body matrices and their
# pinned historical-process replays remain available through explicit full
# mode, outside routine PR and merge-queue qualification.
# Validate before any image/network work; arbitrary test filters are forbidden.
mode="${1-full}"
if [[ "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" != 0 && "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" != 1 ]]; then
  echo "Invalid Canvas qualification mode" >&2
  exit 2
fi
if (( $# > 1 )) || [[ "$mode" != full && "$mode" != full-after-preflights && "$mode" != mixed-roster-preflight && "$mode" != timeout-preflight && "$mode" != body-timeout-preflight && "$mode" != lease-expiry-preflight && "$mode" != worker-full && "$mode" != worker-full-after-preflights && "$mode" != worker-mixed-roster-preflight && "$mode" != worker-timeout-preflight && "$mode" != worker-body-timeout-preflight && "$mode" != worker-lease-expiry-preflight ]]; then
  echo "Usage: run-published-canvas-contracts.sh [full|full-after-preflights|timeout-preflight|lease-expiry-preflight|body-timeout-preflight|mixed-roster-preflight|worker-full|worker-full-after-preflights|worker-timeout-preflight|worker-lease-expiry-preflight|worker-body-timeout-preflight|worker-mixed-roster-preflight]" >&2
  exit 2
fi
if [[ -v MARTY_CANVAS_WORKER_RETRY_AFTER_TIER ]]; then
  echo "Native Retry-After tier is owned by this runner, not caller environment" >&2
  exit 2
fi
if [[ -v MARTY_CANVAS_WORKER_VALIDATION_TIER ]]; then
  echo "Native validation tier is owned by this runner, not caller environment" >&2
  exit 2
fi
retry_after_tier=full
validation_tier=full
if [[ "$mode" == full-after-preflights && "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" == 0 ]]; then
  retry_after_tier=routine
  validation_tier=routine
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
done
find_executable() {
  local target="$1"
  local package
  case "$target" in
    canvas_published_schema_contract) package=marty-canvas-acceptance ;;
    flow_published_schema_contract) package=marty-flow-acceptance ;;
    canvas_published_worker_contract) package=marty-canvas-worker-acceptance ;;
    selfhost_public_image_contract) package=marty-selfhost-acceptance ;;
    *) echo "Unknown Canvas contract target: $target" >&2; return 1 ;;
  esac
  local -a matches=()
  mapfile -t matches < <(jq -r --arg target "$target" --arg package "$package" '
    select(.reason == "compiler-artifact")
    | select(.package_id | contains("#" + $package + "@"))
    | select(.target.name == $target)
    | select(.executable != null) | .executable
  ' "$RUNNER_TEMP/rust-test-artifacts.json" | sort -u)
  [[ ${#matches[@]} == 1 && -x "${matches[0]}" ]] || {
    echo "Expected one executable for $target" >&2
    return 1
  }
  printf '%s\n' "${matches[0]}"
}
find_issuance_package_binary() {
  local target="$1"
  local -a matches=()
  local output
  output=$(jq -r --arg target "$target" '
    select(.reason == "compiler-artifact")
    | select(.package_id | contains("#marty-issuance-service@"))
    | select(.target.name == $target)
    | select(.target.kind | index("bin"))
    | select(.profile.test == false)
    | select(.executable != null) | .executable
  ' "$RUNNER_TEMP/rust-test-artifacts.json" | sort -u) || return 1
  if [[ -n "$output" ]]; then
    mapfile -t matches <<< "$output"
  fi
  [[ ${#matches[@]} == 1 && "${matches[0]}" == /* && -x "${matches[0]}" ]] || {
    echo "Expected one real $target binary artifact (found ${#matches[@]})" >&2
    return 1
  }
  printf '%s\n' "${matches[0]}"
}
# Opt-in diagnostic owner. No current CI selector invokes these modes; the
# default and existing full/preflight paths below retain their original order.
# This branch never loads composition, Gateway, Flow or the public selfhost
# image. It still runs the same compiled worker target against the same pinned
# published process/database and verifies the existing run-bound preflight.
if [[ "$mode" == worker-* ]]; then
  worker_mode="${mode#worker-}"
  worker_executable=$(find_executable canvas_published_worker_contract)
  worker_binary=$(find_issuance_package_binary marty-canvas-sync-worker)
  export MARTY_CANVAS_WORKER_TEST_BINARY="$worker_binary"
  worker_tests=$("$worker_executable" --list)
  printf '%s\n' "$worker_tests" | python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py"
  pull_worker_images() {
    local image
    for image in "${images[@]}"; do
      if [[ "$image" == "${images[0]}" ]]; then
        timed image_pull postgres docker pull "$image"
      else
        timed image_pull published_probe docker pull "$image"
      fi
    done
  }
  worker_preflight_target=""
  case "$worker_mode" in
    timeout-preflight) worker_preflight_target=worker_timeout_matches_frozen_published_process ;;
    lease-expiry-preflight) worker_preflight_target=worker_lease_expiry_matches_frozen_published_process ;;
    body-timeout-preflight) worker_preflight_target=worker_body_timeout_matches_frozen_published_process ;;
    mixed-roster-preflight) worker_preflight_target=worker_mixed_roster_matches_frozen_published_process ;;
  esac
  if [[ -n "$worker_preflight_target" ]]; then
    printf '%s\n' "$worker_tests" | grep -Fx "$worker_preflight_target: test"
    pull_worker_images
    timed canvas_serial "$worker_mode" "$worker_executable" "$worker_preflight_target" --exact --nocapture --test-threads=1
    exit 0
  fi
  worker_preflight_skips=()
  expected_worker_skips=0
  worker_retry_tier=full
  worker_validation_tier=full
  if [[ "$worker_mode" == full-after-preflights ]]; then
    evidence="${RUNNER_TEMP:?}/canvas-published-preflights.sha256"
    [[ -f "$evidence" ]] || { echo "Missing Canvas preflight evidence" >&2; exit 1; }
    mapfile -t proof < "$evidence"
    [[ ${#proof[@]} == 5 && "${proof[0]}" =~ ^[a-f0-9]{64}$ &&
      "${proof[0]}" == "$(sha256sum "$worker_executable" | cut -d' ' -f1)" &&
      "${proof[1]}" == "${GITHUB_RUN_ID:?}" &&
      "${proof[2]}" == "${GITHUB_RUN_ATTEMPT:?}" &&
      "${proof[3]}" == "${GITHUB_JOB:?}" &&
      "${proof[4]}" == "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" ]] || {
      echo "Canvas preflight evidence does not match this CI run and executable" >&2
      exit 1
    }
    worker_preflight_skips=(
      --skip worker_mixed_roster_matches_frozen_published_process
      --skip worker_body_timeout_matches_frozen_published_process
      --skip worker_timeout_matches_frozen_published_process
      --skip worker_lease_expiry_matches_frozen_published_process
    )
    expected_worker_skips=4
    if [[ "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" == 0 ]]; then
      worker_preflight_skips+=(--skip reference_matches_published)
      expected_worker_skips=37
      worker_retry_tier=routine
      worker_validation_tier=routine
    fi
  fi
  worker_serial_test=worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings
  printf '%s\n' "$worker_tests" | grep -Fx "$worker_serial_test: test"
  worker_parallel_list=$("$worker_executable" --list --skip "$worker_serial_test" "${worker_preflight_skips[@]}")
  printf '%s\0%s\n' "$worker_tests" "$worker_parallel_list" | python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" --selected "$worker_mode" "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" "$worker_serial_test"
  worker_all=$(printf '%s\n' "$worker_tests" | grep -c ': test$')
  worker_parallel=$(printf '%s\n' "$worker_parallel_list" | grep -c ': test$')
  [[ $((worker_all - worker_parallel)) == $((1 + expected_worker_skips)) ]]
  pull_worker_images
  timed canvas_serial sql_logging "$worker_executable" "$worker_serial_test" --exact --nocapture --test-threads=1
  worker_log=$(mktemp "${RUNNER_TEMP:?}/canvas-worker-only.XXXXXX")
  trap 'rm -f -- "$worker_log"' EXIT
  timed canvas_target worker env MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$worker_retry_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$worker_validation_tier" "$worker_executable" --skip "$worker_serial_test" "${worker_preflight_skips[@]}" --nocapture --test-threads=4 2>&1 | tee "$worker_log"
  python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" --require-execution canvas "$worker_log"
  exit 0
fi
composition_executable=$(find_executable canvas_published_schema_contract)
worker_executable=$(find_executable canvas_published_worker_contract)
config_skips=()
expected_skipped_config_tests=0
timeout_skips=()
expected_skipped_timeout_tests=0
# The historical HTTPX socket corpus is release evidence. Routine CI proves
# our timeout handling below HTTP and keeps one real native TLS timeout case;
# an exact-main full CI run is mandatory before any stable stack tag claim.
if [[ "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" == 0 && "$mode" == full-after-preflights ]]; then
  timeout_skips=(--skip timeout_consumer_matches_published_socket_behavior)
  expected_skipped_timeout_tests=1
fi
# The early image-free proof is tied to this composition executable, not the
# independently compiled worker preflight executable. Missing/stale proof
# keeps the ordinary full composition run and its completion-marker checks.
if python3 "$(dirname "${BASH_SOURCE[0]}")/run-canvas-config-proofs.py" verify "$composition_executable"; then
  config_skips=(
    --skip rendered_base_process::rendered_base_renewal_config_crosses_encryption_and_private_address_policy
    --skip resolved_kubernetes_runtime::resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy
  )
  expected_skipped_config_tests=2
fi
worker_binary=$(find_issuance_package_binary marty-canvas-sync-worker)
issuance_binary=$(find_issuance_package_binary marty-issuance-service)
export MARTY_CANVAS_WORKER_TEST_BINARY="$worker_binary"
export MARTY_ISSUANCE_TEST_BINARY="$issuance_binary"
composition_tests=$("$composition_executable" --list)
worker_tests=$("$worker_executable" --list)
selfhost_tests=''
if [[ -z "$preflight_target" ]]; then
  selfhost_executable=$(find_executable selfhost_public_image_contract)
  selfhost_tests=$("$selfhost_executable" --list)
  expected_selfhost_tests=$(printf '%s\n' \
  'packaged_remote_secret_fixture_requires_verified_https: test' \
  'selfhost_public_image_loader_isolated: test' \
  'selfhost_public_image_loader_child: test' \
  'selfhost_packaged_runtime::tests::child_stage_diagnostic_accepts_only_closed_values: test' \
  'selfhost_packaged_runtime::tests::database_authentication_failure_never_qualifies_as_healthy: test' \
  'selfhost_packaged_runtime::tests::process_control_child: test' \
  'selfhost_packaged_runtime::tests::host_timeout_and_abrupt_exit_preserve_inputs_until_verified_recovery: test' \
  'selfhost_packaged_runtime::tests::cleanup_failure_retains_scratch_and_original_failure: test' \
  'selfhost_packaged_runtime::tests::held_pending_operation_withholds_recovery_and_retains_scratch: test' \
  'selfhost_packaged_runtime::tests::synthetic_secret_inputs_cover_packaged_issuance_mounts: test' \
  'selfhost_runtime_sidecar::recovery_tests::pending_operation_record_is_exclusive_validated_and_explicitly_completed: test' \
  'selfhost_runtime_sidecar::recovery_tests::exact_parent_native_recovery_refuses_foreign_identity_and_mounts: test')
  [[ "$(printf '%s\n' "$selfhost_tests" | grep ': test$' | LC_ALL=C sort)" == "$(printf '%s\n' "$expected_selfhost_tests" | LC_ALL=C sort)" ]] || {
    echo 'Selfhost executable changed its exact twelve-case owner inventory' >&2
    exit 1
  }
fi
printf '%s\n' "$composition_tests" | grep -Fx 'rendered_base_process::rendered_base_renewal_config_crosses_encryption_and_private_address_policy: test'
if [[ -z "$preflight_target" ]]; then
  printf '%s\n' "$worker_tests" | python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py"
fi
preflight_skips=()
expected_skipped_worker_tests=0
if [[ "$mode" == full-after-preflights ]]; then
  evidence="${RUNNER_TEMP:?}/canvas-published-preflights.sha256"
  [[ -f "$evidence" ]] || { echo "Missing Canvas preflight evidence" >&2; exit 1; }
  mapfile -t proof < "$evidence"
  [[ ${#proof[@]} == 5 && "${proof[0]}" =~ ^[a-f0-9]{64}$ &&
    "${proof[0]}" == "$(sha256sum "$worker_executable" | cut -d' ' -f1)" &&
    "${proof[1]}" == "${GITHUB_RUN_ID:?}" &&
    "${proof[2]}" == "${GITHUB_RUN_ATTEMPT:?}" &&
    "${proof[3]}" == "${GITHUB_JOB:?}" &&
    "${proof[4]}" == "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" ]] || {
    echo "Canvas preflight evidence does not match this CI run and executable" >&2
    exit 1
  }
  if [[ "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" == 1 ]]; then
    # Manual qualification ran all four exact native preflights in this run.
    # Historical references remain in the following full worker target.
    preflight_skips=(
      --skip worker_mixed_roster_matches_frozen_published_process
      --skip worker_body_timeout_matches_frozen_published_process
      --skip worker_timeout_matches_frozen_published_process
      --skip worker_lease_expiry_matches_frozen_published_process
    )
    expected_skipped_worker_tests=4
  else
    # Routine feedback keeps the owned worker timeout/lease preflights but
    # avoids repeating the two long scenario matrices and pinned old process.
    preflight_skips=(
      --skip worker_mixed_roster_matches_frozen_published_process
      --skip worker_body_timeout_matches_frozen_published_process
      --skip worker_timeout_matches_frozen_published_process
      --skip worker_lease_expiry_matches_frozen_published_process
      --skip reference_matches_published
    )
    # All 33 historical process/repository/cycle replays are available in
    # manual qualification, not the PR and merge-queue critical path. A new
    # replay changes this count and must be deliberately classified.
    expected_skipped_worker_tests=37
  fi
fi
pull_images() {
  local image
  for image in "${images[@]}"; do
    # Stable ordinal only: never put an image reference in timing evidence.
    if [[ "$image" == "${images[0]}" ]]; then
      timed image_pull postgres docker pull "$image"
    else
      timed image_pull published_probe docker pull "$image"
    fi
  done
}
if [[ -n "$preflight_target" ]]; then
  printf '%s\n' "$worker_tests" | grep -Fx "$preflight_target: test"
  pull_images
  timed canvas_serial "$mode" "$worker_executable" "$preflight_target" --exact --nocapture --test-threads=1
  exit 0
fi
flow_executable=$(find_executable flow_published_schema_contract)
flow_tests=$("$flow_executable" --list)
expected_flow_tests=$(printf '%s\n' \
  'didcomm_flow_grpc_provider_preserves_keyed_admission: test' \
  'flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http: test' \
  'flow_rendered_provider_child: test' \
  'flow_actual_main_boots_rendered_base_and_preserves_public_admission: test' \
  'flow_rendered_settings_select_native_rpc_and_preserve_legacy_http: test' \
  'didcomm_http_admission_recovers_real_keyed_reservation: test' \
  'didcomm_admission_recovery::flow_consumer::public_startup::loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn: test' \
  'didcomm_admission_recovery::flow_consumer::public_startup::owned_output_child: test' \
  'didcomm_admission_recovery::flow_consumer::public_startup::owned_process_output_and_early_exit_cleanup_are_verified: test')
[[ "$(printf '%s\n' "$flow_tests" | grep ': test$' | LC_ALL=C sort)" == "$(printf '%s\n' "$expected_flow_tests" | LC_ALL=C sort)" ]] || {
  echo 'Flow executable changed its exact nine-case owner inventory' >&2
  exit 1
}
all_test_names=$(printf '%s\n%s\n%s\n%s\n' "$composition_tests" "$flow_tests" "$worker_tests" "$selfhost_tests" | grep ': test$')
[[ -z $(printf '%s\n' "$all_test_names" | sort | uniq -d) ]] || {
  echo 'Duplicate Canvas test names across executables' >&2
  exit 1
}
pull_images
printf '%s\n' "$all_test_names" | grep -Fx 'heartbeat_readiness_matches_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'base_profile_native_renewal_uses_actual_rendered_configuration: test'
printf '%s\n' "$all_test_names" | grep -Fx 'base_profile_gateway_composition_isolated: test'
printf '%s\n' "$all_test_names" | grep -Fx 'base_profile_gateway_composition_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'selfhost_public_image_loader_isolated: test'
printf '%s\n' "$all_test_names" | grep -Fx 'selfhost_public_image_loader_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'kubernetes_resolved_native_profile_delivers_both_encryption_modes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'kubernetes_profile_gateway_composition_isolated: test'
printf '%s\n' "$all_test_names" | grep -Fx 'kubernetes_profile_gateway_composition_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'resolved_kubernetes_runtime::prepared_cleanup_retains_modified_bytes_until_exact_owned_content_is_restored: test'
printf '%s\n' "$all_test_names" | grep -Fx 'base_profile_envoy_composition_isolated: test'
printf '%s\n' "$all_test_names" | grep -Fx 'base_profile_envoy_composition_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'envoy_actual_image_validates_candidate: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_startup_matches_published_process_and_idle_heartbeat: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_rest_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_facts_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_retry_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_retry_after_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_fence_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_fence_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_patch_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_patch_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_retry_after_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_retry_after_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_backoff_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_backoff_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_queue_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_queue_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_repository_selection_matches_published_order: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_lease_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_lease_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_selection_reference_matches_published_repository: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_selection_repository_matches_published: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_validation_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_validation_repository_matches_frozen_errors: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_validation_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_roster_failure_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_roster_failure_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_resource_race_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_resources_unavailable_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_resources_unavailable_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_resource_race_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_resource_race_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_resource_race_repository_preserves_stale_write_fences: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_effect_transaction_obeys_real_database_lease_expiry: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_roster_metadata_reconciliation_preserves_current_fields_and_fences: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_roster_metadata_expired_before_write_preserves_current_fields_and_fences: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_roster_metadata_expired_during_lock_preserves_current_fields_and_fences: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_mixed_roster_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_dispatch_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_mixed_roster_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_mixed_roster_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_retry_after_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_signals_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_final_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_concurrent_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_reclaimers_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_reclaimers_retry_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_reclaimers_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_reclaimers_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_reclaimers_retry_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_reclaimers_retry_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_concurrent_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_concurrent_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_final_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_final_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_signals_match_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_signals_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_retry_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_facts_match_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_rest_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_rest_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_match_frozen_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_reads_match_frozen_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_inputs_match_frozen_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_jobs_match_frozen_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_jobs_are_atomic_and_concurrent: test'
printf '%s\n' "$all_test_names" | grep -Fx 'enqueue_inputs_match_frozen_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_resolution_matches_corrected_published_schema: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_resolution_fences_and_lifecycle_delegate: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'operations_gateway_candidate_preserves_review_lifecycle: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_base_review_gateway_matches_corrected_published_schema: test'
printf '%s\n' "$all_test_names" | grep -Fx 'review_inputs_match_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'review_lifecycle_matches_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_provider_matches_published_python: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_provider_matches_frozen_protocol: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_credential_and_delivery_effects: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_composes_review_resolution_with_configured_http: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_native_composes_crypto_https_and_published_durability: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_fresh_http_admission_composes_reservation_and_delivery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'renewal_postgres_binding_and_same_successor_recovery_are_fenced: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_renewal_http_composes_real_delivery_and_renewal_links: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_renewal_private_ip_refusal_preserves_published_rows: test'
printf '%s\n' "$all_test_names" | grep -Fx 'resolved_kubernetes_runtime::resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy: test'
printf '%s\n' "$all_test_names" | grep -Fx 'renewal_fresh_packaged_main_delivers_both_encryption_modes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'renewal_packaged_main_recovers_historical_keyed_offer: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_renewal_gateway_selects_native_with_required_owner_read: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_renewal_canvas_preserves_real_association_and_delivery_phases: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_unkeyed_grpc_initiation_composes_real_delivery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_historical_keyed_http_recovers_before_fresh_admission_guard: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_fresh_gateway_admission_preserves_public_projection_without_legacy_fallback: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_gateway_candidate_preserves_real_delivery_without_legacy_fallback: test'
printf '%s\n' "$all_test_names" | grep -Fx 'didcomm_transport_reloads_valid_ca_bundles_without_disabling_tls: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_main_process_resolves_reviews_with_real_http_publication_and_mirror: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_unicode_failures_and_recovery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_charset_failures_and_recovery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_iso2022_failures_and_recovery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_ordinal_failures_and_recovery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_preserves_utf7_label_failures_and_recovery: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_matches_utf7_full_credential_routes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_provider_matches_json_consumer_reference: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_matches_json_full_credential_routes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_provider_matches_json_depth_reference: test'
printf '%s\n' "$all_test_names" | grep -Fx 'status_runtime_matches_json_depth_full_credential_routes: test'
printf '%s\n' "$all_test_names" | grep -Fx 'provider_configuration_matches_published_helpers: test'
printf '%s\n' "$all_test_names" | grep -Fx 'validation_boundary_matches_published_http: test'
printf '%s\n' "$all_test_names" | grep -Fx 'timeout_consumer_matches_published_socket_behavior: test'
printf '%s\n' "$all_test_names" | grep -Fx 'utf7_consumer_diagnostic_matches_published_boundaries: test'
printf '%s\n' "$all_test_names" | grep -Fx 'json_consumer_diagnostic_matches_published_boundaries: test'
printf '%s\n' "$all_test_names" | grep -Fx 'json_depth_diagnostic_matches_published_boundaries: test'
printf '%s\n' "$all_test_names" | grep -Fx 'cancelled_pool_release_does_not_wait_for_blocked_query: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_counters_reference_matches_published_cycle: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_counters_matches_frozen_published_cycle: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_secrets_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_secrets_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_secret_reference_constraints_match_published_schema: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_oauth_revocation_empty_token_is_not_dispatched: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_generation_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_generation_preserves_stronger_recovery_fence: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_generation_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_worker_provider_recovery_replay::newer_generation_check_rejects_any_target_mutation: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_final_completion_race_has_one_repository_winner: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_completion_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_completion_preserves_atomic_terminal_winner: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_completion_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_worker_provider_completion_replay::completion_atomicity_check_rejects_reference_or_target_drift: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_first_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_first_preserves_terminal_winner: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_provider_recovery_first_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_worker_provider_completion_replay::rejected_owner_check_rejects_unrelated_or_reference_drift: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_deadline_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_deadline_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_deadline_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_published_borrowed_database::outer_database_owner_survives_forced_borrower_exit: test'
printf '%s\n' "$all_test_names" | grep -Fx 'canvas_published_borrowed_database::borrower_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_timeout_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_body_timeout_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_lease_expiry_reference_matches_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_lease_expiry_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_lease_expiry_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_body_timeout_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_body_timeout_native_child: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_timeout_matches_frozen_published_process: test'
printf '%s\n' "$all_test_names" | grep -Fx 'worker_timeout_native_child: test'
# This diagnostic captures SQLx events through a scoped subscriber. Run it on
# its own so unrelated test threads cannot affect the positive control.
serial_test=worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings
printf '%s\n' "$worker_tests" | grep -Fx "$serial_test: test"
serial_composition_test=json_consumer_diagnostic_matches_published_boundaries
printf '%s\n' "$composition_tests" | grep -Fx "$serial_composition_test: test"
all_tests=$(printf '%s\n' "$all_test_names" | grep -c ': test$')
composition_parallel_tests=$("$composition_executable" --list --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" | grep -c ': test$')
flow_parallel_tests=$(printf '%s\n' "$flow_tests" | grep -c ': test$')
worker_parallel_list=$("$worker_executable" --list --skip "$serial_test" "${preflight_skips[@]}")
worker_parallel_tests=$(printf '%s\n' "$worker_parallel_list" | grep -c ': test$')
selfhost_parallel_tests=$(printf '%s\n' "$selfhost_tests" | grep -c ': test$')
printf '%s\0%s\n' "$worker_tests" "$worker_parallel_list" | python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" --selected "$mode" "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" "$serial_test"
parallel_tests=$((composition_parallel_tests + flow_parallel_tests + worker_parallel_tests + selfhost_parallel_tests))
[[ $((all_tests - parallel_tests)) == $((2 + expected_skipped_worker_tests + expected_skipped_config_tests + expected_skipped_timeout_tests)) ]]
timed canvas_serial sql_logging "$worker_executable" "$serial_test" --exact --nocapture --test-threads=1
# The packaged renewal cases need an actual non-exportable X25519 sender. Keep
# root authority in this acceptance process; the native binary gets only the
# exact-version read/pack token file provisioned by the Rust fixture.
kms_config=$(mktemp "${RUNNER_TEMP:?}/canvas-kms.XXXXXX")
chmod 600 "$kms_config"
kms_container=""
kms_owner_pid=$BASHPID
cleanup_canvas_kms() {
  [[ $BASHPID == "$kms_owner_pid" ]] || return 0
  if [[ -n "$kms_container" ]]; then
    docker rm -f "$kms_container" >/dev/null 2>&1 || true
    kms_container=""
  fi
  rm -f -- "$kms_config"
}
trap cleanup_canvas_kms EXIT
python3 "$(dirname "${BASH_SOURCE[0]}")/start-canvas-didcomm-openbao.py" > "$kms_config"
kms_container=$(jq -er '.container' "$kms_config")
kms_url=$(jq -er '.url' "$kms_config")
kms_root_token=$(jq -er '.root_token' "$kms_config")
[[ "$kms_container" =~ ^canvas-kms-[a-f0-9]{12}$ ]]
[[ "$kms_url" =~ ^http://127\.0\.0\.1:[0-9]+$ ]]
[[ "$kms_root_token" =~ ^[a-f0-9]{32}$ ]]
scoped_signer_test='issuance_named_peers::kms_tests::scoped_transit_signer_verifies_without_key_read_authority'
"$composition_executable" --list --ignored | grep -Fx "$scoped_signer_test: test"
timed canvas_serial kms_scoped_signer env MARTY_CANVAS_OPENBAO_URL="$kms_url" MARTY_CANVAS_OPENBAO_ROOT_TOKEN="$kms_root_token" "$composition_executable" "$scoped_signer_test" --ignored --exact --nocapture --test-threads=1
# This published-process probe covers the full frozen JSON corpus and has a
# fixed 120-second deadline. Keep other Canvas tests off this runner while it
# runs; contention must not turn its contract into an intermittent timeout.
timed canvas_serial json_consumer env MARTY_CANVAS_OPENBAO_URL="$kms_url" MARTY_CANVAS_OPENBAO_ROOT_TOKEN="$kms_root_token" "$composition_executable" "$serial_composition_test" --exact --nocapture --test-threads=1
# Each target owns its disposable database and process fixtures. Keep their
# output separate, normally wait for all owners to finish cleanup, and fail
# if any suite fails. The serial SQL-logging positive control stays outside
# the parallel group. Forced cancellation still has the runner's usual teardown limits.
target_logs=$(mktemp -d "${RUNNER_TEMP:?}/canvas-targets.XXXXXX")
composition_log="$target_logs/composition.log"
flow_log="$target_logs/flow.log"
worker_log="$target_logs/worker.log"
selfhost_log="$target_logs/selfhost.log"
composition_end="$target_logs/composition.end"
flow_end="$target_logs/flow.end"
worker_end="$target_logs/worker.end"
selfhost_end="$target_logs/selfhost.end"
cleanup_target_logs() {
  [[ $BASHPID == "$kms_owner_pid" ]] || return 0
  cleanup_canvas_kms
  rm -f -- "$composition_log" "$flow_log" "$worker_log" "$selfhost_log" "$composition_end" "$flow_end" "$worker_end" "$selfhost_end"
  rmdir -- "$target_logs"
}
trap cleanup_target_logs EXIT
# A background child's redirection may not create its log before the relay
# starts. Create all log files after registering owned cleanup and before any
# tail follows one, so a scheduling race cannot drop that target's phase rows.
: > "$composition_log"
: > "$flow_log"
: > "$worker_log"
: > "$selfhost_log"
relay_target_timing() {
  local pid="$1" log="$2" end_file="$3"
  # This observer cannot own or obscure the Rust child exit status. Its
  # completion clock has at most the 100 ms tail polling resolution.
  if ( set -o pipefail; tail --pid="$pid" --sleep-interval=0.1 -n +1 -f "$log" | sed -u -n '/^MARTY_CI_PHASE_V1 /p' ); then
    python3 -c 'import time; print(time.monotonic_ns())' >"$end_file"
  fi
}
selfhost_started=$(python3 -c 'import time; print(time.monotonic_ns())')
"$selfhost_executable" --nocapture --test-threads=4 >"$selfhost_log" 2>&1 &
selfhost_pid=$!
relay_target_timing "$selfhost_pid" "$selfhost_log" "$selfhost_end" &
selfhost_relay_pid=$!
composition_started=$(python3 -c 'import time; print(time.monotonic_ns())')
MARTY_CANVAS_OPENBAO_URL="$kms_url" MARTY_CANVAS_OPENBAO_ROOT_TOKEN="$kms_root_token" "$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4 >"$composition_log" 2>&1 &
composition_pid=$!
relay_target_timing "$composition_pid" "$composition_log" "$composition_end" &
composition_relay_pid=$!
flow_started=$(python3 -c 'import time; print(time.monotonic_ns())')
"$flow_executable" --nocapture --test-threads=4 >"$flow_log" 2>&1 &
flow_pid=$!
relay_target_timing "$flow_pid" "$flow_log" "$flow_end" &
flow_relay_pid=$!
worker_started=$(python3 -c 'import time; print(time.monotonic_ns())')
MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" "$worker_executable" --skip "$serial_test" "${preflight_skips[@]}" --nocapture --test-threads=4 >"$worker_log" 2>&1 &
worker_pid=$!
relay_target_timing "$worker_pid" "$worker_log" "$worker_end" &
worker_relay_pid=$!
report_target_timing() {
  local name="$1" started="$2" status="$3" end_file="$4" ended
  if [[ ! -s "$end_file" ]]; then
    echo "Optional Canvas target timing unavailable for $name" >&2
    return 0
  fi
  ended=$(<"$end_file")
  if [[ ! "$ended" =~ ^[0-9]+$ ]]; then
    echo "Optional Canvas target timing malformed for $name" >&2
    return 0
  fi
  printf 'MARTY_CI_PHASE_V1 {"phase":"canvas_target","name":"%s","duration_ms":%s,"status":"%s"}\n' \
    "$name" "$(((ended - started) / 1000000))" "$([[ $status == 0 ]] && echo ok || echo failed)"
}
drain_target_relays() {
  # Relays observe only the exact Rust child PIDs; they never own cancellation
  # or gate status. Drain before deleting the complete raw diagnostic logs.
  wait "$composition_relay_pid" || true
  wait "$flow_relay_pid" || true
  wait "$worker_relay_pid" || true
  wait "$selfhost_relay_pid" || true
}
report_target_logs() {
  printf 'Canvas composition target exit: %s\n' "$1"
  # Phase records were relayed live. Keep the complete diagnostic text in the
  # final replay without presenting those same lines as fresh timing events.
  sed 's/^MARTY_CI_PHASE_V1 /[raw-log] MARTY_CI_PHASE_V1 /' "$composition_log"
  printf 'Flow target exit: %s\n' "$4"
  sed 's/^MARTY_CI_PHASE_V1 /[raw-log] MARTY_CI_PHASE_V1 /' "$flow_log"
  printf 'Canvas worker target exit: %s\n' "$2"
  sed 's/^MARTY_CI_PHASE_V1 /[raw-log] MARTY_CI_PHASE_V1 /' "$worker_log"
  printf 'Selfhost target exit: %s\n' "$3"
  sed 's/^MARTY_CI_PHASE_V1 /[raw-log] MARTY_CI_PHASE_V1 /' "$selfhost_log"
}
stop_targets() {
  local composition_stopped=0 flow_stopped=0 worker_stopped=0 selfhost_stopped=0
  trap - INT TERM
  kill "$composition_pid" "$flow_pid" "$worker_pid" "$selfhost_pid" 2>/dev/null || true
  wait "$composition_pid" 2>/dev/null || composition_stopped=$?
  wait "$flow_pid" 2>/dev/null || flow_stopped=$?
  wait "$worker_pid" 2>/dev/null || worker_stopped=$?
  wait "$selfhost_pid" 2>/dev/null || selfhost_stopped=$?
  drain_target_relays
  report_target_timing composition "$composition_started" "$composition_stopped" "$composition_end"
  report_target_timing flow "$flow_started" "$flow_stopped" "$flow_end"
  report_target_timing worker "$worker_started" "$worker_stopped" "$worker_end"
  report_target_timing selfhost "$selfhost_started" "$selfhost_stopped" "$selfhost_end"
  report_target_logs "$composition_stopped" "$worker_stopped" "$selfhost_stopped" "$flow_stopped"
  exit "$1"
}
trap 'stop_targets 130' INT
trap 'stop_targets 143' TERM
composition_status=0
flow_status=0
worker_status=0
selfhost_status=0
wait "$composition_pid" || composition_status=$?
wait "$flow_pid" || flow_status=$?
wait "$worker_pid" || worker_status=$?
wait "$selfhost_pid" || selfhost_status=$?
drain_target_relays
report_target_timing composition "$composition_started" "$composition_status" "$composition_end"
report_target_timing flow "$flow_started" "$flow_status" "$flow_end"
report_target_timing worker "$worker_started" "$worker_status" "$worker_end"
report_target_timing selfhost "$selfhost_started" "$selfhost_status" "$selfhost_end"
report_target_logs "$composition_status" "$worker_status" "$selfhost_status" "$flow_status"
(( composition_status == 0 && flow_status == 0 && worker_status == 0 && selfhost_status == 0 ))
timeout_completions=$(grep -Fo 'PUBLISHED_TIMEOUT_CONSUMER_COMPLETE_V1' "$composition_log" | wc -l || true)
[[ "$timeout_completions" == "$((1 - expected_skipped_timeout_tests))" ]] || {
  echo 'Published HTTPX timeout reference did not match the selected qualification tier' >&2
  exit 1
}
if (( expected_skipped_config_tests == 0 )); then
  [[ $(grep -Fo 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1' "$composition_log" | wc -l) == 1 ]] || {
    echo 'Rendered-base renewal 2x2 configuration proof did not execute and complete exactly once' >&2
    exit 1
  }
  [[ $(grep -Fo 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1' "$composition_log" | wc -l) == 1 ]] || {
    echo 'Resolved Kubernetes renewal 2x2 configuration proof did not execute and complete exactly once' >&2
    exit 1
  }
else
  # A test running despite an authorized skip is not the selected full suite.
  [[ $(grep -Fo 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1' "$composition_log" | wc -l) == 0 ]]
  [[ $(grep -Fo 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1' "$composition_log" | wc -l) == 0 ]]
fi
[[ $(grep -Fo 'DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1' "$composition_log" | wc -l) == 1 ]] || {
  echo 'Published-SQL renewal private-IP refusal proof did not execute and complete exactly once' >&2
  exit 1
}
python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" --require-execution canvas "$worker_log"
