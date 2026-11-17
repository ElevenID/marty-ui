#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/rust_contract_execution.sh"
require_selfhost_tests() {
  local actual="$1" expected
  expected=$(printf '%s\n' \
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
  'selfhost_runtime_sidecar::recovery_tests::exact_parent_native_recovery_refuses_foreign_identity_and_mounts: test' \
  'selfhost_runtime_sidecar::recovery_tests::log_boundary_distinguishes_missing_markers_from_secret_exposure: test' \
  'selfhost_runtime_sidecar::recovery_tests::log_boundary_retries_only_delayed_markers_with_decreasing_read_budget: test' \
  'selfhost_runtime_sidecar::recovery_tests::log_boundary_rejects_leaks_invalid_utf8_and_docker_errors_without_retry: test' \
  'selfhost_runtime_sidecar::recovery_tests::log_boundary_rejects_empty_secret_and_zero_budget_before_reading: test' \
  'selfhost_runtime_sidecar::recovery_tests::log_boundary_does_not_accept_late_success_or_read_again_after_expiry: test')
  [[ "$(printf '%s\n' "$actual" | grep ': test$' | LC_ALL=C sort)" == "$(printf '%s\n' "$expected" | LC_ALL=C sort)" ]] || {
    echo 'Selfhost executable changed its exact seventeen-case owner inventory' >&2
    return 1
  }
}
selfhost_executable=$(resolve_recorded_contract_executable marty-selfhost-acceptance selfhost_public_image_contract)
require_selfhost_tests "$("$selfhost_executable" --list)"
[[ "${MARTY_SELFHOST_TEST_IMAGE:?}" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "${MARTY_SELFHOST_TEST_REVISION:?}" =~ ^[a-f0-9]{40}$ ]]
test -x "${MARTY_SELFHOST_TEST_PACKAGER_BINARY:?}"
test -x "${MARTY_SELFHOST_BUNDLE_TEST_COMPOSE:?}"
[[ "$(docker image inspect --format '{{.Id}}' "$MARTY_SELFHOST_TEST_IMAGE")" == "$MARTY_SELFHOST_TEST_IMAGE" ]]
postgres_image=$(jq -er '.postgres' ../contracts/platform-test-database.json)
[[ "$postgres_image" =~ ^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$ ]]
MARTY_PLATFORM_TEST_POSTGRES_IMAGE="$(bash "$(dirname "${BASH_SOURCE[0]}")/pull-pinned-dockerhub-image.sh" "$postgres_image")"
export MARTY_PLATFORM_TEST_POSTGRES_IMAGE
selfhost_log=$(mktemp "${RUNNER_TEMP:?}/selfhost-acceptance.XXXXXX")
trap 'rm -f -- "$selfhost_log"' EXIT
export MARTY_PLATFORM_SCHEMA_TEST=1
run_timed_rust_test contract selfhost python3 "$(dirname "${BASH_SOURCE[0]}")/rust_db_obligations.py" \
  --name selfhost_acceptance --owner selfhost -- \
  "$selfhost_executable" --nocapture --test-threads=4 2>&1 | tee "$selfhost_log"
grep -Eq '^test result: ok\. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$selfhost_log"
