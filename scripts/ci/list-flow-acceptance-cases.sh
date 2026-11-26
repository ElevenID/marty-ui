#!/usr/bin/env bash
# Shared, exact inventory for full platform and test-source-only Flow runs.
set -euo pipefail
[[ $# == 1 && -x "$1" ]] || exit 2
flow_tests=$("$1" --list)
expected_flow_tests=$(printf '%s\n' \
  'managed_http_provider_tls::native_flow_clients_use_only_selected_ca_and_verify_hostnames: test' \
  'managed_http_provider_tls::selected_ca_cannot_enable_plaintext_or_accept_key_material: test' \
  'base_runtime_redis::tests::ping_cleanup_failure_is_terminal_not_readiness_retry: test' \
  'base_runtime_redis::tests::redis_fixture_requires_exact_owner_storage_and_loopback_without_database_override: test' \
  'base_runtime_redis::tests::namespace_redis_rejects_other_networks_and_every_host_publication: test' \
  'didcomm_gateway_replay::native_selection_is_unchanged_and_legacy_control_changes_only_direct_owner: test' \
  'didcomm_gateway_replay::initiation_native_selection_is_unchanged_and_legacy_control_changes_only_rewritten_post_owner: test' \
  'platform_fixture_recovery_rejects_foreign_topology_before_removal: test' \
  'platform_fixture_uses_current_owned_schema_without_provider_objects: test' \
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
  echo 'Flow executable changed its exact eighteen-case owner inventory' >&2
  exit 1
}
printf '%s\n' "$flow_tests"
