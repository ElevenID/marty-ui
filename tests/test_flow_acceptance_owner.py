"""Retained Flow cases have one platform-owned source, fixture and runner."""
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / "rust/crates/flow-acceptance"
FLOW_OUTER = (
    "didcomm_flow_grpc_provider_preserves_keyed_admission",
    "didcomm_http_admission_recovers_real_keyed_reservation",
    "flow_actual_main_boots_rendered_base_and_preserves_public_admission",
    "flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http",
    "flow_rendered_provider_child",
    "flow_rendered_settings_select_native_rpc_and_preserve_legacy_http",
    "platform_fixture_uses_current_owned_schema_without_provider_objects",
    "platform_fixture_recovery_rejects_foreign_topology_before_removal",
)
FLOW_NESTED = (
    "loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn",
    "owned_output_child",
    "owned_process_output_and_early_exit_cleanup_are_verified",
)


FLOW_SHARED = {
    "managed_http_provider_tls::native_flow_clients_use_only_selected_ca_and_verify_hostnames": "managed_http_provider_tls.rs",
    "managed_http_provider_tls::selected_ca_cannot_enable_plaintext_or_accept_key_material": "managed_http_provider_tls.rs",
    "base_runtime_redis::tests::ping_cleanup_failure_is_terminal_not_readiness_retry": "base_runtime_redis.rs",
    "base_runtime_redis::tests::redis_fixture_requires_exact_owner_storage_and_loopback_without_database_override": "base_runtime_redis.rs",
    "base_runtime_redis::tests::namespace_redis_rejects_other_networks_and_every_host_publication": "base_runtime_redis.rs",
    "didcomm_gateway_replay::native_selection_is_unchanged_and_legacy_control_changes_only_direct_owner": "didcomm_gateway_replay.rs",
    "didcomm_gateway_replay::initiation_native_selection_is_unchanged_and_legacy_control_changes_only_rewritten_post_owner": "didcomm_gateway_replay.rs",
}


def test_flow_cases_have_one_required_source_and_runner_owner():
    source = (FLOW / "tests/flow_published_schema_contract.rs").read_text()
    nested = (FLOW / "tests/support/flow_public_startup.rs").read_text()
    inventory = (ROOT / "scripts/ci/list-flow-acceptance-cases.sh").read_text()
    runner = (ROOT / "scripts/ci/run-flow-acceptance-contracts.sh").read_text()
    assert len(FLOW_OUTER) + len(FLOW_NESTED) + len(FLOW_SHARED) == 18
    for name in FLOW_OUTER:
        assert len(re.findall(rf"(?:async )?fn {name}\(\)", source)) == 1
        assert inventory.count(f"'{name}: test'") == 1
    for name in FLOW_NESTED:
        assert len(re.findall(rf"(?:async )?fn {name}\(\)", nested)) == 1
        assert inventory.count(f"public_startup::{name}: test'") == 1
    for required in ["list-flow-acceptance-cases.sh", "MARTY_PLATFORM_SCHEMA_TEST=1",
                     "MARTY_ISSUANCE_TEST_BINARY=", "--name flow_acceptance --owner flow-pr --",
                     '"$flow_executable" --nocapture --test-threads=4',
                     "18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"]:
        assert required in runner
    for name, file in FLOW_SHARED.items():
        body = (FLOW / "tests/support" / file).read_text()
        assert len(re.findall(rf"fn {name.rsplit('::', 1)[1]}\(\)", body)) == 1
        assert inventory.count(f"'{name}: test'") == 1
    assert "observed_image" not in runner and "canvas" not in runner.lower()


def test_shared_platform_fixtures_have_no_provider_owner_dependency():
    source = (FLOW / "tests/flow_published_schema_contract.rs").read_text()
    manifest = tomllib.loads((FLOW / "Cargo.toml").read_text())
    assert "features" not in manifest
    for name in ["marty-flow", "marty-organization", "marty-credential-template", "marty-issuance-service"]:
        assert name in manifest["dev-dependencies"]
    for shared in ["base_runtime_redis.rs", "didcomm_gateway_replay.rs", "didcomm_native_grpc_fixture.rs", "issuance_named_peers.rs"]:
        assert (ROOT / "rust/acceptance/support" / shared).is_file()
        if shared in {"base_runtime_redis.rs", "didcomm_gateway_replay.rs"}:
            assert source.count(f'#[path = "support/{shared}"]') == 1
            assert f'include!("../../../../acceptance/support/{shared}")' in (FLOW / "tests/support" / shared).read_text()
        else:
            assert source.count(f'#[path = "../../../acceptance/support/{shared}"]') == 1
    assert "mod platform_test_database" in source
    assert "canvas_published_database" not in source
    database = (ROOT / "rust/services/issuance/tests/support/platform_test_database.rs").read_text()
    assert 'start.ends_with("rust/crates/flow-acceptance")' in database
    assert "canvas" not in database.lower()
    for retired in ["observed_image", "start_probe", "extra_fixture", "runpy"]:
        assert retired not in database
