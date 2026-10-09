"""The Flow split retains one executable owner for each published-schema case."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / "rust/crates/flow-acceptance"
CANVAS = ROOT / "rust/crates/canvas-acceptance"
FLOW_OUTER = (
    "didcomm_flow_grpc_provider_preserves_keyed_admission",
    "didcomm_http_admission_recovers_real_keyed_reservation",
    "flow_actual_main_boots_rendered_base_and_preserves_public_admission",
    "flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http",
    "flow_rendered_provider_child",
    "flow_rendered_settings_select_native_rpc_and_preserve_legacy_http",
)
FLOW_NESTED = (
    "loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn",
    "owned_output_child",
    "owned_process_output_and_early_exit_cleanup_are_verified",
)


def test_flow_cases_have_one_required_source_and_runner_owner():
    flow_source = (FLOW / "tests/flow_published_schema_contract.rs").read_text()
    canvas_source = (CANVAS / "tests/canvas_published_schema_contract.rs").read_text()
    nested_source = (FLOW / "tests/support/flow_public_startup.rs").read_text()
    runner = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text()
    assert len(FLOW_OUTER) + len(FLOW_NESTED) == 9
    for name in FLOW_OUTER:
        assert len(re.findall(rf"async fn {name}\(\)", flow_source)) == 1
        assert f"async fn {name}()" not in canvas_source
        assert runner.count(f"'{name}: test'") == 1
    for name in FLOW_NESTED:
        assert len(re.findall(rf"(?:async )?fn {name}\(\)", nested_source)) == 1
        assert runner.count(f"public_startup::{name}: test'") == 1
    assert 'flow_tests=$("$flow_executable" --list)' in runner
    assert '"$flow_executable" --nocapture --test-threads=4' in runner
    assert "Flow executable changed its exact nine-case owner inventory" in runner
    assert "flow_status == 0" in runner


def test_shared_fixtures_keep_canvas_unit_tests_once_and_release_scope():
    canvas_manifest = tomllib.loads((CANVAS / "Cargo.toml").read_text())
    flow_manifest = tomllib.loads((FLOW / "Cargo.toml").read_text())
    assert "marty-flow" not in canvas_manifest["dev-dependencies"]
    assert "marty-flow" in flow_manifest["dev-dependencies"]
    assert "features" not in canvas_manifest
    assert "features" not in flow_manifest
    redis = (ROOT / "rust/services/issuance/tests/support/base_runtime_redis.rs").read_text()
    gateway = (
        ROOT / "rust/services/issuance/tests/support/didcomm_gateway_replay.rs"
    ).read_text()
    redis_owner = (CANVAS / "tests/support/base_runtime_redis.rs").read_text()
    gateway_owner = (CANVAS / "tests/support/didcomm_gateway_replay.rs").read_text()
    assert "fn ping_cleanup_failure_is_terminal_not_readiness_retry" not in redis
    assert "fn ping_cleanup_failure_is_terminal_not_readiness_retry" in redis_owner
    assert "fn native_selection_is_unchanged" not in gateway
    assert "fn native_selection_is_unchanged" in gateway_owner
    assert "include!(" in redis_owner and "include!(" in gateway_owner
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "-p marty-flow-acceptance" in workflow
    assert "--test flow_published_schema_contract" in workflow
    assert "--exclude marty-flow-acceptance" in workflow
    database = (
        ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs"
    ).read_text()
    assert 'start.ends_with("rust/crates/flow-acceptance")' in database


def test_linux_only_canvas_cases_explain_cross_platform_inventory():
    source = (CANVAS / "tests/canvas_published_schema_contract.rs").read_text()
    diagnostics = (CANVAS / "tests/support/runtime_failure_diagnostics.rs").read_text()
    rendered = (CANVAS / "tests/support/rendered_base_process.rs").read_text()
    assert re.search(
        r'#\[cfg\(unix\)\]\s*#\[tokio::test\]\s*async fn canvas_mirror_worker_enabled_packaged_main_runs_and_shuts_down_cleanly',
        source,
    )
    assert re.search(
        r'#\[cfg\(unix\)\]\s*#\[test\]\s*fn linked_directory_marker_and_output_are_refused',
        diagnostics,
    )
    assert re.search(
        r'#\[cfg\(target_os = "linux"\)\]\s*#\[test\]\s*fn rendered_base_renewal_config_crosses_encryption_and_private_address_policy',
        rendered,
    )
