"""Mandatory actual-main registration; no executable/runtime dependencies here."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "flow_actual_main_boots_rendered_base_and_preserves_public_admission"


def test_public_flow_main_gate_is_registered_and_required():
    target = (ROOT / "rust/services/issuance/tests/canvas_published_schema_contract.rs").read_text()
    assert f"async fn {NAME}()" in target
    body = target.split(f"async fn {NAME}()", 1)[1].split("\n}", 1)[0]
    assert "PublishedDatabase::start()" in body
    assert "OwnedRedis::start()" in body
    assert "run_flow_public_startup(&owned.url, redis.url())" in body
    script = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text()
    assert f"grep -Fx '{NAME}: test'" in script
    assert '"${executables[0]}" --nocapture --test-threads=2' in script
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "test -x rust/target/debug/marty-flow" in workflow


def test_public_flow_gate_uses_real_main_and_retains_historical_gates():
    helper = (ROOT / "rust/services/issuance/tests/support/flow_public_startup.rs").read_text()
    assert '"marty-flow.exe"' in helper and '"marty-flow"' in helper
    assert ".env_clear()" in helper
    assert "migrate_flow_schema" not in helper
    assert "validate_flow_schema(&pool)" in helper
    assert "legacy.attempts()" in helper
    assert "FlowServiceClient::new" in helper
    assert '"/v1/flows/instances"' in helper
    script = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text()
    for existing in [
        "flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http",
        "flow_rendered_settings_select_native_rpc_and_preserve_legacy_http",
    ]:
        assert f"grep -Fx '{existing}: test'" in script
