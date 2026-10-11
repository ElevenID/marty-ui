"""Keep the migrated-base pilot manual-only without changing Canvas gates."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
SWITCH = "MARTY_CANVAS_REUSE_PUBLISHED_BASE_PILOT"
DIAGNOSTICS = ROOT / "rust/services/issuance/tests/support/canvas_published_database_diagnostic_tests.rs"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    return _workflow()["jobs"]["test-rust-services"]["steps"]


def test_pilot_requires_explicit_manual_boolean_and_retains_full_qualification() -> None:
    workflow = _workflow()
    events = workflow.get("on", workflow.get(True))
    assert events["workflow_dispatch"]["inputs"]["canvas_migrated_base_pilot"] == {
        "description": "Opt in to isolated Canvas migrated-base reuse qualification",
        "required": False,
        "type": "boolean",
        "default": False,
    }
    assert "pull_request" in events
    assert "merge_group" in events
    assert workflow["env"]["MARTY_CANVAS_FULL_QUALIFICATION"] == (
        "${{ (github.event_name == 'workflow_dispatch' || "
        "github.event_name == 'schedule') && '1' || '0' }}"
    )


def test_only_canvas_database_step_receives_opt_in_and_remains_required() -> None:
    steps = _steps()
    group = next(
        step
        for step in steps
        if step.get("name") == "Run isolated database contract suites concurrently"
    )
    assert "if" not in group
    assert not group.get("continue-on-error", False)
    assert group["env"] == {
        SWITCH: (
            "${{ github.event_name == 'workflow_dispatch' && "
            "inputs.canvas_migrated_base_pilot && matrix.lane == 'canvas' "
            "&& '1' || '0' }}"
        )
    }
    assert "run-db-contract-groups.py worker-canvas" in group["run"]
    assert "run-db-contract-groups.py selfhost-canvas" in group["run"]
    assert "run-db-contract-groups.py ${{ matrix.lane == 'canvas' && 'canvas' || 'rust-db' }}" in group["run"]
    assert all(
        SWITCH not in step.get("env", {})
        for step in steps
        if step is not group
        and step.get("name") != "Verify opted-in Canvas migrated-base parity and isolation"
    )


def test_manual_pilot_runs_exact_ignored_parity_isolation_and_failure_checks() -> None:
    steps = _steps()
    group_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Run isolated database contract suites concurrently"
    )
    diagnostic = steps[group_index + 1]
    assert diagnostic["name"] == "Verify opted-in Canvas migrated-base parity and isolation"
    assert diagnostic["if"] == (
        "github.event_name == 'workflow_dispatch' && "
        "inputs.canvas_migrated_base_pilot && matrix.lane == 'canvas'"
    )
    assert not diagnostic.get("continue-on-error", False)
    assert diagnostic["env"] == {
        SWITCH: "1",
        "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST": "1",
    }
    source = DIAGNOSTICS.read_text(encoding="utf-8")
    for test_name in (
        "eight_fixed_published_databases_keep_migration_heads",
        "immutable_published_base_keeps_revision_parity_and_case_isolation",
        "failed_published_base_restore_removes_only_its_owned_container",
    ):
        assert f"canvas_published_database::diagnostic_tests::{test_name}" in diagnostic["run"]
        assert f"async fn {test_name}()" in source
    assert '"$test_name" --exact --ignored --nocapture --test-threads=1' in diagnostic["run"]
