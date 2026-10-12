"""Keep the migrated-base pilot manual-only without changing Canvas gates."""

import importlib.util
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
SWITCH = "MARTY_CANVAS_REUSE_PUBLISHED_BASE_PILOT"
DIAGNOSTICS = ROOT / "rust/services/issuance/tests/support/canvas_published_database_diagnostic_tests.rs"
EXACT_RUNNER = ROOT / "scripts/ci/run-exact-ignored-canvas-test.py"


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
        "MARTY_CANVAS_OPENBAO_IMAGE": "marty-openbao-didcomm:canvas",
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
    assert diagnostic["timeout-minutes"] == 20
    assert not diagnostic.get("continue-on-error", False)
    assert diagnostic["env"] == {
        SWITCH: "1",
        "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST": "1",
    }
    source = DIAGNOSTICS.read_text(encoding="utf-8")
    for test_name in (
        "eight_fixed_published_databases_keep_migration_heads",
        "immutable_published_base_keeps_revision_parity_and_case_isolation",
        "concurrent_published_base_keeps_eight_cases_isolated",
        "failed_published_base_restore_removes_only_its_owned_container",
    ):
        assert f"canvas_published_database::diagnostic_tests::{test_name}" in diagnostic["run"]
        assert f"async fn {test_name}()" in source
    assert (
        'python3 ../scripts/ci/run-exact-ignored-canvas-test.py "${executables[0]}" "$test_name"'
        in diagnostic["run"]
    )


def test_manual_pilot_prepares_the_same_pinned_postgres_image_as_the_published_runner() -> None:
    diagnostic = next(
        step
        for step in _steps()
        if step.get("name") == "Verify opted-in Canvas migrated-base parity and isolation"
    )
    run = diagnostic["run"]
    assert "jq -er '.observed_postgres_image'" in run
    assert "../contracts/canvas-worker-consumer-range-oracle.json" in run
    assert '[[ "$postgres_image" =~ ^postgres@sha256:[a-f0-9]{64}$ ]]' in run
    assert 'MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE="$(bash \\' in run
    assert '../scripts/ci/pull-pinned-dockerhub-image.sh "$postgres_image"' in run
    assert "export MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE" in run
    assert run.index("export MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE") < run.index(
        "mapfile -t executables"
    )
    published_runner = (
        ROOT / "scripts/ci/run-published-canvas-contracts.sh"
    ).read_text(encoding="utf-8")
    assert "jq -er '.observed_postgres_image, .observed_image'" in published_runner
    assert 'pull-pinned-dockerhub-image.sh" "$1"' in published_runner


def _exact_runner():
    spec = importlib.util.spec_from_file_location("exact_canvas_runner", EXACT_RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exact_ignored_runner_rejects_missing_test(monkeypatch) -> None:
    runner = _exact_runner()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "0 tests, 0 benchmarks\n"),
    )

    def no_execution(*_args, **_kwargs):
        raise AssertionError("Missing test must not execute")

    monkeypatch.setattr(runner.subprocess, "Popen", no_execution)
    assert runner.run_exact_ignored("fixture", "missing") == 1


def test_exact_ignored_runner_rejects_zero_execution(monkeypatch) -> None:
    runner = _exact_runner()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "named: test\n\n1 test, 0 benchmarks\n"),
    )

    class FakeProcess:
        stdout = iter(
            [
                "running 0 tests\n",
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
                "12 filtered out; finished in 0.00s\n",
            ]
        )

        def wait(self):
            return 0

    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    assert runner.run_exact_ignored("fixture", "named") == 1


def test_exact_ignored_runner_accepts_one_executed_test(monkeypatch) -> None:
    runner = _exact_runner()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "named: test\n\n1 test, 0 benchmarks\n"),
    )

    class FakeProcess:
        stdout = iter(
            [
                "running 1 test\n",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "11 filtered out; finished in 0.00s\n",
            ]
        )

        def wait(self):
            return 0

    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    assert runner.run_exact_ignored("fixture", "named") == 0
