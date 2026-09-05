from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow(path: Path) -> tuple[str, dict[str, object]]:
    source = path.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def test_pull_request_classifier_is_conservative_and_merge_queue_is_complete() -> None:
    source, document = _workflow(CI_PATH)
    jobs = document["jobs"]
    changes = jobs["changes"]

    assert changes["name"] == "Classify Changes"
    assert set(changes["outputs"]) == {
        "all",
        "ui",
        "python",
        "rust",
        "release",
        "verification",
        "security",
    }
    assert 'if [[ "${{ github.event_name }}" == merge_group ]]' in source
    assert "Unknown paths deliberately receive the complete suite." in source

    conditional_jobs = {
        "fast-feedback",
        "test-ui",
        "test-services",
        "test-rust-services",
        "rust-lint-policy",
        "test-rust-service-images",
        "public-protocol-contract",
        "test-release-contracts",
        "test-credential-lifecycle-browser",
        "security",
        "rust-supply-chain",
    }
    for name in conditional_jobs:
        assert jobs[name]["needs"] == "changes"
        assert jobs[name]["if"]

    gate_needs = set(jobs["ci-gate"]["needs"])
    assert gate_needs == conditional_jobs | {"changes", "lint"}
    assert '[[ "$result" == success || "$result" == skipped ]]' in source
    assert 'test "$result" = success' in source


def test_published_canvas_schema_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name")
        == "Test native Canvas against published issuance migrations"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert gate["env"] == {"MARTY_CANVAS_PUBLISHED_SCHEMA_TEST": "1"}
    assert "canvas-worker-consumer-range-oracle.json" in gate["run"]
    assert "canvas_published_schema_contract" in gate["run"]
    assert '"${executables[0]}" --list' in gate["run"]
    assert "grep -Fx 'heartbeat_readiness_matches_published_python: test'" in gate["run"]
    assert "grep -Fx 'operations_match_frozen_published_python: test'" in gate["run"]
    assert '"${executables[0]}" --nocapture --test-threads=1' in gate["run"]
    assert "[[ ${#executables[@]} == 1" in gate["run"]


def test_canvas_lti_https_gate_requires_real_linux_parent_test() -> None:
    _source, document = _workflow(CI_PATH)
    gate = next(
        step
        for step in document["jobs"]["test-rust-services"]["steps"]
        if step.get("name") == "Test native Canvas AGS/NRPS over real HTTPS"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert "python3 --version" in gate["run"] and "openssl version" in gate["run"]
    assert "canvas_oauth_behavior" in gate["run"]
    assert "length == 1" in gate["run"]
    assert "actual_ags_nrps_https_uses_child_scoped_trust" in gate["run"]
    assert '"$https_executable" --list' in gate["run"]
    assert (
        '"$https_executable" "$https_test" --exact --nocapture --test-threads=1'
        in gate["run"]
    )


def test_rust_contracts_reuse_local_executables_without_artifact_transfer() -> None:
    source, document = _workflow(CI_PATH)
    rust_job = document["jobs"]["test-rust-services"]
    step_names = {step.get("name") for step in rust_job["steps"]}

    assert rust_job["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
    assert "Run safe Rust contract groups concurrently" in step_names
    assert "Run Flow database contract after workspace suite" in step_names
    assert "Test Rust database and runtime contracts" in step_names
    assert "test-rust-db-contracts" not in document["jobs"]
    assert "rust-db-test-bundle" not in source
    assert "actions/upload-artifact" not in "\n".join(
        str(step) for step in rust_job["steps"]
    )
    for group in ("workspace", "verification", "gateway"):
        assert f'rust-{group}.status' in source
    assert "target/debug/flow-postgres-contract --test-threads=1" in source
    assert "target/debug/verification-postgres-contract" in source
    assert "target/debug/gateway-redis-contract" in source
    assert "FLOW_POSTGRES_TEST_URL: postgresql://postgres:postgres@127.0.0.1:5432/marty_atomic_test" in source
    assert "FLOW_CONTRACT_POSTGRES_URL" not in source
    assert "POSTGRES_DB=marty_atomic_test" not in source
    assert "cargo test --locked -p marty-flow --test postgres_integration" not in source


def test_released_native_backend_is_verified_without_rebuilding_it() -> None:
    source, document = _workflow(CI_PATH)
    service_job = document["jobs"]["test-services"]
    service_source = "\n".join(str(step) for step in service_job["steps"])

    assert "Verify released native trust-registry backend" in service_source
    assert '"trust_registry_sync"' in service_source
    assert "maturin" not in service_source
    assert "ElevenID/marty-core" not in service_source
    assert "MARTY_CORE_TRUST_REGISTRY_REF" not in source


def test_ui_timing_refresh_runs_after_the_required_ci_gate() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )

    assert "workflow_run:" in source
    assert "workflows: [CI]" in source
    refresh = document["jobs"]["refresh"]
    assert refresh["if"] == "github.event.workflow_run.conclusion == 'success'"
    assert "refresh-ui-test-timings" not in yaml.safe_load(
        CI_PATH.read_text(encoding="utf-8")
    )["jobs"]


@pytest.mark.parametrize("scenario", ["missing", "empty", "unrelated", "nested", "malformed", "not_directory"])
def test_ui_timing_refresh_checks_actual_reports(tmp_path: Path, scenario: str) -> None:
    _, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )
    steps = document["jobs"]["refresh"]["steps"]
    guard = next(step for step in steps if step.get("id") == "observations")
    assert guard["if"] == "steps.download.outcome == 'success'"
    for name in ("Produce refreshed timing plan", "Upload refreshed timing plan"):
        step = next(step for step in steps if step.get("name") == name)
        assert step["if"] == "steps.observations.outputs.available == 'true'"

    reports = tmp_path / "reports"
    output = tmp_path / "github-output"
    if scenario == "not_directory":
        reports.write_text("not a directory", encoding="utf-8")
    elif scenario != "missing":
        reports.mkdir()
        if scenario == "unrelated":
            (reports / "notes.txt").write_text("no reports", encoding="utf-8")
            (reports / "directory.json").mkdir()
        elif scenario in {"nested", "malformed"}:
            nested = reports / "shard-1"
            nested.mkdir()
            report = {"testResults": [{
                "name": "/home/runner/work/marty-ui/marty-ui/ui/src/refresh.test.ts",
                "startTime": 100,
                "endTime": 150,
            }]}
            (nested / "results.json").write_text(
                json.dumps(report) if scenario == "nested" else "not JSON",
                encoding="utf-8",
            )

    script = guard["run"].split("<<'NODE'\n", 1)[1].rsplit("\nNODE", 1)[0]
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        env={**os.environ, "TIMINGS_DIRECTORY": str(reports), "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
    )
    if scenario == "not_directory":
        assert result.returncode != 0
        assert not output.exists()
        return
    assert result.returncode == 0, result.stderr
    available = scenario in {"nested", "malformed"}
    assert output.read_text(encoding="utf-8").strip() == f"available={str(available).lower()}"
    if not available:
        assert "skipping timing refresh" in result.stdout
        return

    plan = tmp_path / "plan.json"
    refresh = subprocess.run(
        ["node", str(ROOT / "ui/scripts/update-vitest-timings.mjs"), str(reports), "--output", str(plan)],
        capture_output=True,
        text=True,
    )
    if scenario == "malformed":
        assert refresh.returncode != 0
        assert not plan.exists()
    else:
        assert refresh.returncode == 0, refresh.stderr
        assert json.loads(plan.read_text(encoding="utf-8"))["tests"]["src/refresh.test.ts"] == 50


def test_advanced_codeql_keeps_full_merge_and_scheduled_coverage() -> None:
    rust_source, rust_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-rust.yml"
    )
    actions_source, actions_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-actions.yml"
    )
    production = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-production.yml").read_text(
            encoding="utf-8"
        )
    )
    full = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-full.yml").read_text(
            encoding="utf-8"
        )
    )
    policy = json.loads(
        (ROOT / ".github" / "stack-tag-policy.json").read_text(encoding="utf-8")
    )

    assert "merge_group:" in rust_source
    assert "merge_group:" in actions_source
    assert "schedule:" in rust_source
    assert "schedule:" in actions_source
    assert "github.event_name == 'schedule'" in rust_source
    rust_events = rust_workflow.get("on") or rust_workflow[True]
    actions_events = actions_workflow.get("on") or actions_workflow[True]
    assert rust_events["pull_request"] == {"branches": ["main"]}
    assert actions_events["pull_request"] == {"branches": ["main"]}
    rust_job = rust_workflow["jobs"]["analyze-rust"]
    actions_job = actions_workflow["jobs"]["analyze-actions"]
    for job in (rust_job, actions_job):
        assert "if" not in job
        assert job["env"]["CODEQL_ADVANCED_ENABLED"] == (
            "${{ vars.CODEQL_ADVANCED_ENABLED }}"
        )
        guard = job["steps"][0]
        assert guard["name"] == "Require the completed advanced CodeQL cutover"
        assert 'test "$CODEQL_ADVANCED_ENABLED" = "true"' in guard["run"]
        assert job["permissions"]["pull-requests"] == "read"
        scope = job["steps"][1]
        assert scope["id"] == "scope"
        assert "github.paginate(github.rest.pulls.listFiles" in scope["with"]["script"]
        assert "context.eventName !== 'pull_request'" in scope["with"]["script"]
        assert any(
            step.get("name") == "Record scoped analysis skip"
            for step in job["steps"]
        )
        analysis_steps = [
            step for step in job["steps"] if step.get("name", "").startswith("Analyze")
        ]
        assert analysis_steps
        assert all(
            step["if"] == "steps.scope.outputs.analyze == 'true'"
            for step in analysis_steps
        )
    assert "filename.startsWith('rust/')" in rust_source
    assert "filename.startsWith('.github/codeql/')" in rust_source
    assert "filename === '.github/workflows/codeql-rust.yml'" in rust_source
    assert "filename.startsWith('.github/')" in actions_source
    assert production["paths"] == ["rust/crates/**", "rust/services/**"]
    assert "rust/third_party/**" in production["paths-ignore"]
    assert full["paths"] == ["rust/**"]
    required = policy["required_workflows"]
    assert {
        "path": ".github/workflows/codeql-rust.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": ".github/workflows/codeql-actions.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": "dynamic/github-code-scanning/codeql",
        "event": "dynamic",
    } not in required


def test_warm_cache_uses_the_same_rust_test_profile() -> None:
    _source, document = _workflow(
        ROOT / ".github" / "workflows" / "warm-ci-caches.yml"
    )
    assert document["jobs"]["rust"]["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0


def test_closed_pull_request_cache_cleanup_is_rate_limit_safe() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "cleanup-ci-caches.yml"
    )
    cleanup = document["jobs"]["cleanup"]
    script = cleanup["steps"][0]["with"]["script"]

    assert "Promise.all" not in script
    assert "await delay(500)" in script
    assert "error.status === 429 || error.status === 403" in script
    assert "const maxAttempts = 7" in script
    assert "retry-after" in script
    assert "2_000 * (2 ** attempt)" in script
    assert "maxDeletions = 2000" in source
