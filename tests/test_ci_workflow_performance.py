from __future__ import annotations

import json
from pathlib import Path

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


def test_rust_contracts_reuse_local_executables_without_artifact_transfer() -> None:
    source, document = _workflow(CI_PATH)
    rust_job = document["jobs"]["test-rust-services"]
    step_names = {step.get("name") for step in rust_job["steps"]}

    assert rust_job["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
    assert "Run independent Rust contract groups concurrently" in step_names
    assert "Test Rust database and runtime contracts" in step_names
    assert "test-rust-db-contracts" not in document["jobs"]
    assert "rust-db-test-bundle" not in source
    assert "actions/upload-artifact" not in "\n".join(
        str(step) for step in rust_job["steps"]
    )
    for group in ("workspace", "flow", "verification", "gateway"):
        assert f'rust-{group}.status' in source


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
    assert rust_workflow["jobs"]["analyze-rust"]["if"] == (
        "vars.CODEQL_ADVANCED_ENABLED == 'true'"
    )
    assert actions_workflow["jobs"]["analyze-actions"]["if"] == (
        "vars.CODEQL_ADVANCED_ENABLED == 'true'"
    )
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


def test_warm_cache_uses_the_same_rust_test_profile() -> None:
    _source, document = _workflow(
        ROOT / ".github" / "workflows" / "warm-ci-caches.yml"
    )
    assert document["jobs"]["rust"]["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
