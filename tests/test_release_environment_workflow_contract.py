from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_manifest_covers_every_release_workflow_environment() -> None:
    manifest = json.loads(_text("deploy-config/github-release-environments.json"))

    assert set(manifest["environments"]) == {
        "beta-lifecycle",
        "stack-release",
        "wallet-conformance",
    }


def test_release_workflows_fail_closed_before_protected_jobs() -> None:
    workflows = {
        ".github/workflows/cd.yml": ("stack-release", "validate-stack"),
        ".github/workflows/e2e-tests.yml": (
            "beta-lifecycle",
            "full-stack-credential-lifecycle",
        ),
        ".github/workflows/wallet-conformance.yml": (
            "wallet-conformance",
            "attest-release",
        ),
    }

    for path, (environment, protected_job) in workflows.items():
        workflow = yaml.safe_load(_text(path))
        preflight = workflow["jobs"]["release-environment-preflight"]
        assert preflight["uses"] == (
            "./.github/workflows/release-environment-preflight.yml"
        )
        assert preflight["with"]["environment"] == environment
        needs = workflow["jobs"][protected_job]["needs"]
        dependencies = {needs} if isinstance(needs, str) else set(needs)
        assert "release-environment-preflight" in dependencies


def test_reusable_preflight_uses_only_the_job_token() -> None:
    workflow = _text(".github/workflows/release-environment-preflight.yml")

    assert "actions: read" in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert '--environment "$RELEASE_ENVIRONMENT"' in workflow
    assert "--protection-only" in workflow
    assert "secrets." not in workflow


def test_beta_lifecycle_requires_completed_release_bound_demo_qualification() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")

    assert "Require release-bound public demos on beta" in workflow
    assert 'REQUIRE_LIVE_DEMO_BINDING: "1"' in workflow
    assert "EXPECTED_RELEASE_VERSION: ${{ env.RELEASE_VERSION }}" in workflow
    assert "EXPECTED_BETA_SOURCE_ID: ${{ env.BETA_SOURCE_ID }}" in workflow
    assert "EXPECTED_MARTY_UI_REVISION: ${{ env.MARTY_UI_RELEASE_SHA }}" in workflow
    assert "DEMO_RECORDER_DISPATCH_TOKEN" in workflow
    assert 'gh run download "$DEMO_QUALIFICATION_RUN_ID"' in workflow
    assert '--repo ElevenID/marty-demo-recorder' in workflow
    assert 'repos/ElevenID/marty-demo-recorder/actions/runs/$DEMO_QUALIFICATION_RUN_ID' in workflow
    assert '--bin validate-demo-qualification --' in workflow
    assert '"$MARTY_UI_RELEASE_SHA" "$BETA_SOURCE_ID"' in workflow
    assert '"$DEMO_DEPLOYMENT_MANIFEST_SHA256" "$STACK_MANIFEST_SHA256"' in workflow
    assert 'repos/ElevenID/marty-demo-recorder/dispatches' not in workflow
    assert "marty_ui_release_sha: $marty_ui_release_sha" in workflow
    assert "beta_source_id: $beta_source_id" in workflow


def test_private_qualification_precedes_browser_gates_without_publishing_raw_inputs() -> None:
    workflow = yaml.safe_load(_text(".github/workflows/e2e-tests.yml"))
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert len(inputs) == 10
    for name in ("demo_qualification_run_id", "demo_recorder_sha", "demo_deployment_manifest_sha256"):
        assert inputs[name]["required"] is True
    assert "deployment_evidence" not in inputs
    job = workflow["jobs"]["full-stack-credential-lifecycle"]
    for name in ("DEMO_QUALIFICATION_RUN_ID", "DEMO_RECORDER_SHA", "DEMO_DEPLOYMENT_MANIFEST_SHA256"):
        assert f"github.event.client_payload.{name.lower()}" in job["env"][name]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    name = "Require completed private demo qualification"
    assert names.index(name) < names.index("Install browser test dependencies")
    step = steps[names.index(name)]
    assert "if" not in step
    assert not step.get("continue-on-error", False)
    assert 'mktemp -d "$RUNNER_TEMP/demo-qualification.XXXXXX"' in step["run"]
    assert '> "$private_evidence/run.json"' in step["run"]
    assert '--dir "$private_evidence/report"' in step["run"]
    assert '> tests/artifacts/demo-qualification.json' in step["run"]
    assert 'DEMO_RECORDER_DISPATCH_TOKEN' in step["env"]["GH_TOKEN"]
    upload = steps[names.index("Upload lifecycle evidence")]
    assert upload["with"]["path"] == "tests/artifacts/"
    assert "private_evidence" not in upload["with"]["path"]
