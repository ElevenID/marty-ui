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
        assert workflow["jobs"][protected_job]["needs"] == (
            "release-environment-preflight"
        )


def test_reusable_preflight_uses_only_the_job_token() -> None:
    workflow = _text(".github/workflows/release-environment-preflight.yml")

    assert "actions: read" in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert '--environment "$RELEASE_ENVIRONMENT"' in workflow
    assert "--protection-only" in workflow
    assert "secrets." not in workflow


def test_beta_lifecycle_dispatches_exact_release_to_demo_recorder() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")

    assert "Require release-bound public demos on beta" in workflow
    assert 'REQUIRE_LIVE_DEMO_BINDING: "1"' in workflow
    assert "DEMO_RECORDER_DISPATCH_TOKEN" in workflow
    assert "repos/ElevenID/marty-demo-recorder/dispatches" in workflow
    assert "marty-ui-beta-deployed" in workflow
    assert "marty_ui_release_sha: $marty_ui_release_sha" in workflow
    assert "beta_source_id: $beta_source_id" in workflow
