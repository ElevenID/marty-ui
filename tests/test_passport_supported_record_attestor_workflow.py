"""Hosted record attestation must never accept an arbitrary run artifact."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest
import yaml


WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows"
            / "passport-supported-provisioning-record.yml")


def contract(source: str) -> None:
    value = yaml.safe_load(source)
    trigger = value.get("on", value.get(True))
    assert trigger == {"workflow_run": {
        "workflows": ["Passport Supported Disposable Provisioning Producer"],
        "types": ["completed"],
    }}
    permissions = value["permissions"]
    assert permissions == {"actions": "read", "attestations": "write",
                           "contents": "read", "id-token": "write"}
    job = value["jobs"]["attest-record"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["environment"] == "beta-lifecycle"
    condition = job["if"]
    for requirement in (
        "workflow_run.conclusion == 'success'",
        "workflow_run.event == 'workflow_dispatch'",
        "workflow_run.head_branch == 'main'",
        "workflow_run.head_repository.full_name == 'ElevenID/marty-ui'",
        "workflow_run.head_sha == github.sha",
    ):
        assert requirement in condition
    steps = job["steps"]
    assert steps[0]["uses"].startswith("actions/checkout@")
    assert steps[0]["with"]["persist-credentials"] is False
    run = steps[1]["run"]
    for requirement in (
        "actions/runs/$PRODUCER_RUN_ID",
        "actions/workflows/$PRODUCER_WORKFLOW_ID",
        '.path == ".github/workflows/passport-supported-provisioning-producer.yml"',
        "passport-supported-compose-ownership-$PRODUCER_RUN_ID",
        "actions/runs/$plan_run_id",
        '.path == ".github/workflows/passport-supported-provisioning-plan.yml"',
        "passport-supported-provisioning-plan-$plan_run_id",
        "scripts/check_passport_supported_record_handoff.py",
        '--source-commit "$GITHUB_SHA" --producer-run-id "$PRODUCER_RUN_ID"',
    ):
        assert requirement in run
    assert "docker compose" not in run and "docker run" not in run
    assert steps[2]["uses"].startswith("actions/attest-build-provenance@")
    assert steps[2]["with"]["subject-path"] == (
        "passport-supported-compose-ownership-${{ github.event.workflow_run.id }}.json")
    assert steps[3]["uses"].startswith("actions/upload-artifact@")
    assert steps[3]["with"]["retention-days"] == 30


def test_attestor_has_exact_producer_and_plan_handoff() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    contract(source)
    parsed = yaml.safe_load(source)
    run = parsed["jobs"]["attest-record"]["steps"][1]["run"]
    result = subprocess.run(["bash", "-n"], input=run.encode(), capture_output=True,
                            check=False)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("old,new", [
    ("Passport Supported Disposable Provisioning Producer", "Any Workflow"),
    ("workflow_run.head_branch == 'main'", "workflow_run.head_branch == 'beta'"),
    ("workflow_run.head_sha == github.sha", "workflow_run.head_sha != github.sha"),
    ("ubuntu-latest", "self-hosted"),
    ("passport-supported-compose-ownership-$PRODUCER_RUN_ID", "any-record"),
    ("passport-supported-provisioning-plan-$plan_run_id", "any-plan"),
    ("scripts/check_passport_supported_record_handoff.py", "true"),
])
def test_attestor_contract_rejects_unsafe_changes(old: str, new: str) -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert old in source
    with pytest.raises(AssertionError):
        contract(source.replace(old, new))
