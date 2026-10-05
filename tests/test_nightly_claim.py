from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("nightly_claim", ROOT / "scripts/nightly_claim.py")
assert SPEC and SPEC.loader
nightly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nightly)

SOURCE = "a" * 40


def runs(*, failed: str | None = None) -> dict:
    return {"workflow_runs": [
        {"id": index + 10, "path": path, "event": "merge_group",
         "head_sha": SOURCE, "head_branch": "main", "status": "completed",
         "conclusion": "failure" if path == failed else "success"}
        for index, path in enumerate(nightly.REQUIRED_WORKFLOWS)
    ]}


def claim(*, workflow_runs: dict | None = None) -> dict:
    return nightly.create_claim(
        repository="ElevenID/marty-ui", version="1.2.3", date="20261005",
        run_id="12345", source_sha=SOURCE,
        stack_lock={"schema": "marty.stack-lock/v1", "release": "marty-ui@1.2.3",
                    "release_state": "eligible"},
        workflow_runs=workflow_runs if workflow_runs is not None else runs(),
    )


def preparation_run(**updates: object) -> dict:
    result = {"id": 12345, "path": nightly.PREPARATION_WORKFLOW,
              "event": "workflow_dispatch", "head_branch": "main", "head_sha": SOURCE,
              "status": "completed", "conclusion": "success"}
    result.update(updates)
    return result


def test_nightly_claim_is_distinct_no_write_identity() -> None:
    result = claim()
    assert result["tag"] == "v1.2.3-nightly.20261005.12345"
    assert result["tier"] == "nightly"
    assert result["qualification"] == "not_started"
    assert result["publication"] == "prohibited"
    assert nightly.validate_intake(result, preparation_run(), current_main_sha=SOURCE) == result


@pytest.mark.parametrize("version,date,run_id", [
    ("1.2.3-rc.1", "20261005", "12345"),
    ("01.2.3", "20261005", "12345"),
    ("1.2.3", "20260230", "12345"),
    ("1.2.3", "20261005", "0"),
])
def test_reject_invalid_nightly_identity(version: str, date: str, run_id: str) -> None:
    with pytest.raises((nightly.NightlyClaimError, ValueError)):
        nightly.create_claim(
            repository="ElevenID/marty-ui", version=version, date=date,
            run_id=run_id, source_sha=SOURCE,
            stack_lock={"schema": "marty.stack-lock/v1", "release": f"marty-ui@{version}",
                        "release_state": "eligible"}, workflow_runs=runs(),
        )


def test_reject_missing_or_failed_exact_source_gate() -> None:
    with pytest.raises(nightly.NightlyClaimError, match="workflow failed"):
        claim(workflow_runs=runs(failed=nightly.REQUIRED_WORKFLOWS[0]))
    wrong_source = runs()
    wrong_source["workflow_runs"][0]["head_sha"] = "b" * 40
    with pytest.raises(nightly.NightlyClaimError, match="workflow missing"):
        claim(workflow_runs=wrong_source)


def test_latest_exact_source_gate_must_pass() -> None:
    duplicate = runs()
    duplicate["workflow_runs"].append({
        "id": 100, "path": nightly.REQUIRED_WORKFLOWS[0], "event": "merge_group",
        "head_sha": SOURCE, "head_branch": "gh-readonly-queue/main/test",
        "status": "completed", "conclusion": "failure",
    })
    with pytest.raises(nightly.NightlyClaimError, match="workflow failed"):
        claim(workflow_runs=duplicate)


@pytest.mark.parametrize("run_change", [
    {"event": "repository_dispatch"},
    {"path": ".github/workflows/prepare-stack-tag.yml"},
    {"head_sha": "b" * 40},
    {"conclusion": "failure"},
    {"id": 99999},
])
def test_intake_rejects_wrong_run(run_change: dict) -> None:
    with pytest.raises(nightly.NightlyClaimError):
        nightly.validate_intake(claim(), preparation_run(**run_change), current_main_sha=SOURCE)


def test_intake_rejects_stale_main_and_claim_tampering() -> None:
    with pytest.raises(nightly.NightlyClaimError, match="no longer main"):
        nightly.validate_intake(claim(), preparation_run(), current_main_sha="b" * 40)
    changed = claim()
    changed["publication"] = "permitted"
    with pytest.raises(nightly.NightlyClaimError, match="cannot authorize publication"):
        nightly.validate_intake(changed, preparation_run(), current_main_sha=SOURCE)
    changed = claim()
    changed["tag"] = "v1.2.3"
    with pytest.raises(nightly.NightlyClaimError):
        nightly.validate_intake(changed, preparation_run(), current_main_sha=SOURCE)


def test_workflow_contract_has_no_stable_or_recording_dispatch() -> None:
    prepare = (ROOT / ".github/workflows/prepare-nightly-claim.yml").read_text()
    intake = (ROOT / ".github/workflows/nightly-claim-intake.yml").read_text()
    for workflow in (prepare, intake):
        assert "cd.yml" not in workflow
        assert "e2e-tests.yml" not in workflow
        assert "youtube" not in workflow.lower()
        assert "git push" not in workflow
        assert 'tag_refs="$(git ls-remote --tags origin ' in workflow
        assert "| grep -q ." not in workflow
    assert "workflow_run:" in intake
    assert "nightly-claim.json" in prepare


@pytest.mark.parametrize("workflow_name", [
    "prepare-nightly-claim.yml", "nightly-claim-intake.yml",
])
def test_tag_lookup_failure_cannot_be_accepted_as_absence(workflow_name: str) -> None:
    if sys.platform == "win32":
        pytest.skip("workflow shell model runs under native Bash in Linux CI")
    source = (ROOT / ".github/workflows" / workflow_name).read_text()
    lookup = next(line.strip() for line in source.splitlines()
                  if line.strip().startswith('tag_refs="$(git ls-remote '))
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\ngit() { return 42; }\ntag=test\n"
         + lookup + "\necho accepted"],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 42
    assert "accepted" not in result.stdout
