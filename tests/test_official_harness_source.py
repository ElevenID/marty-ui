from __future__ import annotations

import runpy
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/validate_official_harness_source.py"))
PIN = "a" * 40
CALLER = f"""jobs:
  official-interoperability:
    uses: {GATE['WORKFLOW']}@{PIN}
    with:
      harness_revision: {PIN}

  next-job:
    runs-on: ubuntu-latest
"""


def comparison(status: str = "identical") -> dict:
    return {"status": status, "behind_by": 0,
            "base_commit": {"sha": PIN}, "merge_base_commit": {"sha": PIN}}


@pytest.mark.parametrize("status", ["identical", "ahead"])
def test_accepts_current_main_or_its_ancestor(status: str) -> None:
    assert GATE["harness_pin"](CALLER) == PIN
    GATE["require_main_ancestor"](PIN, comparison(status))


@pytest.mark.parametrize("change", [
    {"status": "behind"}, {"status": "diverged"}, {"behind_by": 1},
    {"behind_by": False}, {"behind_by": None}, {"base_commit": {"sha": "b" * 40}},
    {"merge_base_commit": {"sha": "b" * 40}}, {"merge_base_commit": None},
])
def test_rejects_unmerged_or_inconsistent_comparison(change: dict) -> None:
    with pytest.raises(ValueError, match="accepted commit"):
        GATE["require_main_ancestor"](PIN, comparison() | change)


@pytest.mark.parametrize("response", [None, [], {}, "ahead"])
def test_missing_ancestry_is_not_acceptance(response: object) -> None:
    with pytest.raises(ValueError):
        GATE["require_main_ancestor"](PIN, response)


@pytest.mark.parametrize("caller", [
    CALLER.replace(f"@{PIN}", "@main"),
    CALLER.replace(f"harness_revision: {PIN}", f"harness_revision: {'b' * 40}"),
    CALLER.replace(GATE["REPOSITORY"], "other/repository"),
    CALLER.replace(f"      harness_revision: {PIN}", ""),
    CALLER + CALLER,
    "jobs: {}",
])
def test_rejects_floating_mismatched_or_missing_pin(caller: str) -> None:
    with pytest.raises(ValueError):
        GATE["harness_pin"](caller)


def test_claim_runs_the_guard_and_evidence_verifier_uses_the_same_pin() -> None:
    cd = (ROOT / ".github/workflows/cd.yml").read_text()
    pin = GATE["harness_pin"](cd)
    verifier = yaml.safe_load(cd)["jobs"]["official-gate-evidence"]
    verify_step = next(step for step in verifier["steps"]
                       if step.get("name") == "Require seven passing candidate-bound official lanes")
    assert f'{pin} "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"' in verify_step["run"]
    claim = yaml.safe_load((ROOT / ".github/workflows/prepare-stack-tag.yml").read_text())
    steps = claim["jobs"]["claim-stack-release"]["steps"]
    guard = next(step for step in steps
                 if step.get("name") == "Require an accepted official harness source")
    assert guard["run"] == "python scripts/validate_official_harness_source.py"
    assert guard["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "if" not in guard and "continue-on-error" not in guard
    assert steps.index(guard) < next(i for i, step in enumerate(steps)
                                     if step.get("name") == "Create the durable digest-first release claim")


def test_github_failure_is_bounded_and_does_not_echo_credentials(tmp_path: Path) -> None:
    workflow = tmp_path / "cd.yml"
    workflow.write_text(CALLER)
    error = subprocess.CalledProcessError(1, "gh", stderr="private-token-sentinel")
    with patch("subprocess.run", side_effect=error) as command:
        with pytest.raises(ValueError, match="^Unable to verify official harness main ancestry$"):
            GATE["validate"](workflow)
    args, options = command.call_args
    assert args[0] == ["gh", "api", "--hostname", "github.com",
                       f"repos/{GATE['REPOSITORY']}/compare/{PIN}...main?per_page=1"]
    assert options["timeout"] == 30
    assert options["encoding"] == "utf-8"
