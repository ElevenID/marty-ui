"""Current executable prerequisites; no Kubernetes execution qualification claim."""
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


def require_prerequisites(value):
    steps = value["jobs"]["test-rust-services"]["steps"]
    selected = [step for step in steps if step.get("name") == "Require Kubernetes deployment contract executables"]
    assert len(selected) == 1
    step = selected[0]
    assert step["if"] == "matrix.lane == 'contracts'"
    assert not step.get("continue-on-error")
    assert step["run"].strip().splitlines() == ["set -euo pipefail", "command -v bash", "command -v envsubst"]


def test_current_contract_lane_keeps_required_kubernetes_executables():
    require_prerequisites(workflow())


@pytest.mark.parametrize("fault", ["missing", "optional", "wrong-lane", "missing-bash", "missing-envsubst"])
def test_missing_or_weakened_executable_prerequisite_is_rejected(fault):
    value = deepcopy(workflow())
    steps = value["jobs"]["test-rust-services"]["steps"]
    step = next(step for step in steps if step.get("name") == "Require Kubernetes deployment contract executables")
    if fault == "missing":
        steps.remove(step)
    elif fault == "optional":
        step["continue-on-error"] = True
    elif fault == "wrong-lane":
        step["if"] = "false"
    else:
        step["run"] = step["run"].replace("command -v " + fault.removeprefix("missing-"), "true")
    with pytest.raises(AssertionError):
        require_prerequisites(value)


def test_retired_provider_composite_is_not_a_current_kubernetes_gate():
    assert not (ROOT / "rust/crates/canvas-acceptance").exists()
    assert not (ROOT / "scripts/ci/run-published-canvas-contracts.sh").exists()
    # The retained native publication/model tests own their exact contracts.
    # Full cluster/profile execution requires separately owned qualification.
