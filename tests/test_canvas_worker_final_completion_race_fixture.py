"""Validate normative inputs, not a substitute for the actual repository races."""

import json
from pathlib import Path


def test_final_completion_race_inputs_preserve_normative_winner_and_scope():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    scenario = json.loads(
        (contracts / "canvas-worker-final-completion-race-scenarios.json").read_text()
    )
    contract = json.loads((contracts / "issuance-canvas-sync-worker.json").read_text())
    filename, pointer = scenario["normative_requirement"].split("#")
    assert filename == "issuance-canvas-sync-worker.json"
    requirement = contract
    for key in pointer.strip("/").split("/"):
        requirement = (
            requirement[int(key)] if isinstance(requirement, list) else requirement[key]
        )
    assert requirement["name"] == "final_attempt_completion_race"
    assert scenario["lease_seconds"] == 30
    assert (
        scenario["initial_history"]
        == "canvas-worker-provider-final-scenarios.json#/initial_job_seed"
    )
    assert scenario["cases"] == [
        {
            "winner": "completion",
            "status": "succeeded",
            "completion_return": True,
            "target_enabled": True,
            "terminal_winners": 1,
            "stale_writes": 0,
        },
        {
            "winner": "recovery",
            "status": "dead_letter",
            "completion_return": False,
            "target_enabled": False,
            "terminal_winners": 1,
            "stale_writes": 0,
        },
    ]
    for case in scenario["cases"]:
        for field in ("terminal_winners", "stale_writes"):
            assert case[field] == requirement[field]
    assert "not a captured Python process reference" in scenario["scope"]
    assert (
        "Whole-worker/provider composition remains separately required"
        in scenario["scope"]
    )
