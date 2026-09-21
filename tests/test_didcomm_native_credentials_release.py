from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_didcomm_native_credentials_release import (
    NativeDidcommReleaseError,
    validate_release_gate,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/didcomm-native-consumer-ownership.json").read_text(
        encoding="utf-8"
    )
)
LOCK = json.loads((ROOT / "release/stack-lock.json").read_text(encoding="utf-8"))


def _component(lock: dict) -> dict:
    matches = [
        item
        for item in lock["components"]
        if item["name"] == "marty-credentials-issuance"
    ]
    assert len(matches) == 1
    return matches[0]


def _qualified_models() -> tuple[dict, dict]:
    contract = deepcopy(CONTRACT)
    lock = deepcopy(LOCK)
    # Test-only values exercise the validator; the checked-in release pin stays null.
    release = {
        "version": "999.999.999",
        "commit": contract["release_gate"]["required_source_checkpoint"],
        "digest": "sha256:" + "a" * 64,
    }
    contract["release_gate"].update(state="qualified", qualified_release=release)
    component = _component(lock)
    component.update(version=release["version"], commit=release["commit"])
    component["artifacts"][0]["digest"] = release["digest"]
    return contract, lock


def test_current_activation_is_explicitly_unlandable_without_inventing_a_release() -> (
    None
):
    gate = CONTRACT["release_gate"]
    assert gate["state"] == "blocked_pending_credentials_release"
    assert gate["qualified_release"] is None
    assert gate["required_source_checkpoint"] == (
        "4dbf77f06aa66c9c1bc4fa882d21580782825ec5"
    )
    assert gate["minimum_version"] == "0.1.75"
    component = _component(LOCK)
    assert {
        "version": component["version"],
        "commit": component["commit"],
        "digest": component["artifacts"][0]["digest"],
    } == gate["current_incompatible_lock"]
    with pytest.raises(NativeDidcommReleaseError, match="activation is blocked"):
        validate_release_gate(CONTRACT, LOCK)


def test_exact_future_release_pin_can_satisfy_the_closed_gate() -> None:
    contract, lock = _qualified_models()
    validate_release_gate(contract, lock)


@pytest.mark.parametrize(
    "mutation",
    ["version", "commit", "digest", "checkpoint", "release_commit", "image"],
)
def test_partial_stale_or_wrong_release_pins_fail_closed(mutation: str) -> None:
    contract, lock = _qualified_models()
    component = _component(lock)
    if mutation == "version":
        contract["release_gate"]["qualified_release"]["version"] = "0.1.74"
        component["version"] = "0.1.74"
    elif mutation == "commit":
        component["commit"] = "b" * 40
    elif mutation == "digest":
        component["artifacts"][0]["digest"] = "sha256:" + "b" * 64
    elif mutation == "checkpoint":
        contract["release_gate"]["required_source_checkpoint"] = "c" * 40
    elif mutation == "release_commit":
        contract["release_gate"]["qualified_release"]["commit"] = "c" * 40
        component["commit"] = "c" * 40
    else:
        component["artifacts"][0]["uri"] = "ghcr.io/elevenid/unreviewed"
    with pytest.raises(NativeDidcommReleaseError):
        validate_release_gate(contract, lock)


def test_ci_and_cd_execute_the_unbypassable_release_gate() -> None:
    invocation = "python scripts/check_didcomm_native_credentials_release.py"
    assert invocation in (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert invocation in (ROOT / ".github/workflows/cd.yml").read_text(encoding="utf-8")
