"""Bounded discovery and source-input checks for Canvas's existing tier split."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci.check_canvas_tier_obligations import (
    listed_test_names,
    validate,
    validate_selection,
)

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = json.loads(
    (ROOT / "contracts/canvas-worker-tier-obligations.json").read_text(encoding="utf-8")
)
RUNNER = ROOT / "scripts/ci/run-published-canvas-contracts.sh"


@pytest.mark.parametrize(
    "ignore_file",
    [
        ".dockerignore",
        "services/Dockerfile.dockerignore",
        "rust/services/Dockerfile.ci.dockerignore",
    ],
)
def test_ci_inventory_is_not_copied_into_service_images(ignore_file: str) -> None:
    lines = (ROOT / ignore_file).read_text(encoding="utf-8").splitlines()
    assert "contracts/canvas-worker-tier-obligations.json" in lines


def test_ci_inventory_has_no_rust_runtime_consumer() -> None:
    # A new runtime consumer requires revisiting the CI-only image exclusions.
    for directory in (ROOT / "rust/services", ROOT / "rust/crates"):
        for source in directory.rglob("*.rs"):
            assert "canvas-worker-tier-obligations.json" not in source.read_text(
                encoding="utf-8"
            ), source.relative_to(ROOT)


def discovered() -> set[str]:
    return {
        entry["test"] for entry in INVENTORY["historical"] + INVENTORY["preflights"]
    }


def test_exact_current_inventory_is_source_and_fixture_backed() -> None:
    validate(INVENTORY, discovered())
    assert len(INVENTORY["historical"]) == 33
    assert len(INVENTORY["preflights"]) == 4
    assert (
        "worker_oauth_revocation_counters_reference_matches_published_cycle"
        in discovered()
    )
    assert (
        "worker_oauth_revocation_selection_reference_matches_published_repository"
        in discovered()
    )


def test_compiled_list_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="Duplicate compiled"):
        listed_test_names(
            "worker_timeout_reference_matches_published_process: test\n" * 2
        )


@pytest.mark.parametrize(
    "change", ["missing-historical", "extra-historical", "missing-preflight"]
)
def test_compiled_list_drift_fails_closed(change: str) -> None:
    names = discovered()
    if change == "missing-historical":
        names.remove(INVENTORY["historical"][0]["test"])
    elif change == "extra-historical":
        names.add("worker_new_reference_matches_published_process")
    else:
        names.remove(INVENTORY["preflights"][0]["test"])
    with pytest.raises(ValueError, match="mismatch|missing"):
        validate(INVENTORY, names)


@pytest.mark.parametrize(
    "change", ["duplicate", "assertion", "corpus", "mode", "routine", "input"]
)
def test_inventory_drift_fails_closed(change: str) -> None:
    inventory = deepcopy(INVENTORY)
    if change == "duplicate":
        inventory["historical"][1]["test"] = inventory["historical"][0]["test"]
    elif change == "assertion":
        inventory["historical"][0]["assertion"] = ""
    elif change == "corpus":
        inventory["historical"][0]["test"] = (
            "worker_unknown_reference_matches_published_process"
        )
    elif change == "mode":
        inventory["preflights"][0]["mode"] = "unknown"
    elif change == "routine":
        inventory["preflights"][0]["routine"] = (
            "executed as a routine same-run preflight"
        )
    else:
        inventory["preflights"][0]["inputs"][0] = "contracts/missing-native-input.json"
    with pytest.raises(ValueError):
        validate(inventory, discovered())


def test_guard_is_additive_after_discovery_before_skip_selection() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    discovery = runner.index('worker_tests=$("$worker_executable" --list)')
    guard = runner.index("check_canvas_tier_obligations.py")
    skips = runner.index("preflight_skips=()")
    assert discovery < guard < skips


@pytest.mark.parametrize(
    "mode,qualification",
    [("full", "0"), ("full-after-preflights", "0"), ("full-after-preflights", "1")],
)
def test_exact_selected_set_for_each_tier(mode: str, qualification: str) -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    original = discovered() | {serial, "unrelated_native_worker_test"}
    omitted = {serial}
    if mode == "full-after-preflights":
        omitted |= {entry["test"] for entry in INVENTORY["preflights"]}
        if qualification == "0":
            omitted |= {entry["test"] for entry in INVENTORY["historical"]}
    validate_selection(
        INVENTORY, original, original - omitted, mode, qualification, serial
    )
    if mode == "full-after-preflights" and qualification == "0":
        assert len(omitted - {serial}) == 37
    if mode == "full-after-preflights" and qualification == "1":
        assert len(omitted - {serial}) == 4


def test_same_count_wrong_selected_case_fails_closed() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    extra = "unrelated_native_worker_test"
    original = discovered() | {serial, extra}
    omitted = {serial, extra}
    omitted |= {entry["test"] for entry in INVENTORY["preflights"]}
    omitted |= {entry["test"] for entry in INVENTORY["historical"][1:]}
    assert len(omitted - {serial}) == 37
    with pytest.raises(ValueError, match="selection drift"):
        validate_selection(
            INVENTORY,
            original,
            original - omitted,
            "full-after-preflights",
            "0",
            serial,
        )


def test_unregistered_selected_case_fails_closed() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    original = discovered() | {serial}
    with pytest.raises(ValueError, match="unregistered"):
        validate_selection(
            INVENTORY, original, original | {"new_unknown"}, "full", "0", serial
        )
