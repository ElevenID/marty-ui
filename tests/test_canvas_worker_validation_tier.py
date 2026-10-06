"""Fail-closed native validation selection; these do not execute the real worker."""

import copy
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    monkeypatch.delenv("MARTY_CANVAS_WORKER_VALIDATION_TIER", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_FULL_QUALIFICATION", raising=False)
    return importlib.import_module("test_canvas_worker_rest_https")


@pytest.fixture
def corpus():
    cases = json.loads(
        (ROOT / "contracts/canvas-worker-validation-scenarios.json").read_text()
    )["cases"]
    oracle = json.loads(
        (ROOT / "contracts/canvas-worker-validation-oracle.json").read_text()
    )
    inventory = json.loads(
        (ROOT / "contracts/canvas-worker-tier-obligations.json").read_text()
    )
    return cases, oracle, inventory


def test_native_timing_emits_only_corpus_name_duration_and_status(
    native, monkeypatch, capsys
):
    monkeypatch.setattr(native.time, "monotonic", lambda: 10.125)
    native.emit_phase("scenario", "validation.invalid_roster_batch", 10.0, "failed")
    assert capsys.readouterr().out == (
        'MARTY_CI_PHASE_V1 {"duration_ms":125,"name":"validation.invalid_roster_batch",'
        '"phase":"scenario","status":"failed"}\n'
    )


def test_native_matrix_times_failed_case_without_swallowing_failure(
    native, monkeypatch, capsys
):
    def fail_case(*_arguments):
        raise RuntimeError("synthetic-private-failure")

    monkeypatch.setattr(native, "run_scenario", fail_case)
    with pytest.raises(RuntimeError, match="synthetic-private-failure"):
        native.run("unused-executable", "validation")
    marker = capsys.readouterr().out.strip()
    assert marker.startswith("MARTY_CI_PHASE_V1 ")
    value = json.loads(marker.removeprefix("MARTY_CI_PHASE_V1 "))
    assert set(value) == {"phase", "name", "duration_ms", "status"}
    assert value["phase"] == "scenario"
    assert value["name"].startswith("validation.")
    assert value["status"] == "failed"
    assert "synthetic-private-failure" not in marker


def test_routine_cases_retain_processor_lock_races_and_privacy(native, corpus):
    cases, _, inventory = corpus
    processor = {
        case["name"] for case in cases if case.get("boundary") == "processor_dispatch"
    }
    routine = set(inventory["native_validation"]["routine"])
    full_only = {entry["case"] for entry in inventory["native_validation"]["full_only"]}
    assert len(processor) == 7
    assert processor <= routine
    assert routine - processor == {
        "prohibited_metadata",
        "application_removed_after_target_read",
        "candidate_removed_after_target_read",
    }
    assert full_only == native.VALIDATION_CASES - routine
    assert not full_only & processor


@pytest.mark.parametrize(
    "tier,qualification,count",
    [(None, None, 20), ("full", "1", 20), ("routine", "0", 10)],
)
def test_real_run_selects_exact_cases_before_dispatch(
    native, monkeypatch, tier, qualification, count
):
    if tier is not None:
        monkeypatch.setenv(native.VALIDATION_TIER, tier)
    if qualification is not None:
        monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", "validation")
    names = [call[4]["name"] for call in calls]
    expected = (
        native.ROUTINE_VALIDATION_CASES
        if tier == "routine"
        else native.VALIDATION_CASES
    )
    assert len(names) == count
    assert set(names) == expected
    assert all(
        call[0] == "synthetic-test-executable"
        and call[1] == "validation"
        and len(call[2]["stages"]) == len(call[3]["observations"]) == 1
        and call[2]["stages"][0]["name"] == call[3]["observations"][0]["name"]
        for call in calls
    )


@pytest.mark.parametrize(
    "tier,qualification",
    [
        ("routine", "1"),
        ("routine", "invalid"),
        ("full", "invalid"),
        ("full", ""),
        ("", "0"),
        ("partial", "0"),
    ],
)
def test_invalid_tier_or_qualification_never_starts_child(
    native, monkeypatch, tier, qualification
):
    monkeypatch.setenv(native.VALIDATION_TIER, tier)
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    with pytest.raises(ValueError):
        native.run("synthetic-test-executable", "validation")
    assert not calls


@pytest.mark.parametrize(
    "change",
    [
        "missing-case",
        "duplicate-case",
        "same-count-substitution",
        "missing-oracle",
        "extra-oracle",
        "missing-routine",
        "duplicate-routine",
        "different-routine",
        "missing-full-only",
        "duplicate-full-only",
        "different-fast-owner",
        "missing-native-inventory",
    ],
)
def test_inventory_drift_rejected_before_selection(native, corpus, change):
    cases, oracle, inventory = copy.deepcopy(corpus)
    declared = inventory["native_validation"]
    if change == "missing-case":
        cases.pop()
    elif change == "duplicate-case":
        cases[-1] = cases[0]
    elif change == "same-count-substitution":
        cases[-1] = {**cases[-1], "name": "new_case"}
    elif change == "missing-oracle":
        oracle.pop(next(iter(oracle)))
    elif change == "extra-oracle":
        oracle["new_case"] = {}
    elif change == "missing-routine":
        declared["routine"].pop()
    elif change == "duplicate-routine":
        declared["routine"][-1] = declared["routine"][0]
    elif change == "different-routine":
        declared["routine"][-1] = "target_disabled"
    elif change == "missing-full-only":
        declared["full_only"].pop()
    elif change == "duplicate-full-only":
        declared["full_only"][-1]["case"] = declared["full_only"][0]["case"]
    elif change == "different-fast-owner":
        declared["full_only"][0]["fast_owners"][0] = "not_a_proof"
    else:
        del inventory["native_validation"]
    with pytest.raises(AssertionError, match="inventory changed"):
        native.selected_validation_cases(cases, oracle, inventory, "routine")


@pytest.mark.parametrize("kind", ["scenarios", "oracle"])
def test_complete_frozen_corpus_change_rejected_before_child(native, monkeypatch, kind):
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    monkeypatch.setitem(native.VALIDATION_CORPUS_SHA256, kind, "0" * 64)
    with pytest.raises(
        AssertionError, match=f"Native validation {kind} corpus changed"
    ):
        native.run("synthetic-test-executable", "validation")
    assert not calls
