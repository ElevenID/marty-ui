"""Native deadline comparator tests, not native-worker execution evidence."""

import importlib
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import pytest


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    monkeypatch.delenv("MARTY_CANVAS_WORKER_RETRY_AFTER_TIER", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_FULL_QUALIFICATION", raising=False)
    return importlib.import_module("test_canvas_worker_rest_https")


def observation(delay):
    updated = datetime(2026, 9, 6, tzinfo=timezone.utc)
    return "CANVAS_WORKER_RETRY_TIMING=" + json.dumps(
        {
            "available_at": (updated + timedelta(seconds=delay)).isoformat(),
            "updated_at": updated.isoformat(),
        }
    )


@pytest.mark.parametrize(
    "minimum,maximum,delay", [(15, 20, 15), (15, 20, 20), (86400, 86400, 86400)]
)
def test_actual_delay_within_frozen_bounds(native, minimum, maximum, delay):
    native.assert_retry_timing(
        observation(delay),
        {"name": "bounds", "timing": "bounds", "delay_bounds": [minimum, maximum]},
        [],
        {"kind": "bounds", "matches": True},
    )


@pytest.mark.parametrize(
    "minimum,maximum,delay",
    [(15, 20, 14), (15, 20, 21), (86400, 86400, 15), (86400, 86400, 86401)],
)
def test_incorrect_or_overflow_fallback_delay_is_rejected(
    native, minimum, maximum, delay
):
    with pytest.raises(
        AssertionError, match="Native persisted Retry-After timing differs"
    ):
        native.assert_retry_timing(
            observation(delay),
            {"name": "bounds", "timing": "bounds", "delay_bounds": [minimum, maximum]},
            [],
            {"kind": "bounds", "matches": True},
        )


@pytest.mark.parametrize(
    "difference,passes", [(0, True), (-1, True), (1, True), (-2, False), (2, False)]
)
def test_date_deadline_compared_to_actual_emitted_header(native, difference, passes):
    date = format_datetime(datetime(2026, 9, 6, 0, 1, tzinfo=timezone.utc), usegmt=True)
    args = (
        observation(60 + difference),
        {"name": "date", "timing": "http_date"},
        [date],
        {"kind": "http_date", "matches": True},
    )
    if passes:
        native.assert_retry_timing(*args)
    else:
        with pytest.raises(
            AssertionError, match="Native persisted Retry-After timing differs"
        ):
            native.assert_retry_timing(*args)


@pytest.mark.parametrize("output", ["", observation(15) + "\n" + observation(15)])
def test_missing_or_duplicate_timing_evidence_is_rejected(native, output):
    with pytest.raises(AssertionError, match="Expected one actual durable retry"):
        native.assert_retry_timing(output, {}, [], {})


def test_naive_timestamps_are_rejected(native):
    with pytest.raises(AssertionError):
        native.assert_retry_timing(observation(15).replace("+00:00", ""), {}, [], {})


def test_each_retry_case_uses_a_separate_native_child(native, monkeypatch):
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", "retry-after")
    assert len(calls) == 7
    assert len({call[4]["name"] for call in calls}) == 7
    for executable, scenario, spec, reference, case in calls:
        assert executable == "synthetic-test-executable"
        assert scenario == "retry-after"
        assert len(spec["stages"]) == len(reference["observations"]) == 1
        assert (
            spec["stages"][0]["name"]
            == reference["observations"][0]["name"]
            == case["name"]
        )
        assert spec["stages"][0]["status"] == 429


@pytest.mark.parametrize(
    "tier,expected",
    [
        ("routine", {"http_date_future", "malformed"}),
        (
            "full",
            {
                "http_date_future",
                "http_date_past",
                "malformed",
                "negative",
                "zero",
                "clamped",
                "huge_integer",
            },
        ),
    ],
)
def test_explicit_retry_tiers_select_exact_native_cases(
    native, monkeypatch, tier, expected
):
    monkeypatch.setenv(native.RETRY_AFTER_TIER, tier)
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", "retry-after")
    assert {call[4]["name"] for call in calls} == expected
    assert len(calls) == len(expected)


@pytest.mark.parametrize("tier", ["", "partial", "FULL", "2"])
def test_invalid_retry_tier_fails_before_any_child(native, monkeypatch, tier):
    monkeypatch.setenv(native.RETRY_AFTER_TIER, tier)
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="Invalid native Retry-After tier"):
        native.run("synthetic-test-executable", "retry-after")
    assert calls == []


@pytest.mark.parametrize(
    "tier,qualification",
    [
        ("routine", "1"),
        ("routine", "invalid"),
        ("full", "invalid"),
        ("full", ""),
    ],
)
def test_full_qualification_or_invalid_mode_rejects_before_any_child(
    native, monkeypatch, tier, qualification
):
    monkeypatch.setenv(native.RETRY_AFTER_TIER, tier)
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="qualification"):
        native.run("synthetic-test-executable", "retry-after")
    assert calls == []


def test_explicit_full_qualification_runs_every_case(native, monkeypatch):
    monkeypatch.setenv(native.RETRY_AFTER_TIER, "full")
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", "1")
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", "retry-after")
    assert {call[4]["name"] for call in calls} == native.RETRY_AFTER_CASES
    assert len(calls) == 7


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "extra",
        "duplicate",
        "same_count_substitution",
        "missing_reference",
        "extra_reference",
    ],
)
def test_retry_tier_rejects_matrix_or_oracle_drift(native, change):
    names = sorted(native.RETRY_AFTER_CASES)
    cases = [{"name": name} for name in names]
    reference = {name: {} for name in names}
    if change == "missing":
        cases.pop()
    elif change == "extra":
        cases.append({"name": "new_case"})
    elif change == "duplicate":
        cases[-1]["name"] = cases[0]["name"]
    elif change == "same_count_substitution":
        cases[-1]["name"] = "new_case"
    elif change == "missing_reference":
        del reference[names[-1]]
    else:
        reference["new_case"] = {}
    with pytest.raises(AssertionError, match="inventory changed"):
        native.selected_retry_after_cases(cases, reference, "routine")


@pytest.mark.parametrize("scenario,stages", [("rest", 4), ("facts", 4), ("retry", 5)])
def test_existing_scenarios_keep_one_child_and_all_stages(
    native, monkeypatch, scenario, stages
):
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", scenario)
    assert len(calls) == 1
    assert len(calls[0][2]["stages"]) == len(calls[0][3]["observations"]) == stages
