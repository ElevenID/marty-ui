"""Native deadline comparator tests, not native-worker execution evidence."""

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
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


@pytest.mark.parametrize("scenario,stages", [("rest", 4), ("facts", 4), ("retry", 5)])
def test_existing_scenarios_keep_one_child_and_all_stages(
    native, monkeypatch, scenario, stages
):
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-test-executable", scenario)
    assert len(calls) == 1
    assert len(calls[0][2]["stages"]) == len(calls[0][3]["observations"]) == stages
