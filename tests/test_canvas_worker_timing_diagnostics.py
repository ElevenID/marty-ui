"""Closed timing-failure diagnostics, not a worker timeout qualification."""

import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def owners(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("run_canvas_worker_deadline_oracle"),
        importlib.import_module("prepare_canvas_published_schema"),
    )


def sample(age, before, after):
    return {
        "row": {
            "id": "worker-validation-job",
            "attempt_count": 1,
            "started_at": "private-absolute-timestamp-sentinel",
            "age_seconds": age,
        },
        "before": before,
        "after": after,
    }


def test_real_disagreement_exposes_only_derived_seconds_with_unchanged_tolerance(
    owners,
):
    oracle, probe = owners
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    initial = sample(1, 100, 100.125)
    terminal = sample(30, 130, 130.125)
    with pytest.raises(oracle.DeadlineClockDisagreement) as caught:
        oracle.assert_job_timing(
            terminal, matrix["timing_bounds"], initial, deadline=True
        )
    assert str(caught.value) == "" and caught.value.args == ()
    report = probe.failure_report(caught.value)
    assert report["timing_diagnostics"] == {
        "database_elapsed_seconds": 29,
        "monotonic_lower_seconds": 29.375,
        "monotonic_upper_seconds": 30.625,
    }
    encoded = json.dumps(report, allow_nan=False)
    assert "private-absolute-timestamp-sentinel" not in encoded
    assert "worker-validation-job" not in encoded
    assert all(not key.endswith("_at") for key in report["timing_diagnostics"])


@pytest.mark.parametrize(
    "drift,accepted", [(-0.5, True), (0.5, True), (-0.501, False), (0.501, False)]
)
def test_diagnostic_does_not_widen_or_reverse_clock_agreement(owners, drift, accepted):
    oracle, _ = owners
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    args = (
        sample(30, 129 + drift, 129 + drift),
        matrix["timing_bounds"],
        sample(1, 100, 100),
    )
    if accepted:
        oracle.assert_job_timing(*args, deadline=True)
    else:
        with pytest.raises(oracle.DeadlineClockDisagreement):
            oracle.assert_job_timing(*args, deadline=True)


@pytest.mark.parametrize("value", [25, 35])
def test_non_clock_timing_failure_retains_the_closed_original_envelope(owners, value):
    oracle, probe = owners
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    with pytest.raises(AssertionError) as caught:
        oracle.assert_job_timing(
            sample(value, 99 + value, 99 + value),
            matrix["timing_bounds"],
            sample(1, 100, 100),
            deadline=True,
        )
    assert type(caught.value) is AssertionError
    assert "timing_diagnostics" not in probe.failure_report(caught.value)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "string",
        "bool",
        "nan",
        "positive-infinity",
        "negative-infinity",
        "huge-int",
        "too-large",
        "too-negative",
        "list",
        "dict-subclass",
        "float-subclass",
    ],
)
def test_malformed_diagnostic_payload_never_leaks_or_broadens_envelope(
    owners, mutation
):
    oracle, probe = owners
    failure = oracle.DeadlineClockDisagreement(29, 29.5, 30.5)
    failure.args = ("private-exception-message-sentinel",)
    failure.add_note("private-note-sentinel")
    values = failure.timing_diagnostics
    if mutation == "missing":
        values.pop("database_elapsed_seconds")
    elif mutation == "extra":
        values["private-extra-sentinel"] = "private-payload-sentinel"
    elif mutation in {"list", "dict-subclass"}:
        failure.timing_diagnostics = (
            list(values.values())
            if mutation == "list"
            else type("DerivedDict", (dict,), {})(values)
        )
    else:
        values["database_elapsed_seconds"] = {
            "string": "private-string-sentinel",
            "bool": True,
            "nan": float("nan"),
            "positive-infinity": float("inf"),
            "negative-infinity": float("-inf"),
            "huge-int": 10**1000,
            "too-large": 300.001,
            "too-negative": -300.001,
            "float-subclass": type("DerivedFloat", (float,), {})(29),
        }[mutation]
    report = probe.failure_report(failure)
    assert set(report) == {"status", "error_class", "frames"}
    assert "private-" not in json.dumps(report, allow_nan=False)


@pytest.mark.parametrize("value", [-300, -300.0, 0, 0.0, 300, 300.0])
def test_diagnostic_range_accepts_only_declared_inclusive_relative_seconds(
    owners, value
):
    oracle, probe = owners
    failure = oracle.DeadlineClockDisagreement(value, 29.5, 30.5)
    assert probe.safe_timing_diagnostics(failure)["database_elapsed_seconds"] == value


@pytest.mark.parametrize(
    "kind", ["unknown", "spoof-name", "subclass", "unloaded-owner"]
)
def test_only_exact_already_loaded_exception_class_can_publish_diagnostics(
    owners, monkeypatch, kind
):
    oracle, probe = owners
    if kind == "unknown":
        failure = RuntimeError("private-message-sentinel")
    elif kind == "spoof-name":
        failure = type(
            "DeadlineClockDisagreement",
            (AssertionError,),
            {"__module__": oracle.__name__},
        )("private-message-sentinel")
    elif kind == "subclass":
        failure = type(
            "DerivedClockDisagreement", (oracle.DeadlineClockDisagreement,), {}
        )(29, 29.5, 30.5)
    else:
        failure = oracle.DeadlineClockDisagreement(29, 29.5, 30.5)
        monkeypatch.delitem(probe.sys.modules, "run_canvas_worker_deadline_oracle")
    failure.timing_diagnostics = {
        "database_elapsed_seconds": 29,
        "monotonic_lower_seconds": 29.5,
        "monotonic_upper_seconds": 30.5,
    }
    report = probe.failure_report(failure)
    assert "timing_diagnostics" not in report
    assert "private-message-sentinel" not in json.dumps(report)


def test_finite_input_overflow_is_rejected_without_nonfinite_diagnostics(owners):
    oracle, probe = owners
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    with pytest.raises(AssertionError) as caught:
        oracle.assert_job_timing(
            sample(30, 1e308, 1e308),
            matrix["timing_bounds"],
            sample(1, -1e308, -1e308),
            deadline=True,
        )
    assert type(caught.value) is AssertionError
    assert "timing_diagnostics" not in probe.failure_report(caught.value)
