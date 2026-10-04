"""Closed post-join diagnostics; not a replacement for published replay."""

from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "synthetic-private-lease-observation"
FIELDS = {"jobs", "facts", "oauth", "snapshot", "heartbeat", "target", "shape"}


@pytest.fixture
def owners(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("run_canvas_worker_lease_expiry_oracle"),
        importlib.import_module("prepare_canvas_published_schema"),
    )


def observation():
    return {
        "jobs": [{"result": PRIVATE}],
        "facts": [],
        "oauth": {"status": PRIVATE},
        "snapshot": {"application": PRIVATE},
        "heartbeat": {"phase": "idle"},
        "target": {"config_version": 1},
    }


def test_joined_equality_is_still_required_and_only_fixed_flags_escape(owners):
    oracle, probe = owners
    expected = observation()
    oracle.require_joined_observation(deepcopy(expected), expected)
    current = deepcopy(expected)
    current["heartbeat"]["phase"] = PRIVATE
    with pytest.raises(oracle.LeaseObservationChanged) as caught:
        oracle.require_joined_observation(current, expected)
    assert caught.value.args == ()
    assert set(caught.value.__dict__) == {"changed_sections"}
    report = probe.failure_report(caught.value)
    assert set(report["lease_observation_diagnostics"]) == FIELDS
    assert report["lease_observation_diagnostics"] == {
        field: field == "heartbeat" for field in FIELDS
    }
    assert PRIVATE not in json.dumps(report)


def test_joined_shape_change_still_fails_without_exposing_extra_payload(owners):
    oracle, probe = owners
    expected = observation()
    current = deepcopy(expected)
    current[PRIVATE] = {"secret": PRIVATE}
    with pytest.raises(oracle.LeaseObservationChanged) as caught:
        oracle.require_joined_observation(current, expected)
    report = probe.failure_report(caught.value)
    assert report["lease_observation_diagnostics"]["shape"] is True
    assert sum(report["lease_observation_diagnostics"].values()) == 1
    assert PRIVATE not in json.dumps(report)


@pytest.mark.parametrize(
    "section", ["jobs", "facts", "oauth", "snapshot", "heartbeat", "target"]
)
def test_each_observation_section_is_reported_without_its_value(owners, section):
    oracle, probe = owners
    expected = observation()
    current = deepcopy(expected)
    current[section] = PRIVATE
    with pytest.raises(oracle.LeaseObservationChanged) as caught:
        oracle.require_joined_observation(current, expected)
    report = probe.failure_report(caught.value)
    assert report["lease_observation_diagnostics"] == {
        field: field == section for field in FIELDS
    }
    assert PRIVATE not in json.dumps(report)


@pytest.mark.parametrize("mutation", ["missing", "extra", "string", "subclass"])
def test_malformed_diagnostic_payload_never_escapes(owners, mutation):
    oracle, probe = owners
    failure = oracle.LeaseObservationChanged({field: False for field in FIELDS})
    failure.args = (PRIVATE,)
    failure.add_note(PRIVATE)
    if mutation == "missing":
        failure.changed_sections.pop("jobs")
    elif mutation == "extra":
        failure.changed_sections[PRIVATE] = True
    elif mutation == "string":
        failure.changed_sections["jobs"] = PRIVATE
    else:
        failure.changed_sections = type("DerivedDict", (dict,), {})(
            failure.changed_sections
        )
    report = probe.failure_report(failure)
    assert "lease_observation_diagnostics" not in report
    assert PRIVATE not in json.dumps(report)


@pytest.mark.parametrize("kind", ["other", "spoof", "subclass", "unloaded"])
def test_only_exact_loaded_lease_exception_can_publish(owners, monkeypatch, kind):
    oracle, probe = owners
    if kind == "other":
        failure = AssertionError(PRIVATE)
    elif kind == "spoof":
        failure = type(
            "LeaseObservationChanged", (AssertionError,), {"__module__": oracle.__name__}
        )(PRIVATE)
    elif kind == "subclass":
        failure = type("DerivedLeaseObservation", (oracle.LeaseObservationChanged,), {})({})
    else:
        failure = oracle.LeaseObservationChanged({})
        monkeypatch.delitem(probe.sys.modules, oracle.__name__)
    failure.changed_sections = {field: False for field in FIELDS}
    report = probe.failure_report(failure)
    assert "lease_observation_diagnostics" not in report
    assert PRIVATE not in json.dumps(report)
