"""Failure-only diagnostics must not change frozen assertions or disclose rows."""

import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "synthetic-private-query-and-secret"


@pytest.fixture
def owners(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("run_canvas_worker_lease_expiry_oracle"),
        importlib.import_module("run_canvas_lease_probe_diagnostics"),
    )


def row():
    return dict(waiting_count=1, matching_count=0, worker_pid=300, blocker_pid=200)


def failed_assertion(oracle, value):
    try:
        oracle.assert_blocker(value, 200)
    except AssertionError as failure:
        failure.args = (PRIVATE,)
        failure.add_note(PRIVATE)
        return failure
    raise AssertionError("test did not exercise original rejecting assertion")


def test_original_rejecting_assertion_stays_rejected_and_fields_are_closed(owners):
    oracle, wrapper = owners
    failure = failed_assertion(oracle, row())
    assert wrapper.owned_blocker_diagnostics(failure) == row()
    assert PRIVATE not in json.dumps(wrapper.owned_blocker_diagnostics(failure))


@pytest.mark.parametrize(
    "mutation",
    ["extra", "missing", "bool", "string", "negative", "huge", "owner", "subclass"],
)
def test_invalid_or_private_fields_cannot_escape(owners, mutation):
    oracle, wrapper = owners
    value = row()
    if mutation == "extra":
        value["query"] = PRIVATE
    elif mutation == "missing":
        del value["worker_pid"]
    elif mutation == "bool":
        value["worker_pid"] = True
    elif mutation == "string":
        value["worker_pid"] = PRIVATE
    elif mutation == "negative":
        value["waiting_count"] = -1
    elif mutation == "huge":
        value["worker_pid"] = 2**31
    elif mutation == "owner":
        value["blocker_pid"] = 201
    else:
        value = type("Derived", (dict,), {})(value)
    assert wrapper.owned_blocker_diagnostics(failed_assertion(oracle, value)) is None


def test_other_exception_or_spoofed_frame_is_not_accepted(owners):
    _, wrapper = owners

    def assert_blocker(row, expected_blocker):
        raise AssertionError(PRIVATE)

    try:
        assert_blocker(row(), 200)
    except AssertionError as failure:
        assert wrapper.owned_blocker_diagnostics(failure) is None
    assert wrapper.owned_blocker_diagnostics(RuntimeError(PRIVATE)) is None


def test_cli_success_json_remains_identical(owners, monkeypatch, capsys):
    _, wrapper = owners
    original = {"z": 2, "a": {"status": "passed"}}
    monkeypatch.setattr(wrapper, "prepare", lambda: original)
    assert wrapper.main() == 0
    assert capsys.readouterr().out == json.dumps(original, sort_keys=True) + "\n"


def test_cli_failure_remains_nonzero_with_no_messages_or_notes(
    owners, monkeypatch, capsys
):
    oracle, wrapper = owners

    def prepare():
        raise failed_assertion(oracle, row())

    monkeypatch.setattr(wrapper, "prepare", prepare)
    assert wrapper.main() == 1
    output = capsys.readouterr().out
    assert PRIVATE not in output
    assert json.loads(output)["owned_blocker_diagnostics"] == row()
