"""Held-provider harness integrity; not whole-process parity evidence."""

import importlib
import json
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest


def test_generation_reference_keeps_observed_difference_and_real_crash_history():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (contracts / "canvas-worker-provider-generation-scenarios.json").read_text()
    )
    observed = json.loads(
        (contracts / "canvas-worker-provider-generation-oracle.json").read_text()
    )
    baseline = json.loads(
        (contracts / "canvas-worker-provider-final-oracle.json").read_text()
    )
    assert matrix["extends"] == "canvas-worker-provider-final-scenarios.json"
    assert len(matrix["generation_change_sql"]) == 2
    assert all(
        "canvas_evidence_sync_jobs" not in sql
        for sql in matrix["generation_change_sql"]
    )
    assert "validated_config_version=2" in matrix["generation_change_sql"][1]
    assert observed["generation_edit"] == {
        "before": {"config_version": 1, "enabled": True},
        "after": {"config_version": 2, "enabled": True},
        "job_unchanged": True,
    }
    assert observed["generation_recovered"] == {
        "config_version": 2,
        "enabled": False,
        "other_target_fields_preserved": True,
    }
    # All prior transport, durable job/issuance, renewal and exit observations
    # remain exact; only the explicit new configuration observations are added.
    assert {
        key: value
        for key, value in observed.items()
        if key not in {"generation_edit", "generation_recovered"}
    } == baseline
    assert (
        observed["crash_exit_code"] == -9
        and observed["exit_code_after_interrupt"] == -2
    )
    assert observed["completed"]["jobs"][0]["attempt_count"] == 8
    assert observed["completed"]["jobs"][0]["status"] == "dead_letter"


@pytest.mark.parametrize(
    "failure", [None, "child_exit", "timeout", "wrong_requests", "missing_release"]
)
@pytest.mark.parametrize(
    "scenario", ["generation", "completion", "recovery_first", "resource_race"]
)
def test_generation_parent_requires_release_exact_request_and_clean_child(
    monkeypatch, tmp_path, failure, scenario
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    request = {"method": "GET", "path": "/synthetic"}
    cases = (
        ["platform_reconfigured", "application_removed"]
        if scenario == "resource_race"
        else [scenario]
    )
    response = {"status": 503, "body": {"error": "synthetic-unavailable"}}
    reference = (
        {case: {"requests": [request]} for case in cases}
        if scenario == "resource_race"
        else {
            "case": "final" if scenario == "generation" else scenario,
            "requests": [request],
        }
    )
    inputs = iter(
        [
            json.dumps({"stages": [{}]}),
            json.dumps(reference),
            *(
                [
                    json.dumps(
                        {
                            "cases": [{"name": case} for case in cases],
                            "response": response,
                        }
                    )
                ]
                if scenario == "resource_race"
                else []
            ),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    closed, waits, commands, fixtures, children = [], [], [], [], []

    class Fixture:
        def __enter__(self):
            certificate_root = tmp_path / str(len(fixtures))
            certificate_root.mkdir()
            received = Event()
            received.set()
            self.https = SimpleNamespace(
                certificates=SimpleNamespace(name=str(certificate_root)),
                cert=certificate_root / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=[] if failure == "wrong_requests" else [request],
                received=received,
                release=Event(),
            )
            fixtures.append(self.https)
            return self.https

        def __exit__(self, *_):
            expected = response if scenario == "resource_race" else {}
            assert self.https.stage == {**expected, "hold_response": True}
            closed.append(True)

    class Child:
        returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            assert fixtures[-1].release.is_set()
            if failure == "timeout" and timeout == 90:
                raise native.subprocess.TimeoutExpired("synthetic-child", timeout)
            self.returncode = 1 if failure == "child_exit" else 0
            return "", ""

    def launch(command, **kwargs):
        expected_case = cases[len(commands)]
        commands.append(command)
        assert kwargs["env"]["MARTY_CANVAS_WORKER_SIGNAL_NAME"] == expected_case
        child = Child()
        children.append(child)
        return child

    def wait(actual, predicate, description, timeout=30):
        assert actual is children[-1] and not fixtures[-1].release.is_set()
        waits.append(description)
        if description == "verified pending-I/O state":
            control = Path(fixtures[-1].certificates.name) / "native-control"
            assert (control / "request-received").is_file()
            if failure == "missing_release":
                raise AssertionError("missing committed state")
            (control / "release-response").touch()
        assert predicate()

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(native.subprocess, "Popen", launch)
    monkeypatch.setattr(native, "wait_for", wait)
    if failure is None:
        native.run("synthetic-not-executed", scenario)
    else:
        with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
            native.run("synthetic-not-executed", scenario)
    executed = len(cases) if failure is None else 1
    assert (
        commands
        == [
            [
                "synthetic-not-executed",
                f"worker_provider_{scenario}_native_child",
                "--exact",
                "--nocapture",
            ]
        ]
        * executed
    )
    assert waits == ["actual HTTPS request", "verified pending-I/O state"] * executed
    assert all(child.poll() is not None for child in children)
    assert all(fixture.release.is_set() for fixture in fixtures)
    assert closed == [True] * executed
