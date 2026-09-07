"""Changed-generation harness integrity; not whole-process parity evidence."""

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
@pytest.mark.parametrize("scenario", ["generation", "completion"])
def test_generation_parent_requires_release_exact_request_and_clean_child(
    monkeypatch, tmp_path, failure, scenario
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    request = {"method": "GET", "path": "/synthetic"}
    inputs = iter(
        [
            json.dumps({"stages": [{}]}),
            json.dumps(
                {
                    "case": "final" if scenario == "generation" else "completion",
                    "requests": [request],
                }
            ),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    received, release = Event(), Event()
    received.set()
    closed, waits, commands = [], [], []

    class Fixture:
        def __enter__(self):
            return SimpleNamespace(
                certificates=SimpleNamespace(name=str(tmp_path)),
                cert=tmp_path / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=[] if failure == "wrong_requests" else [request],
                received=received,
                release=release,
            )

        def __exit__(self, *_):
            closed.append(True)

    class Child:
        returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            assert release.is_set()
            if failure == "timeout" and timeout == 90:
                raise native.subprocess.TimeoutExpired("synthetic-child", timeout)
            self.returncode = 1 if failure == "child_exit" else 0
            return "", ""

    child = Child()

    def launch(command, **kwargs):
        commands.append(command)
        assert kwargs["env"]["MARTY_CANVAS_WORKER_SIGNAL_NAME"] == scenario
        return child

    def wait(actual, predicate, description, timeout=30):
        assert actual is child and not release.is_set()
        waits.append(description)
        if description == "verified pending-I/O state":
            assert (tmp_path / "native-control/request-received").is_file()
            if failure == "missing_release":
                raise AssertionError("missing committed state")
            (tmp_path / "native-control/release-response").touch()
        assert predicate()

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(native.subprocess, "Popen", launch)
    monkeypatch.setattr(native, "wait_for", wait)
    if failure is None:
        native.run("synthetic-not-executed", scenario)
    else:
        with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
            native.run("synthetic-not-executed", scenario)
    assert commands == [
        [
            "synthetic-not-executed",
            f"worker_provider_{scenario}_native_child",
            "--exact",
            "--nocapture",
        ]
    ]
    assert waits == ["actual HTTPS request", "verified pending-I/O state"]
    assert child.poll() is not None and release.is_set() and closed == [True]
