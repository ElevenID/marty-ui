"""Fixture failure/ownership tests, not application concurrency parity evidence."""

from contextlib import contextmanager
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fixture_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("run_canvas_worker_startup_oracle")


class Child:
    def __init__(self, returncode=None, fail_wait=False):
        self.returncode = returncode
        self.fail_wait = fail_wait
        self.killed = False
        self.reaped = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        assert timeout == 10
        self.reaped = True
        if self.fail_wait:
            raise RuntimeError("synthetic cleanup failure")
        return self.returncode


class Engine:
    def __init__(self, blocked=2):
        self.blocked = blocked
        self.locked = False
        self.released = False

    @contextmanager
    def begin(self):
        self.locked = True
        try:
            yield SimpleNamespace(exec_driver_sql=lambda sql: None)
        finally:
            self.locked = False
            self.released = True

    @contextmanager
    def connect(self):
        assert self.locked
        yield SimpleNamespace(
            execute=lambda sql: SimpleNamespace(scalar_one=lambda: self.blocked)
        )


def launch(module, engine, callback=lambda: None):
    return module.start_blocked_workers(
        engine,
        {},
        ["worker-a", "worker-b"],
        "fixture barrier",
        "fixture waiters",
        callback,
    )


def test_barrier_releases_and_transfers_live_child_ownership(
    fixture_module, monkeypatch
):
    engine = Engine()
    children = {name: Child() for name in ["worker-a", "worker-b"]}
    monkeypatch.setattr(
        fixture_module, "start_worker", lambda case, name: children[name]
    )
    observed = []
    result = launch(fixture_module, engine, lambda: observed.append(engine.locked))
    assert observed == [True]
    assert result == children and engine.released
    assert all(not child.killed and not child.reaped for child in children.values())
    fixture_module.finish_workers(result)
    assert all(child.killed and child.reaped for child in children.values())


def test_partial_start_failure_reaps_already_started_child(fixture_module, monkeypatch):
    engine, first = Engine(), Child()

    def start(case, name):
        if name == "worker-b":
            raise RuntimeError("synthetic start failure")
        return first

    monkeypatch.setattr(fixture_module, "start_worker", start)
    with pytest.raises(RuntimeError, match="synthetic start failure"):
        launch(fixture_module, engine)
    assert first.killed and first.reaped and engine.released


@pytest.mark.parametrize("failure", ["exit", "timeout", "observation"])
def test_barrier_failure_releases_and_reaps_both(fixture_module, monkeypatch, failure):
    engine = Engine(blocked=1 if failure == "timeout" else 2)
    children = {name: Child() for name in ["worker-a", "worker-b"]}
    if failure == "exit":
        children["worker-a"].returncode = 1
    if failure == "timeout":
        clock = iter([0, 21])
        monkeypatch.setattr(fixture_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        fixture_module, "start_worker", lambda case, name: children[name]
    )

    def observe():
        if failure == "observation":
            raise AssertionError("synthetic observation failure")

    with pytest.raises(AssertionError):
        launch(fixture_module, engine, observe)
    assert engine.released
    assert all(child.reaped for child in children.values())


def test_cleanup_error_does_not_skip_other_owned_children(fixture_module):
    first, second = Child(), Child(fail_wait=True)
    with pytest.raises(RuntimeError, match="synthetic cleanup failure"):
        fixture_module.finish_workers({"worker-a": first, "worker-b": second})
    assert first.killed and first.reaped and second.killed and second.reaped


def test_duplicate_worker_identity_is_rejected_before_start(fixture_module):
    engine = Engine()
    with pytest.raises(AssertionError):
        fixture_module.start_blocked_workers(
            engine, {}, ["same", "same"], "lock", "wait", lambda: None
        )
    assert not engine.locked and not engine.released


def test_process_helpers_import_without_database_library(fixture_module, monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlalchemy", None)
    module = importlib.reload(fixture_module)
    assert callable(module.start_blocked_workers)
    assert callable(module.finish_workers)
