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
        self.statements = []

    @contextmanager
    def begin(self):
        self.locked = True
        try:

            def execute(sql):
                assert self.locked
                self.statements.append(sql)
                if sql == "synthetic release failure":
                    raise RuntimeError(sql)

            yield SimpleNamespace(exec_driver_sql=execute)
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


@pytest.mark.parametrize("identities", [[], ["same", "same"], ["a", "b", "c"]])
def test_invalid_worker_identities_are_rejected_before_start(
    fixture_module, identities
):
    engine = Engine()
    with pytest.raises(AssertionError):
        fixture_module.start_blocked_workers(
            engine, {}, identities, "lock", "wait", lambda: None
        )
    assert not engine.locked and not engine.released


@pytest.mark.parametrize("fails", [False, True])
def test_single_worker_release_is_ordered_and_failure_reaps_child(
    fixture_module, monkeypatch, fails
):
    engine, child = Engine(blocked=1), Child()
    monkeypatch.setattr(fixture_module, "start_worker", lambda case, name: child)
    statement = "synthetic release failure" if fails else "remove fixture reference"

    def observed():
        assert engine.locked and engine.statements == ["lock"]
        engine.statements.append("observed")

    def run():
        return fixture_module.start_blocked_workers(
            engine, {}, ["worker-a"], "lock", "wait", observed, [statement]
        )

    if fails:
        with pytest.raises(RuntimeError, match=statement):
            run()
        assert child.killed and child.reaped
    else:
        assert run() == {"worker-a": child}
        assert not child.killed and not child.reaped
        fixture_module.finish_worker(child)
    assert engine.released
    assert engine.statements == ["lock", "observed", statement]


def test_process_helpers_import_without_database_library(fixture_module, monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlalchemy", None)
    module = importlib.reload(fixture_module)
    assert callable(module.start_blocked_workers)
    assert callable(module.finish_workers)
