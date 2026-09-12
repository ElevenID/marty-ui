"""Execute the shared migration dispatch with synthetic source/DB owners."""

import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("fails", [False, True])
def test_body_capture_dispatch_is_explicit_quiet_and_disposes_database(
    monkeypatch, capsys, fails
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    probe = importlib.import_module("prepare_canvas_published_schema")
    for key in tuple(probe.os.environ):
        if key.startswith("MARTY_CANVAS_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("MARTY_CANVAS_WORKER_BODY_TIMEOUT_CASE", "roster_body_stall")
    source = "synthetic published worker source"
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    fixture = {
        "observed_source_sha256": source_hash,
        "migration_revisions": ["synthetic-revision"],
    }

    def read(path, *args, **kwargs):
        if path.name == "canvas-worker-consumer-range-oracle.json":
            return json.dumps(fixture)
        assert path == Path("/synthetic-worker.py")
        return source

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(
        probe.importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin="/synthetic-worker.py"),
    )
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, statement):
            calls.append(str(statement))
            return SimpleNamespace(scalars=lambda: ["synthetic-revision"])

    engine = SimpleNamespace(
        begin=Connection,
        connect=Connection,
        dispose=lambda: calls.append("dispose"),
    )
    monkeypatch.setattr(probe, "create_engine", lambda *args, **kwargs: engine)
    migration = ModuleType("services.issuance.manage_migrations")
    migration.upgrade = lambda: calls.append("upgrade")
    monkeypatch.setitem(sys.modules, migration.__name__, migration)
    runner = ModuleType("run_canvas_worker_body_timeout_oracle")
    failure = AssertionError("synthetic capture mismatch")
    observation = {"schema": "synthetic-observation", "result": 1.0}

    def run(case):
        assert case == "roster_body_stall"
        calls.append("body")
        print("synthetic private stdout")
        print("synthetic private stderr", file=sys.stderr)
        if fails:
            raise failure
        return observation

    runner.run = run
    monkeypatch.setitem(sys.modules, runner.__name__, runner)
    if fails:
        with pytest.raises(AssertionError) as caught:
            probe.prepare()
        assert caught.value is failure
    else:
        report = probe.prepare()
        assert report["worker_body_timeout"] is observation
        assert report["status"] == "passed"
        assert report["worker_sha256"] == source_hash
        assert not any(key in report for key in ("worker_timeout", "worker_deadline"))
    assert calls[-1] == "dispose"
    assert calls.count("body") == calls.count("upgrade") == calls.count("dispose") == 1
    assert capsys.readouterr() == ("", "")
