"""Exercise concurrency and failure propagation without a live database."""

import importlib.util
from concurrent.futures import Future
from pathlib import Path
import sys
from types import SimpleNamespace
from contextlib import nullcontext

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "db_groups", ROOT / "scripts/ci/run-db-contract-groups.py"
)
GROUPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GROUPS)


@pytest.mark.parametrize("failed", [False, True])
def test_groups_overlap_and_finish_after_sibling_failure(
    tmp_path: Path, failed: bool
) -> None:
    # Each child must see the other start before it can finish: a sequential
    # implementation fails instead of merely satisfying an elapsed-time limit.
    commands = {}
    for name, other in (("first", "second"), ("second", "first")):
        script = (
            "from pathlib import Path; import time, sys\n"
            f"root = Path({str(tmp_path)!r})\n"
            f"(root / '{name}.started').touch()\n"
            "deadline = time.monotonic() + 10\n"
            f"while not (root / '{other}.started').exists():\n"
            "    assert time.monotonic() < deadline, 'sibling never started'\n"
            "    time.sleep(0.01)\n"
            f"(root / '{name}.finished').touch()\n"
            f"sys.exit({7 if failed and name == 'first' else 0})\n"
        )
        commands[name] = [sys.executable, "-c", script]
    results = GROUPS.run_groups(commands, tmp_path)
    assert results == {"first": 7 if failed else 0, "second": 0}
    assert all((tmp_path / f"{name}.finished").exists() for name in commands)


def test_launch_failure_still_runs_sibling(tmp_path: Path) -> None:
    results = GROUPS.run_groups(
        {
            "missing": [str(tmp_path / "nonexistent-executable")],
            "other": [sys.executable, "-c", "print('completed')"],
        },
        tmp_path,
    )
    assert results == {"missing": 1, "other": 0}
    assert "completed" in (tmp_path / "other.log").read_text()


@pytest.mark.parametrize("first_status,second_status", [(0, 7), (7, 0), (-9, 0)])
def test_progress_reports_early_completion_then_waits_with_stable_result_order(
    monkeypatch, capsys, first_status: int, second_status: int
) -> None:
    first, second = Future(), Future()
    first.set_result(first_status)
    second.set_result(second_status)
    scheduled = iter(
        [
            ({first, second}, set(), {first, second}),
            ({first, second}, {second}, {first}),
            ({first}, set(), {first}),
            ({first}, {first}, set()),
        ]
    )

    def controlled_wait(pending, *, timeout, return_when):
        expected, completed, remaining = next(scheduled)
        assert pending == expected
        assert timeout == 30
        assert return_when == GROUPS.FIRST_COMPLETED
        return completed, remaining

    times = iter([40, 42, 72, 75])
    monkeypatch.setattr(GROUPS, "wait", controlled_wait)
    monkeypatch.setattr(GROUPS, "monotonic", lambda: next(times))
    result = GROUPS._wait_for_groups({"first": first, "second": second}, started=10)
    assert result == {"first": first_status, "second": second_status}
    assert list(result) == ["first", "second"]
    assert list(scheduled) == []
    assert capsys.readouterr().out.splitlines() == [
        "[db-contracts] waiting groups=first,second elapsed=30s",
        f"[db-contracts] completed group=second exit={second_status} elapsed=32s",
        "[db-contracts] waiting groups=first elapsed=62s",
        f"[db-contracts] completed group=first exit={first_status} elapsed=65s",
    ]


def test_simultaneous_completion_has_no_spurious_heartbeat(monkeypatch, capsys) -> None:
    first, second = Future(), Future()
    first.set_result(0)
    second.set_result(3)

    def completed(pending, *, timeout, return_when):
        assert pending == {first, second}
        return pending, set()

    monkeypatch.setattr(GROUPS, "wait", completed)
    monkeypatch.setattr(GROUPS, "monotonic", lambda: 35)
    assert GROUPS._wait_for_groups({"first": first, "second": second}, 5) == {
        "first": 0,
        "second": 3,
    }
    assert capsys.readouterr().out.splitlines() == [
        "[db-contracts] completed group=first exit=0 elapsed=30s",
        "[db-contracts] completed group=second exit=3 elapsed=30s",
    ]


def test_progress_keeps_commands_environment_and_raw_output_in_separate_logs(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("DB_GROUP_SYNTHETIC_PRIVATE", "synthetic-environment-value")
    command = [
        sys.executable,
        "-c",
        (
            "import os; print('synthetic-command-value'); "
            "print(os.environ['DB_GROUP_SYNTHETIC_PRIVATE'])"
        ),
    ]
    assert GROUPS.run_groups({"first": command, "second": command}, tmp_path) == {
        "first": 0,
        "second": 0,
    }
    progress = capsys.readouterr().out
    lines = progress.splitlines()
    assert lines[:2] == [
        "[db-contracts] starting group=first",
        "[db-contracts] starting group=second",
    ]
    assert len(lines) == 4
    assert "synthetic-command-value" not in progress
    assert "synthetic-environment-value" not in progress
    assert sys.executable not in progress
    assert str(tmp_path) not in progress
    for name in ("first", "second"):
        assert (tmp_path / f"{name}.log").read_text(encoding="utf-8").splitlines() == [
            "synthetic-command-value",
            "synthetic-environment-value",
        ]


@pytest.mark.parametrize("status,expected", [(0, 0), (7, 1), (-9, 1)])
def test_main_preserves_grouped_logs_and_aggregate_exit_after_wait_all(
    tmp_path: Path, monkeypatch, capsys, status: int, expected: int
) -> None:
    def finished(commands, directory):
        assert list(commands) == ["published-canvas", "rust-db"]
        for name in commands:
            (directory / f"{name}.log").write_text(
                f"{name} complete\n", encoding="utf-8"
            )
        return {"published-canvas": status, "rust-db": 0}

    monkeypatch.setattr(GROUPS, "run_groups", finished)
    monkeypatch.setattr(
        GROUPS,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=lambda **kwargs: nullcontext(str(tmp_path))),
    )
    assert GROUPS.main() == expected
    assert capsys.readouterr().out == (
        f"===== published-canvas: exit {status} =====\n"
        "published-canvas complete\n\n"
        "===== rust-db: exit 0 =====\n"
        "rust-db complete\n\n"
    )
