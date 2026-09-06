"""Exercise concurrency and failure propagation without a live database."""

import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "db_groups", ROOT / "scripts/ci/run-db-contract-groups.py"
)
GROUPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GROUPS)


@pytest.mark.parametrize("failed", [False, True])
def test_groups_overlap_and_finish_after_sibling_failure(tmp_path: Path, failed: bool) -> None:
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
    results = GROUPS.run_groups({
        "missing": [str(tmp_path / "nonexistent-executable")],
        "other": [sys.executable, "-c", "print('completed')"],
    }, tmp_path)
    assert results == {"missing": 1, "other": 0}
    assert "completed" in (tmp_path / "other.log").read_text()
