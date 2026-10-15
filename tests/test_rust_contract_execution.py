"""Fail closed when direct Rust CI harnesses select no tests."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/ci/run-rust-db-contracts.sh"
CANVAS_RUNNER = ROOT / "scripts/ci/run-published-canvas-contracts.sh"
GIT_BASH = Path("C:/Program Files/Git/bin/bash.exe")
if os.name == "nt":
    BASH = str(GIT_BASH) if GIT_BASH.is_file() else None
else:
    BASH = shutil.which("bash")


def test_database_runner_uses_positive_execution_guard() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert 'source "$(dirname "${BASH_SOURCE[0]}")/rust_contract_execution.sh"' in source
    assert source.count("run_timed ") == 19


def test_canvas_serial_runner_uses_positive_execution_guard() -> None:
    source = CANVAS_RUNNER.read_text(encoding="utf-8")
    assert 'source "$(dirname "${BASH_SOURCE[0]}")/rust_contract_execution.sh"' in source
    assert 'if [[ "$phase" == canvas_serial ]]; then\n    run_timed_rust_test "$phase" "$name" "$@"' in source
    assert source.count("timed canvas_serial ") == 9


@pytest.mark.skipif(BASH is None, reason="Bash unavailable")
@pytest.mark.parametrize(
    "phase,invocation",
    [
        ("contract", "run_timed synthetic"),
        ("canvas_serial", "run_timed_rust_test canvas_serial synthetic"),
    ],
)
@pytest.mark.parametrize(
    "summary,exit_status,expected_status",
    [
        (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
            0,
            0,
        ),
        (
            "test result: ok. 11 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s",
            0,
            0,
        ),
        (
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            0,
            1,
        ),
        ("no test summary", 0, 1),
        (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
            7,
            7,
        ),
    ],
)
def test_direct_rust_test_requires_positive_summary_and_command_success(
    phase: str, invocation: str, summary: str, exit_status: int, expected_status: int
) -> None:
    result = subprocess.run(
        [
            BASH,
            "-c",
            # Git Bash on Windows has no python3; only the guard is under test.
            "python3() { date +%s%N; }; "
            "source scripts/ci/rust_contract_execution.sh; "
            f'{invocation} bash tests/fixtures/fake_rust_contract.sh "$1" "$2"',
            "synthetic",
            str(exit_status),
            summary,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_status, (result.stdout, result.stderr)
    assert summary in result.stdout
    marker = next(
        line.removeprefix("MARTY_CI_PHASE_V1 ")
        for line in result.stdout.splitlines()
        if line.startswith("MARTY_CI_PHASE_V1 ")
    )
    timing = json.loads(marker)
    assert timing["phase"] == phase
    assert timing["name"] == "synthetic"
    assert timing["duration_ms"] >= 0
    assert timing["status"] == ("ok" if expected_status == 0 else "failed")
