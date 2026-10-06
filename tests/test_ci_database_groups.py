"""Exercise concurrency and failure propagation without a live database."""

import importlib.util
import json
import re
import sys
from concurrent.futures import Future
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

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


def test_retained_preflights_all_finish_when_one_fails(tmp_path: Path) -> None:
    commands = {
        name: [sys.executable, "-c", f"print('{name}'); raise SystemExit({status})"]
        for name, status in (
            ("timeout-preflight", 0),
            ("lease-expiry-preflight", 7),
        )
    }
    assert GROUPS.run_groups(commands, tmp_path) == {
        name: (7 if name == "lease-expiry-preflight" else 0) for name in commands
    }
    for name in commands:
        assert name in (tmp_path / f"{name}.log").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("canvas", "published-canvas"),
        ("rust-db", "rust-db"),
    ],
)
def test_split_lanes_run_exactly_their_owned_database_group(
    tmp_path: Path, monkeypatch, mode: str, expected: str
) -> None:
    monkeypatch.setattr(GROUPS, "_has_preflight_evidence", lambda: True)
    observed = {}

    def fake_groups(commands, directory):
        observed.update(commands)
        for name in commands:
            (directory / f"{name}.log").write_text("passed\n", encoding="utf-8")
        return {name: 0 for name in commands}

    monkeypatch.setattr(GROUPS, "run_groups", fake_groups)
    assert GROUPS.main(mode) == 0
    assert set(observed) == {expected}
    if mode == "canvas":
        assert observed[expected][-1] == "full-after-preflights"
    else:
        assert "run-rust-db-contracts.sh" in observed[expected][-1]


@pytest.mark.parametrize("qualification", ["0", "1"])
def test_preflight_evidence_requires_both_successes_and_same_executable(
    tmp_path: Path, monkeypatch, qualification: str
) -> None:
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_JOB", "test-rust-services")
    executable = tmp_path / "canvas-contract"
    executable.write_bytes(b"compiled contract v1")
    (tmp_path / "rust-test-artifacts.json").write_text(
        json.dumps(
            {
                "reason": "compiler-artifact",
                "package_id": "path+file:///checkout/rust/crates/canvas-acceptance#marty-canvas-acceptance@0.1.0",
                "target": {"name": "canvas_published_worker_contract"},
                "executable": str(executable),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    evidence = tmp_path / GROUPS.EVIDENCE_NAME
    assert not GROUPS._has_preflight_evidence()

    def fake_groups(commands, directory):
        observed.update(commands)
        for name in commands:
            (directory / f"{name}.log").write_text("finished\n", encoding="utf-8")
        return {
            name: (7 if failed and name == "lease-expiry-preflight" else 0)
            for name in commands
        }

    observed = {}
    monkeypatch.setattr(GROUPS, "run_groups", fake_groups)
    failed = True
    assert GROUPS.main("preflights") == 1
    assert not evidence.exists()
    failed = False
    assert GROUPS.main("preflights") == 0
    assert GROUPS._has_preflight_evidence()
    monkeypatch.setenv(
        "MARTY_CANVAS_FULL_QUALIFICATION", "1" if qualification == "0" else "0"
    )
    assert not GROUPS._has_preflight_evidence()
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    assert GROUPS.main("database") == 0
    assert observed["published-canvas"][-1] == "full-after-preflights"
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    assert not GROUPS._has_preflight_evidence()
    assert GROUPS.main("database") == 0
    assert observed["published-canvas"][-1] != "full-after-preflights"
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    executable.write_bytes(b"compiled contract v2")
    assert not GROUPS._has_preflight_evidence()
    assert GROUPS.main("database") == 0
    assert observed["published-canvas"][-1] != "full-after-preflights"
    assert GROUPS.main("preflights") == 0
    assert GROUPS._has_preflight_evidence()
    failed = True
    assert GROUPS.main("preflights") == 1
    assert not evidence.exists()


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
    assert len(lines) == 6
    for name in ("first", "second"):
        start = f"[db-contracts] starting group={name}"
        assert lines.count(start) == 1
        start_index = lines.index(start)
        assert (
            sum(
                re.fullmatch(
                    rf"\[db-timing\] group={name} phase=contract name=group_total duration_ms=\d+ status=ok",
                    line,
                )
                is not None
                and start_index < index
                for index, line in enumerate(lines)
            )
            == 1
        )
        assert (
            sum(
                re.fullmatch(
                    rf"\[db-contracts\] completed group={name} exit=0 elapsed=\d+s",
                    line,
                )
                is not None
                and start_index < index
                for index, line in enumerate(lines)
            )
            == 1
        )
    assert "synthetic-command-value" not in progress
    assert "synthetic-environment-value" not in progress
    assert sys.executable not in progress
    assert str(tmp_path) not in progress
    for name in ("first", "second"):
        assert (tmp_path / f"{name}.log").read_text(encoding="utf-8").splitlines() == [
            "synthetic-command-value",
            "synthetic-environment-value",
        ]


def test_phase_telemetry_is_live_allowlisted_and_does_not_mask_failure(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    private = "synthetic-private-credential"
    script = (
        "import sys; "
        'print(\'MARTY_CI_PHASE_V1 {"phase":"database_readiness","name":"postgres_ready","duration_ms":12,"status":"ok"}\', flush=True); '
        'print(\'MARTY_CI_PHASE_V1 {"phase":"scenario","name":"bad/path","duration_ms":10,"status":"ok"}\', flush=True); '
        'print(\'MARTY_CI_PHASE_V1 {"phase":"scenario","name":"secret123","duration_ms":10,"status":"ok"}\', flush=True); '
        f"print({private!r}, flush=True); sys.exit(7)"
    )
    assert GROUPS.run_groups({"rust-db": [sys.executable, "-c", script]}, tmp_path) == {
        "rust-db": 7
    }
    progress = capsys.readouterr().out
    assert "postgres_ready" in progress
    assert "group_total" in progress
    assert "bad/path" not in progress
    assert "secret123" not in progress
    assert private not in progress
    evidence = [
        json.loads(line)
        for line in (tmp_path / "rust-build-evidence/db-contract-timing.jsonl")
        .read_text()
        .splitlines()
    ]
    assert evidence == [
        {
            "schema": "marty.ci.db-phase/v1",
            "group": "rust-db",
            "phase": "database_readiness",
            "name": "postgres_ready",
            "duration_ms": 12,
            "status": "ok",
        },
        {
            "schema": "marty.ci.db-phase/v1",
            "group": "rust-db",
            "phase": "contract",
            "name": "group_total",
            "duration_ms": evidence[1]["duration_ms"],
            "status": "failed",
        },
    ]
    assert private in (tmp_path / "rust-db.log").read_text()


@pytest.mark.parametrize(
    "marker",
    [
        '{"phase":["scenario"],"name":"x","duration_ms":1,"status":"ok"}',
        '{"phase":"scenario","name":"x","duration_ms":true,"status":"ok"}',
        '{"phase":"scenario","name":"x","duration_ms":1,"status":["ok"]}',
        '{"phase":"scenario","name":"x","duration_ms":1,"status":"ok","payload":"secret"}',
        '{"phase":"scenario","name":"x","duration_ms":43200001,"status":"ok"}',
    ],
)
def test_phase_parser_rejects_non_schema_or_oversized_values(marker: str) -> None:
    assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "published-canvas") is None


def test_phase_parser_accepts_only_known_case_and_contract_ids() -> None:
    # Published matrix IDs are checked-in case identities, not probe output,
    # environment values, SQL, URLs, or arbitrary text from the child log.
    assert len(GROUPS.PUBLISHED_MATRIX_PROBE_NAMES) == 95
    assert len(GROUPS.PUBLISHED_MATRIX_SCENARIOS) == 21
    for name in GROUPS.PUBLISHED_MATRIX_PROBE_NAMES:
        marker = json.dumps(
            {"phase": "migration_seed", "name": name, "duration_ms": 1, "status": "ok"}
        )
        assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "published-canvas")
    for phase, name in (
        ("migration_seed", "published_probe"),
        ("migration_seed", "json_consumer"),
        ("migration_seed", "json_depth"),
        ("migration_seed", "timeout_consumer"),
        ("migration_seed", "worker_validation_template"),
        ("scenario", "retry-after.http_date_future"),
        ("cleanup", "published_database_removal"),
        ("contract", "canvas_sync_worker_postgres_contract"),
        ("contract_phase", "renewal_job_outcomes"),
    ):
        marker = json.dumps(
            {"phase": phase, "name": name, "duration_ms": 1, "status": "ok"}
        )
        assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "published-canvas")
    marker = '{"phase":"scenario","name":"secret123","duration_ms":1,"status":"ok"}'
    assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "published-canvas") is None
    for name in (
        "case_from_scenario",
        "json_depth_extra",
        "worker_validation_other",
        "validation.not_a_frozen_case",
        "retry-after.http_date_future.extra",
        "retry-after.secret\nvalue",
    ):
        marker = json.dumps(
            {"phase": "migration_seed", "name": name, "duration_ms": 1, "status": "ok"}
        )
        assert (
            GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "published-canvas")
            is None
        )


def test_migration_seed_labels_have_fixed_constructor_owners() -> None:
    support = (
        ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs"
    ).read_text(encoding="utf-8")
    worker = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_worker_contract.rs"
    ).read_text(encoding="utf-8")
    for name in ("json_consumer", "json_depth", "timeout_consumer"):
        assert f'Some("{name}") => "{name}"' in support
    assert support.count('"worker_validation_template"') == 1
    assert (
        worker.count("PublishedDatabase::start_for_worker_validation_template()") == 1
    )
    assert support.count("worker_matrix_timing_name(scenario, case)?") == 1
    assert support.index(
        'return Err("unsupported owned worker matrix case".into());'
    ) < (support.index("worker_matrix_timing_name(scenario, case)?"))
    assert "Self::start_probe_with_migration_named(" in support
    assert 'strip_prefix("worker-")' in support
    # Every Rust wrapper that reaches the shared case constructor must have
    # an exact checked-in scenario family in the timing collector. This also
    # catches a newly added wrapper whose labels would otherwise disappear.
    wrapper_families = re.findall(
        r'Self::start_with_worker_case\(\s*case,\s*include_str!\(\s*"\.\./\.\./\.\./\.\./\.\./contracts/canvas-worker-([a-z-]+)-scenarios\.json"\s*\)',
        support,
    )
    assert len(wrapper_families) == support.count("Self::start_with_worker_case(") == 21
    assert set(wrapper_families) == GROUPS.PUBLISHED_MATRIX_SCENARIOS


def test_composite_phase_allowlist_matches_exact_instrumented_boundaries() -> None:
    source = (
        ROOT / "rust/services/issuance/tests/canvas_sync_worker_postgres_contract.rs"
    ).read_text(encoding="utf-8")
    emitted = re.findall(
        r'(?:CompositePhaseTimer::start|timed_phase)\(\s*"([a-z_]+)"', source
    )
    assert len(emitted) == 15
    assert len(set(emitted)) == len(emitted)
    assert set(emitted) == GROUPS.TIMING_NAMES["contract_phase"]
    assert emitted[0] == "composite_total"
    assert emitted[-1] == "pool_close"
    assert '"\\nMARTY_CI_PHASE_V1 ' in source
    for name in emitted:
        marker = json.dumps(
            {"phase": "contract_phase", "name": name, "duration_ms": 1, "status": "ok"}
        )
        assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + marker, "rust-db")
    unknown = '{"phase":"contract_phase","name":"private_value","duration_ms":1,"status":"ok"}'
    assert GROUPS._safe_phase(GROUPS.TIMING_PREFIX + unknown, "rust-db") is None


def test_unavailable_optional_timing_file_does_not_change_contract_result(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    unavailable = tmp_path / "not-a-directory"
    unavailable.write_text("owned fixture")
    monkeypatch.setenv("RUNNER_TEMP", str(unavailable))
    command = [sys.executable, "-c", "print('contract-passed')"]
    assert GROUPS.run_groups({"rust-db": command}, tmp_path) == {"rust-db": 0}
    progress = capsys.readouterr().out
    assert "optional timing evidence unavailable" in progress
    assert "group=rust-db phase=contract name=group_total" in progress
    assert "contract-passed" in (tmp_path / "rust-db.log").read_text()


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
