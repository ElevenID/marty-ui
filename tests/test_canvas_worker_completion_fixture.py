"""Completion-process fixture integrity, separate from real process execution."""

import json
from pathlib import Path


def test_completion_barrier_journals_only_terminal_writes_and_identifies_reclaimer():
    root = Path(__file__).resolve().parents[1]
    case = json.loads(
        (
            root / "contracts/canvas-worker-provider-completion-scenarios.json"
        ).read_text()
    )
    assert case["case"] == "completion" and case["lease_seconds"] == 30
    assert case["history_scenario"] == "canvas-worker-provider-final-scenarios.json"
    assert "a.usename='synthetic_reclaimer'" in case["reclaimer_wait_sql"]
    assert "pg_blocking_pids(b.pid)" in case["reclaimer_wait_sql"]
    assert "WITH RECURSIVE blockers" in case["reclaimer_wait_sql"]
    assert "NOT p.pid=ANY(b.path)" in case["reclaimer_wait_sql"]
    assert (
        "database=(SELECT oid FROM pg_database WHERE datname=current_database())"
        in case["terminal_wait_sql"]
    )
    assert case["barrier_sql"] == "SELECT pg_advisory_xact_lock(814,51)"
    assert case["setup"][:2] == [
        "CREATE ROLE synthetic_reclaimer LOGIN PASSWORD 'synthetic-reclaimer-local-only'",
        "GRANT oracle TO synthetic_reclaimer",
    ]
    function, trigger = case["setup"][-2:]
    assert "pg_advisory_xact_lock(814,51)" in function
    assert "VALUES(NEW.status); RETURN NEW;" in function
    assert "OLD.id='worker-final-job' AND OLD.status='leased'" in trigger
    assert "NEW.status IN ('succeeded','dead_letter')" in trigger
    assert "lease_expires_at" not in " ".join(case["setup"])
    assert "recovery-first process composition remains separate" in case["scope"]


def test_completion_reference_keeps_actual_target_difference_and_single_terminal_write():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    observed = json.loads(
        (contracts / "canvas-worker-provider-completion-oracle.json").read_text()
    )
    final = json.loads(
        (contracts / "canvas-worker-provider-final-oracle.json").read_text()
    )
    assert observed["before"] == final["before"]
    assert observed["terminal_pending"]["jobs"] == observed["before"]["jobs"]
    assert observed["completed"]["jobs"][0]["status"] == "succeeded"
    assert observed["completed"]["jobs"][0]["attempt_count"] == 8
    assert observed["terminal_journal"] == ["succeeded"]
    assert observed["reclaimer_blocked_by_completion"] is True
    assert observed["target_enabled"] is False
    assert observed["target_success_timestamp_present"] is False
    assert observed["requests"] == final["requests"]
    assert observed["source_sha256"] == final["source_sha256"]
    assert observed["exit_codes_after_interrupt"] == [-2, -2]
    assert observed["rows_unchanged_after_exit"] is True
