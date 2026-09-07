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


def test_recovery_first_uses_statement_barrier_without_changing_rows_or_timeouts():
    root = Path(__file__).resolve().parents[1]
    case = json.loads(
        (
            root / "contracts/canvas-worker-provider-recovery-first-scenarios.json"
        ).read_text()
    )
    assert case["extends"] == "canvas-worker-provider-completion-scenarios.json"
    assert case["case"] == "recovery_first"
    function, trigger = case["owner_barrier_setup"]
    assert "IF current_user='oracle'" in function
    assert "pg_advisory_xact_lock(814,52)" in function
    assert "RETURN NULL;" in function
    assert (
        "BEFORE UPDATE ON issuance_service.canvas_evidence_sync_jobs FOR EACH STATEMENT"
        in trigger
    )
    assert "lease_expires_at" not in function + trigger
    assert "a.usename='oracle'" in case["owner_statement_wait_sql"]
    assert "expired in-flight provider effects are a separate boundary" in case["scope"]


def test_recovery_first_reference_preserves_valid_effects_and_only_recovery_terminal():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    observed = json.loads(
        (contracts / "canvas-worker-provider-recovery-first-oracle.json").read_text()
    )
    completion = json.loads(
        (contracts / "canvas-worker-provider-completion-oracle.json").read_text()
    )
    assert observed["case"] == "recovery_first"
    for key in ("before", "terminal_pending", "requests", "source_sha256"):
        assert observed[key] == completion[key]
    assert observed["contending"] == observed["terminal_pending"]
    assert observed["owner_statement_blocked_before_row_lock"] is True
    assert observed["stale_owner_path"] == "blocked"
    assert observed["reclaimer_blocked_by_completion"] is False
    assert observed["terminal_journal"] == ["dead_letter"]
    assert observed["target_enabled"] is False
    assert observed["target_success_timestamp_present"] is False
    terminal = observed["completed"]
    for key in ("facts", "snapshot", "oauth"):
        assert terminal[key] == observed["terminal_pending"][key]
    assert len(terminal["facts"]) == 1
    assert terminal["snapshot"]["events"] == {"evidence_fact_created": 1}
    assert terminal["snapshot"]["application"]["policy_allowed"] is True
    assert terminal["heartbeat"] == completion["completed"]["heartbeat"]
    assert len(terminal["jobs"]) == 1
    job = terminal["jobs"][0]
    assert job["status"] == "dead_letter"
    assert job["attempt_count"] == job["max_attempts"] == 8
    assert job["last_error_code"] == "canvas_worker_lease_expired"
    assert job["completed"] is True and job["result"] == {}
    assert job["lease_owner_present"] is False
    assert job["lease_expires_present"] is False
    assert observed["same_job_and_original_start"] is True
    assert observed["both_workers_alive_after_completion"] is True
    assert observed["rows_unchanged_after_exit"] is True
    assert observed["exit_codes_after_interrupt"] == [-2, -2]
