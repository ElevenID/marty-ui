"""Exact-run lineage checks for the blocked disposable producer receipt."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import verify_passport_predeletion_producer as producer


COMMIT = "a" * 40


def _runner(args: list[str]) -> str:
    if args[-1].endswith("/actions/runs/21"):
        run_id, workflow_id, event, created, updated = (
            21, 121, "workflow_dispatch", "2026-09-30T10:00:00Z",
            "2026-09-30T10:05:00Z")
    elif args[-1].endswith("/actions/runs/22"):
        run_id, workflow_id, event, created, updated = (
            22, 122, "workflow_run", "2026-09-30T10:06:00Z",
            "2026-09-30T10:07:00Z")
    elif args[-1].endswith("/actions/workflows/121"):
        return json.dumps({"path": producer.PRODUCER_WORKFLOW, "state": "active"})
    elif args[-1].endswith("/actions/workflows/122"):
        return json.dumps({"path": producer.RECORD_WORKFLOW, "state": "active"})
    else:
        raise AssertionError(args)
    return json.dumps({"id": run_id, "workflow_id": workflow_id, "event": event,
                       "status": "completed", "conclusion": "success",
                       "head_branch": "main", "head_sha": COMMIT,
                       "run_attempt": 1, "created_at": created, "updated_at": updated,
                       "repository": {"full_name": producer.REPOSITORY}})


def test_requires_ordered_exact_main_producer_and_attestor_runs() -> None:
    assert producer.verify_runs(22, 21, COMMIT, _runner) == {
        "producer_run_id": 21, "record_run_id": 22,
        "source_commit": COMMIT,
        "record_completed_at_utc": "2026-09-30T10:07:00Z",
    }

    def wrong_source(args: list[str]) -> str:
        value = json.loads(_runner(args))
        if args[-1].endswith("/actions/runs/22"):
            value["head_sha"] = "b" * 40
        return json.dumps(value)

    with pytest.raises(producer.ProducerRecordError, match="exact-main"):
        producer.verify_runs(22, 21, COMMIT, wrong_source)

    def early_attestor(args: list[str]) -> str:
        value = json.loads(_runner(args))
        if args[-1].endswith("/actions/runs/22"):
            value["created_at"] = "2026-09-30T10:04:00Z"
        return json.dumps(value)

    with pytest.raises(producer.ProducerRecordError, match="did not follow"):
        producer.verify_runs(22, 21, COMMIT, early_attestor)


def test_receipt_requires_attestation_and_handoff(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    receipt = tmp_path / "receipt.json"
    plan.write_text('{}\n', encoding="utf-8")
    receipt.write_text('{"plan_run_id":"20"}\n', encoding="utf-8")
    calls = []

    def handoff(*args: object) -> dict:
        calls.append(args)
        return {"status": "blocked", "producer_run_id": "21",
                "source_commit": COMMIT}

    result = producer.verify_receipt(
        plan, receipt, 21, COMMIT,
        attestor=lambda _path, _commit: "c" * 64, handoff=handoff,
    )
    assert result["status"] == "verified_blocked_receipt"
    assert result["receipt"]["plan_run_id"] == "20"
    assert calls == [(plan, receipt, COMMIT, "21")]
    with pytest.raises(producer.ProducerRecordError, match="attestation digest"):
        producer.verify_receipt(
            plan, receipt, 21, COMMIT,
            attestor=lambda _path, _commit: "unverified", handoff=handoff,
        )


def test_rejects_non_main_or_different_workflow() -> None:
    def wrong_workflow(args: list[str]) -> str:
        value = json.loads(_runner(args))
        if args[-1].endswith("/actions/workflows/122"):
            value["path"] = ".github/workflows/other.yml"
        return json.dumps(value)

    with pytest.raises(producer.ProducerRecordError, match="different workflow"):
        producer.verify_runs(22, 21, COMMIT, wrong_workflow)

    def retried(args: list[str]) -> str:
        value = json.loads(_runner(args))
        if args[-1].endswith("/actions/runs/21"):
            value["run_attempt"] = 2
        return json.dumps(value)

    with pytest.raises(producer.ProducerRecordError, match="exact-main"):
        producer.verify_runs(22, 21, COMMIT, retried)
