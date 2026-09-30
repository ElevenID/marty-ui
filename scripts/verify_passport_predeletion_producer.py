#!/usr/bin/env python3
"""Verify the protected disposable producer receipt before acceptance composition.

The returned evidence is still blocked. This verifier establishes its source,
workflow, plan, and attestation lineage; it cannot authorize Python deletion.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable

if __package__:
    from .check_passport_supported_producer_handoff import verify_handoff
else:
    from check_passport_supported_producer_handoff import verify_handoff


REPOSITORY = "ElevenID/marty-ui"
PRODUCER_WORKFLOW = ".github/workflows/passport-supported-provisioning-producer.yml"
RECORD_WORKFLOW = ".github/workflows/passport-supported-provisioning-record.yml"
RECORD_SIGNER = f"{REPOSITORY}/{RECORD_WORKFLOW}"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
Run = Callable[[list[str]], str]


class ProducerRecordError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProducerRecordError(message)


def command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False,
                                timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProducerRecordError("Protected producer provenance command failed") from exc
    require(result.returncode == 0, "Protected producer provenance command failed")
    return result.stdout


def parsed(value: str, message: str) -> Any:
    try:
        return json.loads(value)
    except ValueError as exc:
        raise ProducerRecordError(message) from exc


def _time(value: object) -> datetime:
    require(isinstance(value, str), "Protected producer run timestamp is missing")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProducerRecordError("Protected producer run timestamp is invalid") from exc
    require(instant.utcoffset() is not None
            and instant.utcoffset().total_seconds() == 0,
            "Protected producer run timestamp is not UTC")
    return instant


def _run(run_id: int, source_commit: str, event: str, workflow_path: str,
         runner: Run) -> dict[str, Any]:
    record = parsed(runner(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"]),
                    "Protected producer run metadata is invalid")
    require(isinstance(record, dict)
            and type(record.get("id")) is int and record["id"] == run_id
            and isinstance(record.get("repository"), dict)
            and record["repository"].get("full_name") == REPOSITORY
            and record.get("status") == "completed"
            and record.get("conclusion") == "success"
            and record.get("event") == event
            and record.get("head_branch") == "main"
            and record.get("head_sha") == source_commit
            and type(record.get("run_attempt")) is int
            and record["run_attempt"] == 1
            and type(record.get("workflow_id")) is int,
            "Protected producer run is not successful exact-main evidence")
    workflow = parsed(runner(["gh", "api", f"repos/{REPOSITORY}/actions/workflows/"
                              f"{record['workflow_id']}"]),
                      "Protected producer workflow metadata is invalid")
    require(isinstance(workflow, dict) and workflow.get("path") == workflow_path
            and workflow.get("state") == "active",
            "Protected producer run used a different workflow")
    _time(record.get("created_at"))
    _time(record.get("updated_at"))
    return record


def verify_runs(record_run_id: int, producer_run_id: int, source_commit: str,
                runner: Run = command) -> dict[str, Any]:
    require(type(record_run_id) is int and RUN_ID.fullmatch(str(record_run_id)) is not None
            and type(producer_run_id) is int
            and RUN_ID.fullmatch(str(producer_run_id)) is not None
            and record_run_id != producer_run_id
            and isinstance(source_commit, str) and SHA.fullmatch(source_commit) is not None,
            "Protected producer run or source identity is invalid")
    producer = _run(producer_run_id, source_commit, "workflow_dispatch",
                    PRODUCER_WORKFLOW, runner)
    record = _run(record_run_id, source_commit, "workflow_run",
                  RECORD_WORKFLOW, runner)
    require(_time(producer["created_at"]) < _time(producer["updated_at"])
            <= _time(record["created_at"]) < _time(record["updated_at"]),
            "Protected producer attestor did not follow the producer")
    return {"producer_run_id": producer_run_id, "record_run_id": record_run_id,
            "source_commit": source_commit,
            "record_completed_at_utc": record["updated_at"]}


def verify_attestation(path: Path, source_commit: str,
                       runner: Run = command) -> str:
    output = runner([
        "gh", "attestation", "verify", str(path), "--repo", REPOSITORY,
        "--signer-workflow", RECORD_SIGNER, "--source-ref", "refs/heads/main",
        "--source-digest", source_commit, "--format", "json",
    ])
    verified = parsed(output, "Protected producer attestation output is invalid")
    require(isinstance(verified, list) and len(verified) == 1
            and isinstance(verified[0], dict)
            and isinstance(verified[0].get("attestation"), dict)
            and isinstance(verified[0].get("verificationResult"), dict),
            "Protected producer receipt needs one verified workflow attestation")
    bundle = json.dumps(verified[0]["attestation"], sort_keys=True,
                        separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(bundle).hexdigest()


def verify_receipt(plan: Path, receipt: Path, producer_run_id: int,
                   source_commit: str, *,
                   attestor: Callable[[Path, str], str] = verify_attestation,
                   handoff: Callable[..., dict[str, Any]] = verify_handoff,
                   ) -> dict[str, Any]:
    for path in (plan, receipt):
        require(path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 2 * 1024 * 1024,
                "Protected producer artifact is missing or oversized")
    attestation_sha = attestor(receipt, source_commit)
    require(isinstance(attestation_sha, str)
            and re.fullmatch(r"[0-9a-f]{64}", attestation_sha) is not None,
            "Protected producer attestation digest is invalid")
    handoff_result = handoff(plan, receipt, source_commit, str(producer_run_id))
    require(isinstance(handoff_result, dict)
            and handoff_result.get("status") == "blocked"
            and handoff_result.get("producer_run_id") == str(producer_run_id)
            and handoff_result.get("source_commit") == source_commit,
            "Protected producer handoff is invalid")
    value = parsed(receipt.read_text(encoding="utf-8"),
                   "Protected producer receipt is invalid")
    require(isinstance(value, dict), "Protected producer receipt is invalid")
    return {"status": "verified_blocked_receipt",
            "source_commit": source_commit,
            "producer_run_id": producer_run_id,
            "plan_run_id": value["plan_run_id"],
            "receipt_file_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
            "receipt_attestation_sha256": attestation_sha,
            "receipt": value}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-run-id", type=int, required=True)
    parser.add_argument("--producer-run-id", type=int, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        runs = verify_runs(args.record_run_id, args.producer_run_id,
                           args.source_commit)
        with tempfile.TemporaryDirectory(prefix="passport-predeletion-producer-") as root:
            directory = Path(root)
            command(["gh", "run", "download", str(args.record_run_id),
                     "--repo", REPOSITORY,
                     "--name", f"passport-supported-rust-producer-attested-"
                               f"{args.producer_run_id}", "--dir", str(directory)])
            receipt = directory / f"passport-supported-rust-producer-{args.producer_run_id}.json"
            require({path.name for path in directory.iterdir()} == {receipt.name},
                    "Protected producer artifact has missing or extra files")
            value = parsed(receipt.read_text(encoding="utf-8"),
                           "Protected producer receipt is invalid")
            require(isinstance(value, dict)
                    and isinstance(value.get("plan_run_id"), str)
                    and RUN_ID.fullmatch(value["plan_run_id"]) is not None,
                    "Protected producer plan run is invalid")
            plan_run_id = value["plan_run_id"]
            command(["gh", "run", "download", plan_run_id,
                     "--repo", REPOSITORY,
                     "--name", f"passport-supported-provisioning-plan-{plan_run_id}",
                     "--dir", str(directory)])
            plan = directory / f"passport-supported-provisioning-plan-{plan_run_id}.json"
            require({path.name for path in directory.iterdir()}
                    == {receipt.name, plan.name},
                    "Protected producer and plan artifacts have missing or extra files")
            verified = verify_receipt(plan, receipt, args.producer_run_id,
                                      args.source_commit)
        result = dict(verified)
        result.update(runs)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (ProducerRecordError, OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Protected producer receipt unavailable: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
