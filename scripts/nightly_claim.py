#!/usr/bin/env python3
"""No-write, exact-main nightly claim and workflow-run intake contract.

This contract does not qualify, tag, deploy, or publish a release. The stable
release transaction deliberately cannot consume its separate schema.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from stack_tag_gate import classify_release_tag

SCHEMA = "elevenid.nightly-release-claim/v1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]*\Z")
DATE = re.compile(r"20[0-9]{6}\Z")
PREPARATION_WORKFLOW = ".github/workflows/prepare-nightly-claim.yml"
INTAKE_WORKFLOW = ".github/workflows/nightly-claim-intake.yml"
REQUIRED_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/open-source-policy.yml",
    ".github/workflows/organization-quality.yml",
    ".github/workflows/codeql-rust.yml",
    ".github/workflows/codeql-actions.yml",
)


class NightlyClaimError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NightlyClaimError(message)


def _object(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise NightlyClaimError(f"cannot read {path.name}") from error


def _validate_identity(version: str, date: str, run_id: str, source_sha: str) -> str:
    _require(SHA.fullmatch(source_sha) is not None, "source SHA must be exact")
    _require(RUN_ID.fullmatch(run_id) is not None, "claim run ID is invalid")
    _require(DATE.fullmatch(date) is not None, "nightly date is invalid")
    try:
        datetime.strptime(date, "%Y%m%d")
    except ValueError as error:
        raise NightlyClaimError("nightly date is invalid") from error
    tag = f"v{version}-nightly.{date}.{run_id}"
    _require(classify_release_tag(tag) == ("nightly", tag[1:]), "tag is not nightly")
    return tag


def _required_runs(payload: Any, source_sha: str, current_run_id: str) -> list[dict[str, Any]]:
    pages = payload if isinstance(payload, list) else [payload]
    runs: list[dict[str, Any]] = []
    for page in pages:
        entries = _object(page, "workflow-runs page").get("workflow_runs")
        _require(isinstance(entries, list), "workflow-runs array is missing")
        runs.extend(_object(entry, "workflow run") for entry in entries)
    accepted = []
    for path in REQUIRED_WORKFLOWS:
        matches = [
            run for run in runs
            if run.get("path") == path
            and run.get("event") == "merge_group"
            and run.get("head_sha") == source_sha
            and str(run.get("id")) != current_run_id
            and RUN_ID.fullmatch(str(run.get("id"))) is not None
        ]
        _require(bool(matches), f"exact-main workflow missing: {path}")
        latest = max(matches, key=lambda run: int(run["id"]))
        _require(latest.get("status") == "completed", f"workflow pending: {path}")
        _require(latest.get("conclusion") == "success", f"workflow failed: {path}")
        accepted.append({"path": path, "event": "merge_group", "run_id": latest["id"]})
    return accepted


def create_claim(*, repository: str, version: str, date: str, run_id: str,
                 source_sha: str, stack_lock: Any, workflow_runs: Any) -> dict[str, Any]:
    _require(repository == "ElevenID/marty-ui", "nightly repository changed")
    tag = _validate_identity(version, date, run_id, source_sha)
    lock = _object(stack_lock, "stack lock")
    _require(lock.get("schema") == "marty.stack-lock/v1", "stack lock schema changed")
    _require(lock.get("release") == f"marty-ui@{version}", "version differs from stack lock")
    _require(lock.get("release_state") == "eligible", "stack lock is not eligible")
    return {
        "schema": SCHEMA,
        "tier": "nightly",
        "repository": repository,
        "tag": tag,
        "version": tag[1:],
        "source_sha": source_sha,
        "claim_run_id": run_id,
        "preparation_workflow": PREPARATION_WORKFLOW,
        "intake_workflow": INTAKE_WORKFLOW,
        "required_workflows": _required_runs(workflow_runs, source_sha, run_id),
        "qualification": "not_started",
        "publication": "prohibited",
    }


def validate_intake(claim: Any, run: Any, *, current_main_sha: str) -> dict[str, Any]:
    claim = _object(claim, "nightly claim")
    run = _object(run, "preparation run")
    _require(set(claim) == {
        "schema", "tier", "repository", "tag", "version", "source_sha",
        "claim_run_id", "preparation_workflow", "intake_workflow",
        "required_workflows", "qualification", "publication",
    }, "nightly claim fields changed")
    _require(claim["schema"] == SCHEMA and claim["tier"] == "nightly", "not a nightly claim")
    _require(claim["repository"] == "ElevenID/marty-ui", "nightly repository changed")
    _require(claim["preparation_workflow"] == PREPARATION_WORKFLOW, "preparation path changed")
    _require(claim["intake_workflow"] == INTAKE_WORKFLOW, "intake path changed")
    _require(claim["qualification"] == "not_started", "claim cannot assert qualification")
    _require(claim["publication"] == "prohibited", "claim cannot authorize publication")
    _require(SHA.fullmatch(current_main_sha) is not None, "current main SHA invalid")
    _require(claim["source_sha"] == current_main_sha, "claim source is no longer main")
    _require(RUN_ID.fullmatch(str(claim["claim_run_id"])) is not None, "claim run ID invalid")
    date = claim["tag"].split("-nightly.")[-1].split(".")[0]
    _require(claim["tag"] == _validate_identity(
        claim["version"].split("-nightly.")[0], date,
        str(claim["claim_run_id"]), claim["source_sha"]
    ), "nightly identity changed")
    _require(claim["version"] == claim["tag"][1:], "nightly version changed")
    _require(run.get("id") == int(claim["claim_run_id"]), "preparation run ID changed")
    _require(run.get("path") == PREPARATION_WORKFLOW, "wrong preparation workflow")
    _require(run.get("event") == "workflow_dispatch", "wrong preparation event")
    _require(run.get("head_branch") == "main", "preparation was not on main")
    _require(run.get("head_sha") == claim["source_sha"], "preparation source changed")
    _require(run.get("status") == "completed" and run.get("conclusion") == "success",
             "preparation did not succeed")
    evidence = claim["required_workflows"]
    _require(isinstance(evidence, list) and len(evidence) == len(REQUIRED_WORKFLOWS),
             "required workflow evidence is incomplete")
    for entry, path in zip(evidence, REQUIRED_WORKFLOWS):
        _require(_object(entry, "workflow evidence") == {
            "path": path, "event": "merge_group", "run_id": entry.get("run_id")
        } and RUN_ID.fullmatch(str(entry.get("run_id"))) is not None,
                 f"workflow evidence changed: {path}")
    return claim


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    for name in ("repository", "version", "date", "run-id", "source-sha"):
        create.add_argument(f"--{name}", required=True)
    create.add_argument("--stack-lock", type=Path, required=True)
    create.add_argument("--runs-json", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    intake = sub.add_parser("intake")
    intake.add_argument("--claim", type=Path, required=True)
    intake.add_argument("--run-json", type=Path, required=True)
    intake.add_argument("--current-main-sha", required=True)
    intake.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_claim(
                repository=args.repository, version=args.version, date=args.date,
                run_id=args.run_id, source_sha=args.source_sha,
                stack_lock=_load(args.stack_lock), workflow_runs=_load(args.runs_json),
            )
        else:
            result = validate_intake(_load(args.claim), _load(args.run_json),
                                     current_main_sha=args.current_main_sha)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except NightlyClaimError as error:
        parser.exit(1, f"nightly claim rejected: {error}\n")


if __name__ == "__main__":
    main()
