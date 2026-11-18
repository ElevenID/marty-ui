#!/usr/bin/env python3
"""Fail closed before consuming an opt-in, same-source self-host preparation."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

RUN_ID = re.compile(r"[1-9][0-9]*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPOSITORY = "ElevenID/marty-ui"
WORKFLOW = ".github/workflows/cd.yml"


def _object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("GitHub API response must be an object")
    return value


def verify(run: dict, bundle: dict, transaction: dict, run_id: str,
           source_sha: str) -> dict:
    if not RUN_ID.fullmatch(run_id) or not SHA.fullmatch(source_sha):
        raise ValueError("invalid expected run or source identity")
    if (run.get("id") != int(run_id)
            or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("head_repository", {}).get("full_name") != REPOSITORY
            or run.get("path") != WORKFLOW
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main"
            or run.get("head_sha") != source_sha
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("run_attempt") != 1):
        raise ValueError("producer is not a successful first-attempt protected-main Stack release")

    repository_id = run["repository"].get("id")
    if not isinstance(repository_id, int) or repository_id <= 0:
        raise ValueError("producer repository identity is missing")

    def artifact(response: dict, expected_name: str) -> dict:
        items = response.get("artifacts")
        if (not isinstance(items, list) or response.get("total_count") != 1
                or len(items) != 1):
            raise ValueError(f"{expected_name} is missing or ambiguous")
        item = items[0]
        origin = item.get("workflow_run") if isinstance(item, dict) else None
        if (not isinstance(item, dict) or item.get("name") != expected_name
                or item.get("expired") is not False
                or not isinstance(item.get("id"), int)
                or item["id"] <= 0
                or not isinstance(item.get("digest"), str)
                or not DIGEST.fullmatch(item["digest"])
                or not isinstance(origin, dict)
                or origin.get("id") != int(run_id)
                or origin.get("repository_id") != repository_id
                or origin.get("head_repository_id") != repository_id
                or origin.get("head_branch") != "main"
                or origin.get("head_sha") != source_sha):
            raise ValueError(f"{expected_name} is not the exact producer artifact")
        return {"id": item["id"], "digest": item["digest"]}

    return {
        "schema": "marty.selfhost-preparation-artifact-binding/v1",
        "run_id": run_id,
        "source_sha": source_sha,
        "bundle": artifact(bundle, f"selfhost-lock-preparation-unqualified-{run_id}"),
        "transaction": artifact(transaction, f"stack-release-qualified-{run_id}"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "bundle", "transaction", "run-id", "source-sha", "output"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    binding = verify(_object(Path(args.run)), _object(Path(args.bundle)),
                     _object(Path(args.transaction)), args.run_id, args.source_sha)
    Path(args.output).write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
