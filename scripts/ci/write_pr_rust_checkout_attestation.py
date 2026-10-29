#!/usr/bin/env python3
"""Record PR Rust-lane checkout identity; this record never authorizes a skip.

A future consumer must fetch the immutable artifact through GitHub's API and
independently verify its run, attempt, job, lane, conclusion, and content.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Mapping

SCHEMA = "marty-ci-pr-rust-checkout-v1"
WORKFLOW_PATH = ".github/workflows/ci.yml"
JOB_ID = "test-rust-services"
SHA = re.compile(r"[0-9a-f]{40}\Z")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*\Z")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def sha(value: object, field: str) -> str:
    require(
        isinstance(value, str) and SHA.fullmatch(value) is not None, f"invalid {field}"
    )
    return value


def positive_integer(value: object, field: str) -> int:
    require(
        isinstance(value, str) and POSITIVE_INTEGER.fullmatch(value) is not None,
        f"invalid {field}",
    )
    return int(value)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def build_attestation(
    env: Mapping[str, str], event: object, repo: Path
) -> dict[str, object]:
    require(isinstance(event, dict), "event must be an object")
    require(env.get("GITHUB_EVENT_NAME") == "pull_request", "not a pull_request run")
    require(env.get("GITHUB_JOB") == JOB_ID, "unexpected job identity")
    lane = env.get("MARTY_RUST_ATTESTATION_LANE")
    require(lane in ("canvas", "contracts"), "unexpected Rust lane")
    require(env.get("GITHUB_WORKFLOW") == "CI", "unexpected workflow name")

    repository = env.get("GITHUB_REPOSITORY")
    require(
        isinstance(repository, str) and repository.count("/") == 1, "invalid repository"
    )
    require(all(repository.split("/")), "invalid repository")
    repository_id = positive_integer(env.get("GITHUB_REPOSITORY_ID"), "repository id")
    run_id = positive_integer(env.get("GITHUB_RUN_ID"), "run id")
    run_attempt = positive_integer(env.get("GITHUB_RUN_ATTEMPT"), "run attempt")

    pr = event.get("pull_request")
    event_repo = event.get("repository")
    require(
        isinstance(pr, dict) and isinstance(event_repo, dict), "missing PR/repository"
    )
    number = pr.get("number")
    require(
        type(number) is int and number > 0 and event.get("number") == number,
        "invalid PR number",
    )
    require(event_repo.get("full_name") == repository, "repository name mismatch")
    require(event_repo.get("id") == repository_id, "repository id mismatch")
    base = pr.get("base")
    head = pr.get("head")
    require(isinstance(base, dict) and isinstance(head, dict), "missing PR endpoints")
    require(base.get("ref") == "main", "unexpected PR base branch")
    require(
        isinstance(base.get("repo"), dict) and base["repo"].get("id") == repository_id,
        "PR base repository mismatch",
    )
    base_sha = sha(base.get("sha"), "PR base SHA")
    head_sha = sha(head.get("sha"), "PR head SHA")

    checkout_ref = f"refs/pull/{number}/merge"
    require(env.get("GITHUB_REF") == checkout_ref, "not the PR merge ref")
    workflow_ref = f"{repository}/{WORKFLOW_PATH}@{checkout_ref}"
    require(env.get("GITHUB_WORKFLOW_REF") == workflow_ref, "workflow ref mismatch")
    # GitHub supplies this context value, but this job does not prove which
    # blob that commit contains. A future API consumer must verify that link.
    workflow_context_sha = sha(env.get("GITHUB_WORKFLOW_SHA"), "workflow context SHA")
    checkout_sha = sha(env.get("GITHUB_SHA"), "checkout SHA")
    require(git(repo, "rev-parse", "HEAD") == checkout_sha, "checkout HEAD mismatch")
    # Read the actual commit object: rev-list hides parents at a shallow boundary.
    # Only headers count; a commit-message line beginning with "parent " is data.
    header = git(repo, "cat-file", "-p", "HEAD").split("\n\n", 1)[0]
    parents = [
        line.removeprefix("parent ")
        for line in header.splitlines()
        if line.startswith("parent ")
    ]
    require(parents == [base_sha, head_sha], "PR merge parents mismatch")
    require(
        git(repo, "status", "--porcelain", "--untracked-files=no") == "",
        "tracked checkout changed during Rust tests",
    )
    tree_sha = sha(git(repo, "rev-parse", "HEAD^{tree}"), "checkout tree SHA")
    workflow_blob_sha = sha(
        git(repo, "rev-parse", f"HEAD:{WORKFLOW_PATH}"), "workflow blob SHA"
    )
    producer_blob_sha = sha(
        git(repo, "rev-parse", "HEAD:scripts/ci/write_pr_rust_checkout_attestation.py"),
        "producer blob SHA",
    )

    return {
        "schema": SCHEMA,
        "repository": repository,
        "repository_id": repository_id,
        "workflow_path": WORKFLOW_PATH,
        "workflow_ref": workflow_ref,
        "workflow_context_sha_unverified": workflow_context_sha,
        "workflow_blob_sha": workflow_blob_sha,
        "producer_blob_sha": producer_blob_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job_id": JOB_ID,
        "lane": lane,
        "event": "pull_request",
        "pull_request_number": number,
        "pull_request_base_sha": base_sha,
        "pull_request_head_sha": head_sha,
        "checkout_ref": checkout_ref,
        "checkout_sha": checkout_sha,
        "checkout_tree_sha": tree_sha,
    }


def main() -> int:
    try:
        require(len(sys.argv) == 2, "expected one output path")
        event = json.loads(
            Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")
        )
        repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        output = Path(sys.argv[1])
        require(output.parent.is_dir(), "expected existing output directory")
        record = build_attestation(os.environ, event, repo)
        output.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"PR Rust checkout attestation unavailable: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
