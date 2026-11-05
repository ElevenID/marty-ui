#!/usr/bin/env python3
"""Freeze same-run official evidence and qualify it without a human review wait.

The shared Rust validator owns protocol and browser outcome requirements.
This file authenticates current-run artifact transport and unchanged protected
main. It never reads a manual disposition or turns an upstream REVIEW into PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

if __package__:
    from .release_review_main import gate_authority, strict_json
else:
    from release_review_main import gate_authority, strict_json

REPOSITORY = "ElevenID/marty-ui"
REPOSITORY_ID = "1140864197"
MAX_BYTES = 8 * 1024 * 1024
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
QUALIFICATION_TIMEOUT_SECONDS = 5 * 60


def bounded(path: Path, maximum: int = MAX_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("official evidence input must be a bounded regular file")
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("official evidence input exceeds its size limit")
    return value


def completed(arguments: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise ValueError("official evidence command has no remaining time")
    try:
        result = subprocess.run(arguments, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValueError("official evidence transport or validation exceeded its bound") from None
    if len(result.stdout) > MAX_BYTES or len(result.stderr) > MAX_BYTES:
        raise ValueError("official evidence command output exceeds its size limit")
    return result


def command(arguments: list[str], *, timeout: float = 120) -> bytes:
    result = completed(arguments, timeout=timeout)
    if result.returncode:
        # API errors can contain URLs/configuration; never dump response bodies.
        raise ValueError("official evidence transport or Rust validation failed")
    return result.stdout


def remaining(deadline: float, clock: Callable[[], float] = time.monotonic) -> float:
    value = deadline - clock()
    if not math.isfinite(value) or value <= 0:
        raise ValueError("official evidence qualification exceeded its deadline")
    return value


class GitHub:
    def timeout(self) -> float:
        deadline = getattr(self, "deadline", None)
        return 120 if deadline is None else min(120, remaining(deadline, getattr(self, "clock", time.monotonic)))

    def run(self, arguments: list[str]) -> bytes:
        if getattr(self, "deadline", None) is None:
            return command(arguments)
        return command(arguments, timeout=self.timeout())

    def api(self, path: str, *, raw: bool = False, pages: bool = False) -> bytes:
        args = ["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/{path}"]
        if raw:
            args += ["-H", "Accept: application/vnd.github.raw+json"]
        if pages:
            args += ["--paginate", "--slurp"]
        return self.run(args)

    def download(self, run_id: int, name: str, directory: Path) -> None:
        self.run(["gh", "run", "download", str(run_id), "--repo", f"https://github.com/{REPOSITORY}",
                  "--name", name, "--dir", str(directory)])


def context(args: argparse.Namespace) -> None:
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_RUN_ID") != str(args.run_id)
        or os.environ.get("GITHUB_RUN_ATTEMPT") != str(args.current_attempt)
        or type(args.run_id) is not int or not 0 < args.run_id < 2**53
        or type(args.current_attempt) is not int or not 0 < args.current_attempt < 2**53
        or not isinstance(args.source, str) or not SOURCE.fullmatch(args.source)
        or not isinstance(args.harness, str) or not SOURCE.fullmatch(args.harness)
    ):
        raise ValueError("official evidence requires its exact protected-main release-run context")


def validator(args: argparse.Namespace, attempt: int, mode: list[str]) -> bytes:
    arguments = [str(args.validator), *mode, str(args.snapshot / "stack-manifest.json"),
                 args.source, args.harness, str(args.run_id), str(attempt), str(args.snapshot / "official-summaries")]
    if getattr(args, "qualification_deadline", None) is None:
        return command(arguments)
    return command(arguments, timeout=min(120, remaining(args.qualification_deadline, args.qualification_clock)))


def origin_attempt(args: argparse.Namespace) -> int:
    raw = bounded(args.snapshot / "origin-attempt.txt", 32)
    if re.fullmatch(rb"[1-9][0-9]*\n?", raw) is None:
        raise ValueError("frozen official evidence origin is malformed")
    attempt = int(raw)
    if attempt > args.current_attempt:
        raise ValueError("frozen official evidence is from a future attempt")
    return attempt


def check_snapshot(args: argparse.Namespace) -> tuple[int, dict]:
    if bounded(args.manifest, 2 * 1024 * 1024) != bounded(args.snapshot / "stack-manifest.json", 2 * 1024 * 1024):
        raise ValueError("frozen official evidence belongs to another candidate manifest")
    attempt = origin_attempt(args)
    recorded = bounded(args.snapshot / "assessment.json")
    actual = validator(args, attempt, ["--prepare-review"])
    if actual != recorded:
        raise ValueError("frozen official evidence request differs from its revalidated evidence")
    plan = strict_json(actual)
    return attempt, plan


def lane_artifacts(artifacts: list[dict], lanes: list[str], run_id: int) -> dict[int, dict[str, list[dict]]]:
    attempts: dict[int, dict[str, list[dict]]] = {}
    for lane in lanes:
        prefix = f"official-{lane}-{run_id}-"
        for artifact in artifacts:
            if artifact["name"].startswith(prefix):
                suffix = artifact["name"][len(prefix):]
                if re.fullmatch(r"[1-9][0-9]*", suffix) is None:
                    raise ValueError("official lane artifact attempt is malformed")
                attempts.setdefault(int(suffix), {}).setdefault(lane, []).append(artifact)
    return attempts


def snapshot(args: argparse.Namespace, github: GitHub) -> bool:
    context(args)
    if args.snapshot.exists() or args.snapshot.is_symlink():
        raise ValueError("official snapshot destination already exists")
    name = f"official-evidence-input-{args.run_id}"
    pages = json.loads(github.api(f"actions/runs/{args.run_id}/artifacts?per_page=100", pages=True))
    artifacts = [artifact for page in pages for artifact in page["artifacts"]]
    matches = [artifact for artifact in artifacts if artifact["name"] == name]
    lanes = json.loads(command([str(args.validator), "--list-lanes"]))
    attempts = lane_artifacts(artifacts, lanes, args.run_id)
    if len(matches) > 1 or matches and matches[0].get("expired") is not False:
        raise ValueError("frozen official evidence artifact is duplicated or expired")
    if matches:
        github.download(args.run_id, name, args.snapshot)
        origin, _ = check_snapshot(args)
        if any(attempt > origin for attempt in attempts):
            raise ValueError("newer official lane evidence invalidates the frozen assessment snapshot")
        return False

    # Recover a completed collection even if its first snapshot upload was
    # interrupted. Never assemble different attempts or fall back past a newer
    # partial/failed collection. The Rust assessment still checks every byte.
    if not attempts:
        raise ValueError("official candidate has no collected lane artifacts")
    origin = max(attempts)
    collection = attempts[origin]
    if origin > args.current_attempt or set(collection) != set(lanes) or any(
        len(entries) != 1 or entries[0].get("expired") is not False for entries in collection.values()
    ):
        raise ValueError("latest official candidate collection is incomplete, duplicated or expired")
    args.snapshot.mkdir(parents=True, exist_ok=False)
    (args.snapshot / "stack-manifest.json").write_bytes(bounded(args.manifest, 2 * 1024 * 1024))
    (args.snapshot / "origin-attempt.txt").write_bytes(str(origin).encode("ascii") + b"\n")
    for lane in lanes:
        artifact = f"official-{lane}-{args.run_id}-{origin}"
        github.download(args.run_id, artifact, args.snapshot / "official-summaries" / artifact)
    # Failed or missing protocols cannot produce a valid assessment snapshot.
    # Validate before uploading the immutable evidence-input artifact.
    plan = validator(args, origin, ["--prepare-review"])
    (args.snapshot / "assessment.json").write_bytes(plan)
    return True


def protected_main(github: GitHub) -> str:
    branch = strict_json(github.api("branches/main"))
    if not isinstance(branch, dict):
        raise ValueError("official evidence authorization must come from protected main")
    commit = branch.get("commit")
    main_commit = commit.get("sha") if isinstance(commit, dict) else None
    if (branch.get("name") != "main" or branch.get("protected") is not True
            or not isinstance(main_commit, str) or SOURCE.fullmatch(main_commit) is None):
        raise ValueError("official evidence authorization must come from protected main")
    return main_commit


def write_exclusive(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def qualify(
    args: argparse.Namespace, github: GitHub, *, clock: Callable[[], float] = time.monotonic,
) -> None:
    context(args)
    if (args.current_attempt != 1 or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_SHA") != args.source or os.environ.get("GITHUB_REPOSITORY_ID") != REPOSITORY_ID):
        raise ValueError("bounded qualification requires the original protected-main dispatch attempt")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("official gate output already exists")
    deadline = clock() + QUALIFICATION_TIMEOUT_SECONDS
    args.qualification_deadline, args.qualification_clock = deadline, clock
    github.deadline, github.clock = deadline, clock
    attempt, plan = check_snapshot(args)
    if (attempt != 1 or not isinstance(plan, dict) or not isinstance(plan.get("pending"), list)
            or plan.get("release_qualified") is not False):
        raise ValueError("bounded qualification requires the original complete frozen assessment")
    remaining(deadline, clock)
    if protected_main(github) != args.source:
        raise ValueError("automated qualification requires unchanged protected main")
    remaining(deadline, clock)
    result = validator(args, attempt, ["--automated"])
    digest = "sha256:" + hashlib.sha256(result).hexdigest()
    authority = gate_authority(result, {"repository": REPOSITORY, "source_sha": args.source,
                               "gates": {"official_interoperability": {
                                   "run_id": str(args.run_id), "evidence_sha256": digest}}}, run_id=args.run_id)
    receipt = strict_json(result)
    # Historical v1 receipts and main-review records cannot enter production
    # qualification, even when their source or request bytes happen to match.
    if receipt["schema"] != "marty.official-release-gate/v2":
        raise ValueError("official qualification requires the automated v2 receipt")
    assessment = receipt["automated_qualification"]
    expected_manifest = "sha256:" + hashlib.sha256(bounded(args.manifest, 2 * 1024 * 1024)).hexdigest()
    expected_request = "sha256:" + hashlib.sha256(bounded(args.snapshot / "assessment.json")).hexdigest()
    if (authority["protected_main_commit"] != args.source or authority["review_required"] is not False
            or authority["harness_sha"] != args.harness or authority["manifest_sha256"] != expected_manifest
            or assessment["request_sha256"] != expected_request
            or assessment["automated_cases"] != len(plan["pending"])):
        raise ValueError("official Rust gate output differs from the frozen original assessment")
    remaining(deadline, clock)
    if protected_main(github) != args.source:
        raise ValueError("protected main changed after automated official qualification")
    remaining(deadline, clock)
    write_exclusive(args.output, result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["snapshot", "qualify"])
    parser.add_argument("--validator", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, default=Path("official-evidence-input"))
    parser.add_argument("--output", type=Path, default=Path("official-interoperability.json"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--harness", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--current-attempt", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "snapshot":
            created = snapshot(args, GitHub())
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as outputs:
                outputs.write(f"frozen_new={str(created).lower()}\n")
        else:
            qualify(args, GitHub())
    except (OSError, ValueError, KeyError, TypeError):
        print("Official candidate is not qualified: automated evidence is missing, invalid or rejected.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
