#!/usr/bin/env python3
"""Freeze same-run official evidence and read review authorization from protected main.

All candidate, module, image and disposition decisions belong to the shared
Rust validator. This file handles authenticated GitHub transport and immutable
artifact reuse only. It never writes a review record or contacts a reviewer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

REPOSITORY = "ElevenID/marty-ui"
MAX_BYTES = 8 * 1024 * 1024
SOURCE = re.compile(r"[0-9a-f]{40}\Z")


def bounded(path: Path, maximum: int = MAX_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("official review input must be a bounded regular file")
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("official review input exceeds its size limit")
    return value


def command(arguments: list[str]) -> bytes:
    try:
        result = subprocess.run(arguments, capture_output=True, check=False, timeout=120)
    except subprocess.TimeoutExpired:
        raise ValueError("official review transport or validation exceeded its bound") from None
    if result.returncode:
        # API errors can contain URLs/configuration; never dump response bodies.
        raise ValueError("official review transport or Rust validation failed")
    if len(result.stdout) > MAX_BYTES:
        raise ValueError("official review command output exceeds its size limit")
    return result.stdout


class GitHub:
    def api(self, path: str, *, raw: bool = False, pages: bool = False) -> bytes:
        args = ["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/{path}"]
        if raw:
            args += ["-H", "Accept: application/vnd.github.raw+json"]
        if pages:
            args += ["--paginate", "--slurp"]
        return command(args)

    def download(self, run_id: int, name: str, directory: Path) -> None:
        command(["gh", "run", "download", str(run_id), "--repo", f"https://github.com/{REPOSITORY}",
                 "--name", name, "--dir", str(directory)])


def context(args: argparse.Namespace) -> None:
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_RUN_ID") != str(args.run_id)
        or os.environ.get("GITHUB_RUN_ATTEMPT") != str(args.current_attempt)
        or not 0 < args.run_id < 2**53
        or not 0 < args.current_attempt < 2**53
        or not SOURCE.fullmatch(args.source)
        or not SOURCE.fullmatch(args.harness)
    ):
        raise ValueError("official review requires its exact protected-main release-run context")


def validator(args: argparse.Namespace, attempt: int, mode: list[str]) -> bytes:
    return command([str(args.validator), *mode, str(args.snapshot / "stack-manifest.json"),
                    args.source, args.harness, str(args.run_id), str(attempt),
                    str(args.snapshot / "official-summaries")])


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
    recorded = bounded(args.snapshot / "review-request.json")
    actual = validator(args, attempt, ["--prepare-review"])
    if actual != recorded:
        raise ValueError("frozen official review request differs from its revalidated evidence")
    plan = json.loads(actual)
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
    name = f"official-review-input-{args.run_id}"
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
            raise ValueError("newer official lane evidence invalidates the frozen review snapshot")
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
    # Failed/missing protocols do not produce an approvable snapshot. This must
    # succeed before the workflow uploads the immutable review-input artifact.
    plan = validator(args, origin, ["--prepare-review"])
    (args.snapshot / "review-request.json").write_bytes(plan)
    return True


def qualify(args: argparse.Namespace, github: GitHub) -> None:
    context(args)
    attempt, plan = check_snapshot(args)
    if not plan["pending"]:
        result = validator(args, attempt, [])
    else:
        # Resolve main once, then fetch only that immutable commit. Do not accept
        # candidate-supplied records, arbitrary refs, or older accepted versions
        # when the current main record rejects/revokes a disposition.
        branch = json.loads(github.api("branches/main"))
        main_commit = branch["commit"]["sha"]
        if branch.get("name") != "main" or branch.get("protected") is not True or not SOURCE.fullmatch(main_commit):
            raise ValueError("official review authorization must come from protected main")
        record = github.api(f"contents/release/official-reviews/{args.run_id}-{attempt}.json?ref={main_commit}", raw=True)
        if len(record) > 256 * 1024:
            raise ValueError("official review disposition exceeds its size limit")
        args.authorization.mkdir(parents=True, exist_ok=False)
        path = args.authorization / "record.json"
        path.write_bytes(record)
        (args.authorization / "protected-main.json").write_text(
            json.dumps({"repository": REPOSITORY, "ref": "refs/heads/main", "commit": main_commit, "protected": True}) + "\n",
            encoding="utf-8",
        )
        result = validator(args, attempt, ["--with-main-review", str(path), main_commit])
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("official gate output already exists")
    args.output.write_bytes(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["snapshot", "qualify"])
    parser.add_argument("--validator", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, default=Path("official-review-input"))
    parser.add_argument("--authorization", type=Path, default=Path("official-review-authorization"))
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
        print("Official candidate is not qualified: evidence or protected-main review is missing, invalid or rejected.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
