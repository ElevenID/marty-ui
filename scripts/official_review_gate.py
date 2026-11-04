#!/usr/bin/env python3
"""Freeze same-run official evidence and read review authorization from protected main.

All candidate, module, image and disposition decisions belong to the shared
Rust validator. This file handles authenticated GitHub transport and immutable
artifact reuse only. It never writes a review record or contacts a reviewer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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
    from .release_review_main import (
        MAX_RECORD_BYTES, ROOT, gate_authority, require_review_only_history, review_path, strict_json,
    )
else:
    from release_review_main import (
        MAX_RECORD_BYTES, ROOT, gate_authority, require_review_only_history, review_path, strict_json,
    )

REPOSITORY = "ElevenID/marty-ui"
REPOSITORY_ID = "1140864197"
MAX_BYTES = 8 * 1024 * 1024
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
REVIEW_WAIT_SECONDS = 60 * 60
REVIEW_POLL_SECONDS = 60


def bounded(path: Path, maximum: int = MAX_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("official review input must be a bounded regular file")
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("official review input exceeds its size limit")
    return value


def completed(arguments: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise ValueError("official review command has no remaining time")
    try:
        result = subprocess.run(arguments, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValueError("official review transport or validation exceeded its bound") from None
    if len(result.stdout) > MAX_BYTES or len(result.stderr) > MAX_BYTES:
        raise ValueError("official review command output exceeds its size limit")
    return result


def command(arguments: list[str], *, timeout: float = 120) -> bytes:
    result = completed(arguments, timeout=timeout)
    if result.returncode:
        # API errors can contain URLs/configuration; never dump response bodies.
        raise ValueError("official review transport or Rust validation failed")
    return result.stdout


def remaining(deadline: float, clock: Callable[[], float] = time.monotonic) -> float:
    value = deadline - clock()
    if not math.isfinite(value) or value <= 0:
        raise ValueError("official review deadline expired without complete authorization")
    return value


def http_json_response(raw: bytes) -> tuple[int, dict]:
    """Parse gh's included response header, without normalizing body bytes."""
    markers = [(raw.find(marker), marker) for marker in (b"\r\n\r\n", b"\n\n") if marker in raw]
    marker = min(markers)[1] if markers else b"\r\n\r\n"
    header, separator, body = raw.partition(marker)
    if not separator or len(header) > 65536:
        raise ValueError("official review response headers are malformed")
    lines = header.splitlines()
    status = re.fullmatch(rb"HTTP/(?:1\.[01]|2(?:\.0)?) ([1-5][0-9]{2})(?: [^\r\n]*)?", lines[0]) if lines else None
    if status is None:
        raise ValueError("official review response has no authoritative HTTP status")
    content_types = []
    for line in lines[1:]:
        key, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key):
            raise ValueError("official review response headers are malformed")
        if key.lower() == b"content-type":
            content_types.append(value.strip().lower())
    if len(content_types) != 1 or content_types[0].split(b";", 1)[0] != b"application/json":
        raise ValueError("official review response is not a JSON file response")
    value = strict_json(body)
    if not isinstance(value, dict):
        raise ValueError("official review response body is malformed")
    return int(status[1]), value


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

    def fetch_main(self, commit: str, repository: Path) -> None:
        if SOURCE.fullmatch(commit) is None:
            raise ValueError("official review main identity is malformed")
        base = ["git", "--no-replace-objects", "-C", str(repository),
                "-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false", "-c", "gc.auto=0"]
        self.run([*base, "fetch", "--no-tags", "--no-recurse-submodules",
                  f"https://github.com/{REPOSITORY}.git", "+refs/heads/main:refs/remotes/origin/main"])
        if self.run([*base, "rev-parse", "refs/remotes/origin/main^{commit}"]).strip() != commit.encode("ascii"):
            raise ValueError("protected main changed while loading immutable review history")

    def review_record(self, run_id: int, attempt: int, commit: str) -> bytes | None:
        path = review_path(run_id, attempt)
        if SOURCE.fullmatch(commit) is None:
            raise ValueError("official review main identity is malformed")
        response = completed(
            ["gh", "api", "--hostname", "github.com", "--include", "--method", "GET",
             "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10",
             f"repos/{REPOSITORY}/contents/{path}?ref={commit}"], timeout=self.timeout(),
        )
        status, value = http_json_response(response.stdout)
        if status == 404 and response.returncode == 1 and value.get("message") == "Not Found":
            return None
        if status != 200 or response.returncode != 0:
            raise ValueError("official review record transport did not establish success or absence")
        if (value.get("type") != "file" or value.get("path") != path or value.get("name") != path.rsplit("/", 1)[1]
                or value.get("encoding") != "base64" or type(value.get("size")) is not int
                or not 0 < value["size"] <= MAX_RECORD_BYTES or not isinstance(value.get("content"), str)
                or len(value["content"]) > 2 * MAX_RECORD_BYTES
                or not isinstance(value.get("sha"), str) or SOURCE.fullmatch(value["sha"]) is None):
            raise ValueError("official review record envelope is invalid or oversized")
        try:
            encoded = value["content"].encode("ascii").replace(b"\r", b"").replace(b"\n", b"")
            record = base64.b64decode(encoded, validate=True)
        except (UnicodeError, binascii.Error) as error:
            raise ValueError("official review record content is not valid base64") from error
        blob = hashlib.sha1(b"blob " + str(len(record)).encode("ascii") + b"\0" + record).hexdigest()
        if len(record) != value["size"] or blob != value["sha"]:
            raise ValueError("official review record differs from its immutable file envelope")
        return record


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
        raise ValueError("official review requires its exact protected-main release-run context")


def validator(args: argparse.Namespace, attempt: int, mode: list[str]) -> bytes:
    arguments = [str(args.validator), *mode, str(args.snapshot / "stack-manifest.json"),
                 args.source, args.harness, str(args.run_id), str(attempt), str(args.snapshot / "official-summaries")]
    if getattr(args, "review_deadline", None) is None:
        return command(arguments)
    return command(arguments, timeout=min(120, remaining(args.review_deadline, args.review_clock)))


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


def protected_main(github: GitHub) -> str:
    branch = strict_json(github.api("branches/main"))
    if not isinstance(branch, dict):
        raise ValueError("official review authorization must come from protected main")
    commit = branch.get("commit")
    main_commit = commit.get("sha") if isinstance(commit, dict) else None
    if (branch.get("name") != "main" or branch.get("protected") is not True
            or not isinstance(main_commit, str) or SOURCE.fullmatch(main_commit) is None):
        raise ValueError("official review authorization must come from protected main")
    return main_commit


def write_exclusive(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def qualify(
    args: argparse.Namespace, github: GitHub, *, clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    context(args)
    if (args.current_attempt != 1 or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_SHA") != args.source or os.environ.get("GITHUB_REPOSITORY_ID") != REPOSITORY_ID):
        raise ValueError("bounded qualification requires the original protected-main dispatch attempt")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("official gate output already exists")
    if args.authorization.exists() or args.authorization.is_symlink():
        raise FileExistsError("official review authorization destination already exists")
    deadline = clock() + REVIEW_WAIT_SECONDS
    args.review_deadline, args.review_clock = deadline, clock
    github.deadline, github.clock = deadline, clock
    attempt, plan = check_snapshot(args)
    if (attempt != 1 or not isinstance(plan, dict) or not isinstance(plan.get("pending"), list)
            or plan.get("release_qualified") is not False):
        raise ValueError("bounded qualification requires the original complete frozen review plan")
    pending = bool(plan["pending"])
    repository = getattr(args, "repository", ROOT)
    absent_commit = None
    waiting_announced = False
    while True:
        remaining(deadline, clock)
        main_commit = protected_main(github)
        remaining(deadline, clock)
        if main_commit == absent_commit:
            sleeper(min(REVIEW_POLL_SECONDS, remaining(deadline, clock)))
            continue
        github.fetch_main(main_commit, repository)
        require_review_only_history(args.source, main_commit, args.run_id, attempt, pending,
                                    repository=repository, timeout_seconds=remaining(deadline, clock))
        record = None
        if pending:
            record = github.review_record(args.run_id, attempt, main_commit)
            remaining(deadline, clock)
            if record is None:
                # Only S can have no record: the history check requires the
                # exact new file at an advanced main. Immutable absence at S
                # is safe to cache; no artifact or Rust rerun is needed.
                if main_commit != args.source:
                    raise ValueError("review API absence contradicts the authenticated main tree")
                absent_commit = main_commit
                if not waiting_announced:
                    print("Official review is pending within the original 60-minute attempt.", flush=True)
                    waiting_announced = True
                sleeper(min(REVIEW_POLL_SECONDS, remaining(deadline, clock)))
                continue
            record_digest = "sha256:" + hashlib.sha256(record).hexdigest()
            require_review_only_history(args.source, main_commit, args.run_id, attempt, True,
                                        repository=repository, record_sha256=record_digest,
                                        timeout_seconds=remaining(deadline, clock))
            args.authorization.mkdir(mode=0o700, parents=True, exist_ok=False)
            path = args.authorization / "record.json"
            write_exclusive(path, record)
            write_exclusive(args.authorization / "protected-main.json",
                            (json.dumps({"repository": REPOSITORY, "ref": "refs/heads/main", "commit": main_commit,
                                         "protected": True}) + "\n").encode("utf-8"))
            result = validator(args, attempt, ["--with-main-review", str(path), main_commit])
        else:
            result = validator(args, attempt, [])
        digest = "sha256:" + hashlib.sha256(result).hexdigest()
        authority = gate_authority(result, {"repository": REPOSITORY, "source_sha": args.source,
                                   "gates": {"official_interoperability": {
                                       "run_id": str(args.run_id), "evidence_sha256": digest}}}, run_id=args.run_id)
        expected_manifest = "sha256:" + hashlib.sha256(bounded(args.manifest, 2 * 1024 * 1024)).hexdigest()
        if (authority["protected_main_commit"] != main_commit or authority["review_required"] != pending
                or authority["harness_sha"] != args.harness or authority["manifest_sha256"] != expected_manifest
                or pending and (authority["record_sha256"] != "sha256:" + hashlib.sha256(record).hexdigest()
                                or authority["request_sha256"] != "sha256:" + hashlib.sha256(
                                    bounded(args.snapshot / "review-request.json")).hexdigest())):
            raise ValueError("official Rust gate output differs from the frozen original authorization")
        remaining(deadline, clock)
        if protected_main(github) != main_commit:
            raise ValueError("protected main changed after official review qualification")
        remaining(deadline, clock)
        write_exclusive(args.output, result)
        return


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
    parser.add_argument("--repository", type=Path, default=ROOT)
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
