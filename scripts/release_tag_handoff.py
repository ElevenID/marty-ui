#!/usr/bin/env python3
"""Bound the original CD attempt to an authenticated operator tag result.

This module never executes a release payload and never changes a Git reference.
The separate operator entry point owns the two explicitly reviewed API writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

REPOSITORY = "ElevenID/marty-ui"
REPOSITORY_ID = 1140864197
REPOSITORY_NODE = "R_kgDORAA0xQ"
CD_WORKFLOW = ".github/workflows/cd.yml"
OPERATOR_WORKFLOW = ".github/workflows/release-tag-handoff.yml"
WAIT_STEP = "Wait for the exact operator tag handoff"
MAX_JSON = 4 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
ROOT = Path(__file__).resolve().parents[1]


class HandoffError(ValueError):
    """Authenticated handoff admission or transport failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HandoffError(message)


def positive(value: object) -> bool:
    return type(value) is int and 0 < value < 2**53


def decode(raw: bytes) -> object:
    require(0 < len(raw) <= MAX_JSON, "JSON exceeds its transport bound")

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            require(key not in result, "JSON contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise HandoffError("Non-finite JSON")

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise HandoffError("JSON is malformed") from error


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def bounded_file(path: Path, maximum: int = MAX_JSON) -> bytes:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum,
            "Expected a bounded ordinary file")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size and len(raw) <= maximum, "File changed while reading")
    return raw


def remaining(deadline: datetime | None, maximum: float = 120.0) -> float:
    value = maximum if deadline is None else min(maximum, (deadline - datetime.now(timezone.utc)).total_seconds())
    require(value > 0, "Handoff deadline expired before a command")
    return value


def command(arguments: list[str], *, input_bytes: bytes | None = None,
            maximum: int = MAX_JSON, destination: Path | None = None,
            timeout: float = 120, cwd: Path = ROOT,
            environment: dict[str, str] | None = None) -> tuple[int, bytes]:
    """Bound stdout while it is produced; never echo credentials or stderr."""
    env = environment if environment is not None else dict(
        os.environ, GH_NO_UPDATE_NOTIFIER="1", GH_PROMPT_DISABLED="1",
        GH_PAGER="cat", GIT_TERMINAL_PROMPT="0")
    output = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile() as errors:
        sink = destination.open("xb") if destination is not None else None
        process = None
        try:
            process = subprocess.Popen(arguments, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
            assert process.stdin is not None and process.stdout is not None
            if input_bytes is not None:
                require(len(input_bytes) <= MAX_JSON, "Command input exceeds its bound")
                process.stdin.write(input_bytes)
            process.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "Command exceeded its time bound")
                    for key, _ in selector.select(min(remaining, 1.0)):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(block)
                        require(total <= maximum, "Command output exceeds its size bound")
                        if sink is not None:
                            sink.write(block)
                        else:
                            output.extend(block)
            require(deadline > time.monotonic(), "Command exceeded its time bound")
            returncode = process.wait(timeout=deadline - time.monotonic())
            return returncode, bytes(output)
        except (OSError, subprocess.TimeoutExpired, HandoffError):
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise
        finally:
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
            if sink is not None:
                sink.close()


def git(*arguments: str, repository: Path = ROOT, deadline: datetime | None = None) -> str:
    code, raw = command(["git", "--no-replace-objects", *arguments], cwd=repository,
                        timeout=remaining(deadline, 30))
    require(code == 0, "Git source inspection failed")
    return raw.decode("utf-8").strip()


def parse_http(raw: bytes) -> tuple[int, bytes]:
    # gh --include prints the actual final response status and headers.
    normalized = raw.replace(b"\r\n", b"\n")
    header, separator, body = normalized.partition(b"\n\n")
    first = header.split(b"\n", 1)[0]
    match = re.fullmatch(rb"HTTP/[0-9.]+ ([0-9]{3})(?: [^\n]*)?", first)
    require(bool(separator) and match is not None, "GitHub response status is unavailable")
    assert match is not None
    return int(match.group(1)), body


class GitHub:
    def __init__(self, executable: str = "gh", *, deadline: datetime | None = None) -> None:
        self.executable = executable
        self.deadline = deadline
        self.mutations: list[dict] = []
        self.crypto: list[dict] = []

    def response(self, path: str, *, method: str = "GET", payload: object | None = None) -> tuple[int, bytes]:
        require(path.startswith(f"repos/{REPOSITORY}/") or path in {f"repos/{REPOSITORY}", "graphql"},
                "GitHub endpoint is outside the release repository")
        args = [self.executable, "api", "--hostname", "github.com", "--include",
                "--method", method, path, "-H", "X-GitHub-Api-Version: 2026-03-10"]
        body = None
        if payload is not None:
            args += ["--input", "-"]
            body = encoded(payload)
        observation = None
        if method != "GET":
            observation = {"endpoint": path, "method": method, "request": payload,
                           "requested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "outcome": "unknown"}
            self.mutations.append(observation)
        code, raw = command(args, input_bytes=body, timeout=remaining(self.deadline))
        status, response = parse_http(raw)
        if observation is not None:
            observation.update(http_status=status, response=decode(response), outcome="response_received")
        require(code == 0 or status >= 400 or path == "graphql" and status == 200,
                "GitHub command failed without an HTTP refusal")
        return status, response

    def json(self, path: str, *, absent: bool = False) -> object | None:
        status, raw = self.response(path)
        if absent and status == 404:
            value = decode(raw)
            require(isinstance(value, dict) and value.get("message") == "Not Found",
                    "GitHub absence response is malformed")
            return None
        require(status == 200, f"GitHub read failed with HTTP {status}")
        return decode(raw)

    def pages(self, path: str, key: str) -> list[dict]:
        records: list[dict] = []
        total = None
        for page in range(1, 31):
            value = self.json(f"{path}?per_page=100&page={page}")
            require(isinstance(value, dict) and type(value.get("total_count")) is int,
                    "GitHub listing lacks a complete count")
            count = value["total_count"]
            require(0 <= count <= 3000 and (total is None or total == count),
                    "GitHub listing changed or exceeds its bound")
            total = count
            entries = value.get(key)
            require(isinstance(entries, list) and len(entries) <= 100
                    and all(isinstance(item, dict) and positive(item.get("id")) for item in entries),
                    "GitHub listing entries are malformed")
            records.extend(entries)
            require(len({item["id"] for item in records}) == len(records),
                    "GitHub listing has duplicate IDs")
            if len(records) == count:
                return records
            require(len(entries) == 100 and len(records) < count,
                    "GitHub listing pagination is incomplete")
        raise HandoffError("GitHub listing exceeds the page bound")

    def array_pages(self, path: str) -> list[dict]:
        records: list[dict] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 31):
            entries = self.json(f"{path}{separator}per_page=100&page={page}")
            require(isinstance(entries, list) and len(entries) <= 100
                    and all(isinstance(item, dict) and positive(item.get("id")) for item in entries),
                    "GitHub array listing is malformed")
            records.extend(entries)
            require(len({item["id"] for item in records}) == len(records), "GitHub array listing repeats IDs")
            if len(entries) < 100:
                return records
        raise HandoffError("GitHub array listing exceeds its page bound")

    def artifacts(self, run_id: int) -> list[dict]:
        require(positive(run_id), "Invalid artifact run ID")
        return self.pages(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts", "artifacts")

    def artifact(self, run_id: int, name: str, source: str) -> dict:
        matches = [item for item in self.artifacts(run_id) if item.get("name") == name]
        require(len(matches) == 1, "Expected one immutable handoff artifact")
        item = matches[0]
        require(item.get("expired") is False and isinstance(item.get("digest"), str)
                and DIGEST.fullmatch(item["digest"]) is not None
                and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= MAX_ARCHIVE,
                "Handoff artifact is expired or lacks bounded immutable identity")
        owner = item.get("workflow_run", {})
        require(positive(owner.get("id")) and owner["id"] == run_id and owner.get("head_sha") == source
                and owner.get("head_branch") == "main",
                "Handoff artifact belongs to another source or run")
        if "run_attempt" in owner:
            require(type(owner["run_attempt"]) is int and owner["run_attempt"] == 1,
                    "Handoff artifact attempt identity is malformed")
        return item

    def download(self, artifact: dict, archive: Path) -> None:
        require(not archive.exists() and not archive.is_symlink(), "Artifact destination already exists")
        code, _ = command([self.executable, "api", "--hostname", "github.com",
                           f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                          maximum=artifact["size_in_bytes"], destination=archive,
                          timeout=remaining(self.deadline))
        require(code == 0 and archive.stat().st_size == artifact["size_in_bytes"]
                and file_digest(archive) == artifact["digest"],
                "Artifact ZIP differs from its authenticated API digest")

    def main(self) -> dict:
        branch = self.json(f"repos/{REPOSITORY}/branches/main")
        require(isinstance(branch, dict) and branch.get("name") == "main"
                and branch.get("protected") is True
                and isinstance(branch.get("commit"), dict)
                and SHA.fullmatch(branch["commit"].get("sha", "")) is not None,
                "Authorization requires authenticated protected main")
        return branch

    def run(self, run_id: int, workflow: str, source: str) -> dict:
        require(positive(run_id), "Invalid workflow run ID")
        run = self.json(f"repos/{REPOSITORY}/actions/runs/{run_id}")
        require(isinstance(run, dict) and positive(run.get("id")) and run["id"] == run_id
                and run.get("path") == workflow and run.get("event") == "workflow_dispatch"
                and run.get("head_branch") == "main" and run.get("head_sha") == source
                and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
                and run.get("repository", {}).get("id") == REPOSITORY_ID
                and run.get("repository", {}).get("full_name") == REPOSITORY,
                "Workflow invocation differs from its authenticated first-attempt identity")
        return run


def extract_archive(archive: Path, output: Path, names: set[str], *, maximum: int = MAX_ARCHIVE,
                    limits: dict[str, int] | None = None) -> None:
    require(not output.exists() and not output.is_symlink(), "Extraction destination already exists")
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        files = [item for item in members if not item.is_dir()]
        require(len(files) == len(names) and {item.filename for item in files} == names,
                "Artifact ZIP has missing, duplicate or unexpected files")
        require(len(members) == len({item.filename for item in members}), "Artifact ZIP has duplicate entries")
        directories = {str(Path(name).parent) + "/" for name in names if "/" in name}
        total = 0
        for item in members:
            mode = (item.external_attr >> 16) & 0o170000
            require(not item.flag_bits & 1 and mode in {0, stat.S_IFREG, stat.S_IFDIR},
                    "Artifact ZIP has encrypted or linked entries")
            if item.is_dir():
                require(mode in {0, stat.S_IFDIR} and item.filename in directories and item.file_size == 0,
                        "Artifact ZIP contains an unexpected directory")
            else:
                bound = maximum if limits is None else limits[item.filename]
                require(mode in {0, stat.S_IFREG} and 0 < item.file_size <= bound,
                        "Artifact ZIP member is not a bounded regular file")
                total += item.file_size
        require(total <= maximum, "Artifact ZIP exceeds its expanded bound")
        output.mkdir(mode=0o700)
        for item in files:
            destination = output / item.filename
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.open(item) as reader, destination.open("xb") as writer:
                remaining = item.file_size
                while remaining:
                    block = reader.read(min(1024 * 1024, remaining))
                    require(bool(block), "Artifact ZIP member is truncated")
                    writer.write(block)
                    remaining -= len(block)
                require(not reader.read(1), "Artifact ZIP member exceeds its declared size")
            destination.chmod(0o600)


def timestamp(value: str) -> datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None,
            "Handoff timestamp is malformed")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise HandoffError("Handoff timestamp is invalid") from error


def exact_context(workflow: str) -> tuple[int, str]:
    run = os.environ.get("GITHUB_RUN_ID", "")
    source = os.environ.get("GITHUB_SHA", "")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{workflow}@refs/heads/main"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and re.fullmatch(r"[1-9][0-9]*", run) is not None
            and positive(int(run)) and SHA.fullmatch(source) is not None,
            "Handoff requires its exact first-attempt protected-main workflow context")
    return int(run), source


def tag_message(request: dict, request_sha: str, artifact: dict, operator_run: int) -> str:
    require(positive(operator_run) and DIGEST.fullmatch(request_sha) is not None,
            "Invalid tag handoff identity")
    return (f"Release {request['tag'][1:]}\n\n"
            f"Release-Transaction: {request['transaction_id']}\n"
            f"Claim-Run: {request['claim_run_id']}\n"
            f"Source-SHA: {request['source_sha']}\n"
            f"Review-Main: {request['protected_main_commit']}\n"
            f"Candidate-Run: {request['run_id']}\n"
            "Candidate-Attempt: 1\n"
            f"Handoff-Request: {request_sha}\n"
            f"Handoff-Artifact: {artifact['id']}\n"
            f"Handoff-Artifact-Digest: {artifact['digest']}\n"
            f"Operator-Run: {operator_run}\n"
            "Operator-Attempt: 1\n")


def operator_from_message(message: str) -> int:
    matches = re.findall(r"^Operator-Run: ([1-9][0-9]*)$", message, re.MULTILINE)
    require(len(matches) == 1 and positive(int(matches[0])), "Tag lacks one actual operator run identity")
    return int(matches[0])


def annotated_tag(github: GitHub, tag: str) -> dict | None:
    require(TAG.fullmatch(tag) is not None, "Stable release tag is required")
    ref = github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}", absent=True)
    if ref is None:
        return None
    require(isinstance(ref, dict) and ref.get("ref") == f"refs/tags/{tag}"
            and ref.get("object", {}).get("type") == "tag"
            and SHA.fullmatch(ref.get("object", {}).get("sha", "")) is not None,
            "Release tag is not an exact annotated tag")
    value = github.json(f"repos/{REPOSITORY}/git/tags/{ref['object']['sha']}")
    require(isinstance(value, dict) and value.get("sha") == ref["object"]["sha"]
            and value.get("tag") == tag and value.get("object", {}).get("type") == "commit"
            and SHA.fullmatch(value.get("object", {}).get("sha", "")) is not None,
            "Annotated release tag object is malformed")
    return value


def successful_result(github: GitHub, run_id: int, request: dict, request_sha: str,
                      checkpoint: dict, tag: dict, directory: Path) -> dict | None:
    run = github.run(run_id, OPERATOR_WORKFLOW, request["protected_main_commit"])
    require(timestamp(run["created_at"]) >= timestamp(request["created_at"]),
            "Operator invocation predates the immutable handoff")
    if run.get("status") != "completed":
        require(run.get("status") in {"queued", "in_progress", "waiting", "pending"},
                "Operator invocation has an unknown status")
        return None
    require(run.get("conclusion") == "success", "Operator invocation did not complete successfully")
    name = f"stack-release-tag-handoff-{run_id}-1"
    artifact = github.artifact(run_id, name, request["protected_main_commit"])
    require(artifact["size_in_bytes"] <= 1024 * 1024, "Operator result artifact is oversized")
    archive = directory / "operator-result.zip"
    github.download(artifact, archive)
    held = directory / "operator-result"
    extract_archive(archive, held, {"tag-handoff-result.json"}, maximum=65536)
    value = decode(bounded_file(held / "tag-handoff-result.json", 65536))
    numeric = {"operator_run_id", "operator_run_attempt", "candidate_run_id",
               "candidate_run_attempt", "checkpoint_artifact_id"}
    require(isinstance(value, dict) and all(positive(value.get(key)) for key in numeric),
            "Operator result requires exact positive integer identities")
    expected = {
        "schema": "marty.release-tag-handoff-result/v1", "status": "success", "mode": "create-qualified-tag",
        "repository": REPOSITORY, "operator_run_id": run_id, "operator_run_attempt": 1,
        "operator_source_sha": request["protected_main_commit"], "source_sha": request["source_sha"],
        "candidate_run_id": request["run_id"], "candidate_run_attempt": 1,
        "claim_run_id": request["claim_run_id"], "tag": request["tag"],
        "protected_main_commit": request["protected_main_commit"], "request_sha256": request_sha,
        "checkpoint_artifact_id": checkpoint["id"], "checkpoint_artifact_sha256": checkpoint["digest"],
        "tag_object_sha": tag["sha"], "tag_commit_sha": request["source_sha"],
    }
    require(isinstance(value, dict) and all(value.get(key) == item for key, item in expected.items()),
            "Operator result does not bind this exact candidate, tag and checkpoint")
    require(set(value) == set(expected) | {"completed_at", "crypto_verified", "main_before_sha", "main_after_sha"}
            and value["crypto_verified"] is True
            and value["main_before_sha"] == request["protected_main_commit"]
            and value["main_after_sha"] == request["protected_main_commit"],
            "Operator result schema or explicit verification result is invalid")
    require(timestamp(request["created_at"]) <= timestamp(value["completed_at"]) <= timestamp(request["not_after"]),
            "Operator result is outside the bounded handoff")
    require(github.artifact(run_id, name, request["protected_main_commit"]) == artifact,
            "Operator result artifact changed while reading")
    final_run = github.run(run_id, OPERATOR_WORKFLOW, request["protected_main_commit"])
    require(final_run.get("status") == "completed" and final_run.get("conclusion") == "success",
            "Operator invocation changed while reading its result")
    return {"operator_run_id": run_id, "operator_run_attempt": 1,
            "result_artifact_id": artifact["id"], "result_artifact_sha256": artifact["digest"],
            "result_sha256": sha256(bounded_file(held / "tag-handoff-result.json", 65536)),
            "tag_object_sha": tag["sha"]}


def wait_for_operator(checkpoint_directory: Path, artifact_id: int, artifact_digest: str,
                      output: Path, *, github: GitHub | None = None,
                      now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                      sleep: Callable[[float], None] = time.sleep) -> dict:
    if __package__:
        from .stable_publication_checkpoint import load_checkpoint
        from .release_review_main import gate_authority, require_review_only_history
    else:
        from stable_publication_checkpoint import load_checkpoint
        from release_review_main import gate_authority, require_review_only_history
    github = github or GitHub()
    run_id, source = exact_context(CD_WORKFLOW)
    request = load_checkpoint(checkpoint_directory)
    github.deadline = timestamp(request["not_after"])
    require(request["run_id"] == run_id and request["source_sha"] == source,
            "CD wait checkpoint belongs to another invocation")
    request_sha = sha256(bounded_file(checkpoint_directory / "request.json", 65536))
    digest = artifact_digest if artifact_digest.startswith("sha256:") else "sha256:" + artifact_digest
    name = f"stack-release-publication-inputs-{run_id}-1"
    artifact = github.artifact(run_id, name, source)
    require(artifact["id"] == artifact_id and artifact["digest"] == digest,
            "Uploaded checkpoint identity differs from authenticated artifact API")
    transaction = decode(bounded_file(checkpoint_directory / "assets/release-transaction.json", 65536))
    authority = gate_authority(bounded_file(checkpoint_directory / "official-interoperability.json"),
                               transaction, run_id=run_id, current_attempt=1)
    require(not output.exists() and not output.is_symlink(), "Tag handoff result already exists")
    admitted_main = github.main()["commit"]["sha"]
    require(admitted_main == request["protected_main_commit"], "Protected main differs from the handoff")
    git("fetch", "--no-tags", "origin", admitted_main, deadline=github.deadline)
    require_review_only_history(source, admitted_main, run_id, 1, authority["review_required"],
                                record_sha256=authority["record_sha256"],
                                timeout_seconds=remaining(github.deadline, 30))
    with tempfile.TemporaryDirectory(prefix="marty-tag-result-") as temporary:
        directory = Path(temporary)
        while True:
            require(now() < timestamp(request["not_after"]), "Operator tag handoff deadline expired")
            current = github.run(run_id, CD_WORKFLOW, source)
            require(current.get("status") == "in_progress", "Original CD attempt is no longer running")
            main = github.main()["commit"]["sha"]
            require(main == request["protected_main_commit"], "Protected main changed during tag handoff")
            # These exact immutable commit objects/history were admitted once.
            # Poll only the authenticated current-main identity thereafter.
            tag = annotated_tag(github, request["tag"])
            if tag is not None:
                operator_run = operator_from_message(tag.get("message", ""))
                require(tag["object"]["sha"] == source
                        and tag.get("message", "").rstrip("\n") == tag_message(request, request_sha, artifact, operator_run).rstrip("\n"),
                        "Immutable tag differs from the exact operator handoff")
                result = successful_result(github, operator_run, request, request_sha, artifact, tag, directory)
                if result is not None:
                    # An immutable tag is never sufficient by itself. This read
                    # follows successful operator completion and its bound ZIP.
                    require(github.main()["commit"]["sha"] == main, "Protected main changed before publication")
                    require(annotated_tag(github, request["tag"]) == tag, "Tag changed during result admission")
                    require(now() < timestamp(request["not_after"]), "Operator result arrived after its deadline")
                    require(github.run(run_id, CD_WORKFLOW, source).get("status") == "in_progress",
                            "Original CD attempt stopped before publication")
                    load_checkpoint(checkpoint_directory)
                    output.write_bytes(encoded(result))
                    return result
            sleep(min(30.0, max(0.0, (timestamp(request["not_after"]) - now()).total_seconds())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["wait"])
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        wait_for_operator(args.checkpoint, args.artifact_id, args.artifact_digest, args.output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("Release tag handoff refused; immutable state was preserved.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
