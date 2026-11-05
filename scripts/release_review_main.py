#!/usr/bin/env python3
"""Bind an automatically qualified release candidate to unchanged protected main.

The shared Rust gate owns official protocol and browser outcome requirements.
Production consumers accept only its automated v2 receipt. Historical review
history utilities remain available for local evidence inspection.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ElevenID/marty-ui"
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
LANES = frozenset({"oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"})
MAX_GATE_BYTES = 256 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_HISTORY_COMMITS = 128
MAX_GIT_BYTES = 8 * 1024 * 1024
HISTORY_TIMEOUT_SECONDS = 30


class ReviewMainError(ValueError):
    """The current protected-main authorization is not the original candidate's."""


def strict_json(raw: bytes) -> Any:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ReviewMainError("release review JSON has duplicate keys")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise ReviewMainError("release review JSON contains a non-finite number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReviewMainError("release review JSON is malformed") from error


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewMainError(message)


def _source(value: Any) -> bool:
    return isinstance(value, str) and SOURCE.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _run(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**53


def review_path(run_id: int, origin_attempt: int = 1) -> str:
    _require(_run(run_id) and type(origin_attempt) is int and origin_attempt == 1,
             "bounded release review requires the original first attempt")
    return f"release/official-reviews/{run_id}-{origin_attempt}.json"


def gate_authority(
    gate_bytes: bytes, transaction: dict[str, Any], *, run_id: int, current_attempt: int = 1,
) -> dict[str, Any]:
    """Read an automated v2 receipt after matching its transaction digest.

    The caller authenticates the original run/artifact and the transaction.
    Historical raw-pass and manual-review v1 receipts cannot authorize a new
    release under this policy. The candidate source remains its admitted main.
    """
    _require(_run(run_id) and type(current_attempt) is int and current_attempt == 1,
             "automated qualification requires the original first attempt")
    _require(isinstance(gate_bytes, bytes) and 0 < len(gate_bytes) <= MAX_GATE_BYTES,
             "official gate receipt exceeds its bound")
    _require(isinstance(transaction, dict) and transaction.get("repository") == REPOSITORY,
             "official gate transaction repository differs")
    source = transaction.get("source_sha")
    _require(_source(source), "official gate transaction source is malformed")
    gates = transaction.get("gates")
    binding = gates.get("official_interoperability") if isinstance(gates, dict) else None
    digest = "sha256:" + hashlib.sha256(gate_bytes).hexdigest()
    _require(isinstance(binding, dict) and set(binding) == {"run_id", "evidence_sha256"}
             and binding["run_id"] == str(run_id) and binding["evidence_sha256"] == digest,
             "official gate receipt differs from the transaction binding")
    gate = strict_json(gate_bytes)
    keys = {"schema", "source_sha", "harness_sha", "manifest_sha256", "run_id", "qualification_context",
            "lanes", "automated_qualification"}
    _require(isinstance(gate, dict) and set(gate) == keys,
             "official gate requires the automated v2 receipt shape")
    _require(gate["schema"] == "marty.official-release-gate/v2"
             and gate["source_sha"] == source and _source(gate["harness_sha"])
             and _digest(gate["manifest_sha256"]) and _run(gate["run_id"])
             and gate["run_id"] == run_id and gate["qualification_context"] == "PRE_PUBLICATION_CANDIDATE",
             "official gate receipt belongs to a different candidate or qualification policy")
    lanes = gate["lanes"]
    _require(isinstance(lanes, list) and len(lanes) == len(LANES)
             and all(isinstance(row, dict) and set(row) == {"lane", "summary_sha256"}
                     and isinstance(row["lane"], str) and _digest(row["summary_sha256"]) for row in lanes),
             "official gate lane inventory is malformed")
    _require({row["lane"] for row in lanes} == LANES, "official gate must retain all seven unique lanes")
    assessment = gate["automated_qualification"]
    assessment_keys = {"schema", "policy", "evidence_run_attempt", "request_sha256", "automated_cases",
                       "original_official_results_unchanged"}
    _require(isinstance(assessment, dict) and set(assessment) == assessment_keys,
             "automated official qualification metadata is malformed")
    _require(assessment["schema"] == "marty.automated-official-qualification/v1"
             and assessment["policy"] == "marty.official-verifier-outcome/v1"
             and type(assessment["evidence_run_attempt"]) is int and assessment["evidence_run_attempt"] == 1
             and _digest(assessment["request_sha256"])
             and type(assessment["automated_cases"]) is int and 0 <= assessment["automated_cases"] <= 13
             and assessment["original_official_results_unchanged"] is True,
             "automated official qualification is foreign, incomplete or not the original attempt")
    # The full assessment is already authenticated by gate_sha256. The stable
    # authority projection stays compatible with publication checkpoints, while
    # explicitly removing any ability for review to advance the source commit.
    return {"source_sha": source, "run_id": run_id, "origin_attempt": 1,
            "review_required": False, "protected_main_commit": source,
            "record_sha256": None, "request_sha256": None, "gate_sha256": digest,
            "harness_sha": gate["harness_sha"], "manifest_sha256": gate["manifest_sha256"]}


class _Git:
    def __init__(self, repository: Path, timeout_seconds: float | None = None) -> None:
        self.repository = repository
        if timeout_seconds is None:
            timeout_seconds = HISTORY_TIMEOUT_SECONDS
        _require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds) and timeout_seconds > 0,
                 "release review history timeout must be positive and finite")
        self.deadline = time.monotonic() + min(HISTORY_TIMEOUT_SECONDS, timeout_seconds)
        self.environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
        self.environment.update(GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
                                GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LANG="C")

    def __call__(self, *arguments: str) -> bytes:
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0, "release review history verification exceeded its bound")
        try:
            result = subprocess.run(
                ["git", "--no-replace-objects", "-c", "protocol.allow=never", "-c", "core.fsmonitor=false",
                 "-c", f"core.hooksPath={os.devnull}", *arguments], cwd=self.repository,
                env=self.environment, capture_output=True, check=False, timeout=remaining,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReviewMainError("could not verify the complete release review history") from error
        _require(result.returncode == 0 and len(result.stdout) <= MAX_GIT_BYTES,
                 "could not verify the complete bounded release review history")
        return result.stdout

    def record(self, commit: str, path: str) -> str | None:
        raw = self("ls-tree", "-z", "--full-tree", commit, "--", path)
        if not raw:
            return None
        parts = raw.split(b"\0")
        _require(len(parts) == 2 and not parts[1], "review record tree entry is ambiguous")
        metadata, separator, name = parts[0].partition(b"\t")
        fields = metadata.split(b" ")
        _require(separator == b"\t" and name == path.encode("ascii") and len(fields) == 3
                 and fields[0] == b"100644" and fields[1] == b"blob",
                 "review record must be one ordinary non-executable file")
        try:
            oid = fields[2].decode("ascii")
        except UnicodeError as error:
            raise ReviewMainError("review record object identity is malformed") from error
        _require(_source(oid), "review record object identity is malformed")
        return oid


def require_review_only_history(
    source_sha: str, main_sha: str, run_id: int, origin_attempt: int, review_required: bool, *,
    repository: Path = ROOT, record_sha256: str | None = None,
    timeout_seconds: float | None = None,
) -> None:
    """Permit only the exact original-run disposition on top of candidate S.

    A pending review may observe S itself while the record is still absent.
    Once a record digest is supplied, S itself cannot be an accepted review.
    The caller independently authenticates that main_sha is protected current
    main immediately before and after its production operation.
    """
    path = review_path(run_id, origin_attempt)
    _require(_source(source_sha) and _source(main_sha) and type(review_required) is bool,
             "release review source identity is malformed")
    _require(record_sha256 is None or review_required and _digest(record_sha256),
             "release review record digest is invalid")
    git = _Git(repository, timeout_seconds)
    _require(git("rev-parse", "--is-shallow-repository").strip() == b"false",
             "release review history must not be shallow")
    _require(not git("for-each-ref", "--format=%(refname)", "refs/replace").strip(),
             "release review history cannot contain replace refs")
    grafts = Path(os.fsdecode(git("rev-parse", "--git-path", "info/grafts").strip()))
    if not grafts.is_absolute():
        grafts = repository / grafts
    _require(not grafts.exists() and not grafts.is_symlink(), "release review history cannot contain grafts")
    for commit in {source_sha, main_sha}:
        _require(git("cat-file", "-t", commit).strip() == b"commit", "release review source must be a commit")
    _require(git.record(source_sha, path) is None, "candidate source already contains its review record")
    if not review_required:
        _require(main_sha == source_sha, "an automatically qualified candidate requires unchanged protected main")
        return
    if main_sha == source_sha:
        _require(record_sha256 is None, "accepted review record is absent from candidate source")
        return
    git("merge-base", "--is-ancestor", source_sha, main_sha)
    commits = git("rev-list", f"--max-count={MAX_HISTORY_COMMITS + 1}", f"{source_sha}..{main_sha}").splitlines()
    _require(0 < len(commits) <= MAX_HISTORY_COMMITS, "release review history exceeds its complete bound")
    final_record = git.record(main_sha, path)
    _require(final_record is not None, "advanced protected main lacks the exact review record")
    for raw_commit in commits:
        commit = raw_commit.decode("ascii")
        _require(_source(commit), "release review history contains a malformed commit")
        changes = git("diff-tree", "--no-commit-id", "--no-renames", "--no-ext-diff", "--no-textconv",
                      "--name-status", "-r", "-z", source_sha, commit, "--")
        _require(changes in (b"", b"A\0" + path.encode("ascii") + b"\0"),
                 "protected main contains a change outside the exact new disposition")
        record = git.record(commit, path)
        parents = git("show", "-s", "--format=%P", commit).split()
        for raw_parent in parents:
            parent = raw_parent.decode("ascii")
            _require(_source(parent), "release review parent is malformed")
            previous = git.record(parent, path)
            _require(record is not None or previous is None, "release review history deletes its disposition")
    assert final_record is not None
    size_raw = git("cat-file", "-s", final_record).strip()
    _require(re.fullmatch(rb"[0-9]+", size_raw) is not None and 0 < int(size_raw) <= MAX_RECORD_BYTES,
             "release review record exceeds its size bound")
    if record_sha256 is not None:
        record = git("cat-file", "blob", final_record)
        _require(len(record) == int(size_raw) and "sha256:" + hashlib.sha256(record).hexdigest() == record_sha256,
                 "protected main disposition differs from the accepted original record")
