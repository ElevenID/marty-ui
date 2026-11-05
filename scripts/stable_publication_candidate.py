#!/usr/bin/env python3
"""Immutable v2 candidates; v1 evidence is retained, never renewed or replayed.

The original successful CD producer owns candidate creation. A distinct publisher
must authenticate the original run/artifact and obtain fresh bounded authority.
This module handles data only: it does not publish or execute candidate contents.
"""
from __future__ import annotations

import argparse
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import release_tag_handoff as h
import stable_publication_checkpoint as cp

SCHEMA = "elevenid.stable-publication-candidate/v2"
PUBLISHER_WORKFLOW = ".github/workflows/publish-stable-candidate.yml"
ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "release/stable-publication-policy.json"
POLICY = {"schema": "elevenid.stable-publication-policy/v3", "repository": h.REPOSITORY,
          "producer_workflow": h.CD_WORKFLOW, "publisher_workflow": PUBLISHER_WORKFLOW,
          "candidate_lifetime_seconds": 86400, "authorization_lifetime_seconds": 900,
          "tag_handoff_contract": h.TAG_HANDOFF_CONTRACT}
FIELDS = {"schema", "repository", "producer_workflow", "source_sha", "run_id", "run_attempt", "tag",
          "created_at", "not_after", "policy_sha256", "files", "candidate_id"}
LIMITS = {"checkpoint/" + name: size for name, size in cp.MAX_FILE_BYTES.items()}
LIMITS.update({"tag-admission.json": 65536, "candidate.json": 65536})
FILES = {"checkpoint/" + name for name in cp.CHECKPOINT_FILES} | {"tag-admission.json"}
ADMISSION_FIELDS = {"schema", "tag_handoff_contract", "operator_run_id", "operator_run_attempt", "result_artifact_id",
                    "result_artifact_sha256", "result_sha256", "tag_object_sha"}


def utc(now: datetime | None = None) -> datetime:
    return cp._clock(now).replace(microsecond=0)


def policy_digest(root: Path = ROOT) -> str:
    raw = h.bounded_file(root / POLICY_PATH, 65536)
    h.require(h.decode(raw) == POLICY, "publication policy differs from the supported v2 contract")
    return h.sha256(raw)


def candidate_identity(value: dict) -> str:
    return h.sha256(SCHEMA.encode() + b"\0" + h.encoded({k: v for k, v in value.items() if k != "candidate_id"}))


def validate_manifest(value: object, *, now: datetime | None = None) -> dict:
    h.require(type(value) is dict and set(value) == FIELDS, "candidate fields differ")
    h.require(value["schema"] == SCHEMA and value["repository"] == h.REPOSITORY
              and value["producer_workflow"] == h.CD_WORKFLOW, "candidate producer contract differs")
    h.require(isinstance(value["source_sha"], str) and h.SHA.fullmatch(value["source_sha"])
              and isinstance(value["tag"], str) and h.TAG.fullmatch(value["tag"])
              and h.positive(value["run_id"]) and type(value["run_attempt"]) is int
              and value["run_attempt"] == 1, "candidate identity differs")
    created, expires = h.timestamp(value["created_at"]), h.timestamp(value["not_after"])
    h.require(expires - created == timedelta(seconds=POLICY["candidate_lifetime_seconds"])
              and created <= utc(now) < expires, "candidate is future, expired, or has an extended lifetime")
    h.require(isinstance(value["policy_sha256"], str) and h.DIGEST.fullmatch(value["policy_sha256"]),
              "candidate policy digest differs")
    files = value["files"]
    h.require(type(files) is dict and set(files) == FILES, "candidate file inventory differs")
    for name, item in files.items():
        h.require(type(item) is dict and set(item) == {"size", "sha256"}
                  and type(item["size"]) is int and 0 < item["size"] <= LIMITS[name]
                  and isinstance(item["sha256"], str) and h.DIGEST.fullmatch(item["sha256"]),
                  "candidate file entry is invalid")
    h.require(sum(item["size"] for item in files.values()) <= cp.MAX_TOTAL_BYTES,
              "candidate expanded size is excessive")
    h.require(value["candidate_id"] == candidate_identity(value), "candidate identity digest differs")
    return value


def validate_admission(value: object) -> dict:
    h.require(type(value) is dict and set(value) == ADMISSION_FIELDS, "tag admission fields differ")
    h.require(value["schema"] == h.TAG_ADMISSION_SCHEMA and value["tag_handoff_contract"] == h.TAG_HANDOFF_CONTRACT,
              "tag admission contract differs")
    h.require(all(h.positive(value[key]) for key in ("operator_run_id", "operator_run_attempt", "result_artifact_id"))
              and value["operator_run_attempt"] == 1
              and all(isinstance(value[key], str) and h.DIGEST.fullmatch(value[key]) for key in
                      ("result_artifact_sha256", "result_sha256"))
              and isinstance(value["tag_object_sha"], str) and h.SHA.fullmatch(value["tag_object_sha"]),
              "tag admission identity differs")
    return value


def archived_checkpoint(directory: Path) -> tuple[dict, dict]:
    """Read immutable historical evidence without granting v1 retry authority."""
    files = {}
    with cp._Directory(directory) as root:
        h.require(set(os.listdir(root.fd)) == {"request.json", "official-interoperability.json", "assets"},
                  "archived checkpoint entries differ")
        meta, raw = root.read("request.json", 65536)
        files["checkpoint/request.json"] = meta
        request = cp.validate_request_identity(h.decode(raw))
        meta, gate = root.read("official-interoperability.json", cp.MAX_FILE_BYTES["official-interoperability.json"])
        files["checkpoint/official-interoperability.json"] = meta
        captured = {}
        with cp._Directory(directory / "assets") as assets:
            h.require(set(os.listdir(assets.fd)) == cp.ASSET_NAMES, "archived asset set differs")
            for name in sorted(cp.ASSET_NAMES):
                meta, raw = assets.read(name, cp.MAX_FILE_BYTES["assets/" + name], capture=name in cp.CAPTURE_NAMES)
                h.require(meta == request["assets"][name], "archived asset bytes differ")
                files["checkpoint/assets/" + name] = meta
                if name in cp.CAPTURE_NAMES:
                    captured[name] = raw
            cp._validate_payloads(request, captured, gate)
            assets.unchanged()
        root.unchanged()
    return request, files


def load_candidate(directory: Path, *, now: datetime | None = None) -> tuple[dict, dict, dict]:
    with cp._Directory(directory) as root:
        h.require(set(os.listdir(root.fd)) == {"candidate.json", "checkpoint", "tag-admission.json"},
                  "candidate root entries differ")
        _, raw = root.read("candidate.json", LIMITS["candidate.json"])
        candidate = validate_manifest(h.decode(raw), now=now)
        meta, raw = root.read("tag-admission.json", LIMITS["tag-admission.json"])
        admission = validate_admission(h.decode(raw))
        request, files = archived_checkpoint(directory / "checkpoint")
        files["tag-admission.json"] = meta
        h.require(files == candidate["files"], "candidate bytes differ from immutable inventory")
        h.require(all(candidate[key] == request[key] for key in ("source_sha", "run_id", "run_attempt", "tag"))
                  and h.timestamp(request["created_at"]) <= h.timestamp(candidate["created_at"]) < h.timestamp(request["not_after"]),
                  "candidate was not sealed during its original authorized handoff")
        root.unchanged()
        validate_manifest(candidate, now=now)
        return candidate, request, admission


def seal(checkpoint: Path, admission_path: Path, output: Path, *, root: Path = ROOT,
         environment: dict[str, str] | None = None, now: datetime | None = None) -> dict:
    request = cp.load_checkpoint(checkpoint, now=now)
    run = cp._producer_context(request["source_sha"], os.environ if environment is None else environment)
    h.require(run == request["run_id"], "candidate producer differs from checkpoint")
    admission = validate_admission(h.decode(h.bounded_file(admission_path, 65536)))
    created = utc(now)
    with cp._Directory(output.parent) as parent:
        os.mkdir(output.name, 0o700, dir_fd=parent.fd)
    (output / "checkpoint").mkdir(mode=0o700)
    (output / "checkpoint/assets").mkdir(mode=0o700)
    with cp._Directory(checkpoint) as source, cp._Directory(output / "checkpoint") as dest:
        for name in ("request.json", "official-interoperability.json"):
            source.read(name, cp.MAX_FILE_BYTES[name], capture=False, destination=dest)
        source.unchanged()
    with cp._Directory(checkpoint / "assets") as source, cp._Directory(output / "checkpoint/assets") as dest:
        for name in sorted(cp.ASSET_NAMES):
            meta, _ = source.read(name, cp.MAX_FILE_BYTES["assets/" + name], capture=False, destination=dest)
            h.require(meta == request["assets"][name], "candidate asset changed during copy")
        source.unchanged()
    copied_request, files = archived_checkpoint(output / "checkpoint")
    h.require(copied_request == request, "copied checkpoint identity changed")
    raw = h.encoded(admission)
    files["tag-admission.json"] = {"size": len(raw), "sha256": h.sha256(raw)}
    candidate = {"schema": SCHEMA, "repository": h.REPOSITORY, "producer_workflow": h.CD_WORKFLOW,
                 "source_sha": request["source_sha"], "run_id": run, "run_attempt": 1, "tag": request["tag"],
                 "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "not_after": (created + timedelta(seconds=86400)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "policy_sha256": policy_digest(root), "files": files}
    candidate["candidate_id"] = candidate_identity(candidate)
    validate_manifest(candidate, now=now)
    with cp._Directory(output) as dest:
        dest.write("tag-admission.json", raw)
        dest.write("candidate.json", h.encoded(candidate))
        os.fsync(dest.fd)
    # Original v1 expiry is enforced during creation, never extended in place.
    cp.load_checkpoint(checkpoint, now=now)
    return load_candidate(output, now=now)[0]


def artifact_name(run_id: int, tag: str) -> str:
    h.require(h.positive(run_id) and isinstance(tag, str) and h.TAG.fullmatch(tag), "candidate artifact identity invalid")
    return f"stable-publication-candidate-v2-{run_id}-1-{tag}"


def find_artifact(github: h.GitHub, run_id: int, *, allow_absent: bool = False) -> tuple[dict, dict] | None:
    h.require(h.positive(run_id), "candidate run ID invalid")
    raw = github.json(f"repos/{h.REPOSITORY}/actions/runs/{run_id}")
    h.require(type(raw) is dict and isinstance(raw.get("head_sha"), str) and h.SHA.fullmatch(raw["head_sha"]),
              "original candidate source is invalid")
    run = github.run(run_id, h.CD_WORKFLOW, raw["head_sha"])
    h.require(run.get("status") == "completed" and run.get("conclusion") == "success",
              "original CD qualification must have completed successfully")
    prefix = f"stable-publication-candidate-v2-{run_id}-1-"
    rows = [item for item in github.artifacts(run_id) if isinstance(item.get("name"), str)
            and item["name"].startswith("stable-publication-candidate-v2-")]
    if not rows and allow_absent:
        return None
    h.require(len(rows) == 1 and rows[0]["name"].startswith(prefix), "one original v2 candidate is required")
    tag = rows[0]["name"][len(prefix):]
    h.require(h.TAG.fullmatch(tag), "candidate artifact tag is invalid")
    artifact = github.artifact(run_id, artifact_name(run_id, tag), run["head_sha"])
    return run, artifact


def fetch(github: h.GitHub, run_id: int, output: Path, *, now: datetime | None = None) -> tuple[dict, dict, dict, dict]:
    run, artifact = find_artifact(github, run_id)
    archive = output.with_name(output.name + ".zip")
    github.download(artifact, archive)
    h.extract_archive(archive, output, FILES | {"candidate.json"}, limits=LIMITS)
    candidate, request, admission = load_candidate(output, now=now)
    h.require(candidate["run_id"] == run_id and candidate["source_sha"] == run["head_sha"]
              and artifact["name"] == artifact_name(run_id, candidate["tag"]), "candidate artifact contents differ")
    final_run, final_artifact = find_artifact(github, run_id)
    h.require(final_artifact == artifact and final_run["head_sha"] == run["head_sha"], "candidate API identity changed")
    return candidate, request, admission, artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("seal")
    create.add_argument("--checkpoint", type=Path, required=True)
    create.add_argument("--tag-admission", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        seal(args.checkpoint.absolute(), args.tag_admission.absolute(), args.output.absolute())
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"stable candidate refused: {error}\n")


if __name__ == "__main__":
    main()
