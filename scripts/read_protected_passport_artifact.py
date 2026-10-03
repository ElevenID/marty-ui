#!/usr/bin/env python3
"""Authenticate one protected Marty passport JSON artifact by GitHub run.

The artifact is downloaded from the successful run, never trusted from a
caller-supplied local path. The returned digest binds later compositions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable


REPOSITORY = "ElevenID/marty-ui"
WORKFLOWS = {
    "preliminary": ("passport-beta-preliminary.yml", "passport-beta-preliminary"),
    "soak": ("passport-beta-soak-sample.yml", "passport-beta-soak"),
    "publication": ("passport-beta-demo-publication.yml",
                    "passport-beta-demo-publication"),
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NEGATIVE_MEDIA = {
    "unsigned": ("unsigned-callback-uncut.webm",
                 "unsigned-callback-privacy-scan.json"),
    "foreign": ("foreign-callback-uncut.webm",
                "foreign-callback-privacy-scan.json"),
}


class ProtectedArtifactError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtectedArtifactError(message)


def _utc(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ProtectedArtifactError("Protected GitHub run time is invalid") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0),
            "Protected GitHub run time is not UTC")
    return parsed


def command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=True, capture_output=True,
                                text=True, encoding="utf-8", timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProtectedArtifactError("Protected GitHub artifact request failed") from exc
    return result.stdout


def _read_preliminary_media(directory: Path, value: dict[str, Any]) -> dict[str, str]:
    runs = value.get("negative_runs")
    require(isinstance(runs, dict) and set(runs) == set(NEGATIVE_MEDIA),
            "Protected preliminary negative media receipt is incomplete")
    hashes = {}
    for kind, (video_name, scan_name) in NEGATIVE_MEDIA.items():
        run = runs[kind]
        require(isinstance(run, dict)
                and all(isinstance(run.get(field), str)
                        and SHA256.fullmatch(run[field]) is not None
                        for field in ("video_sha256", "privacy_scan_report_sha256")),
                "Protected preliminary media digest is invalid")
        with (directory / video_name).open("rb") as source:
            video_hash = hashlib.file_digest(source, "sha256").hexdigest()
        scan_raw = (directory / scan_name).read_bytes()
        scan_hash = hashlib.sha256(scan_raw).hexdigest()
        require(video_hash == run["video_sha256"]
                and scan_hash == run["privacy_scan_report_sha256"],
                "Protected preliminary media differs from its receipt")
        try:
            scan = json.loads(scan_raw)
        except ValueError as exc:
            raise ProtectedArtifactError("Protected preliminary privacy scan is invalid") from exc
        require(isinstance(scan, dict)
                and type(scan.get("schemaVersion")) is int
                and scan["schemaVersion"] == 1
                and scan.get("passed") is True
                and scan.get("findings") == []
                and scan.get("videoSha256") == video_hash
                and isinstance(scan.get("frameSamplingFps"), (int, float))
                and not isinstance(scan["frameSamplingFps"], bool)
                and math.isfinite(scan["frameSamplingFps"])
                and scan["frameSamplingFps"] >= 2,
                "Protected preliminary privacy scan did not pass")
        hashes[video_name] = video_hash
        hashes[scan_name] = scan_hash
    require(hashes[NEGATIVE_MEDIA["unsigned"][0]]
            != hashes[NEGATIVE_MEDIA["foreign"][0]],
            "Protected preliminary denial clips are duplicates")
    return hashes


def read_artifact(
    kind: str,
    run_id: int,
    *,
    execute: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    require(kind in WORKFLOWS and type(run_id) is int and run_id > 0,
            "Protected passport artifact selector is invalid")
    workflow, prefix = WORKFLOWS[kind]
    metadata_raw = execute(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"])
    try:
        metadata = json.loads(metadata_raw)
    except ValueError as exc:
        raise ProtectedArtifactError("Protected GitHub run metadata is invalid") from exc
    require(isinstance(metadata, dict)
            and metadata.get("id") == run_id
            and metadata.get("event") == "workflow_dispatch"
            and metadata.get("path") == f".github/workflows/{workflow}"
            and metadata.get("head_branch") == "main"
            and isinstance(metadata.get("head_sha"), str)
            and SHA.fullmatch(metadata["head_sha"]) is not None
            and metadata.get("run_attempt") == 1
            and metadata.get("status") == "completed"
            and metadata.get("conclusion") == "success"
            and isinstance(metadata.get("head_repository"), dict)
            and metadata["head_repository"].get("full_name") == REPOSITORY,
            "Passport artifact did not come from a successful protected main run")
    started = _utc(metadata.get("run_started_at"))
    completed = _utc(metadata.get("updated_at"))
    require(started <= completed, "Protected GitHub run times are inverted")
    artifact_name = f"{prefix}-{run_id}"
    expected_file = f"{artifact_name}.json"
    with tempfile.TemporaryDirectory(prefix="marty-passport-protected-") as directory:
        destination = Path(directory)
        execute(["gh", "run", "download", str(run_id), "--repo", REPOSITORY,
                 "--name", artifact_name, "--dir", str(destination)])
        files = list(destination.rglob("*"))
        expected_names = ({expected_file} | {
            name for pair in NEGATIVE_MEDIA.values() for name in pair
        } if kind == "preliminary" else {expected_file})
        require({file.name for file in files} == expected_names
                and len(files) == len(expected_names)
                and all(file.parent == destination and file.is_file()
                        and not file.is_symlink()
                        and 0 < file.stat().st_size <= (
                            128 * 1024 * 1024 if file.suffix == ".webm"
                            else 1024 * 1024) for file in files),
                "Protected passport artifact shape is invalid")
        raw = (destination / expected_file).read_bytes()
        try:
            value = json.loads(raw)
        except ValueError as exc:
            raise ProtectedArtifactError("Protected passport artifact JSON is invalid") from exc
        require(isinstance(value, dict),
                "Protected passport artifact is not an object")
        if kind == "preliminary":
            require(value.get("schema") == "marty.passport-beta-preliminary/v1"
                    and value.get("status") == "qualified_for_recording",
                    "Protected preliminary artifact did not qualify recording")
            media_hashes = _read_preliminary_media(destination, value)
        elif kind == "soak":
            require(value.get("schema") == "marty.passport-beta-soak-sample/v1"
                    and value.get("status") == "observed"
                    and value.get("protected_run") == {
                        "run_id": str(run_id),
                        "workflow_commit": metadata["head_sha"],
                    },
                    "Protected soak artifact does not bind its workflow run")
            media_hashes = {}
        else:
            require(value.get("schema") == "marty.passport-beta-demo-publication/v1"
                    and value.get("status") == "public_verified"
                    and value.get("protected_run") == {
                        "run_id": str(run_id),
                        "workflow_commit": metadata["head_sha"],
                    },
                    "Protected D-12 publication artifact does not bind its workflow run")
            media_hashes = {}
    return {
        "kind": kind,
        "run_id": run_id,
        "workflow_commit": metadata["head_sha"],
        "run_started_at_utc": started.isoformat(),
        "run_completed_at_utc": completed.isoformat(),
        "artifact_name": artifact_name,
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "media_sha256": media_hashes,
        "value": value,
    }
