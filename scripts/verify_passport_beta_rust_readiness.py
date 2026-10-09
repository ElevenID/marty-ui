#!/usr/bin/env python3
"""Verify protected, source-bound beta readiness before stopping old writers."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable

try:
    from .collect_passport_beta_rust_readiness import WORKFLOW, collect, utc
    from .probe_passport_beta_host import HostProbeError
except ImportError:
    from collect_passport_beta_rust_readiness import WORKFLOW, collect, utc
    from probe_passport_beta_host import HostProbeError


REPOSITORY = "ElevenID/marty-ui"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True,
                            check=False, timeout=60)
    if result.returncode != 0:
        raise HostProbeError("Protected beta readiness verification failed")
    return result.stdout


def checked_run(run_id: int, source_commit: str,
                execute: Callable[[list[str]], str]) -> tuple[datetime, datetime]:
    require(type(run_id) is int and run_id > 0,
            "Protected beta readiness run ID is invalid")
    try:
        run = json.loads(execute([
            "gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}",
        ]))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Protected beta readiness run is unavailable") from exc
    require(isinstance(run, dict) and run.get("id") == run_id
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == WORKFLOW
            and run.get("head_branch") == "main"
            and run.get("head_sha") == source_commit
            and isinstance(run.get("repository"), dict)
            and run["repository"].get("full_name") == REPOSITORY
            and isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("full_name") == REPOSITORY,
            "Beta readiness is not from successful protected main")
    started, completed = utc(run.get("created_at")), utc(run.get("updated_at"))
    require(started < completed,
            "Protected beta readiness workflow timing is invalid")
    return started, completed


def verify(
    path: Path, *, source_commit: str, deletion_head: str,
    snapshot: dict[str, Any], snapshot_path: Path,
    snapshot_file_sha256: str, receipt: dict[str, Any], receipt_path: Path,
    execute: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    require(SHA.fullmatch(source_commit) is not None
            and SHA.fullmatch(deletion_head) is not None,
            "Protected beta readiness source is invalid")
    try:
        report_bytes = path.read_bytes()
        report = json.loads(report_bytes)
        snapshot_bytes = snapshot_path.read_bytes()
        receipt_bytes = receipt_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise HostProbeError("Protected beta readiness files are unreadable") from exc
    run_id = report.get("run_id") if isinstance(report, dict) else None
    require(type(run_id) is int and run_id > 0
            and path.name == f"passport-beta-rust-readiness-{run_id}.json"
            and hashlib.sha256(snapshot_bytes).hexdigest() == snapshot_file_sha256
            and json.loads(snapshot_bytes) == snapshot
            and json.loads(receipt_bytes) == receipt,
            "Protected beta readiness file binding is invalid")
    started, completed = checked_run(run_id, source_commit, execute)
    checked_at = utc(report.get("checked_at_utc"))
    require(started <= checked_at <= completed,
            "Protected beta readiness timestamp differs from its run")
    expected = collect(
        source_commit=source_commit, run_id=run_id,
        deletion_head=deletion_head, snapshot=snapshot,
        snapshot_file_sha256=snapshot_file_sha256,
        installation=receipt,
        installation_file_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        checked_at=checked_at, lineage=lambda _anchor, _current: None,
    )
    require(report == expected,
            "Protected beta readiness differs from the fence and snapshot")
    try:
        pull = json.loads(execute([
            "gh", "api", "repos/ElevenID/marty-credentials/pulls/305",
        ]))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Merged passport deletion is unavailable") from exc
    require(isinstance(pull, dict) and pull.get("state") == "closed"
            and pull.get("merged") is True
            and isinstance(pull.get("head"), dict)
            and pull["head"].get("sha") == deletion_head,
            "Protected beta readiness deletion head changed")
    with tempfile.TemporaryDirectory(prefix="passport-beta-rust-readiness-") as temp:
        for name, original in (
            (f"passport-beta-rust-readiness-{run_id}.json", report_bytes),
            (f"passport-beta-cutover-snapshot-{run_id}.json", snapshot_bytes),
            (f"passport-beta-fence-installation-{run_id}.json", receipt_bytes),
        ):
            directory = Path(temp) / name
            directory.mkdir()
            execute(["gh", "run", "download", str(run_id), "--repo", REPOSITORY,
                     "--name", name.removesuffix(".json"), "--dir", str(directory)])
            downloaded = directory / name
            require(downloaded.is_file() and not downloaded.is_symlink()
                    and sorted(directory.iterdir()) == [downloaded]
                    and downloaded.read_bytes() == original,
                    "Protected beta readiness artifact bytes differ")
            execute([
                "gh", "attestation", "verify", str(downloaded),
                "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
                "--source-digest", source_commit,
                "--source-ref", "refs/heads/main",
            ])
            require(downloaded.read_bytes() == original,
                    "Protected beta readiness artifact changed during verification")
    return {
        "cutover_report_run_id": run_id,
        "cutover_report_file_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
