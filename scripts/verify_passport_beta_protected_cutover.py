#!/usr/bin/env python3
"""Verify the protected final passport report before beta maintenance stops Python."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import require_deletion_lineage
    from .probe_passport_beta_host import HostProbeError
except ImportError:
    from check_passport_beta_fence_authority import require_deletion_lineage
    from probe_passport_beta_host import HostProbeError


WORKFLOW = ".github/workflows/passport-python-deletion-cutover.yml"
REPOSITORY = "ElevenID/marty-ui"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True,
                            check=False, timeout=60)
    if result.returncode != 0:
        raise HostProbeError("Protected passport report verification failed")
    return result.stdout


def utc(value: Any) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"),
            "Protected cutover workflow timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostProbeError("Protected cutover workflow timestamp is invalid") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed),
            "Protected cutover workflow timestamp is invalid")
    return parsed


def checked_run(run_id: int, workflow: str, source_commit: str,
                execute: Callable[[list[str]], str]) -> tuple[datetime, datetime]:
    require(type(run_id) is int and run_id > 0,
            "Protected cutover prerequisite run ID is invalid")
    try:
        run = json.loads(execute([
            "gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}",
        ]))
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Protected cutover workflow is unavailable") from exc
    require(isinstance(run, dict)
            and run.get("id") == run_id
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == workflow
            and run.get("head_branch") == "main"
            and run.get("head_sha") == source_commit
            and isinstance(run.get("repository"), dict)
            and run["repository"].get("full_name") == REPOSITORY
            and isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("full_name") == REPOSITORY,
            "Cutover report is not from a successful protected main workflow")
    started, completed = utc(run.get("created_at")), utc(run.get("updated_at"))
    require(started < completed, "Protected cutover workflow timing is invalid")
    return started, completed


def verify(
    path: Path, *, source_commit: str, deletion_head: str,
    snapshot: dict[str, Any], snapshot_file_sha256: str,
    receipt: dict[str, Any],
    execute: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    """A local report is usable only when exact bytes have protected provenance."""
    require(SHA.fullmatch(source_commit) is not None
            and SHA.fullmatch(deletion_head) is not None,
            "Protected passport source or deletion commit is invalid")
    try:
        local_bytes = path.read_bytes()
        report = json.loads(local_bytes)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Protected final cutover report is unreadable") from exc
    run_id = report.get("run_id") if isinstance(report, dict) else None
    require(type(run_id) is int and run_id > 0
            and path.name == f"passport-python-deletion-cutover-{run_id}.json",
            "Protected final cutover report has no exact workflow identity")
    final_started, final_completed = checked_run(run_id, WORKFLOW,
                                                 source_commit, execute)
    supported_id = report.get("supported_acceptance_run_id")
    predeletion_id = report.get("predeletion_acceptance_run_id")
    supported_started, supported_completed = checked_run(
        supported_id, ".github/workflows/passport-supported-consumer-acceptance.yml",
        source_commit, execute,
    )
    predeletion_started, predeletion_completed = checked_run(
        predeletion_id, ".github/workflows/passport-rust-predeletion-acceptance.yml",
        source_commit, execute,
    )
    require(supported_started < supported_completed < predeletion_started
            < predeletion_completed < final_started < final_completed,
            "Protected acceptance did not precede final cutover")
    try:
        pull = json.loads(execute([
            "gh", "api", "repos/ElevenID/marty-credentials/pulls/305",
        ]))
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Passport Python deletion pull request is unavailable") from exc
    head = pull.get("head") if isinstance(pull, dict) else None
    base = pull.get("base") if isinstance(pull, dict) else None
    require(isinstance(pull, dict) and pull.get("number") == 305
            and pull.get("state") == "closed" and pull.get("merged") is True
            and isinstance(base, dict)
            and base.get("ref") == "main"
            and isinstance(base.get("repo"), dict)
            and base["repo"].get("full_name") == "ElevenID/marty-credentials"
            and isinstance(head, dict)
            and isinstance(head.get("ref"), str) and bool(head["ref"])
            and isinstance(head.get("repo"), dict)
            and head["repo"].get("full_name") == "ElevenID/marty-credentials"
            and head.get("sha") == deletion_head,
            "Passport Python deletion head changed after final cutover")
    artifact = f"passport-python-deletion-cutover-{run_id}"
    with tempfile.TemporaryDirectory(prefix="passport-protected-cutover-") as temporary:
        directory = Path(temporary)
        try:
            execute(["gh", "run", "download", str(run_id), "--repo", REPOSITORY,
                     "--name", artifact, "--dir", str(directory)])
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HostProbeError("Protected final cutover artifact is unavailable") from exc
        downloaded = directory / f"{artifact}.json"
        require(downloaded.is_file() and not downloaded.is_symlink()
                and sorted(directory.iterdir()) == [downloaded],
                "Protected final cutover artifact is ambiguous")
        require(downloaded.read_bytes() == local_bytes,
                "Local cutover report differs from protected run artifact")
        try:
            execute([
                "gh", "attestation", "verify", str(downloaded),
                "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
                "--source-digest", source_commit,
                "--source-ref", "refs/heads/main",
            ])
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HostProbeError("Protected final cutover attestation is unavailable") from exc
        require(downloaded.read_bytes() == local_bytes,
                "Protected final cutover artifact changed during verification")
    legacy = report.get("legacy_source")
    fence = report.get("write_fence")
    counts = report.get("counts")
    first_probe = snapshot.get("fence_first_probe")
    final_probe = snapshot.get("direct_database_probe")
    require(isinstance(legacy, dict) and isinstance(fence, dict)
            and isinstance(counts, dict)
            and isinstance(first_probe, dict)
            and isinstance(final_probe, dict)
            and SHA256.fullmatch(str(first_probe.get("receipt_sha256"))) is not None
            and SHA256.fullmatch(str(final_probe.get("receipt_sha256"))) is not None
            and final_probe["receipt_sha256"] != first_probe["receipt_sha256"]
            and utc(first_probe.get("observed_at_utc"))
                < utc(final_probe.get("observed_at_utc"))
                <= utc(report.get("checked_at_utc")),
            "Protected final report payload is invalid")
    require(report.get("schema") == "marty.passport-python-deletion-cutover/v1"
            and report.get("status") == "accepted"
            and report.get("rust_source_commit") == source_commit
            and report.get("deletion_head") == deletion_head
            and report.get("cutover_snapshot_file_sha256")
                == snapshot_file_sha256
            and report.get("cutover_snapshot_sha256")
                == snapshot.get("snapshot_sha256")
            and SHA256.fullmatch(str(legacy.get("final_snapshot_attestation_sha256")))
                is not None
            and final_started <= utc(report.get("checked_at_utc")) <= final_completed
            and type(report.get("supported_acceptance_run_id")) is int
            and report["supported_acceptance_run_id"] > 0
            and type(report.get("predeletion_acceptance_run_id")) is int
            and report["predeletion_acceptance_run_id"] > 0
            and legacy.get("environment") == "beta"
            and legacy.get("database_uid") == snapshot.get("database_uid")
            and legacy.get("beta_cluster_uid") == snapshot.get("beta_cluster_uid")
            and legacy.get("beta_inventory_attestation_sha256")
                == snapshot.get("beta_inventory_attestation_sha256")
            and legacy.get("writer_deployment_uid")
                == snapshot.get("writer_deployment_uid")
            and legacy.get("writer_image_digest")
                == snapshot.get("writer_image_digest")
            and legacy.get("writer_container_id")
                == snapshot.get("writer_container_id")
            and legacy.get("writer_started_at")
                == snapshot.get("writer_started_at")
            and legacy.get("writer_generation")
                == snapshot.get("writer_generation")
            and legacy.get("writer_running") is True
            and legacy.get("final_watermark")
                == final_probe.get("observation_watermark")
            and fence.get("enabled") is True
            and fence.get("scope")
                == "physical_document_jobs_and_physical_flows"
            and fence.get("unrelated_issuance_continues") is True
            and fence.get("database_uid") == snapshot.get("database_uid")
            and fence.get("writer_deployment_uid")
                == snapshot.get("writer_deployment_uid")
            and fence.get("writer_container_id")
                == snapshot.get("writer_container_id")
            and fence.get("writer_generation")
                == snapshot.get("writer_generation")
            and fence.get("fence_epoch") == snapshot.get("fence_epoch")
            and fence.get("verification_sha256")
                == snapshot.get("fence_verification_sha256")
            and fence.get("direct_database_probe")
                == snapshot.get("direct_database_probe")
            and counts.get("source_database_uid") == snapshot.get("database_uid")
            and all(type(counts.get(name)) is int and counts[name] == 0 for name in (
                "nonterminal_job_count", "legacy_or_unknown_artifact_count",
                "unreadable_artifact_count", "active_passport_flow_count",
            ))
            and report.get("production_snapshot_sha256")
                == snapshot.get("production_snapshot_sha256")
            and report.get("production_unchanged") is True
            and report.get("other_beta_resources_unchanged") is True
            and report.get("authorized_passport_fence_uid")
                == snapshot.get("writer_deployment_uid")
            and report.get("authorized_fence_epoch")
                == snapshot.get("fence_epoch")
            and SHA.fullmatch(str(receipt.get("credentials_deletion_head"))) is not None,
            "Protected final report differs from the live cutover snapshot")
    require_deletion_lineage(receipt["credentials_deletion_head"],
                             deletion_head, execute)
    digest = hashlib.sha256(local_bytes).hexdigest()
    require(SHA256.fullmatch(digest) is not None,
            "Protected final cutover report digest is invalid")
    return {"cutover_report_run_id": run_id,
            "cutover_report_file_sha256": digest}
