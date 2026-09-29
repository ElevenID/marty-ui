#!/usr/bin/env python3
"""Verify the protected final passport report before beta maintenance stops Python."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import file_sha256
    from .probe_passport_beta_host import HostProbeError
except ImportError:
    from check_passport_beta_fence_authority import file_sha256
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
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Protected final cutover report is unreadable") from exc
    run_id = report.get("run_id") if isinstance(report, dict) else None
    require(type(run_id) is int and run_id > 0
            and path.name == f"passport-python-deletion-cutover-{run_id}.json",
            "Protected final cutover report has no exact workflow identity")
    try:
        run = json.loads(execute([
            "gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}",
        ]))
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Protected final cutover workflow is unavailable") from exc
    require(isinstance(run, dict)
            and run.get("id") == run_id
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
            "Final cutover report is not from successful protected main")
    try:
        execute([
            "gh", "attestation", "verify", str(path), "--repo", REPOSITORY,
            "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
            "--source-digest", source_commit,
            "--source-ref", "refs/heads/main",
        ])
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostProbeError("Protected final cutover attestation is unavailable") from exc
    legacy = report.get("legacy_source")
    fence = report.get("write_fence")
    counts = report.get("counts")
    require(report.get("schema") == "marty.passport-python-deletion-cutover/v1"
            and report.get("status") == "accepted"
            and report.get("rust_source_commit") == source_commit
            and report.get("deletion_head") == deletion_head
            and report.get("cutover_snapshot_file_sha256")
                == snapshot_file_sha256
            and report.get("cutover_snapshot_sha256")
                == snapshot.get("snapshot_sha256")
            and type(report.get("supported_acceptance_run_id")) is int
            and report["supported_acceptance_run_id"] > 0
            and type(report.get("predeletion_acceptance_run_id")) is int
            and report["predeletion_acceptance_run_id"] > 0
            and isinstance(legacy, dict) and isinstance(fence, dict)
            and isinstance(counts, dict)
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
                == snapshot.get("observation_watermark")
            and fence.get("enabled") is True
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
            and receipt.get("credentials_deletion_head") == deletion_head,
            "Protected final report differs from the live cutover snapshot")
    digest = file_sha256(path)
    require(SHA256.fullmatch(digest) is not None,
            "Protected final cutover report digest is invalid")
    return {"cutover_report_run_id": run_id,
            "cutover_report_file_sha256": digest}
