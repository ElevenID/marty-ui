#!/usr/bin/env python3
"""Attest the current fenced beta generation for the Rust-only cutover."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import (
        merged_deletion_pr, protected_file, protected_source,
        require_deletion_lineage,
    )
    from .probe_passport_beta_cutover_snapshot import digest, validate_direct_probe
    from .probe_passport_beta_fence_direct_writes import verified_unrelated_writes
    from .probe_passport_beta_host import HostProbeError, run
except ImportError:
    from check_passport_beta_fence_authority import (
        merged_deletion_pr, protected_file, protected_source,
        require_deletion_lineage,
    )
    from probe_passport_beta_cutover_snapshot import digest, validate_direct_probe
    from probe_passport_beta_fence_direct_writes import verified_unrelated_writes
    from probe_passport_beta_host import HostProbeError, run


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r".+@(sha256:[0-9a-f]{64})\Z")
COUNTS = {
    "total_job_count": 0,
    "nonterminal_job_count": 0,
    "legacy_or_unknown_artifact_count": 0,
    "unreadable_artifact_count": 0,
    "active_passport_flow_count": 0,
}
WORKFLOW = ".github/workflows/passport-beta-rust-readiness.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def read(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Beta readiness input is unreadable") from exc
    require(isinstance(value, dict), "Beta readiness input is invalid")
    return value, hashlib.sha256(raw).hexdigest()


def utc(value: Any) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"),
            "Beta readiness timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostProbeError("Beta readiness timestamp is invalid") from exc
    return parsed


def collect(
    *, source_commit: str, run_id: int, deletion_head: str,
    snapshot: dict[str, Any], snapshot_file_sha256: str,
    installation: dict[str, Any], installation_file_sha256: str,
    checked_at: datetime,
    lineage: Callable[[str, str], None] = require_deletion_lineage,
) -> dict[str, Any]:
    require(SHA.fullmatch(source_commit) is not None
            and SHA.fullmatch(deletion_head) is not None
            and type(run_id) is int and run_id > 0
            and SHA256.fullmatch(snapshot_file_sha256) is not None
            and SHA256.fullmatch(installation_file_sha256) is not None,
            "Beta readiness source or input digest is invalid")
    require(installation.get("schema") == "marty.passport-beta-fence-installation/v1"
            and installation.get("source_commit") == source_commit
            and SHA.fullmatch(str(installation.get("credentials_deletion_head"))) is not None,
            "Beta readiness fence source is invalid")
    lineage(installation["credentials_deletion_head"], deletion_head)
    fence = installation.get("fence")
    services = installation.get("beta_services")
    writer = services.get("issuance") if isinstance(services, dict) else None
    image = IMAGE.fullmatch(str(writer.get("configured_image"))) \
        if isinstance(writer, dict) else None
    require(isinstance(fence, dict)
            and fence.get("schema") == "marty.passport-beta-fence-verification/v1"
            and fence.get("phase") == "fully_fenced"
            and type(fence.get("epoch")) is int and fence["epoch"] > 0
            and isinstance(writer, dict) and image is not None,
            "Beta readiness fence or old writer is invalid")
    first = installation.get("direct_database_probe")
    final = snapshot.get("direct_database_probe")
    require(isinstance(first, dict) and isinstance(final, dict),
            "Beta readiness write probes are missing")
    docker = {"context": first.get("docker_context"),
              "daemon_id": first.get("docker_daemon_id")}
    database_uid = ("postgresql:"
                    f"{installation.get('postgres_system_identifier')}:"
                    f"{installation.get('database_oid')}")
    require(isinstance(docker["context"], str) and bool(docker["context"])
            and isinstance(docker["daemon_id"], str) and bool(docker["daemon_id"]),
            "Beta readiness Docker identity is invalid")
    for probe in (first, final):
        validate_direct_probe(
            probe, postgres=installation.get("postgres_container_id"),
            database_uid=database_uid, epoch=fence["epoch"], docker=docker,
        )
    require(isinstance(first, dict) and isinstance(final, dict)
            and verified_unrelated_writes(first.get("unrelated_writes"))
            and verified_unrelated_writes(final.get("unrelated_writes"))
            and SHA256.fullmatch(str(first.get("receipt_sha256"))) is not None
            and SHA256.fullmatch(str(final.get("receipt_sha256"))) is not None
            and first["receipt_sha256"] != final["receipt_sha256"]
            and type(first.get("observation_watermark")) is int
            and type(final.get("observation_watermark")) is int
            and first["observation_watermark"] < final["observation_watermark"]
            and type(snapshot.get("observation_watermark")) is int
            and final["observation_watermark"] < snapshot["observation_watermark"]
            and utc(installation.get("fence_installed_at_utc"))
                < utc(first.get("observed_at_utc"))
                < utc(final.get("observed_at_utc"))
                <= utc(snapshot.get("observed_at_utc")) <= checked_at,
            "Beta readiness write probes are stale or invalid")
    require(snapshot.get("schema") == "marty.passport-beta-cutover-snapshot/v1"
            and snapshot.get("status") == "observed"
            and snapshot.get("installation_provenance") == "local_host_continuity_only"
            and snapshot.get("snapshot_sha256") == digest({
                key: value for key, value in snapshot.items()
                if key != "snapshot_sha256"
            })
            and snapshot.get("installation_receipt_sha256") == digest(installation)
            and snapshot.get("database_uid") == database_uid
            and snapshot.get("beta_cluster_uid") == f"docker:{docker['daemon_id']}"
            and snapshot.get("beta_inventory_attestation_sha256")
                == installation.get("post_install_observation_sha256")
            and snapshot.get("writer_container_id") == writer.get("container_id")
            and snapshot.get("writer_deployment_uid")
                == f"elevenid-beta:issuance:{writer.get('container_id')}"
            and snapshot.get("writer_image_digest") == image.group(1)
            and snapshot.get("writer_started_at") == writer.get("started_at")
            and snapshot.get("writer_generation") == writer.get("restart_count")
            and snapshot.get("fence_epoch") == fence["epoch"]
            and snapshot.get("fence_verification_sha256") == digest(fence)
            and snapshot.get("fence_first_probe") == first
            and snapshot.get("counts") == COUNTS
            and snapshot.get("production_snapshot_sha256")
                == installation.get("production_snapshot_sha256")
            and snapshot.get("production_attachments_sha256")
                == installation.get("production_attachments_sha256"),
            "Beta readiness snapshot differs from the installed fence")
    return {
        "schema": "marty.passport-beta-rust-readiness/v1",
        "status": "accepted", "run_id": run_id,
        "source_commit": source_commit, "deletion_head": deletion_head,
        "fence_installation_receipt_sha256": installation_file_sha256,
        "snapshot_file_sha256": snapshot_file_sha256,
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "database_uid": database_uid,
        "beta_cluster_uid": snapshot["beta_cluster_uid"],
        "writer_container_id": snapshot["writer_container_id"],
        "writer_image_digest": snapshot["writer_image_digest"],
        "writer_started_at": snapshot["writer_started_at"],
        "writer_generation": snapshot["writer_generation"],
        "fence_epoch": snapshot["fence_epoch"],
        "direct_database_probe_sha256": final["receipt_sha256"],
        "production_snapshot_sha256": snapshot["production_snapshot_sha256"],
        "production_attachments_sha256": snapshot["production_attachments_sha256"],
        "checked_at_utc": checked_at.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--installation-receipt", type=Path, required=True)
    parser.add_argument("--deletion-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_REF") == "refs/heads/main",
            "Beta readiness requires protected main")
    source = protected_source(run)
    require(os.environ.get("GITHUB_SHA") == source,
            "Beta readiness checkout differs from workflow source")
    for relative in ("scripts/collect_passport_beta_rust_readiness.py",
                     "scripts/probe_passport_beta_cutover_snapshot.py",
                     "scripts/check_passport_beta_fence_authority.py"):
        protected_file(relative, run)
    run_id = int(os.environ["GITHUB_RUN_ID"])
    require(args.output.name == f"passport-beta-rust-readiness-{run_id}.json",
            "Beta readiness report name differs from workflow run")
    current_head, _ = merged_deletion_pr(run)
    require(args.deletion_head == current_head,
            "Merged passport deletion head changed")
    snapshot, snapshot_sha = read(args.snapshot)
    installation, installation_sha = read(args.installation_receipt)
    report = collect(
        source_commit=source, run_id=run_id, deletion_head=current_head,
        snapshot=snapshot, snapshot_file_sha256=snapshot_sha,
        installation=installation, installation_file_sha256=installation_sha,
        checked_at=datetime.now(timezone.utc),
    )
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
