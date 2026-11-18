#!/usr/bin/env python3
"""Bind a fresh beta drain to the installed passport fence and old writer.

This component records observed facts for a protected predeletion producer.
It does not qualify Rust acceptance or authenticate the snapshot attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

try:
    from .probe_passport_beta_cutover_snapshot import digest, validate_direct_probe
    from .probe_passport_beta_host import HostProbeError
    from .verify_passport_beta_protected_cutover import utc
except ImportError:
    from probe_passport_beta_cutover_snapshot import digest, validate_direct_probe
    from probe_passport_beta_host import HostProbeError
    from verify_passport_beta_protected_cutover import utc


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COUNTS = {
    "total_job_count": 0,
    "nonterminal_job_count": 0,
    "legacy_or_unknown_artifact_count": 0,
    "unreadable_artifact_count": 0,
    "active_passport_flow_count": 0,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def read(path: Path) -> tuple[dict[str, Any], str]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Predeletion drain input is unreadable") from exc
    require(isinstance(value, dict), "Predeletion drain input is not an object")
    return value, hashlib.sha256(payload).hexdigest()


def collect(
    installation: dict[str, Any], snapshot: dict[str, Any], *,
    installation_file_sha256: str, snapshot_file_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    """Project only live, same-generation beta drain facts from the snapshot."""
    require(SHA.fullmatch(source_commit) is not None
            and SHA256.fullmatch(installation_file_sha256) is not None
            and SHA256.fullmatch(snapshot_file_sha256) is not None,
            "Predeletion drain source or file digest is invalid")
    require(installation.get("schema") == "marty.passport-beta-fence-installation/v1"
            and installation.get("source_commit") == source_commit
            and snapshot.get("schema") == "marty.passport-beta-cutover-snapshot/v1"
            and snapshot.get("status") == "observed"
            and snapshot.get("installation_provenance")
                == "local_host_continuity_only"
            and snapshot.get("installation_receipt_sha256") == digest(installation)
            and snapshot.get("snapshot_sha256") == digest({
                key: value for key, value in snapshot.items()
                if key != "snapshot_sha256"
            }), "Predeletion snapshot differs from the protected fence receipt")
    fence = installation.get("fence")
    services = installation.get("beta_services")
    writer = services.get("issuance") if isinstance(services, dict) else None
    first_probe = installation.get("direct_database_probe")
    fresh_probe = snapshot.get("direct_database_probe")
    require(isinstance(fence, dict) and fence.get("phase") == "fully_fenced"
            and type(fence.get("epoch")) is int and fence["epoch"] > 0
            and isinstance(writer, dict)
            and isinstance(first_probe, dict) and isinstance(fresh_probe, dict),
            "Predeletion fence, writer, or database probe is incomplete")
    postgres = installation.get("postgres_container_id")
    system_id = installation.get("postgres_system_identifier")
    database_oid = installation.get("database_oid")
    require(isinstance(postgres, str) and SHA256.fullmatch(postgres) is not None
            and isinstance(system_id, str) and system_id.isdecimal()
            and isinstance(database_oid, str) and database_oid.isdecimal()
            and snapshot.get("database_uid")
                == f"postgresql:{system_id}:{database_oid}"
            and snapshot.get("fence_epoch") == fence["epoch"]
            and snapshot.get("fence_verification_sha256") == digest(fence)
            and snapshot.get("fence_first_probe") == first_probe,
            "Predeletion database or fence identity changed")
    docker = {"context": first_probe.get("docker_context"),
              "daemon_id": first_probe.get("docker_daemon_id")}
    require(all(isinstance(value, str) and bool(value) for value in docker.values())
            and snapshot.get("beta_cluster_uid") == f"docker:{docker['daemon_id']}",
            "Predeletion Docker identity changed")
    for probe in (first_probe, fresh_probe):
        validate_direct_probe(
            probe, postgres=postgres, database_uid=snapshot["database_uid"],
            epoch=fence["epoch"], docker=docker,
        )
    require(type(first_probe.get("observation_watermark")) is int
            and type(fresh_probe.get("observation_watermark")) is int
            and first_probe["observation_watermark"]
                < fresh_probe["observation_watermark"]
            and fresh_probe.get("receipt_sha256") != first_probe.get("receipt_sha256")
            and type(snapshot.get("observation_watermark")) is int
            and snapshot["observation_watermark"]
                > fresh_probe["observation_watermark"]
            and utc(installation.get("fence_installed_at_utc"))
                < utc(first_probe.get("observed_at_utc"))
                < utc(fresh_probe.get("observed_at_utc"))
                <= utc(snapshot.get("observed_at_utc")),
            "Predeletion direct probe or drain is stale")
    configured = writer.get("configured_image")
    image = (re.fullmatch(r".+@(sha256:[0-9a-f]{64})", configured)
             if isinstance(configured, str) else None)
    require(isinstance(writer.get("container_id"), str)
            and SHA256.fullmatch(writer["container_id"]) is not None
            and isinstance(writer.get("started_at"), str)
            and type(writer.get("restart_count")) is int
            and writer["restart_count"] >= 0
            and image is not None
            and snapshot.get("writer_container_id") == writer["container_id"]
            and snapshot.get("writer_deployment_uid")
                == f"elevenid-beta:issuance:{writer['container_id']}"
            and snapshot.get("writer_image_digest") == image.group(1)
            and snapshot.get("writer_started_at") == writer["started_at"]
            and snapshot.get("writer_generation") == writer["restart_count"]
            and snapshot.get("beta_inventory_attestation_sha256")
                == installation.get("post_install_observation_sha256")
            and snapshot.get("counts") == COUNTS
            and snapshot.get("production_snapshot_sha256")
                == installation.get("production_snapshot_sha256")
            and snapshot.get("production_attachments_sha256")
                == installation.get("production_attachments_sha256")
            and snapshot.get("fence_installed_at_utc")
                == installation.get("fence_installed_at_utc"),
            "Predeletion writer generation, counts, or production changed")
    legacy = {
        "environment": "beta", "database_uid": snapshot["database_uid"],
        "beta_cluster_uid": snapshot["beta_cluster_uid"],
        "database_cluster_uid": snapshot["beta_cluster_uid"],
        "writer_cluster_uid": snapshot["beta_cluster_uid"],
        "beta_inventory_attestation_sha256":
            snapshot["beta_inventory_attestation_sha256"],
        "writer_deployment_uid": snapshot["writer_deployment_uid"],
        "writer_owner": "python", "writer_database_role": "marty",
        "writer_image_digest": snapshot["writer_image_digest"],
        "writer_container_id": snapshot["writer_container_id"],
        "writer_running_at_drain": True,
        "writer_generation_at_fence": writer["restart_count"],
        "writer_generation_at_drain": snapshot["writer_generation"],
        "fence_watermark": fence["epoch"],
        "drain_watermark": fresh_probe["observation_watermark"],
        "drain_snapshot_file_sha256": snapshot_file_sha256,
        "fence_enabled_at_utc": installation["fence_installed_at_utc"],
        "drain_checked_at_utc": snapshot["observed_at_utc"],
    }
    write_fence = {
        "scope": "physical_document_jobs_and_physical_flows",
        "enabled": True, "database_uid": snapshot["database_uid"],
        "writer_deployment_uid": snapshot["writer_deployment_uid"],
        "writer_container_id": snapshot["writer_container_id"],
        "writer_generation": snapshot["writer_generation"],
        "fence_epoch": fence["epoch"],
        "verification_sha256": snapshot["fence_verification_sha256"],
        "unrelated_issuance_continues": True,
        "direct_database_probe": fresh_probe,
    }
    return {
        "schema": "marty.passport-rust-predeletion-drain/v1",
        "status": "observed_unattested",
        "source_commit": source_commit,
        "fence_installation_receipt_sha256": installation_file_sha256,
        "snapshot_file_sha256": snapshot_file_sha256,
        "probe": {"verified": True, "evidence": {
            "source_commit": source_commit,
            "python_passport_writes_fenced": True,
            "count_source_database_uid": snapshot["database_uid"],
            "legacy_source": legacy,
            "passport_write_fence": write_fence,
            "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        }},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation-receipt", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        installation, installation_sha = read(args.installation_receipt)
        snapshot, snapshot_sha = read(args.snapshot)
        report = collect(
            installation, snapshot,
            installation_file_sha256=installation_sha,
            snapshot_file_sha256=snapshot_sha,
            source_commit=args.source_commit,
        )
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (HostProbeError, OSError, ValueError) as exc:
        raise SystemExit(f"Predeletion beta drain is unavailable: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
