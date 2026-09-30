#!/usr/bin/env python3
"""Collect the protected final beta passport drain before Python deletion."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

try:
    from .check_passport_beta_fence_authority import protected_file, protected_source
    from .probe_passport_beta_cutover_snapshot import digest
    from .probe_passport_beta_host import HostProbeError, run
    from .verify_passport_beta_protected_cutover import checked_run, command, utc
except ImportError:
    from check_passport_beta_fence_authority import protected_file, protected_source
    from probe_passport_beta_cutover_snapshot import digest
    from probe_passport_beta_host import HostProbeError, run
    from verify_passport_beta_protected_cutover import checked_run, command, utc


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def read(path: Path) -> tuple[dict[str, Any], str]:
    try:
        contents = path.read_bytes()
        value = json.loads(contents)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Protected passport cutover input is unreadable") from exc
    require(isinstance(value, dict), "Protected passport cutover input is invalid")
    return value, hashlib.sha256(contents).hexdigest()


def pull_head(deletion_head: str) -> None:
    try:
        pull = json.loads(command([
            "gh", "api", "repos/ElevenID/marty-credentials/pulls/305",
        ]))
    except ValueError as exc:
        raise HostProbeError("Python deletion pull request is unavailable") from exc
    base = pull.get("base") if isinstance(pull, dict) else None
    head = pull.get("head") if isinstance(pull, dict) else None
    require(isinstance(pull, dict) and pull.get("number") == 305
            and pull.get("state") == "open"
            and isinstance(base, dict) and base.get("ref") == "main"
            and isinstance(base.get("repo"), dict)
            and base["repo"].get("full_name") == "ElevenID/marty-credentials"
            and isinstance(head, dict) and head.get("sha") == deletion_head
            and isinstance(head.get("repo"), dict)
            and head["repo"].get("full_name") == "ElevenID/marty-credentials",
            "Python deletion pull request differs from approved head")


def collect(
    *, source_commit: str, run_id: int, deletion_head: str,
    supported_run_id: int, predeletion_run_id: int,
    supported: dict[str, Any], predeletion: dict[str, Any],
    snapshot: dict[str, Any], snapshot_file_sha256: str,
    installation: dict[str, Any], installation_file_sha256: str,
    checked_at: datetime,
) -> dict[str, Any]:
    require(SHA.fullmatch(source_commit) is not None
            and SHA.fullmatch(deletion_head) is not None
            and type(run_id) is int and run_id > 0
            and SHA256.fullmatch(snapshot_file_sha256) is not None,
            "Protected cutover source or snapshot identity is invalid")
    require(SHA256.fullmatch(installation_file_sha256) is not None
            and predeletion.get("fence_installation_receipt_sha256")
                == installation_file_sha256,
            "Protected fence receipt differs from attested predeletion installation")
    require(supported.get("schema") == "marty.passport-supported-consumer-acceptance/v1"
            and supported.get("status") == "accepted"
            and supported.get("source_commit") == source_commit
            and supported.get("legacy_source_binding") == {
                "database_uid": snapshot.get("database_uid"),
                "writer_deployment_uid": snapshot.get("writer_deployment_uid"),
            }, "Supported consumer does not bind the old beta passport writer")
    probes = predeletion.get("probes")
    drain = probes.get("legacy_drain") if isinstance(probes, dict) else None
    evidence = drain.get("evidence") if isinstance(drain, dict) else None
    legacy = evidence.get("legacy_source") if isinstance(evidence, dict) else None
    fence = evidence.get("passport_write_fence") if isinstance(evidence, dict) else None
    require(predeletion.get("schema") == "marty.passport-rust-predeletion-acceptance/v1"
            and predeletion.get("status") == "accepted"
            and isinstance(predeletion.get("release"), dict)
            and predeletion["release"].get("source_commit") == source_commit
            and isinstance(legacy, dict) and isinstance(fence, dict)
            and legacy.get("database_uid") == snapshot.get("database_uid")
            and legacy.get("beta_cluster_uid") == snapshot.get("beta_cluster_uid")
            and legacy.get("beta_inventory_attestation_sha256")
                == snapshot.get("beta_inventory_attestation_sha256")
            and legacy.get("writer_deployment_uid")
                == snapshot.get("writer_deployment_uid")
            and legacy.get("writer_container_id")
                == snapshot.get("writer_container_id")
            and legacy.get("writer_image_digest")
                == snapshot.get("writer_image_digest")
            and legacy.get("writer_generation_at_drain")
                == snapshot.get("writer_generation")
            and legacy.get("writer_database_role") == "marty"
            and SHA256.fullmatch(str(legacy.get("drain_snapshot_attestation_sha256")))
                is not None
            and legacy["drain_snapshot_attestation_sha256"]
                != snapshot_file_sha256
            and fence.get("scope")
                == "physical_document_jobs_and_physical_flows"
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
            and fence.get("unrelated_issuance_continues") is True,
            "Final beta cutover differs from protected predeletion acceptance")
    prior_probe = fence.get("direct_database_probe")
    final_probe = snapshot.get("direct_database_probe")
    counts = snapshot.get("counts")
    require(isinstance(prior_probe, dict) and isinstance(final_probe, dict)
            and isinstance(counts, dict)
            and type(legacy.get("drain_watermark")) is int
            and type(final_probe.get("observation_watermark")) is int
            and final_probe["observation_watermark"] > legacy["drain_watermark"]
            and type(snapshot.get("observation_watermark")) is int
            and snapshot["observation_watermark"]
                > final_probe["observation_watermark"]
            and SHA256.fullmatch(str(prior_probe.get("receipt_sha256"))) is not None
            and SHA256.fullmatch(str(final_probe.get("receipt_sha256"))) is not None
            and final_probe["receipt_sha256"] != prior_probe["receipt_sha256"]
            and utc(prior_probe.get("observed_at_utc"))
                < utc(final_probe.get("observed_at_utc"))
                <= utc(snapshot.get("observed_at_utc"))
                <= checked_at
            and utc(legacy.get("drain_checked_at_utc")) < checked_at
            and counts == {
                "total_job_count": 0, "nonterminal_job_count": 0,
                "legacy_or_unknown_artifact_count": 0,
                "unreadable_artifact_count": 0,
                "active_passport_flow_count": 0,
            }, "Final beta drain is stale or passport jobs remain")
    require(snapshot.get("schema") == "marty.passport-beta-cutover-snapshot/v1"
            and snapshot.get("status") == "observed"
            and snapshot.get("installation_provenance") == "local_host_continuity_only"
            and snapshot.get("snapshot_sha256") == digest({
                key: value for key, value in snapshot.items()
                if key != "snapshot_sha256"
            })
            and installation.get("schema")
                == "marty.passport-beta-fence-installation/v1"
            and installation.get("source_commit") == source_commit
            and installation.get("credentials_deletion_head") == deletion_head
            and snapshot.get("installation_receipt_sha256")
                == digest(installation)
            and snapshot.get("fence_first_probe")
                == installation.get("direct_database_probe")
            and snapshot.get("production_snapshot_sha256")
                == installation.get("production_snapshot_sha256")
            and snapshot.get("production_attachments_sha256")
                == installation.get("production_attachments_sha256"),
            "Final snapshot differs from protected fence installation")
    checked_text = checked_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema": "marty.passport-python-deletion-cutover/v1",
        "status": "accepted", "run_id": run_id,
        "rust_source_commit": source_commit,
        "deletion_head": deletion_head,
        "supported_acceptance_run_id": supported_run_id,
        "predeletion_acceptance_run_id": predeletion_run_id,
        "cutover_snapshot_file_sha256": snapshot_file_sha256,
        "cutover_snapshot_sha256": snapshot["snapshot_sha256"],
        "legacy_source": {
            "environment": "beta", "database_uid": snapshot["database_uid"],
            "beta_cluster_uid": snapshot["beta_cluster_uid"],
            "beta_inventory_attestation_sha256":
                snapshot["beta_inventory_attestation_sha256"],
            "writer_deployment_uid": snapshot["writer_deployment_uid"],
            "writer_image_digest": snapshot["writer_image_digest"],
            "writer_database_role": "marty",
            "writer_started_at": snapshot["writer_started_at"],
            "writer_generation": snapshot["writer_generation"],
            "writer_container_id": snapshot["writer_container_id"],
            "writer_running": True,
            "final_watermark": final_probe["observation_watermark"],
            "final_snapshot_attestation_sha256": snapshot_file_sha256,
        },
        "counts": {
            "source_database_uid": snapshot["database_uid"],
            "nonterminal_job_count": 0,
            "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0,
            "active_passport_flow_count": 0,
        },
        "write_fence": {
            "enabled": True,
            "scope": "physical_document_jobs_and_physical_flows",
            "database_uid": snapshot["database_uid"],
            "writer_deployment_uid": snapshot["writer_deployment_uid"],
            "writer_generation": snapshot["writer_generation"],
            "writer_container_id": snapshot["writer_container_id"],
            "verification_sha256": snapshot["fence_verification_sha256"],
            "unrelated_issuance_continues": True,
            "fence_epoch": snapshot["fence_epoch"],
            "direct_database_probe": final_probe,
        },
        "production_snapshot_sha256": snapshot["production_snapshot_sha256"],
        "production_unchanged": True,
        "other_beta_resources_unchanged": True,
        "authorized_passport_fence_uid": snapshot["writer_deployment_uid"],
        "authorized_fence_epoch": snapshot["fence_epoch"],
        "checked_at_utc": checked_text,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--installation-receipt", type=Path, required=True)
    parser.add_argument("--supported-report", type=Path, required=True)
    parser.add_argument("--predeletion-report", type=Path, required=True)
    parser.add_argument("--supported-run-id", type=int, required=True)
    parser.add_argument("--predeletion-run-id", type=int, required=True)
    parser.add_argument("--deletion-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REF") == "refs/heads/main",
                "Final cutover producer requires protected main")
        source = protected_source(run)
        require(os.environ.get("GITHUB_SHA") == source,
                "Final cutover checkout differs from workflow source")
        for relative in ("scripts/collect_passport_python_deletion_cutover.py",
                         "scripts/probe_passport_beta_cutover_snapshot.py",
                         "scripts/verify_passport_beta_protected_cutover.py"):
            protected_file(relative, run)
        run_id = int(os.environ["GITHUB_RUN_ID"])
        require(args.output.name == f"passport-python-deletion-cutover-{run_id}.json",
                "Final cutover report name differs from protected run")
        pull_head(args.deletion_head)
        supported_started, supported_completed = checked_run(
            args.supported_run_id,
            ".github/workflows/passport-supported-consumer-acceptance.yml",
            source, command)
        predeletion_started, predeletion_completed = checked_run(
            args.predeletion_run_id,
            ".github/workflows/passport-rust-predeletion-acceptance.yml",
            source, command)
        current_run = json.loads(command([
            "gh", "api", f"repos/ElevenID/marty-ui/actions/runs/{run_id}",
        ]))
        require(isinstance(current_run, dict)
                and current_run.get("id") == run_id
                and current_run.get("event") == "workflow_dispatch"
                and current_run.get("path")
                    == ".github/workflows/passport-python-deletion-cutover.yml"
                and current_run.get("head_branch") == "main"
                and current_run.get("head_sha") == source
                and isinstance(current_run.get("repository"), dict)
                and current_run["repository"].get("full_name") == "ElevenID/marty-ui",
                "Final cutover workflow identity is invalid")
        final_started = utc(current_run.get("created_at"))
        require(supported_started < supported_completed < predeletion_started
                < predeletion_completed < final_started < datetime.now(timezone.utc),
                "Protected acceptance did not precede final cutover")
        supported, _ = read(args.supported_report)
        predeletion, _ = read(args.predeletion_report)
        snapshot, snapshot_file_sha256 = read(args.snapshot)
        installation, installation_file_sha256 = read(args.installation_receipt)
        result = collect(
            source_commit=source, run_id=run_id,
            deletion_head=args.deletion_head,
            supported_run_id=args.supported_run_id,
            predeletion_run_id=args.predeletion_run_id,
            supported=supported, predeletion=predeletion,
            snapshot=snapshot, snapshot_file_sha256=snapshot_file_sha256,
            installation=installation,
            installation_file_sha256=installation_file_sha256,
            checked_at=datetime.now(timezone.utc),
        )
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (HostProbeError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected final beta cutover is unavailable: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
