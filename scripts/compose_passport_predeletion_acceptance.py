#!/usr/bin/env python3
"""Join attested Rust producer and beta drain with fresh protected isolation."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

try:
    from .project_passport_predeletion_producer import probe
    from .project_passport_predeletion_producer import project
    from .check_passport_beta_fence_authority import manifest_source
except ImportError:
    from project_passport_predeletion_producer import probe
    from project_passport_predeletion_producer import project
    from check_passport_beta_fence_authority import manifest_source


SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RUNTIME_PROBES = {
    "managed_csca_dsc_chain", "sod_signature", "nine_route_gateway_flow",
    "packaged_image", "physical_bureau_submission", "physical_bureau_batch",
    "simulator_material_receipt", "signed_bureau_callback",
    "rust_restart_resume", "physical_claim_boundary",
}


class AcceptanceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def utc(value: object) -> datetime:
    require(isinstance(value, str), "Protected acceptance timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AcceptanceError("Protected acceptance timestamp is invalid") from error
    require(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed),
            "Protected acceptance timestamp is not UTC")
    return parsed


def compose(
    projection: dict[str, Any], observation: dict[str, Any],
    fresh_snapshot: dict[str, Any], *, run_id: int,
    workflow_started_at_utc: str, accepted_at_utc: str,
) -> dict[str, Any]:
    """Accept only same-source evidence collected in the required time order.

    The caller must first run the exact-workflow producer and observation
    verifiers, and collect ``fresh_snapshot`` through the protected beta host
    snapshot command in this acceptance run.
    """
    require(isinstance(projection, dict)
            and projection.get("schema")
                == "marty.passport-rust-predeletion-producer-projection/v1"
            and projection.get("status") == "blocked"
            and isinstance(observation, dict)
            and observation.get("schema") == "marty.passport-rust-predeletion-drain/v1"
            and observation.get("status") == "verified_observation"
            and isinstance(fresh_snapshot, dict)
            and fresh_snapshot.get("schema") == "marty.passport-beta-cutover-snapshot/v1"
            and fresh_snapshot.get("status") == "observed"
            and type(run_id) is int and run_id > 0,
            "Protected Rust producer, beta drain, or fresh snapshot is unavailable")
    source = projection.get("source_commit")
    release = projection.get("release")
    identity = projection.get("deployment")
    probes = projection.get("probes")
    drain = observation.get("probe")
    installation = observation.get("installation")
    observed_snapshot = observation.get("snapshot")
    require(isinstance(source, str) and SHA.fullmatch(source) is not None
            and observation.get("source_commit") == source
            and isinstance(release, dict) and release.get("source_commit") == source
            and isinstance(identity, dict) and identity.get("source_commit") == source
            and identity.get("kind") == "compose"
            and identity.get("production_resources_excluded") is True
            and isinstance(probes, dict) and set(probes) == RUNTIME_PROBES
            and all(isinstance(item, dict) and item.get("verified") is True
                    for item in probes.values())
            and isinstance(drain, dict) and drain.get("verified") is True
            and isinstance(drain.get("evidence"), dict)
            and isinstance(installation, dict)
            and installation.get("source_commit") == source
            and isinstance(observed_snapshot, dict),
            "Predeletion inputs have different protected sources")
    started = utc(workflow_started_at_utc)
    accepted = utc(accepted_at_utc)
    checked = utc(drain["evidence"].get("legacy_source", {}).get("drain_checked_at_utc"))
    require(utc(projection.get("record_completed_at_utc")) < started
            and checked < utc(observation.get("observation_completed_at_utc")) < started
            and started <= utc(fresh_snapshot.get("observed_at_utc")) <= accepted,
            "Protected producer, drain, and acceptance chronology is invalid")
    preserved = (
        "installation_receipt_sha256", "database_uid", "beta_cluster_uid",
        "beta_inventory_attestation_sha256", "writer_deployment_uid",
        "writer_container_id", "writer_image_digest", "writer_started_at",
        "writer_generation", "fence_epoch", "fence_installed_at_utc",
        "fence_verification_sha256", "production_snapshot_sha256",
        "production_attachments_sha256",
    )
    require(all(fresh_snapshot.get(name) == observed_snapshot.get(name)
                for name in preserved)
            and isinstance(fresh_snapshot.get("snapshot_sha256"), str)
            and SHA256.fullmatch(fresh_snapshot["snapshot_sha256"]) is not None
            and fresh_snapshot["snapshot_sha256"]
                != observed_snapshot.get("snapshot_sha256")
            and isinstance(fresh_snapshot.get("direct_database_probe"), dict)
            and isinstance(observed_snapshot.get("direct_database_probe"), dict)
            and type(fresh_snapshot["direct_database_probe"].get(
                "observation_watermark")) is int
            and type(observed_snapshot["direct_database_probe"].get(
                "observation_watermark")) is int
            and fresh_snapshot["direct_database_probe"]["observation_watermark"]
                > observed_snapshot["direct_database_probe"]["observation_watermark"]
            and fresh_snapshot.get("counts") == observed_snapshot.get("counts")
            and fresh_snapshot.get("counts") == {
                "total_job_count": 0, "nonterminal_job_count": 0,
                "legacy_or_unknown_artifact_count": 0,
                "unreadable_artifact_count": 0,
                "active_passport_flow_count": 0,
            },
            "Fresh beta isolation differs from attested zero drain or protected inventory")
    legacy = drain["evidence"]
    require(legacy.get("source_commit") == source
            and legacy.get("python_passport_writes_fenced") is True
            and legacy.get("count_source_database_uid")
                == fresh_snapshot["database_uid"]
            and isinstance(legacy.get("legacy_source"), dict)
            and legacy["legacy_source"].get("writer_deployment_uid")
                == fresh_snapshot["writer_deployment_uid"],
            "Protected beta drain and fresh writer generation differ")
    deployment = copy.deepcopy(identity)
    deployment.update({
        "mode": "disposable", "provider_mode": "simulator",
        "resource_identity_verified": True,
        # The owned Compose project has one dedicated PostgreSQL service.
        # This logical UID cannot equal the live beta PostgreSQL system UID.
        "database_uid": f"compose-project:{identity['project_id']}/postgres",
    })
    require(deployment["database_uid"] != fresh_snapshot["database_uid"],
            "Disposable and beta database identities coincide")
    isolation = {
        "production_unchanged": True,
        "other_beta_resources_unchanged": True,
        "authorized_passport_fence_uid": fresh_snapshot["writer_deployment_uid"],
        "disposable_resource_identity_verified": True,
        "fresh_beta_snapshot_sha256": fresh_snapshot["snapshot_sha256"],
        "production_snapshot_sha256": fresh_snapshot["production_snapshot_sha256"],
        "production_attachments_sha256": fresh_snapshot[
            "production_attachments_sha256"],
    }
    joined_probes = copy.deepcopy(probes)
    joined_probes["legacy_drain"] = probe(legacy, identity)
    joined_probes["production_isolation"] = probe(isolation, identity)
    return {
        "schema": "marty.passport-rust-predeletion-acceptance/v1",
        "status": "accepted", "run_id": run_id,
        "accepted_at_utc": accepted_at_utc,
        "physical_claim": "not_claimed",
        "release": copy.deepcopy(release),
        "deployment": deployment,
        "runtime_images": copy.deepcopy(projection["runtime_images"]),
        "pre_restart_native_runtime": copy.deepcopy(
            projection["pre_restart_native_runtime"]),
        "probes": joined_probes,
        "producer_provenance": {key: projection[key] for key in (
            "producer_run_id", "record_run_id", "producer_receipt_sha256",
            "producer_attestation_sha256", "plan_sha256")},
        "drain_provenance": {
            "observation_run_id": observation["observation_run_id"],
            "attestation_sha256": copy.deepcopy(observation["attestation_sha256"]),
            "fresh_snapshot_sha256": fresh_snapshot["snapshot_sha256"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--fresh-snapshot", type=Path, required=True)
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        environment = os.environ
        source = environment.get("GITHUB_SHA")
        run = environment.get("GITHUB_RUN_ID")
        require(environment.get("GITHUB_ACTIONS") == "true"
                and environment.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
                and environment.get("GITHUB_REF") == "refs/heads/main"
                and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and environment.get("GITHUB_WORKFLOW_REF") == (
                    "ElevenID/marty-ui/.github/workflows/"
                    "passport-rust-predeletion-acceptance.yml@refs/heads/main")
                and environment.get("GITHUB_RUN_ATTEMPT") == "1"
                and isinstance(source, str) and SHA.fullmatch(source) is not None
                and isinstance(run, str) and run.isdecimal() and int(run) > 0,
                "Protected predeletion acceptance context is invalid")
        release = manifest_source(args.stack_manifest, source)
        require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.release_tag)
                is not None
                and release["release"] == f"marty-ui@{args.release_tag[1:]}",
                "Official release tag and signed manifest differ")
        metadata = subprocess.run(
            ["gh", "api", f"repos/ElevenID/marty-ui/actions/runs/{run}"],
            capture_output=True, text=True, check=True, timeout=120,
        )
        current = json.loads(metadata.stdout)
        require(isinstance(current, dict)
                and current.get("id") == int(run)
                and current.get("head_sha") == source
                and current.get("head_branch") == "main"
                and current.get("event") == "workflow_dispatch"
                and current.get("run_attempt") == 1,
                "Protected acceptance run is not exact main")
        producer = json.loads(args.producer.read_text(encoding="utf-8"))
        observation = json.loads(args.observation.read_text(encoding="utf-8"))
        fresh = json.loads(args.fresh_snapshot.read_text(encoding="utf-8"))
        signed_release = {
            "source_commit": source,
            "stack_manifest_sha256": release["manifest_sha256"],
            "oci_digests": release["oci_digests"],
            "signed_manifest_verified": True,
        }
        projected = project(producer, signed_release)
        result = compose(
            projected, observation, fresh, run_id=int(run),
            workflow_started_at_utc=current["created_at"],
            accepted_at_utc=datetime.now(timezone.utc).isoformat(),
        )
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (AcceptanceError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as exc:
        parser.exit(1, f"Protected predeletion acceptance unavailable: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
