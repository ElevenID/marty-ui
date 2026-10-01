#!/usr/bin/env python3
"""Match authenticated preliminary and soak evidence to one live beta release.

The final acceptance producer must obtain these inputs from the protected
artifact readers and the live aggregate collector. This join does not accept a
release or replace the D-12 publication and deletion checks.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

if __package__:
    from .collect_passport_beta_acceptance import verify_attestations
    from .collect_passport_beta_aggregate_acceptance import collect_aggregate
    from .read_protected_passport_artifact import read_artifact
    from .verify_protected_passport_soak import verify_protected
else:
    from collect_passport_beta_acceptance import verify_attestations
    from collect_passport_beta_aggregate_acceptance import collect_aggregate
    from read_protected_passport_artifact import read_artifact
    from verify_protected_passport_soak import verify_protected


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SELECTED_PROBES = (
    "managed_csca_dsc_chain", "sod_signature", "simulator_material_receipt",
    "nine_route_gateway_flow", "physical_bureau_submission",
    "physical_bureau_batch", "signed_bureau_callback",
    "physical_claim_boundary", "unsigned_or_foreign_callback_denied",
)


class LineageError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LineageError(message)


def utc(value: Any) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise LineageError("Passport beta lineage time is invalid") from exc
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0),
            "Passport beta lineage time is not UTC")
    return result


def probe(probes: Any, name: str) -> dict[str, Any]:
    require(isinstance(probes, dict), "Preliminary passport probes are unavailable")
    item = probes.get(name)
    require(isinstance(item, dict) and item.get("verified") is True
            and isinstance(item.get("evidence"), dict),
            f"Preliminary passport probe is unverified: {name}")
    return item["evidence"]


def match_preliminary_soak(
    live: dict[str, Any],
    preliminary: dict[str, Any],
    soak: dict[str, Any],
) -> dict[str, Any]:
    """Return only source, deployment, and selected-job commitments in common."""
    require(isinstance(live, dict)
            and live.get("schema") == "marty.passport-beta-acceptance/v1"
            and live.get("status") == "blocked"
            and live.get("beta_origin") == "https://beta.elevenidllc.com"
            and live.get("physical_claim") == "not_claimed"
            and isinstance(live.get("release"), dict)
            and live["release"].get("signed_manifest_verified") is True
            and isinstance(live.get("deployment"), dict)
            and live["deployment"].get("provider_mode") == "simulator",
            "Live signed simulator deployment is unavailable")
    release, deployment = live["release"], live["deployment"]
    identity = {
        "source_commit": release.get("source_commit"),
        "stack_manifest_sha256": release.get("stack_manifest_sha256"),
    }
    deployment_identity = {
        name: deployment.get(name) for name in (
            "aggregate_deployment_receipt_sha256", "aggregate_plan_sha256",
            "production_snapshot_commitment", "production_attachment_commitment",
        )
    }
    require(isinstance(identity["source_commit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]) is not None
            and isinstance(identity["stack_manifest_sha256"], str)
            and SHA256.fullmatch(identity["stack_manifest_sha256"]) is not None
            and all(isinstance(value, str) and SHA256.fullmatch(value) is not None
                    for value in deployment_identity.values()),
            "Live release or deployment lineage is incomplete")
    require(isinstance(preliminary, dict)
            and preliminary.get("kind") == "preliminary"
            and type(preliminary.get("run_id")) is int
            and preliminary["run_id"] > 0
            and preliminary.get("artifact_name")
                == f"passport-beta-preliminary-{preliminary['run_id']}"
            and isinstance(preliminary.get("artifact_sha256"), str)
            and SHA256.fullmatch(preliminary["artifact_sha256"]) is not None
            and preliminary.get("workflow_commit") == identity["source_commit"]
            and isinstance(preliminary.get("value"), dict),
            "Protected preliminary artifact identity is incomplete")
    value = preliminary["value"]
    require(value.get("schema") == "marty.passport-beta-preliminary/v1"
            and value.get("status") == "qualified_for_recording"
            and value.get("beta_origin") == live["beta_origin"]
            and value.get("physical_claim") == "not_claimed"
            and value.get("synthetic_identities_only") is True
            and isinstance(value.get("release"), dict)
            and value["release"].get("signed_manifest_verified") is True
            and all(value["release"].get(name) == expected
                    for name, expected in identity.items())
            and isinstance(value.get("deployment"), dict)
            and value["deployment"].get("provider_mode") == "simulator"
            and all(value["deployment"].get(name) == deployment_identity[name]
                    for name in ("aggregate_deployment_receipt_sha256",
                                 "aggregate_plan_sha256")),
            "Preliminary recording differs from the live aggregate beta release")
    probes = value.get("probes")
    evidence = {name: probe(probes, name) for name in SELECTED_PROBES}
    require(evidence["physical_claim_boundary"] == {
                "physical_claim": "not_claimed", "booklet_verified": False},
            "Preliminary recording claims physical booklet verification")
    selected = evidence["nine_route_gateway_flow"]
    source = selected.get("source_job_commitment")
    bureau = selected.get("bureau_job_commitment")
    require(isinstance(source, str) and SHA256.fullmatch(source) is not None
            and isinstance(bureau, str) and SHA256.fullmatch(bureau) is not None
            and evidence["physical_bureau_submission"].get(
                "selected_source_job_commitment") == source
            and evidence["physical_bureau_submission"].get(
                "selected_bureau_job_commitment") == bureau
            and evidence["physical_bureau_batch"].get(
                "selected_source_job_commitment") == source
            and evidence["physical_bureau_batch"].get(
                "selected_bureau_job_commitment") == bureau
            and evidence["signed_bureau_callback"].get(
                "source_job_commitment") == source
            and evidence["signed_bureau_callback"].get(
                "bureau_job_commitment") == bureau
            and evidence["unsigned_or_foreign_callback_denied"].get(
                "source_job_commitment") == source
            and evidence["unsigned_or_foreign_callback_denied"].get(
                "bureau_job_commitment") == bureau,
            "Preliminary passport probes do not refer to one selected job")
    require(isinstance(soak, dict)
            and soak.get("schema") == "marty.passport-beta-soak-window/v1"
            and soak.get("status") == "protected_window_verified"
            and soak.get("provenance_pending") is False
            and soak.get("protected_runs_verified") is True
            and type(soak.get("sample_count")) is int
            and soak["sample_count"] >= 3
            and soak.get("minimum_hours") == 24
            and soak.get("maximum_gap_hours") == 13
            and isinstance(soak.get("identity"), dict)
            and soak["identity"].get("release") == identity
            and soak["identity"].get("deployment") == deployment_identity
            and soak["identity"].get("selected_source_job_commitment") == source
            and soak["identity"].get("selected_bureau_job_commitment") == bureau
            and isinstance(soak.get("samples"), list)
            and len(soak["samples"]) == soak["sample_count"],
            "Protected passport soak differs from the selected beta job")
    first = utc(soak.get("first_observed_at_utc"))
    last = utc(soak.get("last_observed_at_utc"))
    preliminary_completed = utc(preliminary.get("run_completed_at_utc"))
    require(preliminary_completed <= first < last
            and last - first >= timedelta(hours=24),
            "Protected passport soak did not follow preliminary recording")
    return {
        "release": identity,
        "deployment": deployment_identity,
        "selected_source_job_commitment": source,
        "selected_bureau_job_commitment": bureau,
        "preliminary_run_id": preliminary["run_id"],
        "preliminary_artifact_sha256": preliminary["artifact_sha256"],
        "soak_samples": soak["samples"],
        "soak_first_observed_at_utc": first.isoformat(),
        "soak_last_observed_at_utc": last.isoformat(),
    }


def authenticate_preliminary_soak_lineage(
    artifact_dir: Path,
    api_key: str,
    preliminary_run_id: int,
    soak_run_ids: list[int],
    *,
    as_of: datetime,
    collector: Callable[..., dict[str, Any]] = collect_aggregate,
    reader: Callable[[str, int], dict[str, Any]] = read_artifact,
    soak_verifier: Callable[..., dict[str, Any]] = verify_protected,
) -> dict[str, Any]:
    """Read the live aggregate and protected GitHub evidence before joining."""
    require(isinstance(artifact_dir, Path)
            and (artifact_dir / "aggregate-deployment.json").is_file(),
            "Exact aggregate beta deployment is unavailable")
    require(isinstance(api_key, str) and len(api_key) >= 32,
            "Passport beta API key is unavailable")
    require(type(preliminary_run_id) is int and preliminary_run_id > 0,
            "Protected preliminary run ID is invalid")
    require(isinstance(soak_run_ids, list)
            and len(soak_run_ids) >= 3 and all(type(run) is int and run > 0
            for run in soak_run_ids) and len(set(soak_run_ids)) == len(soak_run_ids),
            "Protected soak run IDs are incomplete or repeated")
    live = collector(artifact_dir, api_key=api_key, attest=verify_attestations)
    preliminary = reader("preliminary", preliminary_run_id)
    soak = soak_verifier(soak_run_ids, as_of=as_of, reader=reader)
    return match_preliminary_soak(live, preliminary, soak)
