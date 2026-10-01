#!/usr/bin/env python3
"""Record one read-only, source-bound passport beta soak observation.

This is a sample, not the final acceptance decision. A later protected gate
must join multiple samples with the D-12 publication and preliminary receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

if __package__:
    from .collect_passport_beta_acceptance import (
        EvidenceError, collect, production_attachment_commitment,
        production_snapshot_commitment, require, verify_attestations,
    )
    from .probe_passport_beta_host import (
        beta_legacy_drain, beta_native_route_ownership,
        production_attachment_sha256, production_snapshot,
    )
    from .probe_passport_beta_gateway import request_beta
    from .probe_passport_beta_batch import _identity_commit
else:
    from collect_passport_beta_acceptance import (
        EvidenceError, collect, production_attachment_commitment,
        production_snapshot_commitment, require, verify_attestations,
    )
    from probe_passport_beta_host import (
        beta_legacy_drain, beta_native_route_ownership,
        production_attachment_sha256, production_snapshot,
    )
    from probe_passport_beta_gateway import request_beta
    from probe_passport_beta_batch import _identity_commit


def read_private_handoff(path: Path, artifact_dir: Path) -> dict[str, str]:
    require(path.is_file() and not path.is_symlink(),
            "Private selected passport handoff is unavailable")
    resolved = path.resolve(strict=True)
    require(not resolved.is_relative_to(Path.cwd().resolve())
            and not resolved.is_relative_to(artifact_dir.resolve()),
            "Private selected passport handoff is inside the checkout or deployment")
    require(stat.S_IMODE(resolved.stat().st_mode) == 0o600,
            "Private selected passport handoff must have mode 0600")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError("Private selected passport handoff is invalid") from exc
    require(isinstance(value, dict)
            and value.get("schema") == "marty.passport-beta-demo-private/v1"
            and all(isinstance(value.get(name), str) and value[name]
                    for name in ("source_commit", "stack_manifest_sha256",
                                 "organization_id", "application_id",
                                 "source_job_id", "bureau_job_id")),
            "Private selected passport handoff is incomplete")
    return value


def protected_context(environment: dict[str, str]) -> dict[str, str]:
    run_id = environment.get("GITHUB_RUN_ID", "")
    source = environment.get("GITHUB_SHA", "")
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
            and environment.get("GITHUB_REF") == "refs/heads/main"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_WORKFLOW_REF") == (
                "ElevenID/marty-ui/.github/workflows/"
                "passport-beta-soak-sample.yml@refs/heads/main")
            and environment.get("GITHUB_RUN_ATTEMPT") == "1"
            and run_id.isdecimal() and int(run_id) > 0
            and re.fullmatch(r"[0-9a-f]{40}", source) is not None,
            "Protected passport beta soak workflow context is invalid")
    return {"run_id": run_id, "workflow_commit": source}


def sample(
    artifact_dir: Path,
    api_key: str,
    selected_handoff: dict[str, str],
    context: dict[str, str],
    *,
    collector: Callable[..., dict[str, Any]] = collect,
    attestor: Callable[..., bool] = verify_attestations,
    snapshot: Callable[[], dict[str, Any]] = production_snapshot,
    attachments: Callable[[], str] = production_attachment_sha256,
    drain: Callable[[], dict[str, Any]] = beta_legacy_drain,
    native_routes: Callable[..., dict[str, Any]] = beta_native_route_ownership,
    status_request: Callable[..., tuple[int, dict[str, Any]]] = request_beta,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    require((artifact_dir / "aggregate-deployment.json").is_file(),
            "Passport soak requires the exact aggregate deployment")
    require(isinstance(context, dict)
            and isinstance(context.get("run_id"), str)
            and context["run_id"].isdecimal()
            and int(context["run_id"]) > 0
            and isinstance(context.get("workflow_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", context["workflow_commit"]) is not None,
            "Passport soak run provenance is invalid")
    require(isinstance(api_key, str) and len(api_key) >= 32,
            "Passport soak API key is unavailable")
    report = collector(artifact_dir, api_key=api_key, attest=attestor)
    release = report.get("release")
    deployment = report.get("deployment")
    probes = report.get("probes")
    runtime = report.get("runtime_images")
    require(report.get("schema") == "marty.passport-beta-acceptance/v1"
            and report.get("status") == "blocked"
            and report.get("beta_origin") == "https://beta.elevenidllc.com"
            and report.get("physical_claim") == "not_claimed"
            and isinstance(release, dict)
            and release.get("signed_manifest_verified") is True
            and isinstance(deployment, dict)
            and deployment.get("provider_mode") == "simulator"
            and isinstance(probes, dict)
            and probes.get("capabilities_http", {}).get("verified") is True
            and probes.get("unauthenticated_denial", {}).get("verified") is True
            and probes.get("physical_claim_boundary") == {"verified": True,
                "evidence": {"physical_claim": "not_claimed", "booklet_verified": False}}
            and isinstance(runtime, dict)
            and isinstance(runtime.get("passport-beta-bureau"), dict),
            "Signed Rust passport beta runtime is not ready for soak")
    observed_production = snapshot()
    observed_attachments = attachments()
    require(isinstance(observed_production, dict)
            and production_snapshot_commitment(api_key,
                observed_production.get("sha256"))
                == deployment.get("production_snapshot_commitment")
            and production_attachment_commitment(api_key,
                observed_attachments)
                == deployment.get("production_attachment_commitment"),
            "Production differs from the aggregate deployment baseline")
    route_result = native_routes(runtime)
    drain_result = drain()
    require(route_result.get("verified") is True
            and drain_result == {"verified": True, "evidence": {
                "in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
                "active_physical_document_flows": 0,
                "database": "beta", "source": "live PostgreSQL"}},
            "Native passport route or beta drain is not healthy")
    require(isinstance(selected_handoff, dict)
            and selected_handoff.get("schema") == "marty.passport-beta-demo-private/v1"
            and selected_handoff.get("source_commit") == release["source_commit"]
            and selected_handoff.get("stack_manifest_sha256")
                == release["stack_manifest_sha256"]
            and all(isinstance(selected_handoff.get(name), str)
                    and selected_handoff[name]
                    for name in ("organization_id", "application_id",
                                 "source_job_id", "bureau_job_id")),
            "Selected passport job does not match the aggregate release")
    path = ("/v1/passport/applications/"
            + quote(selected_handoff["application_id"], safe="")
            + "/production-status")
    status_code, selected_status = status_request("GET", path, None, api_key)
    require(status_code == 200 and isinstance(selected_status, dict)
            and selected_status.get("id") == selected_handoff["source_job_id"]
            and selected_status.get("application_id")
                == selected_handoff["application_id"]
            and selected_status.get("bureau_job_id")
                == selected_handoff["bureau_job_id"]
            and selected_status.get("organization_id")
                == selected_handoff["organization_id"]
            and selected_status.get("status") == "ACTIVE",
            "Selected passport job is no longer active on the signed beta runtime")
    observed_at = clock()
    require(isinstance(observed_at, datetime)
            and observed_at.tzinfo is not None
            and observed_at.utcoffset().total_seconds() == 0,
            "Passport soak clock must be UTC")
    bureau = runtime["passport-beta-bureau"]
    return {
        "schema": "marty.passport-beta-soak-sample/v1",
        "status": "observed",
        "observed_at_utc": observed_at.isoformat(),
        "beta_origin": report["beta_origin"],
        "physical_claim": "not_claimed",
        "protected_run": context,
        "release": {
            "source_commit": release["source_commit"],
            "stack_manifest_sha256": release["stack_manifest_sha256"],
        },
        "deployment": {
            "aggregate_deployment_receipt_sha256": deployment[
                "aggregate_deployment_receipt_sha256"],
            "aggregate_plan_sha256": deployment["aggregate_plan_sha256"],
            "production_snapshot_commitment": deployment[
                "production_snapshot_commitment"],
            "production_attachment_commitment": deployment[
                "production_attachment_commitment"],
        },
        "checks": {
            "signed_live_runtime": True,
            "managed_issuer_capability": True,
            "native_gateway_flow_and_callback_route": True,
            "selected_passport_job_active": True,
            "selected_source_job_commitment": _identity_commit(
                api_key, "source-job", selected_handoff["source_job_id"]),
            "selected_bureau_job_commitment": _identity_commit(
                api_key, "bureau-job", selected_handoff["bureau_job_id"]),
            "beta_passport_drain": True,
            "production_containers_unchanged": True,
            "production_attachments_unchanged": True,
            "simulator_container_id": bureau["container_id"],
            "simulator_oci_digest": bureau["oci_digest"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--private-selected-handoff", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = sample(
            args.artifact_dir, os.environ.get("PASSPORT_ACCEPTANCE_API_KEY", ""),
            read_private_handoff(args.private_selected_handoff, args.artifact_dir),
            protected_context(dict(os.environ)),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (EvidenceError, KeyError, OSError, ValueError) as exc:
        raise SystemExit(f"Passport beta soak sample blocked: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
