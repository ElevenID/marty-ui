#!/usr/bin/env python3
"""Verify the bounded passport beta observation window without accepting release.

The final compositor must separately authenticate every named protected GitHub
run and artifact digest. This verifier only checks continuity and elapsed time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MINIMUM_HOURS = 24
MAXIMUM_GAP_HOURS = 13
MINIMUM_SAMPLES = 3
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_CHECKS = (
    "signed_live_runtime", "managed_issuer_capability",
    "native_gateway_flow_and_callback_route", "selected_passport_job_active",
    "beta_passport_drain", "production_containers_unchanged",
    "production_attachments_unchanged",
)


class WindowError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WindowError(message)


def _timestamp(value: Any) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise WindowError("Passport soak timestamp is invalid") from exc
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0),
            "Passport soak timestamp must be UTC")
    return result


def _load(path: Path) -> tuple[dict[str, Any], str, datetime]:
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size <= 128 * 1024,
            "Passport soak sample file is unavailable or oversized")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise WindowError("Passport soak sample JSON is invalid") from exc
    require(isinstance(value, dict)
            and value.get("schema") == "marty.passport-beta-soak-sample/v1"
            and value.get("status") == "observed"
            and value.get("beta_origin") == "https://beta.elevenidllc.com"
            and value.get("physical_claim") == "not_claimed",
            "Passport soak sample does not describe the beta simulator")
    release, deployment, checks, run = (value.get(name) for name in (
        "release", "deployment", "checks", "protected_run"))
    require(isinstance(release, dict)
            and isinstance(release.get("source_commit"), str)
            and SHA.fullmatch(release["source_commit"]) is not None
            and isinstance(release.get("stack_manifest_sha256"), str)
            and SHA256.fullmatch(release["stack_manifest_sha256"]) is not None
            and isinstance(deployment, dict)
            and all(isinstance(deployment.get(name), str)
                    and SHA256.fullmatch(deployment[name]) is not None
                    for name in ("aggregate_deployment_receipt_sha256",
                                 "aggregate_plan_sha256",
                                 "production_snapshot_commitment",
                                 "production_attachment_commitment"))
            and isinstance(checks, dict)
            and all(checks.get(name) is True for name in REQUIRED_CHECKS)
            and isinstance(checks.get("simulator_container_id"), str)
            and CONTAINER.fullmatch(checks["simulator_container_id"]) is not None
            and isinstance(checks.get("simulator_oci_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}",
                             checks["simulator_oci_digest"]) is not None
            and all(isinstance(checks.get(name), str)
                    and SHA256.fullmatch(checks[name]) is not None
                    for name in ("selected_source_job_commitment",
                                 "selected_bureau_job_commitment"))
            and isinstance(run, dict)
            and isinstance(run.get("run_id"), str)
            and run["run_id"].isdecimal() and int(run["run_id"]) > 0
            and isinstance(run.get("workflow_commit"), str)
            and SHA.fullmatch(run["workflow_commit"]) is not None,
            "Passport soak sample lacks signed runtime, job or run lineage")
    return value, hashlib.sha256(raw).hexdigest(), _timestamp(value.get("observed_at_utc"))


def verify(paths: list[Path], *, as_of: datetime) -> dict[str, Any]:
    require(len(paths) >= MINIMUM_SAMPLES,
            "Passport soak requires at least three protected samples")
    require(as_of.tzinfo is not None and as_of.utcoffset() == timedelta(0),
            "Passport soak as-of time must be UTC")
    loaded = [(*_load(path), path.name) for path in paths]
    loaded.sort(key=lambda row: row[2])
    first = loaded[0][0]
    first_checks = first["checks"]
    first_identity = {
        "release": first["release"],
        "deployment": first["deployment"],
        "simulator_container_id": first_checks["simulator_container_id"],
        "simulator_oci_digest": first_checks["simulator_oci_digest"],
        "selected_source_job_commitment": first_checks[
            "selected_source_job_commitment"],
        "selected_bureau_job_commitment": first_checks[
            "selected_bureau_job_commitment"],
    }
    seen_runs: set[str] = set()
    previous: datetime | None = None
    for value, _, captured, _ in loaded:
        identity = {
            "release": value["release"], "deployment": value["deployment"],
            **{name: value["checks"][name] for name in (
                "simulator_container_id", "simulator_oci_digest",
                "selected_source_job_commitment",
                "selected_bureau_job_commitment")},
        }
        require(identity == first_identity,
                "Passport soak source, deployment, runtime or selected job changed")
        run_id = value["protected_run"]["run_id"]
        require(run_id not in seen_runs,
                "Passport soak reuses a protected workflow run")
        seen_runs.add(run_id)
        require(captured <= as_of
                and (previous is None or timedelta(0) < captured - previous
                     <= timedelta(hours=MAXIMUM_GAP_HOURS)),
                "Passport soak has a future, duplicate or missing observation")
        previous = captured
    start, end = loaded[0][2], loaded[-1][2]
    require(end - start >= timedelta(hours=MINIMUM_HOURS)
            and as_of - end <= timedelta(hours=MAXIMUM_GAP_HOURS),
            "Passport soak observation window is short or stale")
    return {
        "schema": "marty.passport-beta-soak-window/v1",
        "status": "window_observed",
        "provenance_pending": True,
        "verified_at_utc": as_of.isoformat(),
        "first_observed_at_utc": start.isoformat(),
        "last_observed_at_utc": end.isoformat(),
        "minimum_hours": MINIMUM_HOURS,
        "maximum_gap_hours": MAXIMUM_GAP_HOURS,
        "sample_count": len(loaded),
        "identity": first_identity,
        "samples": [{"name": name, "sha256": digest,
                     "run_id": value["protected_run"]["run_id"],
                     "workflow_commit": value["protected_run"]["workflow_commit"]}
                    for value, digest, _, name in loaded],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.reports, as_of=datetime.now(timezone.utc))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (WindowError, OSError) as exc:
        raise SystemExit(f"Passport beta soak window blocked: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
