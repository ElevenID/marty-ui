#!/usr/bin/env python3
"""Verify consecutive Rust beta soak samples before Python deletion."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SERVICE_REQUIREMENTS = {
    "event-stream": {
        "minimum_days": 7,
        "checks": {
            "runtime-services-release",
            "runtime-services-source",
            "runtime-ui-release",
            "runtime-ui-source",
            "event-stream-running",
            "event-stream-healthy",
            "event-stream-zero-restarts",
            "event-stream-release",
            "event-stream-source",
            "event-stream-no-errors",
            "event-stream-no-panics",
            "event-health",
            "event-ready",
            "event-started",
            "event-zero-drops",
        },
    },
    "revocation-profile": {
        "minimum_days": 14,
        "checks": {
            "runtime-services-release",
            "runtime-services-source",
            "runtime-ui-release",
            "runtime-ui-source",
            "revocation-profile-running",
            "revocation-profile-healthy",
            "revocation-profile-zero-restarts",
            "revocation-profile-release",
            "revocation-profile-source",
            "revocation-profile-no-errors",
            "revocation-profile-no-panics",
            "revocation-ready",
            "revocation-dependencies",
            "revocation-native-available",
            "revocation-native-backend",
            "revocation-native-release",
            "revocation-native-source",
            "revocation-native-capabilities",
            "revocation-native-metric",
        },
    },
}


class WindowError(ValueError):
    pass


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise WindowError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WindowError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise WindowError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _load_report(
    path: Path, release_version: str, source_revision: str
) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WindowError(f"Could not read soak report {path.name}") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema") != "marty.rust-beta-soak/v1"
    ):
        raise WindowError(f"{path.name} has the wrong soak evidence schema")
    if report.get("release_version") != release_version:
        raise WindowError(f"{path.name} release version mismatch")
    if report.get("source_revision") != source_revision:
        raise WindowError(f"{path.name} source revision mismatch")
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise WindowError(f"{path.name} has no check records")
    by_id: dict[str, str] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise WindowError(f"{path.name} contains a malformed check")
        check_id = str(check.get("id") or "")
        if not check_id or check_id in by_id:
            raise WindowError(f"{path.name} contains a missing or duplicate check ID")
        status = str(check.get("status") or "")
        if status not in {"pass", "fail"}:
            raise WindowError(f"{path.name} check {check_id} has an invalid status")
        by_id[check_id] = status
    return {
        "path": path.as_posix(),
        "captured_at": _timestamp(
            report.get("captured_at"), f"{path.name} captured_at"
        ),
        "checks": by_id,
    }


def _service_passes(sample: dict[str, Any], service: str) -> tuple[bool, list[str]]:
    required = SERVICE_REQUIREMENTS[service]["checks"]
    checks = sample["checks"]
    failed = sorted(check_id for check_id in required if checks.get(check_id) != "pass")
    return not failed, failed


def _window(
    samples: list[dict[str, Any]],
    *,
    service: str,
    cutover_at: datetime,
    as_of: datetime,
    maximum_gap: timedelta,
) -> dict[str, Any]:
    minimum_days = SERVICE_REQUIREMENTS[service]["minimum_days"]
    window_start: datetime | None = None
    accepted: list[dict[str, Any]] = []
    interruptions: list[dict[str, Any]] = []
    previous_at: datetime | None = None

    for sample in samples:
        captured_at = sample["captured_at"]
        if captured_at < cutover_at:
            continue
        passes, failed_checks = _service_passes(sample, service)
        if not passes:
            interruptions.append(
                {
                    "captured_at": captured_at.isoformat(),
                    "reason": "failed-sample",
                    "failed_checks": failed_checks,
                }
            )
            window_start = None
            accepted = []
            previous_at = None
            continue

        if previous_at is None:
            initial_gap = captured_at - cutover_at
            if (
                window_start is None
                and not interruptions
                and initial_gap <= maximum_gap
            ):
                window_start = cutover_at
            else:
                window_start = captured_at
        elif captured_at - previous_at > maximum_gap:
            interruptions.append(
                {
                    "captured_at": captured_at.isoformat(),
                    "reason": "evidence-gap",
                    "gap_hours": (captured_at - previous_at).total_seconds() / 3600,
                }
            )
            window_start = captured_at
            accepted = []
        accepted.append(sample)
        previous_at = captured_at

    stale = previous_at is None or as_of - previous_at > maximum_gap
    if stale and previous_at is not None:
        interruptions.append(
            {
                "captured_at": as_of.isoformat(),
                "reason": "latest-sample-stale",
                "gap_hours": (as_of - previous_at).total_seconds() / 3600,
            }
        )
    duration = (
        timedelta(0)
        if window_start is None or previous_at is None
        else previous_at - window_start
    )
    distinct_dates = sorted(
        {sample["captured_at"].date().isoformat() for sample in accepted}
    )
    eligible = (
        not stale
        and duration >= timedelta(days=minimum_days)
        and len(distinct_dates) >= minimum_days
    )
    return {
        "service": service,
        "minimum_days": minimum_days,
        "eligible_for_deletion": eligible,
        "current_window_started_at": window_start.isoformat() if window_start else None,
        "latest_sample_at": previous_at.isoformat() if previous_at else None,
        "current_window_hours": duration.total_seconds() / 3600,
        "sample_count": len(accepted),
        "distinct_utc_dates": distinct_dates,
        "interruptions": interruptions,
    }


def verify(
    *,
    report_paths: list[Path],
    release_version: str,
    source_revision: str,
    cutover_at: datetime,
    as_of: datetime,
    maximum_gap_hours: int,
) -> dict[str, Any]:
    if not report_paths:
        raise WindowError("At least one soak report is required")
    if maximum_gap_hours < 1:
        raise WindowError("maximum_gap_hours must be positive")
    if as_of < cutover_at:
        raise WindowError("as_of cannot precede cutover_at")
    samples = [
        _load_report(path, release_version, source_revision) for path in report_paths
    ]
    samples.sort(key=lambda sample: sample["captured_at"])
    timestamps = [sample["captured_at"] for sample in samples]
    if len(timestamps) != len(set(timestamps)):
        raise WindowError("Soak reports contain duplicate capture timestamps")
    if any(timestamp > as_of for timestamp in timestamps):
        raise WindowError("Soak report capture time cannot be later than as_of")

    maximum_gap = timedelta(hours=maximum_gap_hours)
    services = {
        service: _window(
            samples,
            service=service,
            cutover_at=cutover_at,
            as_of=as_of,
            maximum_gap=maximum_gap,
        )
        for service in SERVICE_REQUIREMENTS
    }
    return {
        "schema": "marty.rust-beta-soak-window/v1",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "cutover_at": cutover_at.isoformat(),
        "release_version": release_version,
        "source_revision": source_revision,
        "maximum_gap_hours": maximum_gap_hours,
        "report_count": len(samples),
        "services": services,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, nargs="+", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--cutover-at", required=True)
    parser.add_argument("--as-of")
    parser.add_argument("--maximum-gap-hours", type=int, default=26)
    parser.add_argument(
        "--require-eligible",
        choices=["none", "event-stream", "revocation-profile", "all"],
        default="none",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = verify(
            report_paths=args.reports,
            release_version=args.release_version,
            source_revision=args.source_revision,
            cutover_at=_timestamp(args.cutover_at, "cutover_at"),
            as_of=_timestamp(args.as_of, "as_of")
            if args.as_of
            else datetime.now(timezone.utc),
            maximum_gap_hours=args.maximum_gap_hours,
        )
    except WindowError as exc:
        raise SystemExit(f"Rust beta soak window verification failed: {exc}") from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    required = (
        list(SERVICE_REQUIREMENTS)
        if args.require_eligible == "all"
        else [args.require_eligible]
    )
    required = [] if required == ["none"] else required
    failed = [
        service
        for service in required
        if not result["services"][service]["eligible_for_deletion"]
    ]
    for service, evidence in result["services"].items():
        print(
            f"{service}: {'ELIGIBLE' if evidence['eligible_for_deletion'] else 'NOT ELIGIBLE'}"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
