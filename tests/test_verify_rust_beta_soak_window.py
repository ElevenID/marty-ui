from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_rust_beta_soak_window",
    ROOT / "scripts/verify_rust_beta_soak_window.py",
)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

RELEASE = "1.1.160"
SOURCE = "a" * 40
CUTOVER = datetime(2026, 8, 13, 21, 42, 51, tzinfo=timezone.utc)
ALL_CHECKS = set().union(
    *(requirements["checks"] for requirements in VERIFIER.SERVICE_REQUIREMENTS.values())
)


def _report(
    root: Path,
    index: int,
    captured_at: datetime,
    *,
    failed_checks: set[str] | None = None,
    source_revision: str = SOURCE,
) -> Path:
    failed_checks = failed_checks or set()
    value = {
        "schema": "marty.rust-beta-soak/v1",
        "captured_at": captured_at.isoformat(),
        "release_version": RELEASE,
        "source_revision": source_revision,
        "overall_valid": not failed_checks,
        "failed_checks": sorted(failed_checks),
        "checks": [
            {
                "id": check_id,
                "status": "fail" if check_id in failed_checks else "pass",
                "observed": None,
            }
            for check_id in sorted(ALL_CHECKS)
        ],
    }
    path = root / f"sample-{index:02d}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _daily_reports(root: Path, count: int) -> list[Path]:
    return [
        _report(root, index, CUTOVER + timedelta(hours=3, days=index))
        for index in range(count)
    ]


def _verify(paths: list[Path], as_of: datetime) -> dict:
    return VERIFIER.verify(
        report_paths=paths,
        release_version=RELEASE,
        source_revision=SOURCE,
        cutover_at=CUTOVER,
        as_of=as_of,
        maximum_gap_hours=26,
    )


def test_fifteen_daily_samples_satisfy_both_deletion_windows(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 15)
    result = _verify(paths, CUTOVER + timedelta(days=14, hours=4))

    assert result["schema"] == "marty.rust-beta-soak-window/v1"
    assert result["services"]["event-stream"]["eligible_for_deletion"] is True
    assert result["services"]["revocation-profile"]["eligible_for_deletion"] is True
    assert result["services"]["revocation-profile"]["sample_count"] == 15


def test_eight_daily_samples_satisfy_only_event_stream_window(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 8)
    result = _verify(paths, CUTOVER + timedelta(days=7, hours=4))

    assert result["services"]["event-stream"]["eligible_for_deletion"] is True
    assert result["services"]["revocation-profile"]["eligible_for_deletion"] is False


def test_failed_revocation_sample_resets_only_revocation_window(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 8)
    failed_at = CUTOVER + timedelta(days=4, hours=3)
    paths[4] = _report(
        tmp_path,
        4,
        failed_at,
        failed_checks={"revocation-native-available"},
    )
    result = _verify(paths, CUTOVER + timedelta(days=7, hours=4))

    assert result["services"]["event-stream"]["eligible_for_deletion"] is True
    revocation = result["services"]["revocation-profile"]
    assert revocation["eligible_for_deletion"] is False
    assert revocation["sample_count"] == 3
    assert revocation["interruptions"][0]["reason"] == "failed-sample"


def test_evidence_gap_resets_current_window(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 4)
    paths.extend(
        _report(tmp_path, index + 4, CUTOVER + timedelta(days=index + 5, hours=9))
        for index in range(3)
    )
    result = _verify(paths, CUTOVER + timedelta(days=7, hours=10))

    event = result["services"]["event-stream"]
    assert event["eligible_for_deletion"] is False
    assert event["sample_count"] == 3
    assert any(item["reason"] == "evidence-gap" for item in event["interruptions"])


def test_stale_latest_sample_is_not_eligible(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 15)
    result = _verify(paths, CUTOVER + timedelta(days=16))

    assert result["services"]["event-stream"]["eligible_for_deletion"] is False
    assert result["services"]["revocation-profile"]["eligible_for_deletion"] is False
    assert (
        result["services"]["event-stream"]["interruptions"][-1]["reason"]
        == "latest-sample-stale"
    )


def test_mixed_source_reports_are_rejected(tmp_path: Path) -> None:
    paths = _daily_reports(tmp_path, 2)
    paths[1] = _report(
        tmp_path, 1, CUTOVER + timedelta(days=1), source_revision="f" * 40
    )

    with pytest.raises(VERIFIER.WindowError, match="source revision mismatch"):
        _verify(paths, CUTOVER + timedelta(days=1, hours=1))
