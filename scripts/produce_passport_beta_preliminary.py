#!/usr/bin/env python3
"""Join protected beta passport evidence before a D-12 recording receipt.

The acceptance runner remains blocked. Its selected job evidence and the two
uncut negative callback recordings are independently verified before this
producer can qualify a preliminary receipt.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MEDIA_FILES = {
    "unsigned": ("unsigned-callback-uncut.webm", "unsigned-callback-privacy-scan.json"),
    "foreign": ("foreign-callback-uncut.webm", "foreign-callback-privacy-scan.json"),
}
CASE_FIELDS = {
    "http_status", "webhook_owner", "request_kind", "response_projection",
    "organization_commitment", "source_job_commitment", "bureau_job_commitment",
    "job_state_before_commitment", "job_state_after_commitment",
    "video_sha256", "privacy_scan_report_sha256",
}


class PreliminaryEvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreliminaryEvidenceError(message)


def _digest(path: Path, limit: int) -> str:
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= limit,
            "Negative callback media is missing or oversized")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    _digest(path, limit)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PreliminaryEvidenceError("Negative callback evidence is invalid") from exc
    require(isinstance(value, dict), "Negative callback evidence is invalid")
    return value


def verify_negative_media(
    media_dir: Path,
    *,
    release: dict[str, Any],
    deployment: dict[str, Any],
    selected: dict[str, str],
) -> dict[str, Any]:
    """Return only bounded, same-job denial evidence for the preliminary report."""
    require(media_dir.is_dir() and not media_dir.is_symlink(),
            "Negative callback media directory is unavailable")
    require(all(isinstance(selected.get(key), str)
                and SHA256.fullmatch(selected[key]) is not None
                for key in ("organization_commitment", "source_job_commitment",
                            "bureau_job_commitment")),
            "Selected passport job commitments are unavailable")
    require(isinstance(release.get("source_commit"), str)
            and COMMIT.fullmatch(release["source_commit"]) is not None
            and isinstance(release.get("stack_manifest_sha256"), str)
            and SHA256.fullmatch(release["stack_manifest_sha256"]) is not None
            and all(isinstance(deployment.get(key), str)
                    and SHA256.fullmatch(deployment[key]) is not None
                    for key in ("aggregate_deployment_receipt_sha256",
                                "aggregate_plan_sha256")),
            "Selected signed beta release or deployment lineage is unavailable")
    media = _read_json(media_dir / "negative-callback-media.json", 1024 * 1024)
    require(set(media) == {"schema", "verified", "physical_claim", "release",
                           "deployment", "negative_runs"}
            and media.get("schema") == "marty.passport-beta-negative-media/v1"
            and media.get("verified") is True
            and media.get("physical_claim") == "not_claimed"
            and isinstance(media.get("release"), dict)
            and set(media["release"]) == {"source_commit", "stack_manifest_sha256"}
            and all(media["release"].get(field) == release.get(field)
                    for field in ("source_commit", "stack_manifest_sha256"))
            and isinstance(media.get("deployment"), dict)
            and set(media["deployment"]) == {"aggregate_deployment_receipt_sha256",
                                            "aggregate_plan_sha256"}
            and all(media["deployment"].get(field) == deployment.get(field)
                    for field in ("aggregate_deployment_receipt_sha256",
                                  "aggregate_plan_sha256"))
            and isinstance(media.get("negative_runs"), dict)
            and set(media["negative_runs"]) == set(MEDIA_FILES),
            "Negative callback media differs from the selected beta deployment")
    runs = media["negative_runs"]
    for name, (video_name, scan_name) in MEDIA_FILES.items():
        run = runs[name]
        expected_fields = CASE_FIELDS | ({"signature_valid", "foreign_organization"}
                                         if name == "foreign" else set())
        require(isinstance(run, dict) and set(run) == expected_fields
                and run.get("webhook_owner") == "issuance-native"
                and run.get("request_kind") == ("missing_signature_header" if name == "unsigned"
                                                else "signed_foreign_organization")
                and run.get("http_status") == (422 if name == "unsigned" else 404)
                and run.get("response_projection") == ({"missing_signature_header": True}
                                                       if name == "unsigned" else
                                                       {"webhook_job_not_found": True})
                and run.get("source_job_commitment") == selected["source_job_commitment"]
                and run.get("bureau_job_commitment") == selected["bureau_job_commitment"]
                and all(isinstance(run.get(key), str) and SHA256.fullmatch(run[key]) is not None
                        for key in ("organization_commitment", "job_state_before_commitment",
                                    "job_state_after_commitment", "video_sha256",
                                    "privacy_scan_report_sha256"))
                and run["job_state_before_commitment"] == run["job_state_after_commitment"],
                f"{name} callback denial is incomplete or differs from selected job")
        if name == "unsigned":
            require(run["organization_commitment"] == selected["organization_commitment"],
                    "Unsigned callback organization differs from selected job")
        else:
            require(run["organization_commitment"] != selected["organization_commitment"]
                    and run.get("signature_valid") is True
                    and run.get("foreign_organization") is True,
                    "Foreign callback organization or signature is unproven")
        video_digest = _digest(media_dir / video_name, 128 * 1024 * 1024)
        scan_path = media_dir / scan_name
        scan_digest = _digest(scan_path, 1024 * 1024)
        require(video_digest == run["video_sha256"]
                and scan_digest == run["privacy_scan_report_sha256"],
                f"{name} callback media digest differs from receipt")
        scan = _read_json(scan_path, 1024 * 1024)
        require(set(scan) == {"schemaVersion", "passed", "findings", "videoSha256",
                              "frameSamplingFps"}
                and scan.get("schemaVersion") == 1 and scan.get("passed") is True
                and scan.get("findings") == []
                and scan.get("videoSha256") == video_digest
                and isinstance(scan.get("frameSamplingFps"), (int, float))
                and not isinstance(scan["frameSamplingFps"], bool)
                and scan["frameSamplingFps"] >= 2,
                f"{name} callback privacy scan is incomplete")
    unsigned, foreign = runs["unsigned"], runs["foreign"]
    require(unsigned["video_sha256"] != foreign["video_sha256"]
            and unsigned["job_state_before_commitment"]
            == foreign["job_state_before_commitment"],
            "Negative callback clips do not prove one unchanged selected job")
    return {
        "negative_runs": {name: dict(runs[name]) for name in MEDIA_FILES},
        "probe": {"verified": True, "evidence": {
            "unsigned_denied": True, "foreign_organization_denied": True,
            "job_unchanged": True,
            "source_job_commitment": selected["source_job_commitment"],
            "bureau_job_commitment": selected["bureau_job_commitment"],
            "unsigned_uncut_video_sha256": unsigned["video_sha256"],
            "foreign_uncut_video_sha256": foreign["video_sha256"],
        }},
    }
