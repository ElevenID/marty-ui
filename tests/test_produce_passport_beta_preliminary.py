"""Preliminary negative media must describe two real clips of one beta job."""

from __future__ import annotations

import hashlib
import json
import copy
from pathlib import Path

import pytest

from scripts.produce_passport_beta_preliminary import (
    PreliminaryEvidenceError, verify_negative_media,
)


RELEASE = {"source_commit": "a" * 40, "stack_manifest_sha256": "b" * 64}
DEPLOYMENT = {"aggregate_deployment_receipt_sha256": "c" * 64,
              "aggregate_plan_sha256": "d" * 64}
SELECTED = {"organization_commitment": "1" * 64,
            "source_job_commitment": "2" * 64,
            "bureau_job_commitment": "3" * 64}


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def media_fixture(directory: Path) -> dict:
    runs = {}
    for name, status, organization, projection in (
        ("unsigned", 422, SELECTED["organization_commitment"],
         {"missing_signature_header": True}),
        ("foreign", 404, "4" * 64, {"webhook_job_not_found": True}),
    ):
        video = b"\x1aE\xdf\xa3" + name.encode() + b" uncut browser callback"
        video_name = f"{name}-callback-uncut.webm"
        (directory / video_name).write_bytes(video)
        scan = {"schemaVersion": 1, "passed": True, "findings": [],
                "videoSha256": digest(video), "frameSamplingFps": 2}
        scan_name = f"{name}-callback-privacy-scan.json"
        write_json(directory / scan_name, scan)
        runs[name] = {
            "http_status": status, "webhook_owner": "issuance-native",
            "request_kind": ("missing_signature_header" if name == "unsigned"
                             else "signed_foreign_organization"),
            "response_projection": projection,
            "organization_commitment": organization,
            "source_job_commitment": SELECTED["source_job_commitment"],
            "bureau_job_commitment": SELECTED["bureau_job_commitment"],
            "job_state_before_commitment": "5" * 64,
            "job_state_after_commitment": "5" * 64,
            "video_sha256": digest(video),
            "privacy_scan_report_sha256": digest((directory / scan_name).read_bytes()),
        }
    runs["foreign"].update(signature_valid=True, foreign_organization=True)
    report = {"schema": "marty.passport-beta-negative-media/v1", "verified": True,
              "physical_claim": "not_claimed", "release": copy.deepcopy(RELEASE),
              "deployment": copy.deepcopy(DEPLOYMENT), "negative_runs": runs}
    write_json(directory / "negative-callback-media.json", report)
    return report


def test_qualifies_two_scanned_denials_of_selected_job(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    result = verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                                   selected=SELECTED)
    assert result["probe"]["verified"] is True
    assert result["probe"]["evidence"]["source_job_commitment"] == SELECTED["source_job_commitment"]
    assert result["negative_runs"]["unsigned"]["http_status"] == 422
    assert result["negative_runs"]["foreign"]["http_status"] == 404


@pytest.mark.parametrize("change", [
    lambda media: media["release"].update(source_commit="f" * 40),
    lambda media: media["deployment"].update(aggregate_plan_sha256="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(source_job_commitment="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(
        organization_commitment=SELECTED["organization_commitment"]),
    lambda media: media["negative_runs"]["foreign"].update(signature_valid=False),
    lambda media: media["negative_runs"]["unsigned"].update(http_status=200),
    lambda media: media["negative_runs"]["foreign"].update(job_state_after_commitment="f" * 64),
    lambda media: media["negative_runs"]["foreign"].update(job_state_before_commitment="f" * 64,
                                                              job_state_after_commitment="f" * 64),
])
def test_rejects_cross_deployment_or_cross_job_negative_media(tmp_path: Path, change) -> None:
    media = media_fixture(tmp_path)
    change(media)
    write_json(tmp_path / "negative-callback-media.json", media)
    with pytest.raises(PreliminaryEvidenceError):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


def test_rejects_changed_video_or_scan(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    video = tmp_path / "unsigned-callback-uncut.webm"
    video.write_bytes(video.read_bytes() + b"changed")
    with pytest.raises(PreliminaryEvidenceError, match="digest"):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)


def test_rejects_symlink_media(tmp_path: Path) -> None:
    media_fixture(tmp_path)
    video = tmp_path / "unsigned-callback-uncut.webm"
    data = tmp_path / "other.webm"
    video.rename(data)
    try:
        video.symlink_to(data)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(PreliminaryEvidenceError, match="missing or oversized"):
        verify_negative_media(tmp_path, release=RELEASE, deployment=DEPLOYMENT,
                              selected=SELECTED)
