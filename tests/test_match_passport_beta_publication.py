import copy
from datetime import datetime, timedelta, timezone

import pytest

from scripts.match_passport_beta_preliminary_soak import LineageError
from scripts.match_passport_beta_publication import (
    MEDIA_FIELDS, YOUTUBE_HASH_FIELDS, authenticate_publication_lineage,
    match_publication,
)


SOURCE = "a" * 40
START = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def lineage():
    return {
        "release": {"source_commit": SOURCE, "stack_manifest_sha256": "b" * 64},
        "deployment": {
            "aggregate_deployment_receipt_sha256": "c" * 64,
            "aggregate_plan_sha256": "d" * 64,
            "production_snapshot_commitment": "e" * 64,
            "production_attachment_commitment": "f" * 64,
        },
        "selected_source_job_commitment": "1" * 64,
        "selected_bureau_job_commitment": "2" * 64,
        "preliminary_run_id": 111,
        "preliminary_artifact_sha256": "3" * 64,
        "preliminary_completed_at_utc": START.isoformat(),
        "preliminary_negative_media_sha256": {
            "unsigned-callback-uncut.webm": "4" * 64,
            "foreign-callback-uncut.webm": "5" * 64,
            "unsigned-callback-privacy-scan.json": "6" * 64,
            "foreign-callback-privacy-scan.json": "7" * 64,
        },
        "soak_first_observed_at_utc": (START + timedelta(hours=1)).isoformat(),
    }


def publication():
    media = {name: "8" * 64 for name in MEDIA_FIELDS}
    media.update({
        "unsigned_uncut_video_sha256": "4" * 64,
        "foreign_uncut_video_sha256": "5" * 64,
        "unsigned_privacy_scan_sha256": "6" * 64,
        "foreign_privacy_scan_sha256": "7" * 64,
    })
    youtube = {name: "9" * 64 for name in YOUTUBE_HASH_FIELDS}
    youtube.update({
        "channel_id": "UCjUbog1b4zEdck5pV78EgCw",
        "channel_title": "ElevenID LLC",
        "playlist_id": "PLH1b0jTIP3-4",
        "video_id": "abcdefghijk",
        "privacy_status": "public", "upload_status": "processed",
        "embeddable": True, "captions_verified": True,
        "playlist_membership_verified": True,
        "live_checked_at_utc": (START + timedelta(minutes=20)).isoformat(),
    })
    return {
        "kind": "publication", "run_id": 222,
        "artifact_name": "passport-beta-demo-publication-222",
        "artifact_sha256": "a" * 64,
        "workflow_commit": SOURCE,
        "run_started_at_utc": (START + timedelta(minutes=10)).isoformat(),
        "run_completed_at_utc": (START + timedelta(minutes=30)).isoformat(),
        "value": {
            "schema": "marty.passport-beta-demo-publication/v1",
            "status": "public_verified",
            "protected_run": {"run_id": "222", "workflow_commit": SOURCE},
            "beta_origin": "https://beta.elevenidllc.com",
            "physical_claim": "not_claimed", "booklet_verified": False,
            "release": lineage()["release"],
            "deployment": lineage()["deployment"],
            "preliminary": {"run_id": 111, "artifact_sha256": "3" * 64},
            "selected_source_job_commitment": "1" * 64,
            "selected_bureau_job_commitment": "2" * 64,
            "media": media, "youtube": youtube,
        },
    }


def test_joins_protected_publication_to_selected_beta_job():
    result = authenticate_publication_lineage(
        lineage(), 222, reader=lambda kind, run: publication())
    assert result["verified"] is True
    assert result["evidence"]["video_id"] == "abcdefghijk"
    assert result["evidence"]["preliminary_run_id"] == 111


@pytest.mark.parametrize("path,value,reason", [
    (("selected_source_job_commitment",), "f" * 64, "selected beta passport job"),
    (("media", "unsigned_uncut_video_sha256"), "f" * 64, "preliminary clips"),
    (("youtube", "channel_id"), "UC0000000000000000000000", "YouTube"),
    (("youtube", "playlist_membership_verified"), False, "YouTube"),
])
def test_rejects_mismatched_selected_job_media_or_youtube(path, value, reason):
    altered = copy.deepcopy(publication())
    target = altered["value"]
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    with pytest.raises(LineageError, match=reason):
        match_publication(lineage(), altered)


def test_rejects_publication_outside_protected_run_or_after_soak():
    altered = copy.deepcopy(publication())
    altered["value"]["youtube"]["live_checked_at_utc"] = (
        START + timedelta(hours=2)).isoformat()
    with pytest.raises(LineageError, match="preliminary qualification and precede soak"):
        match_publication(lineage(), altered)
    altered = copy.deepcopy(publication())
    altered["run_completed_at_utc"] = (START + timedelta(hours=2)).isoformat()
    with pytest.raises(LineageError, match="preliminary qualification and precede soak"):
        match_publication(lineage(), altered)


def test_rejects_publication_before_preliminary_qualification():
    altered = copy.deepcopy(publication())
    altered["run_started_at_utc"] = (START - timedelta(minutes=5)).isoformat()
    with pytest.raises(LineageError, match="preliminary qualification and precede soak"):
        match_publication(lineage(), altered)
