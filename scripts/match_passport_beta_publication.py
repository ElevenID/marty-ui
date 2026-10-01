#!/usr/bin/env python3
"""Join a protected D-12 publication to one selected signed beta passport job.

The caller supplies the authenticated live/preliminary/soak lineage and a
publication artifact downloaded through read_protected_passport_artifact.
The protected publication producer is responsible for rehashing local media,
review files, and live YouTube state before it emits its successful artifact.
"""

from __future__ import annotations

import re
from typing import Any, Callable

if __package__:
    from .match_passport_beta_preliminary_soak import (
        SHA256, require, utc,
    )
    from .read_protected_passport_artifact import read_artifact
else:
    from match_passport_beta_preliminary_soak import SHA256, require, utc
    from read_protected_passport_artifact import read_artifact


CHANNEL_ID = "UCjUbog1b4zEdck5pV78EgCw"
VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}\Z")
PLAYLIST_ID = re.compile(r"PL[A-Za-z0-9_-]{10,}\Z")
MEDIA_FIELDS = (
    "positive_uncut_video_sha256", "unsigned_uncut_video_sha256",
    "foreign_uncut_video_sha256", "unsigned_privacy_scan_sha256",
    "foreign_privacy_scan_sha256", "master_video_sha256",
    "master_privacy_scan_sha256", "captions_sha256",
    "composition_report_sha256", "run_report_sha256",
    "review_report_sha256", "publication_config_sha256",
    "public_manifest_sha256",
)
YOUTUBE_HASH_FIELDS = (
    "publication_result_sha256", "automated_verification_report_sha256",
    "public_page_smoke_report_sha256", "publication_attestation_sha256",
)


def match_publication(
    lineage: dict[str, Any], publication: dict[str, Any],
) -> dict[str, Any]:
    """Return only reviewed public-video evidence bound to the selected job."""
    require(isinstance(lineage, dict)
            and isinstance(lineage.get("release"), dict)
            and isinstance(lineage.get("deployment"), dict)
            and isinstance(lineage.get("preliminary_negative_media_sha256"), dict)
            and type(lineage.get("preliminary_run_id")) is int
            and isinstance(lineage.get("preliminary_artifact_sha256"), str)
            and SHA256.fullmatch(lineage["preliminary_artifact_sha256"]) is not None,
            "Authenticated passport beta lineage is incomplete")
    source = lineage["release"].get("source_commit")
    require(isinstance(source, str)
            and re.fullmatch(r"[0-9a-f]{40}", source) is not None
            and isinstance(publication, dict)
            and publication.get("kind") == "publication"
            and type(publication.get("run_id")) is int
            and publication["run_id"] > 0
            and publication.get("artifact_name")
                == f"passport-beta-demo-publication-{publication['run_id']}"
            and isinstance(publication.get("artifact_sha256"), str)
            and SHA256.fullmatch(publication["artifact_sha256"]) is not None
            and publication.get("workflow_commit") == source
            and isinstance(publication.get("value"), dict),
            "Protected D-12 publication artifact identity is incomplete")
    value = publication["value"]
    require(value.get("schema") == "marty.passport-beta-demo-publication/v1"
            and value.get("status") == "public_verified"
            and value.get("protected_run") == {
                "run_id": str(publication["run_id"]),
                "workflow_commit": source,
            }
            and value.get("beta_origin") == "https://beta.elevenidllc.com"
            and value.get("physical_claim") == "not_claimed"
            and value.get("booklet_verified") is False
            and value.get("release") == lineage["release"]
            and value.get("deployment") == lineage["deployment"]
            and value.get("preliminary") == {
                "run_id": lineage["preliminary_run_id"],
                "artifact_sha256": lineage["preliminary_artifact_sha256"],
            }
            and value.get("selected_source_job_commitment")
                == lineage.get("selected_source_job_commitment")
            and value.get("selected_bureau_job_commitment")
                == lineage.get("selected_bureau_job_commitment"),
            "D-12 publication differs from the selected beta passport job")
    media = value.get("media")
    require(isinstance(media, dict) and set(media) == set(MEDIA_FIELDS)
            and all(isinstance(media[name], str)
                    and SHA256.fullmatch(media[name]) is not None
                    for name in MEDIA_FIELDS)
            and media["unsigned_uncut_video_sha256"]
                == lineage["preliminary_negative_media_sha256"].get(
                    "unsigned-callback-uncut.webm")
            and media["foreign_uncut_video_sha256"]
                == lineage["preliminary_negative_media_sha256"].get(
                    "foreign-callback-uncut.webm")
            and media["unsigned_privacy_scan_sha256"]
                == lineage["preliminary_negative_media_sha256"].get(
                    "unsigned-callback-privacy-scan.json")
            and media["foreign_privacy_scan_sha256"]
                == lineage["preliminary_negative_media_sha256"].get(
                    "foreign-callback-privacy-scan.json")
            and len({media[name] for name in (
                "positive_uncut_video_sha256", "unsigned_uncut_video_sha256",
                "foreign_uncut_video_sha256")}) == 3,
            "D-12 publication media differs from protected preliminary clips")
    youtube = value.get("youtube")
    require(isinstance(youtube, dict)
            and youtube.get("channel_id") == CHANNEL_ID
            and youtube.get("channel_title") == "ElevenID LLC"
            and isinstance(youtube.get("playlist_id"), str)
            and PLAYLIST_ID.fullmatch(youtube["playlist_id"]) is not None
            and isinstance(youtube.get("video_id"), str)
            and VIDEO_ID.fullmatch(youtube["video_id"]) is not None
            and youtube.get("privacy_status") == "public"
            and youtube.get("upload_status") == "processed"
            and youtube.get("embeddable") is True
            and youtube.get("captions_verified") is True
            and youtube.get("playlist_membership_verified") is True
            and all(isinstance(youtube.get(name), str)
                    and SHA256.fullmatch(youtube[name]) is not None
                    for name in YOUTUBE_HASH_FIELDS),
            "Approved public ElevenID LLC YouTube publication is unverified")
    started = utc(publication.get("run_started_at_utc"))
    completed = utc(publication.get("run_completed_at_utc"))
    checked = utc(youtube.get("live_checked_at_utc"))
    preliminary_completed = utc(lineage.get("preliminary_completed_at_utc"))
    soak_started = utc(lineage.get("soak_first_observed_at_utc"))
    require(preliminary_completed <= started <= checked <= completed < soak_started,
            "D-12 publication did not follow preliminary qualification and precede soak")
    return {
        "verified": True,
        "evidence": {
            "publication_run_id": publication["run_id"],
            "publication_artifact_sha256": publication["artifact_sha256"],
            "preliminary_run_id": lineage["preliminary_run_id"],
            "preliminary_artifact_sha256": lineage[
                "preliminary_artifact_sha256"],
            "video_id": youtube["video_id"],
            "channel_id": CHANNEL_ID,
            "playlist_id": youtube["playlist_id"],
            "master_video_sha256": media["master_video_sha256"],
            "physical_claim": "not_claimed",
            "booklet_verified": False,
        },
    }


def authenticate_publication_lineage(
    lineage: dict[str, Any], run_id: int, *,
    reader: Callable[[str, int], dict[str, Any]] = read_artifact,
) -> dict[str, Any]:
    require(type(run_id) is int and run_id > 0,
            "Protected D-12 publication run ID is invalid")
    return match_publication(lineage, reader("publication", run_id))
