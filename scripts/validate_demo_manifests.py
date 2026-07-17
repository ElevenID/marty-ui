#!/usr/bin/env python3
"""Validate public ElevenID LLC release demo manifests without optional dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


STACK_VERSION = re.compile(r"^\d{4}\.\d{2}\.\d+$")
MIP_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
GIT_REVISION = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
YOUTUBE_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
YOUTUBE_CHANNEL_ID = re.compile(r"^UC[A-Za-z0-9_-]{22}$")
YOUTUBE_HANDLE = re.compile(r"^@[A-Za-z0-9._-]{3,30}$")
YOUTUBE_PLAYLIST_ID = re.compile(r"^[A-Za-z0-9_-]{10,64}$")

FINAL_PROTOCOLS = {
    "openid4vci-1.0",
    "openid4vp-1.0",
    "dcql-1.0",
    "sd-jwt-vc",
    "open-badges-3.0",
    "lti-1.3",
}
SENSITIVE_KEYS = {
    "credential",
    "credential_payload",
    "credential_offer",
    "credential_offer_uri",
    "request_uri",
    "qr_data",
    "access_token",
    "refresh_token",
    "api_key",
    "password",
    "secret",
    "private_key",
    "email",
}
REQUIRED_SCENARIOS = {
    "membership-badge-login",
    "organization-primitives",
    "first-party-browser-wallet",
    "independent-wallet-interoperability",
    "canvas-learning-achievement",
    "credential-lifecycle",
}
SCENARIO_PUBLICATION_CHECKS = {
    "accessibility", "captions", "evidence", "links", "playback", "privacy", "thumbnail", "transcript",
}
RELEASE_PUBLICATION_CHECKS = {
    "accessibility", "canonical-urls", "metadata", "navigation", "playback", "privacy",
    "responsive-layouts", "version-selection",
}
PENDING_PUBLICATION_LANGUAGE = re.compile(r"\b(awaiting|must pass before|not completed|not run|pending)\b", re.IGNORECASE)


class ManifestValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestValidationError(message)


def reject_sensitive_keys(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() not in SENSITIVE_KEYS, f"{path}.{key}: sensitive fields are forbidden")
            reject_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_keys(child, f"{path}[{index}]")


def validate_timestamp(value: Any, label: str) -> None:
    require(isinstance(value, str) and "T" in value, f"{label} requires an ISO date-time timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ManifestValidationError(f"{label} timestamp is invalid") from error
    require(parsed.tzinfo is not None, f"{label} timestamp requires a timezone")


def validate_publication_attestation(value: Any, expected_checks: set[str], published_at: Any, label: str) -> None:
    require(isinstance(value, dict), f"{label} requires publication attestation evidence")
    require(value.get("kind") == "AUTOMATED", f"{label} attestation kind must be AUTOMATED")
    require(bool(GIT_REVISION.fullmatch(value.get("pipeline_revision", ""))), f"{label} pipeline revision is invalid")
    validate_timestamp(value.get("published_at"), f"{label} attestation")
    require(value.get("published_at") == published_at, f"{label} attestation time must match published_at")
    checks = value.get("checks")
    require(isinstance(checks, list) and len(checks) == len(set(checks)), f"{label} attestation checks must be unique")
    require(set(checks) == expected_checks, f"{label} attestation checks are incomplete")
    for field in ("verification_report_sha256", "result_sha256", "smoke_report_sha256"):
        require(bool(SHA256.fullmatch(value.get(field, ""))), f"{label} {field} is invalid")
    require(value.get("youtube_privacy_status") == "public", f"{label} YouTube privacy status must be public")


def validate_media_evidence(value: Any, label: str) -> None:
    require(isinstance(value, dict), f"{label} requires release-bound media evidence")
    for field in (
        "video_sha256", "captions_sha256", "thumbnail_sha256", "privacy_scan_sha256",
        "publication_config_sha256",
    ):
        require(bool(SHA256.fullmatch(value.get(field, ""))), f"{label} {field} is invalid")
    validate_timestamp(value.get("youtube_uploaded_at"), f"{label} YouTube upload")


def validate_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version", "stack_version", "release_name", "mip_version", "publication_state",
        "coverage_state", "release_ready", "public_demo_ready", "published_at", "publication_attestation",
        "video_distribution",
        "deployment_release_marker", "recorder_revision", "component_revisions",
        "image_digests", "release_evidence", "release_differences", "scenarios",
    }
    missing = sorted(required - manifest.keys())
    require(not missing, f"missing required fields: {', '.join(missing)}")
    require(manifest["schema_version"] == 2, "schema_version must be 2")
    require(bool(STACK_VERSION.fullmatch(manifest["stack_version"])), "stack_version must use YYYY.MM.PATCH")
    release_name = manifest["release_name"]
    require(isinstance(release_name, str) and 3 <= len(release_name.strip()) <= 80, "release_name must be descriptive")
    require(bool(MIP_VERSION.fullmatch(manifest["mip_version"])), "mip_version must be semantic and independent")
    require(manifest["publication_state"] in {"DRAFT", "PUBLIC", "SUPERSEDED"}, "invalid publication_state")
    require(manifest["coverage_state"] in {"PARTIAL", "COMPLETE", "SUPERSEDED"}, "invalid coverage_state")

    distribution = manifest["video_distribution"]
    require(distribution.get("provider") == "YOUTUBE", "video distribution provider must be YOUTUBE")
    require(distribution.get("channel_name") == "ElevenID LLC", "video distribution must use the ElevenID LLC channel")
    require(distribution.get("privacy_enhanced_embeds") is True, "privacy-enhanced YouTube embeds are required")
    distribution_status = distribution.get("status")
    require(distribution_status in {"PENDING_CHANNEL_SETUP", "CONFIGURED"}, "invalid video distribution status")
    if distribution_status == "CONFIGURED":
        channel_id = distribution.get("channel_id", "")
        channel_handle = distribution.get("channel_handle")
        playlist_id = distribution.get("playlist_id", "")
        require(bool(YOUTUBE_CHANNEL_ID.fullmatch(channel_id)), "configured YouTube channel ID is invalid")
        require(channel_handle is None or bool(YOUTUBE_HANDLE.fullmatch(channel_handle)), "configured YouTube handle is invalid")
        expected_channel_urls = {f"https://www.youtube.com/channel/{channel_id}"}
        if channel_handle:
            expected_channel_urls.add(f"https://www.youtube.com/{channel_handle}")
        require(distribution.get("channel_url") in expected_channel_urls, "configured YouTube channel URL does not match its identity")
        require(bool(YOUTUBE_PLAYLIST_ID.fullmatch(playlist_id)), "configured YouTube playlist ID is invalid")
        require(distribution.get("playlist_url") == f"https://www.youtube.com/playlist?list={playlist_id}", "configured YouTube playlist URL does not match its identity")
        require(bool(distribution.get("verified_at")), "configured YouTube distribution requires verification time")
    else:
        for field in ("channel_id", "channel_handle", "channel_url", "playlist_id", "playlist_url", "verified_at"):
            require(distribution.get(field) is None, f"pending YouTube distribution cannot publish {field}")

    recorder = manifest["recorder_revision"]
    require(recorder.get("kind") in {"git", "unversioned-source-snapshot"}, "invalid recorder revision kind")
    if recorder.get("kind") == "git":
        require(bool(GIT_REVISION.fullmatch(recorder.get("value", ""))), "recorder git revision must be a full SHA")
    else:
        require(not manifest["release_ready"] and manifest["publication_state"] == "DRAFT", "unversioned recorder evidence is preview-only")
        require(bool(SHA256.fullmatch(recorder.get("value", ""))), "recorder source snapshot must be a SHA-256")

    components = manifest["component_revisions"]
    require(isinstance(components, list) and components, "component_revisions cannot be empty")
    for component in components:
        require(bool(GIT_REVISION.fullmatch(component.get("revision", ""))), f"{component.get('component')}: revision must be a full SHA")

    images = manifest["image_digests"]
    require(isinstance(images, list) and images, "image_digests cannot be empty")
    for image in images:
        require(bool(DIGEST.fullmatch(image.get("digest", ""))), f"{image.get('component')}: immutable image digest required")

    require(bool(manifest["release_evidence"].get("displayed_offers_invalidated_at")), "displayed offers must be invalidated before evidence publication")

    scenarios = manifest["scenarios"]
    require(isinstance(scenarios, list) and scenarios, "scenarios cannot be empty")
    slugs = [scenario.get("slug") for scenario in scenarios]
    require(len(slugs) == len(set(slugs)), "scenario slugs must be unique")
    require(REQUIRED_SCENARIOS.issubset(set(slugs)), "all six release scenarios must be represented")

    for scenario in scenarios:
        slug = scenario.get("slug", "unknown")
        require(scenario.get("mip_version") == manifest["mip_version"], f"{slug}: scenario MIP version must match release metadata")
        protocols = set(scenario.get("protocols", []))
        require(bool(protocols), f"{slug}: at least one protocol is required")
        unsupported = protocols - FINAL_PROTOCOLS
        require(not unsupported, f"{slug}: unsupported or deprecated protocol(s): {', '.join(sorted(unsupported))}")
        require(not any("draft" in protocol.lower() or "presentation-exchange" in protocol.lower() for protocol in protocols), f"{slug}: draft and deprecated protocols are forbidden")

        state = scenario.get("state")
        require(state in {"DRAFT", "VALIDATED", "YOUTUBE_UNLISTED", "PUBLIC", "SUPERSEDED"}, f"{slug}: invalid state")
        youtube_id = scenario.get("youtube_id")
        if youtube_id is not None:
            require(bool(YOUTUBE_ID.fullmatch(youtube_id)), f"{slug}: invalid YouTube ID")
        if state in {"YOUTUBE_UNLISTED", "PUBLIC"}:
            require(youtube_id is not None, f"{slug}: published states require a YouTube ID")
            require(distribution_status == "CONFIGURED", f"{slug}: published states require a verified ElevenID LLC YouTube channel and release playlist")
            validate_media_evidence(scenario.get("media_evidence"), slug)
        if state == "PUBLIC":
            validate_timestamp(scenario.get("published_at"), f"{slug}: PUBLIC")
            validate_publication_attestation(
                scenario.get("publication_attestation"),
                SCENARIO_PUBLICATION_CHECKS,
                scenario.get("published_at"),
                f"{slug}: PUBLIC",
            )
            require(bool(scenario.get("transcript", {}).get("segments")), f"{slug}: PUBLIC requires a transcript")
            require(bool(scenario.get("chapters")), f"{slug}: PUBLIC requires chapters")
            assertions = scenario.get("assertions", [])
            require(bool(assertions), f"{slug}: PUBLIC requires evidence assertions")
            require(
                all(item.get("result") == "PASS" and bool(SHA256.fullmatch(item.get("evidence_sha256", ""))) for item in assertions),
                f"{slug}: every PUBLIC assertion must PASS with an evidence hash",
            )
            require(
                not any(PENDING_PUBLICATION_LANGUAGE.search(item) for item in scenario.get("limitations", [])),
                f"{slug}: PUBLIC limitations cannot contain unresolved publication language",
            )
        elif state != "SUPERSEDED":
            require(scenario.get("published_at") is None, f"{slug}: non-public scenario cannot retain published_at")
            require(scenario.get("publication_attestation") is None, f"{slug}: non-public scenario cannot retain publication attestation")
            if state not in {"YOUTUBE_UNLISTED"}:
                require(scenario.get("media_evidence") is None, f"{slug}: unpublished scenario cannot retain media evidence")

        poster = scenario.get("poster", {})
        require(str(poster.get("src", "")).startswith(f"/images/demos/{manifest['stack_version']}/"), f"{slug}: poster must be release-bound")
        require(bool(SHA256.fullmatch(poster.get("sha256", ""))), f"{slug}: poster hash is required")

        inheritance = scenario.get("inherited_evidence")
        if inheritance is not None:
            require(inheritance.get("source_stack_version") != manifest["stack_version"], f"{slug}: inherited evidence must come from another ElevenID LLC release")
            for field in ("byte_identical_components", "unchanged_protocols", "unchanged_wallets", "unchanged_behavior"):
                require(inheritance.get(field) is True, f"{slug}: inheritance requires {field}=true")
            require(bool(SHA256.fullmatch(inheritance.get("attestation_sha256", ""))), f"{slug}: inheritance attestation hash required")

    if manifest["coverage_state"] == "COMPLETE":
        require(manifest["publication_state"] == "PUBLIC" and manifest["public_demo_ready"], "COMPLETE coverage must be publicly approved")
        require(all(scenario.get("state") == "PUBLIC" for scenario in scenarios if scenario.get("slug") in REQUIRED_SCENARIOS), "COMPLETE coverage requires all required scenarios to be PUBLIC")
        independent = next(item for item in scenarios if item.get("slug") == "independent-wallet-interoperability")
        require(any(wallet.get("classification") == "INDEPENDENT" and wallet.get("result") == "PASS" for wallet in independent.get("wallets", [])), "COMPLETE coverage requires passing independent-wallet evidence")

    if manifest["publication_state"] == "PUBLIC":
        require(manifest["release_ready"], "PUBLIC release evidence requires release_ready")
        require(manifest["public_demo_ready"], "PUBLIC release evidence requires public_demo_ready")
        validate_timestamp(manifest.get("published_at"), "PUBLIC release")
        validate_publication_attestation(
            manifest.get("publication_attestation"),
            RELEASE_PUBLICATION_CHECKS,
            manifest.get("published_at"),
            "PUBLIC release",
        )
        require(any(scenario.get("state") == "PUBLIC" for scenario in scenarios), "PUBLIC release requires at least one PUBLIC scenario")
    elif manifest["publication_state"] != "SUPERSEDED":
        require(manifest.get("published_at") is None, "non-public release cannot retain published_at")
        require(manifest.get("publication_attestation") is None, "non-public release cannot retain publication attestation")
    reject_sensitive_keys(manifest)


def validate_index(index: dict[str, Any], manifests: dict[str, dict[str, Any]]) -> None:
    require(index.get("schema_version") == 2, "index schema_version must be 2")
    releases = index.get("releases")
    require(isinstance(releases, list) and releases, "index releases cannot be empty")
    versions = [release.get("stack_version") for release in releases]
    require(len(versions) == len(set(versions)), "index ElevenID LLC versions must be unique")
    for release in releases:
        version = release.get("stack_version", "")
        require(version in manifests, f"index references missing manifest {version}")
        require(release.get("release_name") == manifests[version]["release_name"], f"{version}: index release name mismatch")
        require(release.get("mip_version") == manifests[version]["mip_version"], f"{version}: index MIP version mismatch")
        require(release.get("publication_state") == manifests[version]["publication_state"], f"{version}: index publication state mismatch")
        require(release.get("coverage_state") == manifests[version]["coverage_state"], f"{version}: index coverage mismatch")
        require(release.get("manifest_url") == f"/demos/manifests/{version}.json", f"{version}: canonical manifest URL mismatch")
    latest = index.get("latest_approved_stack_version")
    if latest is not None:
        require(latest in manifests, "latest approved ElevenID LLC release is missing")
        require(manifests[latest]["publication_state"] == "PUBLIC", "latest approved ElevenID LLC release must be PUBLIC")


def load_manifests(root: Path, version_file: Path | None = None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    index_path = root / "index.json"
    require(index_path.exists(), f"missing {index_path}")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    manifests: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        if path.name == "index.json":
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        validate_manifest(manifest)
        require(path.stem == manifest["stack_version"], f"{path.name}: filename must match stack_version")
        public_root = root.parent.parent
        for scenario in manifest["scenarios"]:
            poster_path = public_root / scenario["poster"]["src"].lstrip("/")
            require(poster_path.exists(), f"{scenario['slug']}: poster is missing: {poster_path}")
            poster_hash = hashlib.sha256(poster_path.read_bytes()).hexdigest()
            require(poster_hash == scenario["poster"]["sha256"], f"{scenario['slug']}: poster SHA-256 mismatch")
        manifests[manifest["stack_version"]] = manifest
    validate_index(index, manifests)
    if version_file is not None and version_file.exists():
        release_version = version_file.read_text(encoding="utf-8").strip()
        require(index.get("latest_available_stack_version") == release_version, "latest available ElevenID LLC release must match VERSION")
    return index, manifests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("ui/public/demos/manifests"))
    parser.add_argument("--version-file", type=Path, default=Path("VERSION"))
    args = parser.parse_args()
    try:
        index, manifests = load_manifests(args.root, args.version_file)
    except (ManifestValidationError, json.JSONDecodeError) as error:
        print(f"Demo manifest validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Validated {len(manifests)} ElevenID LLC demo manifest(s); latest approved: {index.get('latest_approved_stack_version') or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
