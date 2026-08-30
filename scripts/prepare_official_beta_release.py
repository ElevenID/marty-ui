#!/usr/bin/env python3
"""Validate an official stack release for an exact beta deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"[0-9a-f]{40}$")
VERSION = re.compile(r"marty-ui@(\d+\.\d+\.\d+)$")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REQUIRED_COMPONENTS = {
    "marty-api-core",
    "marty-blog",
    "marty-core-python",
    "marty-verification-python",
    "marty-iso18013-python",
    "marty-credentials-issuance",
    "marty-common",
    "marty-cli",
    "marty-integration-tests",
    "marty-ui",
}
REQUIRED_IMAGE_ROLES = {
    "ui": ("marty-ui", "ui"),
    "services": ("marty-ui", "services"),
    "migrations": ("marty-ui", "migrations"),
    "issuance": ("marty-credentials-issuance", "marty-credentials-issuance"),
}


class OfficialReleaseError(RuntimeError):
    """The official release cannot safely drive beta deployment."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OfficialReleaseError(message)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OfficialReleaseError(
            f"Could not read official stack manifest: {exc}"
        ) from exc
    _require(isinstance(value, dict), "Official stack manifest must be a JSON object")
    return value


def _checksum_map(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise OfficialReleaseError(
            f"Could not read official release checksums: {exc}"
        ) from exc
    checksums: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([^/\\]+)", line)
        _require(match is not None, "Official release checksum line is invalid")
        digest, filename = match.groups()
        _require(
            filename not in checksums,
            f"Official release checksum is duplicated: {filename}",
        )
        checksums[filename] = digest
    _require(bool(checksums), "Official release checksum file is empty")
    return checksums


def _repository_key(repository: str) -> str:
    _require(
        REPOSITORY.fullmatch(repository) is not None,
        f"Invalid component repository: {repository}",
    )
    return repository.rsplit("/", 1)[1].lower()


def _image_reference(artifact: dict[str, Any], expected_name: str) -> dict[str, str]:
    uri = artifact.get("uri")
    digest = artifact.get("digest")
    _require(
        isinstance(uri, str) and uri.startswith("ghcr.io/"),
        f"{expected_name} image URI must use GHCR",
    )
    _require(
        "@" not in uri and ":" not in uri.rsplit("/", 1)[-1],
        f"{expected_name} image URI must not contain a mutable tag",
    )
    _require(
        uri.rstrip("/").rsplit("/", 1)[-1] == expected_name,
        f"{expected_name} image repository is incorrect",
    )
    _require(
        isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
        f"{expected_name} image digest is invalid",
    )
    return {"uri": uri, "digest": digest, "reference": f"{uri}@{digest}"}


def prepare_release(
    manifest_path: Path,
    checksums_path: Path,
    *,
    recorder_revision: str,
    expected_ui_revision: str,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    checksums_path = checksums_path.resolve()
    _require(
        manifest_path.parent == checksums_path.parent,
        "Manifest and checksums must share one release directory",
    )
    checksums = _checksum_map(checksums_path)
    manifest_digest = _sha256(manifest_path)
    _require(
        checksums.get(manifest_path.name) == manifest_digest,
        "Official stack manifest checksum does not match SHA256SUMS",
    )
    _require(
        COMMIT.fullmatch(recorder_revision) is not None,
        "Recorder revision must be a full lowercase commit SHA",
    )
    _require(
        COMMIT.fullmatch(expected_ui_revision) is not None,
        "Expected UI revision must be a full lowercase commit SHA",
    )

    manifest = _load_json(manifest_path)
    _require(
        manifest.get("schema") == "marty.stack/v1",
        "Official stack manifest schema is unsupported",
    )
    version_match = VERSION.fullmatch(str(manifest.get("release", "")))
    _require(version_match is not None, "Official stack release identifier is invalid")
    release_version = version_match.group(1)
    components = manifest.get("components")
    _require(
        isinstance(components, list) and components,
        "Official stack manifest has no components",
    )

    components_by_name: dict[str, dict[str, Any]] = {}
    revisions_by_repository: dict[str, tuple[str, str]] = {}
    for component in components:
        _require(isinstance(component, dict), "Official stack component is invalid")
        name = component.get("name")
        repository = component.get("repository")
        commit = component.get("commit")
        _require(
            isinstance(name, str) and name, "Official stack component name is invalid"
        )
        _require(
            name not in components_by_name,
            f"Official stack component is duplicated: {name}",
        )
        _require(
            isinstance(repository, str),
            f"Official stack component repository is invalid: {name}",
        )
        key = _repository_key(repository)
        _require(
            isinstance(commit, str) and COMMIT.fullmatch(commit) is not None,
            f"Official stack component commit is invalid: {name}",
        )
        previous = revisions_by_repository.get(key)
        _require(
            previous is None or previous == (repository, commit),
            f"Official stack repository has conflicting revisions: {repository}",
        )
        revisions_by_repository[key] = (repository, commit)
        artifacts = component.get("artifacts")
        _require(
            isinstance(artifacts, list) and artifacts,
            f"Official stack component has no artifacts: {name}",
        )
        for artifact in artifacts:
            _require(
                isinstance(artifact, dict),
                f"Official stack artifact is invalid: {name}",
            )
            digest = artifact.get("digest")
            _require(
                isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
                f"Official stack artifact digest is invalid: {name}",
            )
            _require(
                isinstance(artifact.get("uri"), str) and artifact["uri"],
                f"Official stack artifact URI is invalid: {name}",
            )
        components_by_name[name] = component

    missing = sorted(REQUIRED_COMPONENTS - set(components_by_name))
    _require(
        not missing,
        f"Official stack manifest is missing components: {', '.join(missing)}",
    )
    ui_component = components_by_name["marty-ui"]
    _require(
        ui_component["repository"] == "ElevenID/marty-ui",
        "Official stack UI repository is incorrect",
    )
    _require(
        ui_component["commit"] == expected_ui_revision,
        "Official stack UI commit does not match the executing release source",
    )
    _require(
        ui_component.get("version") == release_version,
        "Official stack UI component version does not match the release identifier",
    )

    images: dict[str, dict[str, str]] = {}
    for role, (component_name, image_name) in REQUIRED_IMAGE_ROLES.items():
        candidates = [
            artifact
            for artifact in components_by_name[component_name]["artifacts"]
            if artifact.get("type") == "oci"
            and isinstance(artifact.get("uri"), str)
            and artifact["uri"].rstrip("/").rsplit("/", 1)[-1] == image_name
        ]
        _require(
            len(candidates) == 1,
            f"Official stack must contain exactly one {role} image",
        )
        images[role] = _image_reference(candidates[0], image_name)
    _require(
        len({image["digest"] for image in images.values()}) == len(images),
        "Official stack image roles must resolve to unique digests",
    )

    _require(
        "marty-demo-recorder" not in revisions_by_repository,
        "Official stack unexpectedly duplicates the recorder input",
    )
    revisions_by_repository["marty-demo-recorder"] = (
        "ElevenID/marty-demo-recorder",
        recorder_revision,
    )
    repositories = {
        key: {
            "repository": f"https://github.com/{repository}",
            "revision": commit,
            "source": "official-stack-manifest"
            if key != "marty-demo-recorder"
            else "protected-recorder-main",
        }
        for key, (repository, commit) in sorted(revisions_by_repository.items())
    }
    component_revisions = [
        {
            "component": key,
            "repository": record["repository"],
            "revision": record["revision"],
        }
        for key, record in repositories.items()
    ]
    source_manifest = {
        "schema_version": 2,
        "release_version": release_version,
        "mip_version": "0.5.0",
        "source_kind": "official-stack-release",
        "marty_ui_sha": expected_ui_revision,
        "created_at": manifest.get("generated_at"),
        "mixed_versions_supported": False,
        "promotion_eligible": True,
        "release_ready": True,
        "stack_manifest_sha256": manifest_digest,
        "repositories": repositories,
        "component_revisions": component_revisions,
    }
    return {
        "schema_version": 1,
        "release_version": release_version,
        "marty_ui_sha": expected_ui_revision,
        "stack_manifest_sha256": manifest_digest,
        "source_manifest": source_manifest,
        "images": images,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--recorder-revision", required=True)
    parser.add_argument("--expected-ui-revision", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        plan = prepare_release(
            args.manifest,
            args.checksums,
            recorder_revision=args.recorder_revision,
            expected_ui_revision=args.expected_ui_revision,
        )
    except (OSError, OfficialReleaseError) as exc:
        print(f"Official beta release preparation failed: {exc}")
        return 1
    print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
