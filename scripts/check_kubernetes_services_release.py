#!/usr/bin/env python3
"""Require a signed Rust-only stack release before selecting a Kubernetes image."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Callable

if __package__:
    from .collect_passport_beta_acceptance import verify_attestations
    from .prepare_official_beta_release import OfficialReleaseError, validate_release_inputs
else:
    from collect_passport_beta_acceptance import verify_attestations
    from prepare_official_beta_release import OfficialReleaseError, validate_release_inputs


REFUSAL = "Kubernetes services image is not bound to a signed Rust-only stack release"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"ghcr\.io/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)+services@sha256:[0-9a-f]{64}\Z")
UI_IMAGES = {
    "ui": "ghcr.io/elevenid/marty-ui-oss/ui",
    "services": "ghcr.io/elevenid/marty-ui-oss/services",
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations",
}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(REFUSAL)
        value[key] = item
    return value


def validate(manifest_path: Path, reference: str, expected_source: str, *,
             attest: Callable[[Path, dict[str, str], str], bool] = verify_attestations) -> str:
    try:
        if not IMAGE.fullmatch(reference) or not COMMIT.fullmatch(expected_source):
            raise ValueError(REFUSAL)
        if manifest_path.name != "stack-manifest.json":
            raise ValueError(REFUSAL)
        with manifest_path.open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError(REFUSAL)
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
        components = manifest.get("components")
        if not isinstance(components, list):
            raise ValueError(REFUSAL)
        ui = [item for item in components if isinstance(item, dict)
              and item.get("name") == "marty-ui"]
        if (len(ui) != 1 or not isinstance(ui[0].get("commit"), str)
                or not COMMIT.fullmatch(ui[0]["commit"])):
            raise ValueError(REFUSAL)
        source_commit = ui[0]["commit"]
        if source_commit != expected_source:
            raise ValueError(REFUSAL)
        release = validate_release_inputs(
            manifest_path, manifest_path.parent / "SHA256SUMS",
            expected_ui_revision=source_commit, rust_only=True,
        )
        images = release["images"]
        if any(images[role]["uri"] != uri for role, uri in UI_IMAGES.items()):
            raise ValueError(REFUSAL)
        artifacts = ui[0]["artifacts"]
        if sorted(item["uri"] for item in artifacts if item["type"] == "oci") \
                != sorted(UI_IMAGES.values()):
            raise ValueError(REFUSAL)
        if reference != images["services"]["reference"]:
            raise ValueError(REFUSAL)
        digests = {images[role]["uri"]: images[role]["digest"] for role in UI_IMAGES}
        if attest(manifest_path, digests, source_commit) is not True:
            raise ValueError(REFUSAL)
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            OfficialReleaseError) as exc:
        raise ValueError(REFUSAL) from exc
    return reference


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        validate(args.manifest, args.image, args.source_sha)
    except ValueError:
        parser.exit(1, REFUSAL + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
