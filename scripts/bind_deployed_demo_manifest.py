#!/usr/bin/env python3
"""Bind a pending demo manifest to an exact successful beta deployment."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

if __package__:
    from .validate_demo_manifests import validate_manifest
else:
    from validate_demo_manifests import validate_manifest


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def bind_manifest(
    template: dict[str, Any],
    source_manifest: dict[str, Any],
    image_digests: dict[str, str],
) -> dict[str, Any]:
    _require(
        template.get("binding_state") == "PENDING_DEPLOYMENT",
        "Demo manifest template must be pending deployment",
    )
    _require(
        template.get("mip_version") == source_manifest.get("mip_version"),
        "Demo and source manifests have different MIP versions",
    )
    release_version = source_manifest.get("release_version")
    source_marker = source_manifest.get("marty_ui_sha")
    _require(isinstance(release_version, str) and release_version, "Source release marker is missing")
    _require(
        isinstance(source_marker, str)
        and len(source_marker) == 40
        and all(character in "0123456789abcdef" for character in source_marker),
        "Source marker must be 40 lowercase hexadecimal characters",
    )

    components = source_manifest.get("component_revisions")
    repositories = source_manifest.get("repositories")
    _require(isinstance(components, list) and components, "Source component revisions are missing")
    _require(isinstance(repositories, dict) and repositories, "Source repositories are missing")
    component_by_name: dict[str, dict[str, Any]] = {}
    for component in components:
        _require(isinstance(component, dict), "Source component revision is invalid")
        name = component.get("component")
        _require(isinstance(name, str) and name, "Source component name is invalid")
        _require(name not in component_by_name, f"Source component revision is duplicated: {name}")
        component_by_name[name] = copy.deepcopy(component)
    _require(
        set(component_by_name) == set(repositories),
        "Source component revisions do not cover the exact repository set",
    )
    _require("marty-ui" in component_by_name, "Source manifest omits marty-ui")
    _require(
        "marty-demo-recorder" in component_by_name,
        "Source manifest omits marty-demo-recorder",
    )

    _require(isinstance(image_digests, dict) and image_digests, "Deployment image digests are missing")
    images: list[dict[str, str]] = []
    for component, digest in sorted(image_digests.items()):
        _require(isinstance(component, str) and component, "Deployment image component is invalid")
        _require(
            isinstance(digest, str)
            and len(digest) == 71
            and digest.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in digest[7:]),
            f"Deployment image digest is invalid: {component}",
        )
        images.append({"component": component, "digest": digest})

    bound = copy.deepcopy(template)
    bound["binding_state"] = "DEPLOYED_PENDING_EVIDENCE"
    bound["deployment_release_marker"] = release_version
    bound["recorder_revision"] = {
        "kind": "git",
        "value": component_by_name["marty-demo-recorder"]["revision"],
    }
    bound["demo_application_revision"] = component_by_name["marty-ui"]["revision"]
    bound["component_revisions"] = [component_by_name[name] for name in sorted(component_by_name)]
    bound["image_digests"] = images
    bound["release_evidence"] = {
        "environment": "beta",
        "recorded_at": None,
        "displayed_offers_invalidated_at": None,
        "source_marker": source_marker,
        "artifacts": [],
    }
    validate_manifest(bound)
    return bound


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--image-digests-json", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        output = args.output.resolve()
        _require(
            output not in {args.template.resolve(), args.source_manifest.resolve()},
            "Bound demo manifest output must not overwrite an input manifest",
        )
        template = json.loads(args.template.read_text(encoding="utf-8"))
        source_manifest = json.loads(args.source_manifest.read_text(encoding="utf-8"))
        image_digests = json.loads(args.image_digests_json)
        _require(isinstance(template, dict), "Demo manifest template must be an object")
        _require(isinstance(source_manifest, dict), "Source manifest must be an object")
        _require(isinstance(image_digests, dict), "Image digests must be an object")
        bound = bind_manifest(template, source_manifest, image_digests)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(bound, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Demo deployment binding failed: {exc}")
        return 1
    print(json.dumps({"manifest": str(output), "binding_state": bound["binding_state"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
