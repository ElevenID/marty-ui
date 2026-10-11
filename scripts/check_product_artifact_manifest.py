#!/usr/bin/env python3
"""Fail-closed structural checks for one exact product artifact descriptor.

This does not qualify an artifact, verify signatures, or establish public access.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "deploy-config/schemas/product-artifact-manifest.schema.json"
OCI = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@(?P<digest>sha256:[0-9a-f]{64})$")


def _is_https_file(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "https" and bool(parts.hostname) and bool(parts.path.strip("/")) and not parts.username and not parts.password and not parts.fragment


def validate_manifest(manifest: object, schema: dict) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda e: (list(map(str, e.path)), e.message))
    if errors:
        error = errors[0]
        path = ".".join(map(str, error.path)) or "manifest"
        raise ValueError(f"{path}: {error.message}")

    assert isinstance(manifest, dict)  # enforced by schema
    for field in ("artifact", "sbom", "provenance"):
        item = manifest[field]
        uri, digest = item["uri"], item["digest"]
        oci = OCI.fullmatch(uri)
        if oci:
            if oci.group("digest") != digest:
                raise ValueError(f"{field}: OCI URI digest differs from declared digest")
        elif not _is_https_file(uri):
            raise ValueError(f"{field}: URI must be an HTTPS file or digest-pinned OCI reference")

    notice = manifest["license"]["notice"]
    if not _is_https_file(notice["uri"]):
        raise ValueError("license.notice: URI must be an HTTPS file")

    names = [dependency["name"] for dependency in manifest["dependencies"]]
    if len(names) != len(set(names)):
        raise ValueError("dependencies: names must be unique across scopes")
    optional = {item["name"] for item in manifest["dependencies"] if item["scope"] == "optional-extension"}
    if optional != set(manifest["extensions"]):
        raise ValueError("extensions: must exactly match optional-extension dependency names")

    if manifest["qualification"]["state"] == "qualified" and not manifest["qualification"]["evidence"]:
        raise ValueError("qualification.evidence: qualified artifacts require evidence references")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest, schema)
    print(f"Valid product artifact descriptor: {manifest['product']} ({manifest['support_state']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
