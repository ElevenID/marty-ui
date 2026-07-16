#!/usr/bin/env python3
"""Validate a stack lock and emit the public marty.stack/v1 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ARTIFACT_TYPES = {"crate", "python", "npm", "oci", "release"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _validate_url(value: str, field: str) -> None:
    parsed = urlparse(value)
    _require(parsed.scheme == "https" and bool(parsed.netloc), f"{field} must be an HTTPS URL")


def validate_component(component: dict) -> None:
    name = component.get("name", "<unnamed>")
    _require(isinstance(component.get("name"), str) and component["name"], "component name is required")
    _require(isinstance(component.get("repository"), str) and "/" in component["repository"], f"{name}: repository must be owner/name")
    _require(isinstance(component.get("version"), str) and component["version"], f"{name}: version is required")
    _require(bool(SHA_RE.fullmatch(str(component.get("commit", "")))), f"{name}: commit must be a full lowercase SHA")
    artifacts = component.get("artifacts")
    _require(isinstance(artifacts, list) and artifacts, f"{name}: at least one artifact is required")
    for artifact in artifacts:
        artifact_type = artifact.get("type")
        _require(artifact_type in ARTIFACT_TYPES, f"{name}: unsupported artifact type {artifact_type!r}")
        uri = str(artifact.get("uri", ""))
        if artifact_type == "oci":
            _require(bool(re.fullmatch(r"[a-z0-9.-]+/[a-z0-9._/-]+", uri)), f"{name}: OCI URI must be registry/path without a tag")
        else:
            _validate_url(uri, f"{name} artifact URI")
        _require(bool(DIGEST_RE.fullmatch(str(artifact.get("digest", "")))), f"{name}: artifact digest must be sha256:<64 hex>")
        _validate_url(str(artifact.get("sbom", "")), f"{name} SBOM")
        _validate_url(str(artifact.get("provenance", "")), f"{name} provenance")


def validate_lock(lock: dict) -> None:
    _require(lock.get("schema") == "marty.stack-lock/v1", "lock schema must be marty.stack-lock/v1")
    _require(isinstance(lock.get("release"), str) and lock["release"].startswith("marty-ui@"), "release must be marty-ui@<version>")
    components = lock.get("components")
    _require(isinstance(components, list) and components, "components must be a non-empty list")
    names = [component.get("name") for component in components]
    _require(len(names) == len(set(names)), "component names must be unique")
    for component in components:
        validate_component(component)


def verify_http_artifacts(lock: dict) -> None:
    for component in lock["components"]:
        for artifact in component["artifacts"]:
            if artifact["type"] == "oci":
                continue
            digest = hashlib.sha256()
            request = urllib.request.Request(artifact["uri"], headers={"User-Agent": "marty-stack-verifier/1"})
            with urllib.request.urlopen(request, timeout=120) as response:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
            actual = f"sha256:{digest.hexdigest()}"
            _require(actual == artifact["digest"], f"{component['name']}: digest mismatch for {artifact['uri']}")


def build_manifest(lock: dict, generated_at: str | None = None) -> dict:
    validate_lock(lock)
    return {
        "schema": "marty.stack/v1",
        "release": lock["release"],
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "components": lock["components"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-http", action="store_true")
    args = parser.parse_args()

    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    manifest = build_manifest(lock)
    if args.verify_http:
        verify_http_artifacts(lock)
    if args.output:
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Validated {len(manifest['components'])} immutable stack components.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
