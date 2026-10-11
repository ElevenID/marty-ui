#!/usr/bin/env python3
"""Fail-closed structural checks for one exact product artifact descriptor.

This does not qualify an artifact, verify signatures, or establish public access.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "deploy-config/schemas/product-artifact-manifest.schema.json"
OCI = re.compile(r"^(?P<registry>[a-z0-9.-]+(?::[0-9]+)?)/(?P<path>[a-z0-9._/-]+)@(?P<digest>sha256:[0-9a-f]{64})$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
OCI_SEGMENT = re.compile(r"^[a-z0-9]+(?:[._-]+[a-z0-9]+)*$")


def _valid_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return len(host) <= 253 and all(DNS_LABEL.fullmatch(label) for label in host.split("."))


def _is_https_file(uri: str) -> bool:
    if any(ord(char) <= 32 or ord(char) == 127 for char in uri):
        return False
    try:
        parts = urlsplit(uri)
        port = parts.port  # Access validates malformed/out-of-range port text.
        return (parts.scheme == "https" and _valid_host(parts.hostname)
                and (port is None or port > 0) and bool(parts.path.strip("/"))
                and parts.username is None and parts.password is None
                and not parts.fragment)
    except ValueError:
        return False


def _is_canonical_oci(uri: str, digest: str) -> bool:
    match = OCI.fullmatch(uri)
    if not match:
        return False
    if match.group("digest") != digest:
        raise ValueError("OCI URI digest differs from declared digest")
    try:
        registry = urlsplit("https://" + match.group("registry") + "/image")
        port = registry.port
    except ValueError:
        return False
    return (_valid_host(registry.hostname) and (port is None or port > 0)
            and all(OCI_SEGMENT.fullmatch(part) for part in match.group("path").split("/")))


def validate_manifest(manifest: object, schema: dict) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda e: (list(map(str, e.path)), e.message))
    if errors:
        error = errors[0]
        path = ".".join(map(str, error.path)) or "manifest"
        raise ValueError(f"{path}: {error.message}")

    assert isinstance(manifest, dict)  # enforced by schema
    for field in ("artifact", "sbom", "provenance", "signature"):
        item = manifest[field]
        uri, digest = item["uri"], item["digest"]
        try:
            canonical_oci = _is_canonical_oci(uri, digest)
        except ValueError as error:
            raise ValueError(f"{field}: {error}") from error
        if not canonical_oci and not _is_https_file(uri):
            raise ValueError(f"{field}: URI must be an HTTPS file or digest-pinned OCI reference")

    notice = manifest["license"]["notice"]
    if not _is_https_file(notice["uri"]):
        raise ValueError("license.notice: URI must be an HTTPS file")

    urls = [("source.repository", manifest["source"]["repository"]),
            ("installation.channel", manifest["installation"]["channel"]),
            ("installation.guide", manifest["installation"]["guide"])]
    urls.extend((f"dependencies.{item['name']}.source", item["source"])
                for item in manifest["dependencies"])
    urls.extend(("qualification.evidence", uri)
                for uri in manifest["qualification"]["evidence"])
    for field, uri in urls:
        if not _is_https_file(uri):
            raise ValueError(f"{field}: URL must be HTTPS with a valid host/path and no credentials or fragment")

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
