#!/usr/bin/env python3
"""Bind the canonical Credentials SPDX document to one exact OCI digest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
IMAGE = "ghcr.io/elevenid/marty-credentials-issuance"


class CredentialsSbomError(RuntimeError):
    """The release SBOM does not describe the selected Credentials image."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CredentialsSbomError(message)


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialsSbomError("Credentials SBOM is unreadable") from exc
    _require(isinstance(value, dict), "Credentials SBOM must be a JSON object")
    return value


def validate_sbom(document: dict[str, Any], *, image: str, digest: str) -> None:
    """Require the SPDX document root to describe the exact selected OCI image."""

    _require(image == IMAGE, "Credentials SBOM image name is not canonical")
    _require(
        DIGEST.fullmatch(digest) is not None, "Credentials image digest is invalid"
    )
    _require(
        document.get("spdxVersion") == "SPDX-2.3", "Credentials SBOM is not SPDX 2.3"
    )
    _require(
        document.get("SPDXID") == "SPDXRef-DOCUMENT",
        "Credentials SBOM document ID is invalid",
    )
    _require(document.get("name") == image, "Credentials SBOM document name changed")

    relationships = document.get("relationships")
    _require(
        isinstance(relationships, list), "Credentials SBOM relationships are missing"
    )
    describes = [
        item
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and item.get("relationshipType") == "DESCRIBES"
    ]
    _require(len(describes) == 1, "Credentials SBOM must describe exactly one root")
    root_id = describes[0].get("relatedSpdxElement")
    _require(
        isinstance(root_id, str) and root_id, "Credentials SBOM root ID is invalid"
    )

    packages = document.get("packages")
    _require(isinstance(packages, list), "Credentials SBOM packages are missing")
    roots = [
        item
        for item in packages
        if isinstance(item, dict) and item.get("SPDXID") == root_id
    ]
    _require(len(roots) == 1, "Credentials SBOM described root is ambiguous")
    root = roots[0]
    _require(root.get("name") == image, "Credentials SBOM root image changed")
    _require(
        root.get("versionInfo") == digest,
        "Credentials SBOM root is not bound to the selected OCI digest",
    )


def check_sbom(path: Path, *, image: str, digest: str) -> None:
    validate_sbom(_load(path), image=image, digest=digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        check_sbom(args.sbom, image=args.image, digest=args.digest)
    except CredentialsSbomError as exc:
        print(f"Credentials SBOM verification failed: {exc}")
        return 1
    print("Credentials SBOM describes the exact selected OCI digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
