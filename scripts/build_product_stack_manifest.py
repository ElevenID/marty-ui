#!/usr/bin/env python3
"""Build the same digest-bound product manifest before and after qualification."""

from __future__ import annotations

import argparse
import json
import runpy
from copy import deepcopy
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
TRANSACTION = runpy.run_path(str(SCRIPTS / "release_transaction.py"))
MANIFEST = runpy.run_path(str(SCRIPTS / "build_stack_manifest.py"))


def build_product_manifest(lock_path: Path, transaction_path: Path, generated_at: str) -> dict:
    claim = TRANSACTION["validate_claim"](json.loads(transaction_path.read_text(encoding="utf-8")))
    if not claim["images"] or claim["state"] == "tombstoned":
        raise ValueError("product manifest requires recorded non-tombstoned image digests")
    if TRANSACTION["file_digest"](lock_path) != claim["stack_lock_sha256"]:
        raise ValueError("product stack lock differs from the frozen release claim")
    lock = deepcopy(json.loads(lock_path.read_text(encoding="utf-8")))
    if lock.get("release") != f"marty-ui@{claim['version']}":
        raise ValueError("product stack lock version differs from the release claim")
    if any(component.get("name") == "marty-ui" for component in lock["components"]):
        raise ValueError("product stack lock already contains the product component")
    provenance = "https://github.com/ElevenID/marty-ui/attestations"
    artifacts = []
    for role in TRANSACTION["REQUIRED_IMAGE_ROLES"]:
        image = claim["images"][role]
        suffix = "" if role == "ui" else "-" + role.replace("_", "-")
        artifacts.append({
            "type": "oci", "uri": image["uri"], "digest": image["digest"],
            "sbom": f"https://github.com/ElevenID/marty-ui/releases/download/{claim['tag']}/marty-ui{suffix}-sbom.cdx.json",
            "provenance": provenance,
        })
    lock["components"].append({
        "name": "marty-ui", "repository": claim["repository"],
        "version": claim["version"], "commit": claim["source_sha"], "artifacts": artifacts,
    })
    return MANIFEST["build_manifest"](lock, generated_at=generated_at)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--transaction", type=Path, required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_product_manifest(args.lock, args.transaction, args.generated_at)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
