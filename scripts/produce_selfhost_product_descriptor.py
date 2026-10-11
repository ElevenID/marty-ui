#!/usr/bin/env python3
"""Describe one prepared self-host ZIP without asserting release qualification.

The output is a local, content-addressed candidate. It is not a download URL,
signature, installation approval, or claim that the ZIP is independently supported.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import release_transaction
from check_product_artifact_manifest import SCHEMA, validate_manifest
from record_selfhost_bundle_preparation import record


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def produce(archive: Path, image_lock: Path, transaction: Path, receipt_path: Path) -> dict:
    receipt = _json(receipt_path)
    if receipt.get("schema") != "marty.selfhost-bundle-preparation/v1":
        raise ValueError("unsupported preparation receipt")
    if receipt.get("qualification") != "unqualified":
        raise ValueError("preparation receipt must be unqualified")
    source_sha, run_id = receipt.get("source_sha"), receipt.get("run_id")
    if not isinstance(source_sha, str) or not isinstance(run_id, str):
        raise ValueError("preparation receipt lacks source/run identity")
    # Re-extract and verify the complete ZIP, its owned inventory, embedded lock,
    # rendered Compose image closure, and every recorded byte digest.
    if receipt != record(archive, image_lock, transaction, source_sha, run_id):
        raise ValueError("preparation receipt differs from exact inputs")
    claim = release_transaction.validate_claim(_json(transaction))
    if claim["source_sha"] != source_sha:
        raise ValueError("transaction source differs from preparation receipt")
    if claim["state"] not in {"qualified", "promoting", "promoted", "published"}:
        raise ValueError("transaction lacks stack qualification gate evidence")
    if claim["repository"] != "ElevenID/marty-ui" or len(claim["gates"]) != 2:
        raise ValueError("transaction repository or stack gates changed")
    lock = _json(image_lock)
    if lock.get("release") != f"marty-ui@{claim['version']}":
        raise ValueError("image lock release differs from transaction")
    locked_images = lock.get("services")
    if not isinstance(locked_images, dict):
        raise ValueError("image lock lacks service closure")
    for role in ("services", "migrations"):
        recorded = claim["images"][role]
        exact_image = recorded["uri"] + "@" + recorded["digest"]
        if exact_image not in locked_images.values():
            raise ValueError(f"image lock omits transaction {role} image")
    archive_digest = "sha256:" + receipt["archive_sha256"]
    manifest = {
        "schema": "marty.product-artifact/v1",
        "product": "organizational-platform",
        "support_state": "experimental",
        "artifact": {"uri": "urn:" + archive_digest, "digest": archive_digest},
        "source": {"repository": "https://github.com/ElevenID/marty-ui", "commit": source_sha},
        "qualification": {"state": "unqualified", "evidence": []},
        "preparation": {
            "run_id": run_id,
            "receipt_sha256": release_transaction.file_digest(receipt_path),
            "image_lock_sha256": "sha256:" + receipt["image_lock_sha256"],
            "transaction_sha256": "sha256:" + receipt["transaction_sha256"],
        },
    }
    validate_manifest(manifest, _json(SCHEMA))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    value = produce(args.archive, args.image_lock, args.transaction, args.receipt)
    if args.output.exists():
        raise ValueError("descriptor output already exists")
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
