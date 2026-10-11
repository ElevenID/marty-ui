#!/usr/bin/env python3
"""Audit the exact public assets needed for a self-host customer handoff.

This is an asset-closure check, not a signature verifier or runtime qualifier.
Run it on files downloaded anonymously from one GitHub release. A prepared ZIP
remains unqualified until a separate installed business journey is published.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from check_prepared_selfhost_consumer import verify_descriptor, verify_receipt
from check_product_artifact_manifest import SCHEMA, validate_manifest
from record_selfhost_bundle_preparation import file_digest
from release_transaction import validate_claim
from selfhost_handoff_contract import PINNED_INTEGRATION_SHA


REQUIRED = frozenset({
    "selfhost-bundle.zip",
    "selfhost-images.json",
    "selfhost-bundle-preparation.json",
    "selfhost-preparation-transaction.json",
    "prepared-selfhost-product-descriptor.json",
    "selfhost-product-descriptor.json",
    "selfhost-qualification.json",
    "release-transaction.json",
    "SHA256SUMS",
})
SHA = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
JOURNEY_STEPS = frozenset({
    "fresh_extract", "anonymous_image_pull", "external_openbao_bootstrap",
    "migrations", "service_readiness", "kms_custody", "customer_login", "credential_issuance",
    "wallet_receipt", "presentation", "verification", "owned_cleanup",
    "revoked_credential_denied",
})


def checksum_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None or match[2] in entries:
            raise ValueError("release checksum file contains an invalid or duplicate entry")
        entries[match[2]] = match[1]
    return entries


def audit(directory: Path, tag: str) -> dict:
    if VERSION.fullmatch(tag) is None:
        raise ValueError("release tag must be an exact semantic version")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release asset directory is missing or linked")
    missing = sorted(name for name in REQUIRED if not (directory / name).is_file())
    if missing:
        raise ValueError("public self-host handoff assets missing: " + ", ".join(missing))
    checksums = checksum_entries(directory / "SHA256SUMS")
    for name in sorted(REQUIRED - {"SHA256SUMS"}):
        path = directory / name
        if path.is_symlink() or checksums.get(name) != file_digest(path):
            raise ValueError(f"release checksum missing or mismatched: {name}")
    transaction_path = directory / "release-transaction.json"
    transaction = validate_claim(json.loads(transaction_path.read_text(encoding="utf-8")))
    if (transaction["repository"] != "ElevenID/marty-ui"
            or transaction["version"] != tag.removeprefix("v")
            or transaction["state"] != "promoted"):
        raise ValueError("public release transaction is not promoted for this tag")
    source_sha = transaction["source_sha"]
    preparation_transaction = directory / "selfhost-preparation-transaction.json"
    prepared_claim = validate_claim(json.loads(preparation_transaction.read_text(encoding="utf-8")))
    if (prepared_claim["repository"] != transaction["repository"]
            or prepared_claim["version"] != transaction["version"]
            or prepared_claim["source_sha"] != source_sha
            or prepared_claim["transaction_id"] != transaction["transaction_id"]
            or prepared_claim["state"] not in {"qualified", "promoting", "promoted"}):
        raise ValueError("self-host preparation belongs to another release transaction")
    receipt_path = directory / "selfhost-bundle-preparation.json"
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    run_id = receipt_data.get("run_id")
    if not isinstance(run_id, str) or not run_id.isdecimal():
        raise ValueError("self-host preparation run ID is invalid")
    archive = directory / "selfhost-bundle.zip"
    lock = directory / "selfhost-images.json"
    receipt = verify_receipt(archive, lock, preparation_transaction, receipt_path,
                             source_sha, run_id)
    verify_descriptor(archive, lock, preparation_transaction, receipt_path,
                      directory / "prepared-selfhost-product-descriptor.json")
    descriptor = json.loads((directory / "selfhost-product-descriptor.json").read_text(encoding="utf-8"))
    validate_manifest(descriptor, json.loads(SCHEMA.read_text(encoding="utf-8")))
    if descriptor["qualification"]["state"] != "qualified":
        raise ValueError("self-host descriptor is not qualified for customer handoff")
    if (descriptor["product"] != "organizational-platform"
            or descriptor["source"]["commit"] != source_sha
            or descriptor["artifact"]["digest"] != "sha256:" + receipt["archive_sha256"]):
        raise ValueError("qualified descriptor differs from the prepared release")
    expected_preparation = {
        "run_id": run_id,
        "receipt_sha256": "sha256:" + file_digest(receipt_path),
        "image_lock_sha256": "sha256:" + receipt["image_lock_sha256"],
        "transaction_sha256": "sha256:" + receipt["transaction_sha256"],
    }
    if descriptor.get("preparation") != expected_preparation:
        raise ValueError("qualified descriptor omits the exact preparation lineage")
    expected_evidence_url = (
        f"https://github.com/ElevenID/marty-ui/releases/download/{tag}/selfhost-qualification.json"
    )
    if expected_evidence_url not in descriptor["qualification"]["evidence"]:
        raise ValueError("qualified descriptor omits public journey evidence")
    evidence = json.loads((directory / "selfhost-qualification.json").read_text(encoding="utf-8"))
    if (not isinstance(evidence, dict)
            or evidence.get("source_sha") != source_sha
            or evidence.get("archive_sha256") != receipt["archive_sha256"]
            or evidence.get("image_lock_sha256") != receipt["image_lock_sha256"]
            or evidence.get("transaction_sha256") != receipt["transaction_sha256"]
            or evidence.get("run_id") != run_id
            or evidence.get("integration_revision") != PINNED_INTEGRATION_SHA
            or evidence.get("qualification") != "qualified"):
        raise ValueError("installed qualification evidence does not bind the exact release")
    steps = evidence.get("steps")
    if (not isinstance(steps, dict) or set(steps) != JOURNEY_STEPS
            or any(not isinstance(value, dict)
                   or set(value) != {"status", "evidence_sha256"}
                   or value["status"] != "passed"
                   or SHA.fullmatch(str(value["evidence_sha256"])) is None
                   for value in steps.values())):
        raise ValueError("installed qualification lacks complete passing business journey")
    return {"schema": "marty.selfhost-release-handoff-audit/v1", "tag": tag,
            "source_sha": source_sha, "archive_sha256": receipt["archive_sha256"],
            "asset_closure": "present-and-checksummed",
            "qualification_metadata": "present-and-bound",
            "signature_verification": "not-performed",
            "runtime_replay": "not-performed"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        result = audit(args.release_dir, args.tag)
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"self-host handoff audit failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
