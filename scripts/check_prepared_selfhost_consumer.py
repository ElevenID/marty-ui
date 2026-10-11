#!/usr/bin/env python3
"""Fail-closed consumer preflight for an unqualified prepared self-host ZIP.

This checks an artifact downloaded across a job boundary. It is not an
installed-runtime qualification or permission to publish the ZIP.
"""

import argparse
import json
from pathlib import Path

from produce_selfhost_product_descriptor import produce
from record_selfhost_bundle_preparation import record


def verify_receipt(archive: Path, lock: Path, transaction: Path, receipt_path: Path,
                   source_sha: str | None = None, run_id: str | None = None) -> dict:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("schema") != "marty.selfhost-bundle-preparation/v1" or receipt.get("qualification") != "unqualified":
        raise ValueError("expected an unqualified preparation receipt")
    if ((source_sha is not None and receipt.get("source_sha") != source_sha)
            or (run_id is not None and receipt.get("run_id") != run_id)):
        raise ValueError("preparation receipt belongs to another source or run")
    expected = record(archive, lock, transaction, receipt["source_sha"], receipt["run_id"])
    if receipt != expected:
        raise ValueError("prepared ZIP, image lock, transaction, or receipt changed")
    return expected


def verify_descriptor(archive: Path, lock: Path, transaction: Path,
                      receipt_path: Path, descriptor_path: Path) -> None:
    actual = json.loads(descriptor_path.read_text(encoding="utf-8"))
    expected = produce(archive, lock, transaction, receipt_path)
    if actual != expected:
        raise ValueError("prepared product descriptor differs from exact inputs")


def check(archive: Path, lock: Path, transaction: Path, receipt_path: Path,
          compose_model: Path, source_checkout: Path, source_sha: str | None = None,
          run_id: str | None = None) -> dict:
    expected = verify_receipt(archive, lock, transaction, receipt_path, source_sha, run_id)
    receipt = expected

    model = json.loads(compose_model.read_text(encoding="utf-8"))
    services = model.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("installed Compose model has no services")
    if set(services) != set(expected["images"]):
        raise ValueError("installed Compose service closure differs from ZIP")
    checkout = source_checkout.resolve()

    def reject_checkout_source(source: object, label: str) -> None:
        if not isinstance(source, str) or not Path(source).is_absolute():
            raise ValueError(f"{label} has an unresolved host source")
        path = Path(source).resolve()
        if path == checkout or checkout in path.parents:
            raise ValueError(f"{label} mounts the source checkout")

    for name, service in services.items():
        if not isinstance(service, dict) or "build" in service:
            raise ValueError(f"installed service {name} has a source build")
        if service.get("image") != expected["images"][name]:
            raise ValueError(f"installed service {name} has an unlocked image")
        for volume in service.get("volumes", []):
            if not isinstance(volume, dict):
                raise TypeError(f"installed service {name} has an unparsed volume")
            if volume.get("type") != "bind":
                continue
            reject_checkout_source(volume.get("source"), f"installed service {name}")
    for kind in ("secrets", "configs"):
        entries = model.get(kind, {})
        if not isinstance(entries, dict):
            raise TypeError(f"installed Compose {kind} are invalid")
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                raise TypeError(f"installed Compose {kind}.{name} is invalid")
            if "file" in entry:
                reject_checkout_source(entry["file"], f"installed Compose {kind}.{name}")
    return {"schema": "marty.selfhost-consumer-preflight/v1",
            "qualification": "unqualified", "archive_sha256": receipt["archive_sha256"],
            "source_sha": receipt["source_sha"], "run_id": receipt["run_id"],
            "service_count": len(services)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-run-id", required=True)
    for name in ("compose-model", "source-checkout", "output"):
        parser.add_argument(f"--{name}")
    parser.add_argument("--verify-archive-only", action="store_true")
    args = parser.parse_args()
    verify_descriptor(Path(args.archive), Path(args.image_lock), Path(args.transaction),
                      Path(args.receipt), Path(args.descriptor))
    if args.verify_archive_only:
        verify_receipt(Path(args.archive), Path(args.image_lock),
                       Path(args.transaction), Path(args.receipt),
                       args.expected_source_sha, args.expected_run_id)
        return
    if not all((args.compose_model, args.source_checkout, args.output)):
        parser.error("compose-model, source-checkout, and output are required for full preflight")
    result = check(Path(args.archive), Path(args.image_lock), Path(args.transaction),
                   Path(args.receipt), Path(args.compose_model), Path(args.source_checkout),
                   args.expected_source_sha, args.expected_run_id)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
