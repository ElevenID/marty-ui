#!/usr/bin/env python3
"""Fail-closed consumer preflight for an unqualified prepared self-host ZIP.

This checks an artifact downloaded across a job boundary. It is not an
installed-runtime qualification or permission to publish the ZIP.
"""

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path
from typing import BinaryIO

from produce_selfhost_product_descriptor import produce
from record_selfhost_bundle_preparation import record


def stream_digest(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_extracted_bundle(archive: Path, install_root: Path) -> None:
    """Bind the rendered installation tree to the already-validated ZIP bytes."""
    if install_root.is_symlink() or not install_root.is_dir():
        raise ValueError("installed ZIP root is missing or not a directory")
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        bundle_root = members[0].filename.split("/", 1)[0]
        if install_root.name != bundle_root:
            raise ValueError("installed ZIP root name differs from archive")
        expected = {}
        for member in members:
            if member.filename.rstrip("/") == bundle_root:
                continue
            relative = member.filename[len(bundle_root) + 1:].rstrip("/")
            if member.is_dir():
                expected[relative] = ("directory", 0, "")
            else:
                with bundle.open(member) as source:
                    expected[relative] = ("file", member.file_size, stream_digest(source))
    seen = set()
    for path in install_root.rglob("*"):
        metadata = path.lstat()
        mode = metadata.st_mode
        relative = path.relative_to(install_root).as_posix()
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("installed ZIP contains a symlink or special file")
        if relative not in expected:
            raise ValueError("installed ZIP tree differs from archive")
        kind, size, digest = expected[relative]
        if stat.S_ISDIR(mode):
            if kind != "directory":
                raise ValueError("installed ZIP tree differs from archive")
        elif kind != "file" or metadata.st_size != size:
            raise ValueError("installed ZIP tree differs from archive")
        else:
            with path.open("rb") as source:
                if stream_digest(source) != digest:
                    raise ValueError("installed ZIP tree differs from archive")
        seen.add(relative)
    if seen != expected.keys():
        raise ValueError("installed ZIP tree differs from archive")


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
          run_id: str | None = None, install_root: Path | None = None,
          state_root: Path | None = None, secret_root: Path | None = None) -> dict:
    expected = verify_receipt(archive, lock, transaction, receipt_path, source_sha, run_id)
    receipt = expected

    model = json.loads(compose_model.read_text(encoding="utf-8"))
    services = model.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("installed Compose model has no services")
    if set(services) != set(expected["images"]):
        raise ValueError("installed Compose service closure differs from ZIP")
    checkout = source_checkout.resolve()
    roots = (install_root, state_root, secret_root)
    if any(root is not None for root in roots) and not all(root is not None for root in roots):
        raise ValueError("install, state and secret roots must be supplied together")
    confined = all(root is not None for root in roots)
    if confined:
        if install_root.is_symlink():
            raise ValueError("installed ZIP root is a symlink")
        installed, state, secrets = (root.resolve() for root in roots)
        for label, root in (("install", installed), ("state", state), ("secret", secrets)):
            if root == checkout or checkout in root.parents or root in checkout.parents:
                raise ValueError(f"{label} root overlaps source checkout")
        if len({installed, state, secrets}) != 3 or any(
            left in right.parents or right in left.parents
            for left, right in ((installed, state), (installed, secrets), (state, secrets))
        ):
            raise ValueError("install, state and secret roots overlap")
        if not installed.is_dir():
            raise ValueError("installed ZIP root is missing")
        verify_extracted_bundle(archive, installed)

    def within(path: Path, root: Path) -> bool:
        return path == root or root in path.parents

    def reject_checkout_source(source: object, label: str, allowed: tuple[Path, ...] = ()) -> None:
        if not isinstance(source, str) or not Path(source).is_absolute():
            raise ValueError(f"{label} has an unresolved host source")
        path = Path(source).resolve()
        if path == checkout or checkout in path.parents:
            raise ValueError(f"{label} mounts the source checkout")
        if confined and not any(within(path, root) for root in allowed):
            raise ValueError(f"{label} mounts outside the isolated installation")

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
            reject_checkout_source(volume.get("source"), f"installed service {name}",
                                   (installed, state) if confined else ())
            if (confined and within(Path(volume["source"]).resolve(), installed)
                    and (not Path(volume["source"]).exists() or not volume.get("read_only"))):
                raise ValueError(f"installed service {name} has a missing or writable bundle mount")
    for kind in ("secrets", "configs"):
        entries = model.get(kind, {})
        if not isinstance(entries, dict):
            raise TypeError(f"installed Compose {kind} are invalid")
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                raise TypeError(f"installed Compose {kind}.{name} is invalid")
            if "file" in entry:
                allowed = ((secrets,) if kind == "secrets" else (installed, secrets)) if confined else ()
                reject_checkout_source(entry["file"], f"installed Compose {kind}.{name}", allowed)
                if (confined and within(Path(entry["file"]).resolve(), installed)
                        and not Path(entry["file"]).is_file()):
                    raise ValueError(f"installed Compose {kind}.{name} has a missing bundle file")
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
    for name in ("install-root", "state-root", "secret-root"):
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
    if not all((args.compose_model, args.source_checkout, args.output,
                args.install_root, args.state_root, args.secret_root)):
        parser.error("compose-model, source-checkout, output, and isolated roots are required for full preflight")
    result = check(Path(args.archive), Path(args.image_lock), Path(args.transaction),
                   Path(args.receipt), Path(args.compose_model), Path(args.source_checkout),
                   args.expected_source_sha, args.expected_run_id,
                   install_root=Path(args.install_root) if args.install_root else None,
                   state_root=Path(args.state_root) if args.state_root else None,
                   secret_root=Path(args.secret_root) if args.secret_root else None)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
