#!/usr/bin/env python3
"""Record an unqualified, exact ZIP/image-lock handoff for later install testing."""

import argparse
import hashlib
import json
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import yaml


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(archive: Path, lock_path: Path, transaction: Path, source_sha: str, run_id: str) -> dict:
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise ValueError("source SHA must be a full lowercase Git commit")
    if not run_id.isdecimal():
        raise ValueError("run ID must be numeric")
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    if lock.get("schema") != "marty.selfhost-image-lock/v1":
        raise ValueError("unsupported image lock")
    transaction_bytes = transaction.read_bytes()
    with zipfile.ZipFile(archive) as bundle, tempfile.TemporaryDirectory(prefix="selfhost-fresh-") as scratch:
        files = {}
        directories = set()
        roots = set()
        extracted = Path(scratch)
        total_size = 0
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            if (path.is_absolute() or "\\" in member.filename or ":" in member.filename
                    or any(part in (".", "..", "") for part in member.filename.rstrip("/").split("/"))):
                raise ValueError("unsafe ZIP member")
            roots.add(path.parts[0])
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in ((0, stat.S_IFDIR) if member.is_dir() else (0, stat.S_IFREG)):
                raise ValueError("special ZIP member")
            target = extracted.joinpath(*path.parts)
            if member.is_dir():
                if member.filename in directories:
                    raise ValueError("duplicate ZIP directory")
                directories.add(member.filename)
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.filename in files:
                raise ValueError("duplicate ZIP member")
            total_size += member.file_size
            if member.file_size > 64 * 1024 * 1024 or total_size > 256 * 1024 * 1024:
                raise ValueError("ZIP member or bundle exceeds extraction limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))
            files[member.filename] = target.read_bytes()
        if len(roots) != 1:
            raise ValueError("ZIP must have one bundle root")
        root = next(iter(roots))
        embedded_lock = (extracted / root / ".marty-selfhost-images.json").read_bytes()
        if embedded_lock != lock_bytes:
            raise ValueError("embedded image lock differs from prepared lock")
        marker = json.loads((extracted / root / ".marty-selfhost-bundle.json").read_bytes())
        if marker.get("schema") != "marty.selfhost-bundle-files/v1":
            raise ValueError("unsupported bundle inventory")
        expected_directories = {f"{root}/{name}/" if name else f"{root}/"
                                for name in marker["directories"]}
        if directories != expected_directories:
            raise ValueError("ZIP directories differ from owned bundle")
        expected = {f"{root}/{name}": value for name, value in marker["files"].items()}
        actual = {name: digest(data) for name, data in files.items()
                  if name != f"{root}/.marty-selfhost-bundle.json"}
        if actual != expected:
            raise ValueError("ZIP inventory differs from owned bundle")
        compose = yaml.safe_load((extracted / root / "docker-compose.yml").read_bytes())
        images = {name: service.get("image") for name, service in compose["services"].items()
                  if "image" in service}
        if images != lock["services"]:
            raise ValueError("ZIP Compose image closure differs from lock")
    return {
        "schema": "marty.selfhost-bundle-preparation/v1",
        "qualification": "unqualified",
        "source_sha": source_sha,
        "run_id": run_id,
        "release": lock["release"],
        "archive_sha256": digest(archive.read_bytes()),
        "image_lock_sha256": digest(lock_bytes),
        "transaction_sha256": digest(transaction_bytes),
        "images": images,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "source-sha", "run-id", "output"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    result = record(Path(args.archive), Path(args.image_lock), Path(args.transaction),
                    args.source_sha, args.run_id)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
