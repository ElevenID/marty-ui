#!/usr/bin/env python3
"""Stage an exact self-host preview ZIP and disposable credentials, unqualified."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from check_prepared_selfhost_consumer import (
    verify_descriptor,
    verify_extracted_bundle,
    verify_receipt,
)
from generate_selfhost_disposable_credentials import generate
from record_selfhost_bundle_preparation import extract_owned_zip, file_digest


ASSETS = frozenset({
    "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json",
    "prepared-selfhost-bundle.json", "prepared-selfhost-product-descriptor.json",
    "selfhost-preparation-transaction.json", "SELFHOST-PREVIEW-README.md",
})
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def trusted_parent(parent: Path) -> None:
    """Exclude local-user swaps during owned partial-tree cleanup."""
    if parent.is_symlink() or parent.resolve() != parent:
        raise ValueError("private root parent must have a canonical path")
    owner = os.getuid()
    state = parent.stat()
    if (state.st_uid != owner or stat.S_IMODE(state.st_mode) & 0o022
            or stat.S_IMODE(state.st_mode) & 0o300 != 0o300):
        raise ValueError("private root parent must be operator-owned and private")
    for ancestor in (parent, *parent.parents):
        state = ancestor.lstat()
        mode = stat.S_IMODE(state.st_mode)
        if not stat.S_ISDIR(state.st_mode):
            raise ValueError("private root path has a linked or non-directory ancestor")
        if (mode & 0o022 and not (mode & stat.S_ISVTX and state.st_uid in {0, owner})):
            raise ValueError("private root path has an unsafe writable ancestor")


def verify_checksums(assets: Path) -> None:
    sums = assets / "SHA256SUMS"
    if sums.is_symlink() or not sums.is_file() or sums.stat().st_size > 8192:
        raise ValueError("preview checksum inventory is absent or invalid")
    listed: dict[str, str] = {}
    for line in sums.read_text(encoding="ascii").splitlines():
        digest, separator, name = line.partition("  ")
        if (separator != "  " or not SHA256.fullmatch(digest)
                or name not in ASSETS or name in listed):
            raise ValueError("preview checksum inventory has an invalid entry")
        listed[name] = digest
    if set(listed) != ASSETS:
        raise ValueError("preview checksum inventory is incomplete")
    for name, digest in listed.items():
        target = assets / name
        if target.is_symlink() or not target.is_file() or file_digest(target) != digest:
            raise ValueError("preview asset checksum differs from inventory")


def clean_source_sha(source: Path) -> str:
    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise ValueError("source checkout is invalid")
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    status = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                            capture_output=True, text=True, timeout=20, check=True).stdout
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or status:
        raise ValueError("source checkout is not clean or pinned")
    return revision


def stage(assets: Path, source: Path, private_root: Path) -> dict:
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("disposable staging requires a non-root Linux operator")
    if (not assets.is_absolute() or assets.is_symlink() or not assets.is_dir()
            or not private_root.is_absolute() or private_root.is_symlink()
            or private_root.exists() or not private_root.parent.is_dir()):
        raise ValueError("preview asset or fresh private root is invalid")
    trusted_parent(private_root.parent)
    source = source.resolve()
    assets = assets.resolve()
    target = private_root.resolve()
    if (source == assets or source in assets.parents or assets in source.parents
            or any(root == target or root in target.parents or target in root.parents
                   for root in (source, assets))):
        raise ValueError("preview staging paths overlap")
    verify_checksums(assets)
    archive = assets / "prepared-selfhost-bundle.zip"
    lock = assets / "prepared-selfhost-images.json"
    transaction = assets / "selfhost-preparation-transaction.json"
    receipt = assets / "prepared-selfhost-bundle.json"
    descriptor = assets / "prepared-selfhost-product-descriptor.json"
    source_sha = clean_source_sha(source)
    verify_descriptor(archive, lock, transaction, receipt, descriptor)
    bound = verify_receipt(archive, lock, transaction, receipt, source_sha)
    private_root.mkdir(mode=0o700)
    owned = private_root.lstat()
    try:
        if stat.S_IMODE(owned.st_mode) != 0o700:
            raise ValueError("private root does not have owner-only permissions")
        install_parent = private_root / "install"
        install_parent.mkdir(mode=0o700)
        for name in ("state", "secrets", "openbao-state"):
            (private_root / name).mkdir(mode=0o700)
        with zipfile.ZipFile(archive) as bundle:
            root_name, _, _ = extract_owned_zip(bundle, install_parent)
        install_root = install_parent / root_name
        verify_extracted_bundle(archive, install_root)
        if file_digest(archive) != bound["archive_sha256"]:
            raise ValueError("preview ZIP changed during staging")
        generate(private_root / "secrets")
        report = {
            "schema": "marty.selfhost-disposable-stage/v1",
            "qualification": "unqualified",
            "source_sha": source_sha,
            "run_id": bound["run_id"],
            "archive_sha256": bound["archive_sha256"],
            "image_lock_sha256": bound["image_lock_sha256"],
            "install_root": str(install_root),
            "next_step": "provision disposable OpenBao and run installed journey",
        }
        with (private_root / "stage.json").open("x", encoding="utf-8") as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write("\n")
        return report
    except BaseException:
        current = private_root.lstat()
        if (not stat.S_ISDIR(current.st_mode) or
                (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino)):
            raise RuntimeError("private staging root changed; manual recovery required") from None
        shutil.rmtree(private_root)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--source-checkout", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = stage(args.assets_dir, args.source_checkout, args.private_root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"disposable preview staging failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"Staged unqualified preview from run {report['run_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
