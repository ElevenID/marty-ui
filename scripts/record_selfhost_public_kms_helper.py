"""Record the already-exercised release KMS public-key helper for later admission.

This is a producer receipt, not evidence of reproducible compilation or a
general Linux ABI promise. Consumers must verify its same-run attestation and
their own runtime compatibility before replacing the source-build path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import struct
from pathlib import Path

SCHEMA = "marty.selfhost-public-kms-helper/v1"
MAX_SIZE = 64 * 1024 * 1024


def record(binary: Path, source_sha: str, run_id: str) -> dict:
    if (
        re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or re.fullmatch(r"[1-9][0-9]*", run_id) is None
    ):
        raise ValueError("helper source or run identity is invalid")
    os_release = platform.freedesktop_os_release()
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or os_release.get("ID") != "ubuntu"
        or os_release.get("VERSION_ID") != "24.04"
    ):
        raise ValueError("helper producer is not the pinned Linux amd64 baseline")
    if binary.name != "public-kms-jwk" or binary.is_symlink() or not binary.is_file():
        raise ValueError("helper must be an ordinary file")
    metadata = binary.stat()
    if not stat.S_ISREG(metadata.st_mode) or not 64 <= metadata.st_size <= MAX_SIZE:
        raise ValueError("helper size or file type is invalid")
    digest = hashlib.sha256()
    with binary.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ValueError("helper changed before hashing")
        header = source.read(64)
        if (
            header[:4] != b"\x7fELF"
            or header[4:6] != b"\x02\x01"
            or struct.unpack_from("<H", header, 16)[0] not in (2, 3)
            or struct.unpack_from("<H", header, 18)[0] != 62
        ):
            raise ValueError("helper is not an amd64 ELF executable")
        digest.update(header)
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
        finished = os.fstat(source.fileno())
    if (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) or binary.stat().st_size != metadata.st_size:
        raise ValueError("helper changed while hashing")
    return {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "run_id": run_id,
        "platform": "linux-amd64-ubuntu-24.04",
        "binary": "public-kms-jwk",
        "sha256": digest.hexdigest(),
        "size": metadata.st_size,
        "qualification": "producer-only-unqualified",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = record(args.binary, args.source_sha, args.run_id)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
