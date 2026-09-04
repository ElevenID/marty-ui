#!/usr/bin/env python3
"""Extract one digest-verified release source archive without trusting its paths."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 5_000
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ROOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class SourceArchiveError(ValueError):
    """The release source archive is unsafe or does not match its pin."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceArchiveError(message)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _copy_exact(source: BinaryIO, target: Path, expected_size: int) -> None:
    copied = 0
    with target.open("xb") as output:
        while copied < expected_size:
            chunk = source.read(min(1024 * 1024, expected_size - copied))
            _require(bool(chunk), "archive member ended before its declared size")
            output.write(chunk)
            copied += len(chunk)
        _require(source.read(1) == b"", "archive member exceeds its declared size")


def extract_verified_source(
    archive_path: Path,
    destination: Path,
    *,
    expected_root: str,
    expected_sha256: str,
) -> None:
    """Verify and stream-extract a regular-file-only, single-root tar.gz archive."""

    _require(SAFE_ROOT.fullmatch(expected_root) is not None, "expected root is invalid")
    _require(SHA256.fullmatch(expected_sha256) is not None, "expected digest is invalid")
    _require(archive_path.is_file(), "source archive is missing")
    archive_size = archive_path.stat().st_size
    _require(0 < archive_size <= MAX_ARCHIVE_BYTES, "source archive size is invalid")
    _require(_digest(archive_path) == expected_sha256, "source archive digest changed")
    _require(not destination.exists(), "source destination already exists")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="marty-release-source-", dir=destination.parent
    ) as temporary:
        temporary_path = Path(temporary)
        seen: set[str] = set()
        member_count = 0
        expanded_bytes = 0
        regular_files = 0
        try:
            with tarfile.open(archive_path, mode="r|gz") as archive:
                for member in archive:
                    member_count += 1
                    _require(member_count <= MAX_MEMBERS, "source archive has too many members")
                    name = member.name
                    _require("\\" not in name and "\x00" not in name, "archive path is invalid")
                    path = PurePosixPath(name)
                    parts = path.parts
                    _require(
                        bool(parts)
                        and not path.is_absolute()
                        and all(part not in {"", ".", ".."} for part in parts),
                        "archive path is unsafe",
                    )
                    _require(parts[0] == expected_root, "archive root changed")
                    normalized = path.as_posix()
                    _require(normalized not in seen, "archive path is duplicated")
                    seen.add(normalized)
                    _require(
                        member.isdir() or member.isreg(),
                        "archive contains a non-file member",
                    )
                    _require(0 <= member.size <= MAX_FILE_BYTES, "archive member is too large")
                    expanded_bytes += member.size
                    _require(
                        expanded_bytes <= MAX_EXPANDED_BYTES,
                        "source archive expands beyond its limit",
                    )

                    target = temporary_path.joinpath(*parts)
                    if member.isdir():
                        _require(not target.is_file(), "archive directory conflicts with a file")
                        target.mkdir(parents=True, exist_ok=True, mode=0o755)
                        continue

                    target.parent.mkdir(parents=True, exist_ok=True)
                    _require(not target.exists(), "archive file conflicts with another member")
                    source = archive.extractfile(member)
                    _require(source is not None, "archive file cannot be read")
                    with source:
                        _copy_exact(source, target, member.size)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
                    regular_files += 1
        except (OSError, tarfile.TarError) as exc:
            raise SourceArchiveError("source archive cannot be read") from exc

        extracted_root = temporary_path / expected_root
        _require(regular_files > 0, "source archive contains no files")
        _require(extracted_root.is_dir(), "source archive root is missing")
        os.replace(extracted_root, destination)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--expected-root", required=True)
    parser.add_argument("--expected-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        extract_verified_source(
            args.archive,
            args.destination,
            expected_root=args.expected_root,
            expected_sha256=args.expected_sha256,
        )
    except SourceArchiveError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
