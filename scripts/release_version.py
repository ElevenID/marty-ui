#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FORBIDDEN_TAGS = {"latest", "prod", "main", "dev"}
RELEASE_TAG_PATTERN = re.compile(r"^(?P<year>\d{4})\.(?P<month>0[1-9]|1[0-2])\.(?P<patch>\d+)(?:-rc\.(?P<rc>\d+))?$")


class ReleaseVersionError(ValueError):
    pass


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_version_file(repo_root: Path) -> Path:
    return repo_root / "VERSION"


def normalize_version_file_path(repo_root: Path, version_file: Path | None) -> Path:
    if version_file is None:
        return default_version_file(repo_root)
    if version_file.is_absolute():
        return version_file
    return (repo_root / version_file).resolve()


def read_version_file(version_file: Path) -> str:
    try:
        raw_text = version_file.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ReleaseVersionError(
            f"Release version file not found: {version_file}. Pass --tag explicitly or create VERSION."
        ) from exc

    values = [
        line.strip()
        for line in raw_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not values:
        raise ReleaseVersionError(
            f"Release version file is empty: {version_file}. Put a release tag like 2026.05.0 in VERSION."
        )
    if len(values) != 1:
        raise ReleaseVersionError(
            f"Release version file must contain exactly one non-comment value: {version_file}"
        )
    return values[0]


def validate_release_tag(tag: str) -> str:
    normalized = tag.strip()
    if not normalized:
        raise ReleaseVersionError("Release tag is empty. Use a tag like 2026.05.0.")

    lowered = normalized.lower()
    if lowered in FORBIDDEN_TAGS:
        forbidden = ", ".join(sorted(FORBIDDEN_TAGS))
        raise ReleaseVersionError(
            f"Release tag '{normalized}' is not allowed. Reserved mutable tags: {forbidden}."
        )

    if not RELEASE_TAG_PATTERN.fullmatch(normalized):
        raise ReleaseVersionError(
            f"Release tag '{normalized}' is invalid. Expected YYYY.MM.PATCH or YYYY.MM.PATCH-rc.N."
        )

    return normalized


def resolve_release_tag(repo_root: Path, tag: str | None = None, version_file: Path | None = None) -> str:
    candidate = tag.strip() if tag else ""
    if not candidate:
        candidate = read_version_file(normalize_version_file_path(repo_root, version_file))
    return validate_release_tag(candidate)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve and validate Marty self-host release versions.")
    parser.add_argument(
        "command",
        choices=["resolve", "validate"],
        help="Resolve a release tag from --tag or VERSION, or validate the supplied tag.",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Release tag to validate. If omitted, falls back to the VERSION file.",
    )
    parser.add_argument(
        "--repo-root",
        default=str(default_repo_root()),
        help="Repository root containing VERSION. Defaults to this script's repo.",
    )
    parser.add_argument(
        "--version-file",
        default="",
        help="Optional VERSION file path. Relative paths are resolved from --repo-root.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    version_file = Path(args.version_file).expanduser() if args.version_file else None

    if args.command == "resolve":
        print(resolve_release_tag(repo_root=repo_root, tag=args.tag, version_file=version_file))
        return 0

    print(validate_release_tag(resolve_release_tag(repo_root=repo_root, tag=args.tag, version_file=version_file)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseVersionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
