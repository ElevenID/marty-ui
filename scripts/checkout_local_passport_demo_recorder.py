#!/usr/bin/env python3
"""Check out reviewed recorder code from the beta runner's local Git cache."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


REPOSITORY = "https://github.com/ElevenID/marty-demo-recorder.git"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-tip", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()

    if not COMMIT.fullmatch(args.source_tip) or not COMMIT.fullmatch(args.revision):
        parser.error("source tip and revision must be full lowercase Git commits")
    if not args.source.is_absolute() or not args.destination.is_absolute():
        parser.error("source and destination must be absolute paths")
    source = args.source.resolve(strict=True)
    destination = args.destination
    if not source.is_dir() or destination.exists() or destination.is_symlink():
        parser.error("source must be a directory and destination must not exist")
    if Path(git("-C", str(source), "rev-parse", "--show-toplevel")).resolve() != source:
        parser.error("source must be the recorder repository root")
    if git("-C", str(source), "remote", "get-url", "origin") != REPOSITORY:
        parser.error("source is not the reviewed recorder repository")
    if git("-C", str(source), "symbolic-ref", "--short", "HEAD") != "main":
        parser.error("source must be on main")
    for ref in ("HEAD", "refs/remotes/origin/main"):
        if git("-C", str(source), "rev-parse", ref) != args.source_tip:
            parser.error(f"source {ref} does not match reviewed tip")
    subprocess.run(
        ["git", "-C", str(source), "merge-base", "--is-ancestor", args.revision, args.source_tip],
        check=True,
    )
    if not destination.parent.is_dir():
        parser.error("destination parent must exist")
    subprocess.run(
        ["git", "clone", "--no-hardlinks", "--no-checkout", str(source), str(destination)],
        check=True,
    )
    subprocess.run(["git", "-C", str(destination), "checkout", "--detach", args.revision], check=True)
    if git("-C", str(destination), "rev-parse", "HEAD") != args.revision:
        parser.error("checkout does not match reviewed revision")
    if git("-C", str(destination), "status", "--porcelain"):
        parser.error("reviewed checkout is dirty")
    print(destination)


if __name__ == "__main__":
    main()
