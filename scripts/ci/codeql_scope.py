#!/usr/bin/env python3
"""Read a complete exact-tree Git diff for CodeQL; API file limits cannot skip inputs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from affected_components import identity, website_only


def parse_diff(raw: bytes):
    if not raw:
        return []
    if not raw.endswith(b"\0"):
        raise ValueError("unterminated Git diff")
    pieces = raw[:-1].split(b"\0")
    if len(pieces) % 2:
        raise ValueError("incomplete Git diff")
    files = []
    seen = set()
    for status, path in zip(pieces[::2], pieces[1::2], strict=True):
        name = path.decode("utf-8", "strict")
        if status not in {b"M", b"A", b"D", b"T"} or not name or name in seen:
            raise ValueError("unknown status, empty or duplicate diff path")
        seen.add(name)
        files.append({"filename": name, "status": "modified" if status == b"M" else "changed"})
    return files


def main():
    binding = identity(os.environ)
    head = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], text=True).strip()
    if head != binding["source_sha"]:
        raise ValueError("CodeQL checkout differs from event source")
    files = []
    if binding["event"] in {"pull_request", "merge_group"}:
        subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", binding["base_sha"]], check=True)
        raw = subprocess.check_output(["git", "diff", "--name-status", "-z", "--no-renames", binding["base_sha"], "HEAD"])
        files = parse_diff(raw)
    paths = b"".join(item["filename"].encode("utf-8") + b"\0" for item in files)
    scope = {**binding, "files": files, "website_only": website_only(Path.cwd(), paths)}
    Path(os.environ["CODEQL_SCOPE_FILE"]).write_text(json.dumps(scope))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"CodeQL scope rejected: {exc}", file=sys.stderr)
        sys.exit(1)
