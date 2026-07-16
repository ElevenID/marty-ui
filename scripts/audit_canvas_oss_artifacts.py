#!/usr/bin/env python3
"""Reject high-risk browser/session captures from Canvas portability artifacts."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


FORBIDDEN_NAMES = re.compile(r"(\.har$|storage|cookie|session-state|trace\.zip|token|raw-claims)", re.IGNORECASE)
FORBIDDEN_TEXT = re.compile(
    r'(?i)('
    r'"(?:access_token|refresh_token|id_token|session_token|token|authorization|cookie|client_secret|api_key|password|private_key|d|p|q|dp|dq|qi)"\s*:'
    r'|bearer\s+[a-z0-9._~-]{12,}'
    r'|eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}'
    r')'
)
TEXT_EXTENSIONS = {".json", ".xml", ".html", ".css", ".js", ".txt", ".md"}


def audit_artifacts(artifact_root: Path) -> list[str]:
    failures: list[str] = []
    for path in artifact_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(artifact_root).as_posix()
        if FORBIDDEN_NAMES.search(relative):
            failures.append(f"forbidden artifact name: {relative}")
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS:
            text = path.read_text(encoding="utf-8", errors="replace")
            if FORBIDDEN_TEXT.search(text):
                failures.append(f"possible credential/session material: {relative}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    args = parser.parse_args()
    failures = audit_artifacts(args.artifact_root)
    if failures:
        print("Canvas OSS artifact audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Canvas OSS artifact bundle contains no forbidden capture types or token fields.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
