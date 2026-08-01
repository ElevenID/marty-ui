#!/usr/bin/env python3
"""Verify generated clients belong to the exact pinned Marty-Protocol source."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def assert_generated_bindings_current(protocol_root: Path) -> None:
    """Regenerate all bindings disposably and reject any checked-in drift."""

    generator = protocol_root / "scripts" / "codegen.py"
    if not generator.is_file():
        raise AssertionError(
            "pinned marty-protocol is missing scripts/codegen.py; cannot verify "
            "the Python, Rust, and TypeScript bindings"
        )

    completed = subprocess.run(
        [sys.executable, str(generator), "--check"],
        cwd=protocol_root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        output = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr)
            if part.strip()
        )
        raise AssertionError(
            "pinned marty-protocol generated bindings are stale; public clients "
            "must be regenerated from the exact reviewed schema commit"
            + (f":\n{output}" if output else "")
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-root", type=Path, required=True)
    args = parser.parse_args()
    assert_generated_bindings_current(args.protocol_root.resolve())
    print("Pinned Marty-Protocol Python, Rust, and TypeScript bindings are current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
