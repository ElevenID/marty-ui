"""Thin CLI adapter for the source-matched Rust beta runtime stager."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from selfhost_native_operator import operator_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        output = operator_bytes(root, "operator", "beta-runtime-config", str(root), args.source_revision)
    except (OSError, RuntimeError) as error:
        raise SystemExit("Rust beta runtime configuration staging failed; preserve any incomplete generation for inspection") from error
    # Windows PowerShell 5 decodes native stdout using the console code page.
    # ASCII JSON preserves Unicode paths through that boundary.
    sys.stdout.write(json.dumps(json.loads(output), ensure_ascii=True))


if __name__ == "__main__":
    main()
