#!/usr/bin/env python3
"""Create a sanitized, fixed-allowlist upload directory.

Raw driver output is never uploaded. Visual/browser reports are copied only
after a full canonical pass and after the entire raw tree passes token/session
scanning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

try:
    from scripts.audit_canvas_oss_artifacts import audit_artifacts
except ModuleNotFoundError:  # direct `python scripts/...` execution
    from audit_canvas_oss_artifacts import audit_artifacts


FIXED_FILES = (
    "bootstrap-audit.json",
    "fresh-state-audit.json",
    "runtime-context.json",
    "runtime-context-after.json",
    "beta-continuity.json",
    "beta-host-state.json",
    "beta-capability-preflight.json",
    "runner-preflight.json",
    "contract-driver-manifest.json",
    "observations.json",
    "portable-attestation.json",
    "junit.xml",
    "image/canvas-oss-image-manifest.json",
)


def copy_file(source_root: Path, output_root: Path, relative: str) -> bool:
    source = source_root / relative
    if not source.is_file():
        return False
    destination = output_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.source.is_dir():
        print("Canvas OSS raw artifact directory is missing", file=sys.stderr)
        return 1
    failures = audit_artifacts(args.source)
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print("Refusing to stage any Canvas OSS artifacts from an unsafe raw tree", file=sys.stderr)
        return 1
    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)
    copied = [relative for relative in FIXED_FILES if copy_file(args.source, args.output, relative)]

    canonical_path = args.source / "portable-attestation.json"
    full_pass = False
    if canonical_path.is_file():
        canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
        full_pass = canonical.get("status") == "passed" and canonical.get("run", {}).get("mode") == "full"
    if full_pass:
        video = "video/canvas-oss-portability.webm"
        if not copy_file(args.source, args.output, video):
            print("Full portability result is missing its required video", file=sys.stderr)
            return 1
        copied.append(video)
        for directory, extensions in (("screenshots", {".png"}), ("playwright-report", {".html", ".css", ".js"})):
            root = args.source / directory
            if not root.exists():
                continue
            for source in root.rglob("*"):
                if source.is_file() and source.suffix.lower() in extensions:
                    relative = source.relative_to(args.source).as_posix()
                    copy_file(args.source, args.output, relative)
                    copied.append(relative)

    manifest = {
        "schema_version": 1,
        "full_pass_visuals_included": full_pass,
        "files": [
            {
                "path": relative,
                "sha256": hashlib.sha256((args.output / relative).read_bytes()).hexdigest(),
                "bytes": (args.output / relative).stat().st_size,
            }
            for relative in sorted(copied)
        ],
    }
    (args.output / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
