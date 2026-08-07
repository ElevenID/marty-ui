#!/usr/bin/env python3
"""Reject documentation that recommends private signing selectors."""

from __future__ import annotations

import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Public documentation may name private selectors when it explains that they
# are rejected or internal. It must never instruct a caller or UI developer to
# select custody routing, persist it on a public template, or forward it to
# issuance. These phrases came from a retired pre-DID-first gap analysis and
# represent the prohibited design rather than merely the prohibited field.
FORBIDDEN_PUBLIC_SIGNING_GUIDANCE = {
    "signing service selector",
    "signing_service_id override",
    "store signing_service_id on credential template",
    "pass signing_service_id through to issuance",
}


def assert_documented_public_boundary(root: Path = REPO_ROOT) -> None:
    violations: dict[str, list[str]] = {}
    markdown_paths = sorted(root.glob("*.md"))
    docs_root = root / "docs"
    if docs_root.is_dir():
        markdown_paths.extend(sorted(docs_root.rglob("*.md")))

    for path in markdown_paths:
        source = (
            path.read_text(encoding="utf-8")
            .lower()
            .replace("`", "")
            .replace("**", "")
        )
        matched = sorted(
            phrase for phrase in FORBIDDEN_PUBLIC_SIGNING_GUIDANCE if phrase in source
        )
        if matched:
            violations[str(path.relative_to(root))] = matched

    if violations:
        raise AssertionError(
            "Documentation recommends private signing selectors at the public "
            f"boundary: {violations}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    assert_documented_public_boundary(args.root.resolve())
    print("Public documentation preserves the DID-only signing boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
