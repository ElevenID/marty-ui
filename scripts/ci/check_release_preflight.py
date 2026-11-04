#!/usr/bin/env python3
"""Cheap source-only validation before dependency setup or release compilation.

An internally consistent development lock on hold is valid CI input, but it is
not a release claim. Release entry points explicitly require eligibility.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_stack_manifest import validate_lock
from product_package_plan import PRODUCTS, build_plan
from stack_tag_gate import require_release_eligible, version_from_tag


def check(root: Path, source_sha: str, *, require_eligible: bool = False) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("source SHA must be a full lowercase commit")
    lock = json.loads((root / "release/stack-lock.json").read_bytes())
    validate_lock(lock)
    version = version_from_tag("v" + lock["release"].removeprefix("marty-ui@"))
    if lock.get("release_state") not in ("eligible", "hold"):
        raise ValueError("release_state must be eligible or hold")
    if require_eligible:
        require_release_eligible(root, "v" + version)

    # The UI npm package and the independent products have their own versions.
    # Compare each version with its actual owner, never with the stack version.
    package = json.loads((root / "ui/package.json").read_bytes())
    npm_lock = json.loads((root / "ui/package-lock.json").read_bytes())
    npm_root = npm_lock.get("packages", {}).get("", {})
    if not isinstance(package.get("version"), str):
        raise ValueError("UI package version is missing")
    version_from_tag("v" + package["version"])
    if npm_lock.get("version") != package["version"] or npm_root.get("version") != package["version"]:
        raise ValueError("UI package and lock versions differ")
    components = {item["name"]: item for item in lock["components"]}
    for name in ("marty-api-core", "marty-blog"):
        component = components.get(name, {})
        artifacts = [item for item in component.get("artifacts", []) if item["type"] == "npm"]
        if len(artifacts) != 1:
            raise ValueError(f"{name} must have exactly one pinned npm artifact")
        dependency = "@elevenid/" + name
        expected = artifacts[0]["uri"]
        if (package.get("dependencies", {}).get(dependency) != expected or
                npm_root.get("dependencies", {}).get(dependency) != expected):
            raise ValueError(f"{name} UI dependency differs from the stack lock")

    plans = {product: build_plan(root, product, source_sha) for product in PRODUCTS}
    return {
        "schema": "marty.release-preflight/v1", "source_sha": source_sha,
        "stack_version": version, "release_state": lock["release_state"],
        "claim_eligible": lock["release_state"] == "eligible",
        "product_tags": {product: plan["tag"] for product, plan in plans.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--require-eligible", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = check(args.root, args.source_sha, require_eligible=args.require_eligible)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Release preflight failed: {error}\n")
    payload = json.dumps(result, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
