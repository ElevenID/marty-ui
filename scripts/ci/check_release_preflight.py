#!/usr/bin/env python3
"""Cheap source-only validation before dependency setup or release compilation.

An internally consistent development lock on hold is valid CI input, but it is
not a release claim. Release entry points explicitly require eligibility.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_stack_manifest import validate_lock
from localize_marty_core_dependencies import (
    CORE_REPOSITORY,
    _dependency_tables,
    _manifests,
    validate_workspace_dependencies,
)
from product_package_plan import PRODUCTS, build_plan
from stack_tag_gate import require_release_eligible, version_from_tag


def _reviewed_kms_core_revision(root: Path) -> str:
    policy = root / "scripts/ci/check_marty_core_kms_boundary.py"
    try:
        document = ast.parse(policy.read_text(encoding="utf-8"), filename=str(policy))
    except SyntaxError:
        raise ValueError(f"Reviewed KMS boundary is not valid Python: {policy}") from None
    # Read the existing fixed declaration only. Never import or execute policy
    # code, and never derive the reviewed policy value from Cargo declarations.
    declarations = [
        node for node in document.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "CORE_REVISION"
    ]
    bindings = [
        node for node in ast.walk(document)
        if isinstance(node, ast.Name) and node.id == "CORE_REVISION"
        and isinstance(node.ctx, ast.Store)
    ]
    if len(declarations) != 1 or len(bindings) != 1:
        raise ValueError(f"Reviewed KMS boundary needs one literal CORE_REVISION: {policy}")
    value = declarations[0].value
    if (not isinstance(value, ast.Constant) or not isinstance(value.value, str)
            or re.fullmatch(r"[0-9a-f]{40}", value.value) is None):
        raise ValueError(f"Reviewed KMS boundary needs one literal CORE_REVISION: {policy}")
    return value.value


def _release_core_entries(documents: dict[Path, dict]):
    for manifest, document in documents.items():
        for location, entries in _dependency_tables(document):
            for alias, specification in entries.items():
                if not isinstance(specification, dict):
                    continue
                repository = specification.get("git")
                if isinstance(repository, str) and repository.removesuffix(".git") == CORE_REPOSITORY:
                    yield manifest, location, alias, specification


def _release_core_revision(reference) -> str:
    manifest, location, alias, specification = reference
    label = f"{manifest} [{'.'.join(location)}].{alias}"
    revision = specification.get("rev")
    if (not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or any(field in specification for field in ("path", "tag", "branch"))):
        raise ValueError(f"Core release dependency must use one full immutable rev: {label}")
    return revision


def _validate_release_core_lock(lock_path: Path, revision: str) -> None:
    document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = [*document.get("package", []), *document.get("patch", {}).get("unused", [])]
    found = False
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError(f"Invalid Cargo lock entry: {lock_path}")
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("git+"):
            continue
        repository = source[4:].split("?", 1)[0].split("#", 1)[0]
        if repository.removesuffix(".git") != CORE_REPOSITORY:
            continue
        found = True
        if source != f"git+{repository}?rev={revision}#{revision}":
            raise ValueError(f"Core lock source differs from release revision: {lock_path}")
    if not found:
        raise ValueError(f"Cargo lock contains no Marty Core source: {lock_path}")


def validate_release_core_sources(root: Path) -> None:
    """Check release Core source agreement without fetching or resolving Cargo.

    The localizer's read-only traversal covers production members and local path
    dependencies. Its development transformations still permit mixed revisions.
    This rule also covers the named governed probe, not independent workspaces.
    Registry resolution and native compilation remain the locked CI gates' job.
    """
    production_manifest = root / "rust/Cargo.toml"
    production = _manifests(production_manifest)
    references = list(_release_core_entries(production))
    if not references:
        return  # Non-Core source fixtures retain their existing release checks.
    revision = _release_core_revision(references[0])
    for reference in references[1:]:
        if _release_core_revision(reference) != revision:
            raise ValueError(f"Core release revision differs: {reference[0]}")

    probe_manifest = root / ".github/feature-regression/rust-probe/Cargo.toml"
    probe = _manifests(probe_manifest)
    for reference in _release_core_entries(probe):
        if _release_core_revision(reference) != revision:
            raise ValueError(f"Core release revision differs: {reference[0]}")
    production_patches = production[production_manifest.resolve()].get("patch", {}).get("crates-io", {})
    probe_patches = probe[probe_manifest.resolve()].get("patch", {}).get("crates-io", {})
    if probe_patches != production_patches:
        raise ValueError(f"Governed probe patches differ from production: {probe_manifest}")

    for manifest in (production_manifest, probe_manifest):
        _validate_release_core_lock(manifest.with_name("Cargo.lock"), revision)
    if revision != _reviewed_kms_core_revision(root):
        raise ValueError("Core release revision differs from reviewed KMS boundary")


def check(root: Path, source_sha: str, *, require_eligible: bool = False) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("source SHA must be a full lowercase commit")
    # The same source-only validator runs before any dependency/build setup.
    validate_workspace_dependencies(root / "rust/Cargo.toml")
    validate_release_core_sources(root)
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
