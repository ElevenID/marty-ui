#!/usr/bin/env python3
"""Check self-host Compose secret ownership before any installed-runtime fixture.

This reads declarations and placeholder filenames only. It never generates,
reads, prints, or uploads secret values and does not qualify a release.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def _mapping(path: Path, label: str) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def validate(compose_path: Path, catalog_path: Path, stack_path: Path,
             example_dir: Path) -> dict[str, object]:
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    if not isinstance(compose, dict) or not isinstance(compose.get("services"), dict):
        raise TypeError("Compose has no service map")
    declarations = compose.get("secrets")
    if not isinstance(declarations, dict) or not declarations:
        raise ValueError("Compose has no secret declarations")
    catalog = _mapping(catalog_path, "secret catalog").get("secrets")
    stack = _mapping(stack_path, "stack specification")
    if not isinstance(catalog, dict) or not isinstance(stack.get("required_secrets"), list):
        raise TypeError("catalog or stack has no secret map/list")
    if any(not isinstance(name, str) for name in stack["required_secrets"]):
        raise ValueError("stack required secrets contain a non-name")

    errors: list[str] = []
    declared = set(declarations)
    referenced: set[str] = set()
    for name, service in compose["services"].items():
        if not isinstance(service, dict):
            errors.append(f"service {name} is not an object")
            continue
        for entry in service.get("secrets", []):
            secret = entry if isinstance(entry, str) else entry.get("source") if isinstance(entry, dict) else None
            if not isinstance(secret, str):
                errors.append(f"service {name} has an invalid secret reference")
                continue
            referenced.add(secret)
    if declared != referenced:
        errors.append("Compose declared/reference mismatch: "
                      f"unreferenced={sorted(declared - referenced)} "
                      f"undeclared={sorted(referenced - declared)}")

    catalog_by_compose: dict[str, dict] = {}
    catalog_required: set[str] = set()
    for name, entry in catalog.items():
        if not isinstance(entry, dict):
            errors.append(f"catalog entry {name} is not an object")
            continue
        compose_name = entry.get("compose_secret")
        if compose_name is not None:
            if compose_name in catalog_by_compose:
                errors.append(f"catalog duplicate Compose secret {compose_name}")
            catalog_by_compose[compose_name] = entry
        if "selfhost-production" in entry.get("required_for", []):
            catalog_required.add(name)
    missing_catalog = declared - set(catalog_by_compose)
    if missing_catalog:
        errors.append(f"Compose secrets absent from catalog: {sorted(missing_catalog)}")
    stack_required = set(stack["required_secrets"])
    if len(stack_required) != len(stack["required_secrets"]):
        errors.append("stack required secrets contain duplicates")
    if stack_required != catalog_required:
        errors.append("stack/catalog required mismatch: "
                      f"catalog_not_stack={sorted(catalog_required - stack_required)} "
                      f"stack_not_catalog={sorted(stack_required - catalog_required)}")
    if not catalog_required <= declared:
        errors.append(f"required catalog secrets absent from Compose: {sorted(catalog_required - declared)}")

    for name, entry in declarations.items():
        expected = "${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/" + name
        if not isinstance(entry, dict) or entry.get("file") != expected:
            errors.append(f"Compose secret {name} does not use its isolated file path")
        placeholder = example_dir / name
        if not placeholder.is_file() or placeholder.is_symlink():
            errors.append(f"Compose secret {name} lacks a regular example file")
    if errors:
        raise ValueError("; ".join(errors))
    return {"schema": "marty.selfhost-install-secret-closure/v1",
            "qualification": "unqualified", "declared_secret_names": sorted(declared),
            "required_secret_names": sorted(catalog_required)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compose", "catalog", "stack", "example-dir"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.compose, args.catalog, args.stack, args.example_dir)
    except (TypeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
