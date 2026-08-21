#!/usr/bin/env python3
"""Validate Rust ownership metadata and reject new non-Rust crypto kernels."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any


MANIFEST_PATH = Path("docs/rust-migration-ownership.json")
VALID_STATUSES = {"native-active", "cutover-in-progress", "planned", "decision-pending"}
REQUIRED_CAPABILITY_KEYS = {"id", "phase", "status", "canonical", "legacy"}


def _import_statement(node: ast.Import | ast.ImportFrom) -> str:
    names = ", ".join(
        alias.name + (f" as {alias.asname}" if alias.asname else "")
        for alias in node.names
    )
    if isinstance(node, ast.ImportFrom):
        return f"from {node.module or ''} import {names}"
    return f"import {names}"


def _restricted_root(node: ast.Import | ast.ImportFrom) -> str:
    if isinstance(node, ast.ImportFrom):
        return (node.module or "").split(".", 1)[0]
    return node.names[0].name.split(".", 1)[0]


def _python_files(root: Path, guardrails: dict[str, Any]):
    excluded = set(guardrails["excluded_path_parts"])
    for source_root in guardrails["python_scan_roots"]:
        base = root / source_root
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            relative = path.relative_to(root)
            if excluded.intersection(relative.parts) or path.name.startswith("test_"):
                continue
            yield path


def _validate_capabilities(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if manifest.get("schema") != "marty.rust-ownership/v1":
        findings.append("manifest schema must be marty.rust-ownership/v1")
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        return findings + ["manifest capabilities must be a non-empty list"]
    seen: set[str] = set()
    for index, capability in enumerate(capabilities):
        prefix = f"capabilities[{index}]"
        if not isinstance(capability, dict):
            findings.append(f"{prefix} must be an object")
            continue
        missing = REQUIRED_CAPABILITY_KEYS - capability.keys()
        if missing:
            findings.append(f"{prefix} is missing: {', '.join(sorted(missing))}")
            continue
        capability_id = capability["id"]
        if not isinstance(capability_id, str) or not capability_id:
            findings.append(f"{prefix}.id must be a non-empty string")
        elif capability_id in seen:
            findings.append(f"duplicate capability id: {capability_id}")
        else:
            seen.add(capability_id)
        if capability["status"] not in VALID_STATUSES:
            findings.append(f"{prefix}.status is invalid: {capability['status']}")
        if not isinstance(capability["phase"], int) or not 0 <= capability["phase"] <= 9:
            findings.append(f"{prefix}.phase must be an integer from 0 through 9")
        canonical = capability["canonical"]
        if not isinstance(canonical, dict) or not canonical.get("repository") or not canonical.get("paths"):
            findings.append(f"{prefix}.canonical must name one repository and at least one path")
        legacy = capability["legacy"]
        if not isinstance(legacy, list):
            findings.append(f"{prefix}.legacy must be a list")
    return findings


def _scan_restricted_imports(
    root: Path,
    guardrails: dict[str, Any],
) -> list[str]:
    restricted = set(guardrails["restricted_import_roots"])
    actual: Counter[tuple[str, str]] = Counter()
    findings: list[str] = []
    for path in _python_files(root, guardrails):
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as error:
            findings.append(f"cannot inspect {relative}: {error}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and _restricted_root(node) in restricted:
                actual[(relative, _import_statement(node))] += 1
    approved: Counter[tuple[str, str]] = Counter()
    for entry in guardrails["approved_imports"]:
        approved[(entry["path"], entry["statement"])] += int(entry.get("count", 1))
    for key, count in sorted((actual - approved).items()):
        findings.append(f"unapproved non-Rust crypto import ({count}x): {key[0]}: {key[1]}")
    for key, count in sorted((approved - actual).items()):
        findings.append(f"stale crypto import allowance ({count}x): {key[0]}: {key[1]}")
    return findings


def _scan_text_rules(root: Path, guardrails: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    for rule in guardrails["text_rules"]:
        actual: dict[str, int] = {}
        regex = re.compile(rule["pattern"])
        for path in root.glob(rule["glob"]):
            if not path.is_file():
                continue
            count = len(regex.findall(path.read_text(encoding="utf-8")))
            if count:
                actual[path.relative_to(root).as_posix()] = count
        expected = rule["expected_matches"]
        if actual != expected:
            findings.append(
                f"text guard {rule['id']} changed: expected {expected}, found {actual}"
            )
    return findings


def _scan_native_service_guards(
    root: Path,
    manifest: dict[str, Any],
    guardrails: dict[str, Any],
) -> list[str]:
    findings: list[str] = []
    statuses = {
        capability["id"]: capability["status"]
        for capability in manifest["capabilities"]
        if isinstance(capability, dict)
        and isinstance(capability.get("id"), str)
        and isinstance(capability.get("status"), str)
    }
    for guard in guardrails.get("native_service_guards", []):
        capability_id = guard.get("capability_id")
        if capability_id not in statuses:
            findings.append(
                f"native service guard references unknown capability: {capability_id}"
            )
            continue
        if statuses[capability_id] != "native-active":
            continue
        for pattern in guard.get("forbidden_globs", []):
            for path in sorted(root.glob(pattern)):
                if path.is_file():
                    findings.append(
                        "native service contains forbidden non-Rust source "
                        f"({capability_id}): {path.relative_to(root).as_posix()}"
                    )
    return findings


def scan_repository(root: Path, manifest_path: Path | None = None) -> list[str]:
    root = root.resolve()
    path = manifest_path or root / MANIFEST_PATH
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot load Rust ownership manifest: {error}"]
    if not isinstance(manifest, dict):
        return ["Rust ownership manifest must be an object"]
    findings = _validate_capabilities(manifest)
    guardrails = manifest.get("guardrails")
    if not isinstance(guardrails, dict):
        return sorted(findings + ["manifest guardrails must be an object"])
    findings.extend(_scan_restricted_imports(root, guardrails))
    findings.extend(_scan_text_rules(root, guardrails))
    findings.extend(_scan_native_service_guards(root, manifest, guardrails))
    return sorted(findings)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    findings = scan_repository(args.repo_root, args.manifest)
    if findings:
        print("Rust ownership guard failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("Rust ownership manifest and shrinking non-Rust baseline are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
