#!/usr/bin/env python3
"""Localize a complete Cargo workspace against an existing Marty Core checkout.

This is a local developer source transformation, not release qualification.
Core and unrelated dependency graphs are read-only. No Cargo command is run.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import tomllib
from pathlib import Path

CORE_REPOSITORY = "https://github.com/ElevenID/marty-core"
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}


def _dependency_tables(document: dict):
    for key in DEPENDENCY_TABLES:
        if key in document:
            yield (key,), document[key]
    if "dependencies" in document.get("workspace", {}):
        yield ("workspace", "dependencies"), document["workspace"]["dependencies"]
    for target, tables in document.get("target", {}).items():
        for key in DEPENDENCY_TABLES:
            if key in tables:
                yield ("target", target, key), tables[key]
    for registry, entries in document.get("patch", {}).items():
        yield ("patch", registry), entries


def _manifests(root_manifest: Path) -> dict[Path, dict]:
    root = root_manifest.parent.resolve()
    pending = [root_manifest.resolve()]
    documents = {}
    while pending:
        manifest = pending.pop()
        if manifest in documents:
            continue
        if not manifest.is_relative_to(root):
            # Never adopt or rewrite a sibling repository's path dependencies.
            continue
        if not manifest.is_file():
            raise ValueError(f"Missing local Cargo manifest: {manifest}")
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        documents[manifest] = document
        for member in document.get("workspace", {}).get("members", []):
            matches = sorted(manifest.parent.glob(member))
            if not matches:
                raise ValueError(f"Missing workspace member: {member}")
            pending.extend((directory / "Cargo.toml").resolve() for directory in matches)
        for _, entries in _dependency_tables(document):
            for specification in entries.values():
                if isinstance(specification, dict) and "path" in specification:
                    pending.append((manifest.parent / specification["path"] / "Cargo.toml").resolve())
    return documents


def _core_packages(core_root: Path) -> dict[str, Path]:
    packages = {}
    for manifest, document in _manifests(core_root / "Cargo.toml").items():
        name = document.get("package", {}).get("name")
        if name:
            if name in packages:
                raise ValueError(f"Ambiguous Core package: {name}")
            packages[name] = manifest.parent
    if not packages:
        raise ValueError("Core checkout contains no packages")
    return packages


def _value(value) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    raise ValueError(f"Unsupported dependency field value: {value!r}")


def _header_path(header: str) -> tuple[str, ...]:
    document = tomllib.loads(header + "\n__localizer_section__ = true\n")
    path = []
    while isinstance(document, dict) and "__localizer_section__" not in document:
        if len(document) != 1:
            raise ValueError("Unsupported Cargo table header")
        key, document = next(iter(document.items()))
        path.append(key)
    return tuple(path)


def _sections(source: str):
    headers = list(re.finditer(r"(?m)^\s*(\[[^\r\n]+\])[^\S\r\n]*(?:#[^\r\n]*)?\r?$", source))
    for index, header in enumerate(headers):
        if header.group(1).startswith("[["):
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(source)
        yield _header_path(header.group(1)), header.start(), header.end(), end


def _replacement(source: str, location: tuple[str, ...], alias: str, old: dict, new: dict):
    rendered = "{ " + ", ".join(f"{json.dumps(k)} = {_value(v)}" for k, v in new.items()) + " }"
    for section, start, body, end in _sections(source):
        if section == (*location, alias):
            fields = "\n".join(f"{json.dumps(k)} = {_value(v)}" for k, v in new.items())
            return start, end, source[start:body] + "\n" + fields + "\n"
        if section != location:
            continue
        content = source[body:end]
        for match in re.finditer(r"(?m)^([^\r\n=]+)=", content):
            try:
                key = next(iter(tomllib.loads(match.group(1).strip() + " = 0")))
            except tomllib.TOMLDecodeError:
                continue
            if key != alias:
                continue
            entry_start = body + match.start()
            # Parse the complete assignment instead of guessing at braces in
            # quoted strings, arrays or multiline dependency specifications.
            for line in re.finditer(r"\n|$", source[entry_start:end]):
                entry_end = entry_start + line.end()
                try:
                    entry = tomllib.loads(source[entry_start:entry_end])
                except tomllib.TOMLDecodeError:
                    continue
                if entry == {alias: old}:
                    return entry_start, entry_end, f"{json.dumps(alias)} = {rendered}\n"
    raise ValueError(f"Unsupported dependency syntax: {'.'.join(location)}.{alias}")


def plan_localization(manifest_paths: list[Path], core_root: Path):
    core_root = core_root.resolve()
    packages = _core_packages(core_root)
    documents = {}
    for manifest in manifest_paths:
        documents.update(_manifests(manifest.resolve()))
    plan = {}
    localized = []
    for manifest, parsed in documents.items():
        original = manifest.read_bytes()
        source = original.decode("utf-8")
        expected = copy.deepcopy(parsed)
        replacements = []
        for location, dependencies in _dependency_tables(parsed):
            for alias, specification in dependencies.items():
                if not isinstance(specification, dict):
                    continue
                repository = specification.get("git", "")
                if repository.removesuffix(".git") != CORE_REPOSITORY:
                    continue
                name = specification.get("package", alias)
                if name not in packages:
                    raise ValueError(f"Missing Core package: {name}")
                if "path" in specification:
                    raise ValueError(f"Mixed Git/path Core dependency: {alias}")
                try:
                    local_path = Path(os.path.relpath(packages[name], manifest.parent)).as_posix()
                except ValueError:
                    local_path = packages[name].as_posix()  # Different Windows volume.
                replacement = {k: v for k, v in specification.items()
                               if k not in {"git", "rev", "tag", "branch"}}
                replacement["path"] = local_path
                replacements.append(_replacement(source, location, alias, specification, replacement))
                target = expected
                for key in location:
                    target = target[key]
                target[alias] = replacement
                localized.append(alias)
        if replacements:
            for start, end, replacement in sorted(replacements, reverse=True):
                source = source[:start] + replacement + source[end:]
            if tomllib.loads(source) != expected:
                raise ValueError(f"Localization changed unrelated manifest fields: {manifest}")
            plan[manifest] = (original, source.encode("utf-8"))
    if not localized:
        raise ValueError(f"No dependencies pinned to {CORE_REPOSITORY} were found")
    return plan, localized


def localize_manifests(manifest_paths: list[Path], core_root: Path, *, dry_run: bool = False) -> list[str]:
    plan, localized = plan_localization(manifest_paths, core_root)
    if not dry_run:
        # Validate the entire workspace and detect changes before the first write.
        if any(path.read_bytes() != before for path, (before, _) in plan.items()):
            raise ValueError("Cargo manifest changed while localization was planned")
        attempted = []
        try:
            for path, (_, after) in plan.items():
                attempted.append(path)
                path.write_bytes(after)
        except OSError as error:
            # Ordinary file writes are not a cross-file transaction. Restore
            # every attempted path, including a potentially partial current
            # write, and report any restoration failure without skipping others.
            unrestored = []
            for path in reversed(attempted):
                try:
                    path.write_bytes(plan[path][0])
                except OSError:
                    unrestored.append(str(path))
            if unrestored:
                raise OSError("Localization failed; could not restore: " + ", ".join(unrestored)) from error
            raise
    return localized


def localize_manifest(manifest_path: Path, core_root: str) -> list[str]:
    # Preserve the original API's manifest-relative local dependency paths.
    return localize_manifests([manifest_path], manifest_path.parent / core_root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="+")
    parser.add_argument("--core-root", type=Path, default=Path("../marty-core"),
                        help="Existing Core checkout relative to the first manifest's directory")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    # Keep the original single-manifest default and manifest-relative meaning;
    # additional roots share that same explicitly selected Core checkout.
    core_root = args.manifest[0].parent / args.core_root
    localized = localize_manifests(args.manifest, core_root, dry_run=args.dry_run)
    print("Localized Marty Core dependencies: " + ", ".join(localized))


if __name__ == "__main__":
    main()
