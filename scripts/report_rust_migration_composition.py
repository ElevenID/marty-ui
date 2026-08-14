#!/usr/bin/env python3
"""Create commit-pinned language and dependency evidence for Rust migrations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "marty.rust-migration-composition/v1"
LANGUAGES = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".dart": "Dart",
    ".h": "C/C++ Header",
    ".hh": "C/C++ Header",
    ".hpp": "C/C++ Header",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".py": "Python",
    ".ps1": "PowerShell",
    ".rs": "Rust",
    ".sh": "Shell",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}
EXCLUDED_COMPONENTS = {
    ".dart_tool",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "fixtures",
    "generated",
    "node_modules",
    "snapshots",
    "target",
    "vendor",
    "venv",
}
DEPENDENCY_SECTIONS = {
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
}
PYTHON_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


class ReportError(ValueError):
    """Raised when evidence cannot be produced safely."""


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ReportError(f"git {' '.join(args)} failed for {root}: {detail}")
    return result.stdout


def _tracked_files(root: Path) -> list[str]:
    output = _git(root, "ls-files", "-z")
    return sorted(path for path in output.split("\0") if path)


def _is_excluded(path: str) -> bool:
    return bool(EXCLUDED_COMPONENTS.intersection(PurePosixPath(path).parts))


def _language(path: str) -> str | None:
    name = PurePosixPath(path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def _empty_metrics() -> dict[str, int]:
    return {"files": 0, "bytes": 0, "lines": 0, "nonblank_lines": 0}


def _add_metrics(target: dict[str, int], source: dict[str, int]) -> None:
    for field in _empty_metrics():
        target[field] += source[field]


def _file_metrics(path: Path) -> dict[str, int]:
    content = path.read_bytes()
    text = content.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return {
        "files": 1,
        "bytes": len(content),
        "lines": len(lines),
        "nonblank_lines": sum(bool(line.strip()) for line in lines),
    }


def source_metrics(root: Path, files: Iterable[str]) -> dict[str, Any]:
    languages: dict[str, dict[str, int]] = defaultdict(_empty_metrics)
    excluded = _empty_metrics()
    included = _empty_metrics()
    for relative in sorted(set(files)):
        language = _language(relative)
        if language is None:
            continue
        metrics = _file_metrics(root / relative)
        if _is_excluded(relative):
            _add_metrics(excluded, metrics)
            continue
        _add_metrics(languages[language], metrics)
        _add_metrics(included, metrics)
    return {
        "totals": included,
        "languages": dict(sorted(languages.items())),
        "excluded_from_maintained_source": excluded,
    }


def _normalize_dependency(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements_dependencies(root: Path, files: Iterable[str]) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {}
    for relative in files:
        name = PurePosixPath(relative).name.lower()
        if not (name.startswith("requirements") and name.endswith(".txt")):
            continue
        dependencies: set[str] = set()
        logical = ""
        for raw_line in (root / relative).read_text(encoding="utf-8").splitlines():
            line = raw_line.partition("#")[0].strip()
            logical += line.removesuffix("\\").strip()
            if line.endswith("\\"):
                continue
            if logical and not logical.startswith(("-", "http:", "https:", "git+")):
                match = PYTHON_NAME.match(logical)
                if match:
                    dependencies.add(_normalize_dependency(match.group(1)))
            logical = ""
        manifests[relative] = sorted(dependencies)
    return manifests


def _pyproject_dependencies(root: Path, files: Iterable[str]) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {}
    for relative in files:
        if PurePosixPath(relative).name != "pyproject.toml":
            continue
        data = tomllib.loads((root / relative).read_text(encoding="utf-8"))
        dependencies: set[str] = set()
        project = data.get("project", {})
        for requirement in project.get("dependencies", []):
            match = PYTHON_NAME.match(requirement)
            if match:
                dependencies.add(_normalize_dependency(match.group(1)))
        for group in project.get("optional-dependencies", {}).values():
            for requirement in group:
                match = PYTHON_NAME.match(requirement)
                if match:
                    dependencies.add(_normalize_dependency(match.group(1)))
        poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies"):
            dependencies.update(
                _normalize_dependency(name)
                for name in poetry.get(section, {})
                if name.lower() != "python"
            )
        for group in poetry.get("group", {}).values():
            dependencies.update(
                _normalize_dependency(name)
                for name in group.get("dependencies", {})
                if name.lower() != "python"
            )
        manifests[relative] = sorted(dependencies)
    return manifests


def _cargo_dependencies(root: Path, files: Iterable[str]) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {}
    for relative in files:
        if PurePosixPath(relative).name != "Cargo.toml":
            continue
        data = tomllib.loads((root / relative).read_text(encoding="utf-8"))
        dependencies: set[str] = set()
        for section in DEPENDENCY_SECTIONS:
            dependencies.update(data.get(section, {}))
        workspace = data.get("workspace", {})
        dependencies.update(workspace.get("dependencies", {}))
        target = data.get("target", {})
        for target_config in target.values():
            for section in DEPENDENCY_SECTIONS:
                dependencies.update(target_config.get(section, {}))
        manifests[relative] = sorted(dependencies)
    return manifests


def _node_dependencies(root: Path, files: Iterable[str]) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {}
    for relative in files:
        if PurePosixPath(relative).name != "package.json":
            continue
        data = json.loads((root / relative).read_text(encoding="utf-8"))
        dependencies: set[str] = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            dependencies.update(data.get(section, {}))
        manifests[relative] = sorted(dependencies)
    return manifests


def _pubspec_dependencies(root: Path, files: Iterable[str]) -> dict[str, list[str]]:
    manifests: dict[str, list[str]] = {}
    for relative in files:
        if PurePosixPath(relative).name != "pubspec.yaml":
            continue
        dependencies: set[str] = set()
        active = False
        for raw_line in (root / relative).read_text(encoding="utf-8").splitlines():
            if raw_line and not raw_line[0].isspace():
                active = raw_line.rstrip() in {"dependencies:", "dev_dependencies:"}
                continue
            if active:
                match = re.match(r"^  ([A-Za-z0-9_-]+):", raw_line)
                if match:
                    dependencies.add(match.group(1))
        manifests[relative] = sorted(dependencies)
    return manifests


def dependency_inventory(root: Path, files: list[str]) -> dict[str, Any]:
    ecosystems = {
        "cargo": _cargo_dependencies(root, files),
        "dart": _pubspec_dependencies(root, files),
        "node": _node_dependencies(root, files),
        "python_pyproject": _pyproject_dependencies(root, files),
        "python_requirements": _requirements_dependencies(root, files),
    }
    result: dict[str, Any] = {}
    for ecosystem, manifests in ecosystems.items():
        unique = sorted({dependency for values in manifests.values() for dependency in values})
        result[ecosystem] = {"unique": unique, "manifests": dict(sorted(manifests.items()))}
    return result


def inspect_repository(root: Path, *, allow_dirty: bool = False) -> tuple[dict[str, Any], list[str]]:
    root = root.resolve()
    if not (root / ".git").exists():
        raise ReportError(f"repository path is not a Git checkout: {root}")
    dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=no").strip())
    if dirty and not allow_dirty:
        raise ReportError(f"repository has tracked changes: {root}")
    files = _tracked_files(root)
    return (
        {
            "path": str(root),
            "revision": _git(root, "rev-parse", "HEAD").strip(),
            "dirty": dirty,
            "source": source_metrics(root, files),
            "dependencies": dependency_inventory(root, files),
        },
        files,
    )


def _files_for_paths(files: Iterable[str], paths: Iterable[str]) -> tuple[list[str], list[str]]:
    selected: set[str] = set()
    missing: list[str] = []
    for raw_path in paths:
        path = raw_path.strip("/")
        matches = [item for item in files if item == path or item.startswith(f"{path}/")]
        if matches:
            selected.update(matches)
        else:
            missing.append(raw_path)
    return sorted(selected), missing


def _capability_evidence(
    ownership: dict[str, Any],
    repositories: dict[str, dict[str, Any]],
    tracked: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    capabilities: list[dict[str, Any]] = []
    missing_paths: list[dict[str, str]] = []
    for capability in ownership["capabilities"]:
        canonical = capability["canonical"]
        canonical_paths = [*canonical.get("paths", []), *canonical.get("binding_paths", [])]
        canonical_files, canonical_missing = _files_for_paths(
            tracked.get(canonical["repository"], []), canonical_paths
        )
        canonical_result = {
            "repository": canonical["repository"],
            "paths": canonical_paths,
            "source": source_metrics(
                Path(repositories[canonical["repository"]]["path"]), canonical_files
            )
            if canonical["repository"] in repositories
            else None,
        }
        for path in canonical_missing:
            missing_paths.append(
                {"capability": capability["id"], "kind": "canonical", "repository": canonical["repository"], "path": path}
            )

        binding_results = []
        for binding in capability.get("bindings", []):
            binding_files, binding_missing = _files_for_paths(
                tracked.get(binding["repository"], []), binding.get("paths", [])
            )
            binding_results.append(
                {
                    **binding,
                    "source": source_metrics(
                        Path(repositories[binding["repository"]]["path"]), binding_files
                    )
                    if binding["repository"] in repositories
                    else None,
                }
            )
            for path in binding_missing:
                missing_paths.append(
                    {"capability": capability["id"], "kind": "binding", "repository": binding["repository"], "path": path}
                )

        legacy_results = []
        for legacy in capability.get("legacy", []):
            legacy_files, legacy_missing = _files_for_paths(
                tracked.get(legacy["repository"], []), legacy.get("paths", [])
            )
            legacy_results.append(
                {
                    **legacy,
                    "source": source_metrics(
                        Path(repositories[legacy["repository"]]["path"]), legacy_files
                    )
                    if legacy["repository"] in repositories
                    else None,
                }
            )
            for path in legacy_missing:
                missing_paths.append(
                    {"capability": capability["id"], "kind": "legacy", "repository": legacy["repository"], "path": path}
                )
        capabilities.append(
            {
                "id": capability["id"],
                "phase": capability["phase"],
                "status": capability["status"],
                "canonical": canonical_result,
                "bindings": binding_results,
                "legacy": legacy_results,
            }
        )
    return capabilities, missing_paths


def _dependency_set(repository: dict[str, Any], ecosystem: str) -> set[str]:
    return set(repository.get("dependencies", {}).get(ecosystem, {}).get("unique", []))


def baseline_delta(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("schema") != SCHEMA:
        raise ReportError(f"baseline schema must be {SCHEMA}")
    result: dict[str, Any] = {}
    for name, repository in current["repositories"].items():
        previous = baseline.get("repositories", {}).get(name)
        if previous is None:
            result[name] = {"baseline_missing": True}
            continue
        languages = set(repository["source"]["languages"]) | set(previous["source"]["languages"])
        language_delta = {}
        for language in sorted(languages):
            now = repository["source"]["languages"].get(language, _empty_metrics())
            before = previous["source"]["languages"].get(language, _empty_metrics())
            language_delta[language] = {
                field: now[field] - before[field] for field in _empty_metrics()
            }
        dependencies = {}
        ecosystems = set(repository.get("dependencies", {})) | set(previous.get("dependencies", {}))
        for ecosystem in sorted(ecosystems):
            now = _dependency_set(repository, ecosystem)
            before = _dependency_set(previous, ecosystem)
            dependencies[ecosystem] = {
                "added": sorted(now - before),
                "removed": sorted(before - now),
            }
        result[name] = {"languages": language_delta, "dependencies": dependencies}
    return result


def build_report(
    ownership_path: Path,
    repository_paths: dict[str, Path],
    *,
    require_all_repositories: bool = False,
    allow_dirty: bool = False,
    generated_at: str | None = None,
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ownership_path = ownership_path.resolve()
    ownership_bytes = ownership_path.read_bytes()
    ownership = json.loads(ownership_bytes)
    if ownership.get("schema") != "marty.rust-ownership/v1":
        raise ReportError("ownership manifest schema must be marty.rust-ownership/v1")
    required = {
        capability["canonical"]["repository"] for capability in ownership["capabilities"]
    }
    required.update(
        legacy["repository"]
        for capability in ownership["capabilities"]
        for legacy in capability.get("legacy", [])
    )
    required.update(
        binding["repository"]
        for capability in ownership["capabilities"]
        for binding in capability.get("bindings", [])
    )
    missing_repositories = sorted(required - repository_paths.keys())
    if require_all_repositories and missing_repositories:
        raise ReportError(f"repository mappings are missing: {', '.join(missing_repositories)}")

    repositories: dict[str, dict[str, Any]] = {}
    tracked: dict[str, list[str]] = {}
    for name, root in sorted(repository_paths.items()):
        repositories[name], tracked[name] = inspect_repository(root, allow_dirty=allow_dirty)
    ownership_repository = repositories.get("ElevenID/marty-ui")
    ownership_matches_repository = False
    if ownership_repository is not None:
        expected_ownership_path = (
            Path(ownership_repository["path"]) / "docs" / "rust-migration-ownership.json"
        ).resolve()
        ownership_matches_repository = ownership_path == expected_ownership_path
        if require_all_repositories and ownership_path != expected_ownership_path:
            raise ReportError(
                "ownership manifest must come from the mapped ElevenID/marty-ui checkout: "
                f"{expected_ownership_path}"
            )
    capabilities, missing_paths = _capability_evidence(ownership, repositories, tracked)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "ownership": {
            "path": str(ownership_path),
            "schema": ownership["schema"],
            "sha256": hashlib.sha256(ownership_bytes).hexdigest(),
            "repository": "ElevenID/marty-ui" if ownership_matches_repository else None,
            "revision": ownership_repository["revision"] if ownership_matches_repository else None,
        },
        "policy": {
            "tracked_files_only": True,
            "clean_tracked_worktrees_required": not allow_dirty,
            "excluded_path_components": sorted(EXCLUDED_COMPONENTS),
        },
        "repositories": repositories,
        "missing_repositories": missing_repositories,
        "capabilities": capabilities,
        "missing_paths": missing_paths,
    }
    if baseline is not None:
        report["baseline_delta"] = baseline_delta(report, baseline)
    return report


def _repository_mapping(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or "/" not in name or not raw_path:
        raise argparse.ArgumentTypeError("repository must be OWNER/NAME=PATH")
    return name, Path(raw_path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ownership", type=Path, default=Path("docs/rust-migration-ownership.json"))
    parser.add_argument("--repository", action="append", type=_repository_mapping, default=[])
    parser.add_argument("--require-all-repositories", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repository_paths = dict(args.repository)
    if len(repository_paths) != len(args.repository):
        raise ReportError("repository mappings must be unique")
    baseline = json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else None
    report = build_report(
        args.ownership,
        repository_paths,
        require_all_repositories=args.require_all_repositories,
        allow_dirty=args.allow_dirty,
        baseline=baseline,
    )
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
