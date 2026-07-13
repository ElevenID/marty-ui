#!/usr/bin/env python3
"""Create immutable evidence for a coordinated release built from local worktrees."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPOSITORIES = (
    "marty-ui",
    "marty-protocol",
    "marty-credentials",
    "marty-core",
    "marty-cli",
    "marty-blog",
    "marty-subscriptions",
    "marty-microservices-framework",
    "longfellow-zk",
)

REPOSITORY_INCLUDE_PREFIXES = {
    # The public UI image consumes only these named-context paths.
    "marty-blog": ("package.json", "src/"),
    "marty-subscriptions": ("package.json", "src/"),
}

REPOSITORY_EXCLUDE_PREFIXES = {
    "marty-ui": (
        ".selfhost-state/",
        "tests/artifacts/",
        "tests/demo-recordings/",
        "tests/demo-recordings-report/",
        "tests/pytest-results/",
        "tests/wallet-debug",
        "ui/build/",
        "ui/dist/",
        "ui/dist-selfhost/",
    ),
}


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.STDOUT,
    )


def _in_release_scope(repo: Path, relative: Path) -> bool:
    path = relative.as_posix()
    include_prefixes = REPOSITORY_INCLUDE_PREFIXES.get(repo.name)
    if include_prefixes and not any(
        path == prefix or path.startswith(prefix)
        for prefix in include_prefixes
    ):
        return False
    return not any(
        path == prefix or path.startswith(prefix)
        for prefix in REPOSITORY_EXCLUDE_PREFIXES.get(repo.name, ())
    )


def release_files(repo: Path) -> list[Path]:
    output = _git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    files: list[Path] = []
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        absolute = repo / relative
        if _in_release_scope(repo, relative) and (absolute.is_file() or absolute.is_symlink()):
            files.append(relative)
    return sorted(files, key=lambda path: path.as_posix())


def worktree_digest(repo: Path, files: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for relative in files:
        absolute = repo / relative
        path_bytes = relative.as_posix().encode("utf-8")
        mode = absolute.lstat().st_mode & 0o777
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(mode.to_bytes(4, "big"))
        if absolute.is_symlink():
            content = os.readlink(absolute).encode("utf-8")
        else:
            content = absolute.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def write_snapshot(repo: Path, files: Iterable[Path], destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative in files:
                    absolute = repo / relative
                    info = archive.gettarinfo(str(absolute), arcname=relative.as_posix())
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    if info.isfile():
                        with absolute.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def repository_record(repo: Path, snapshot_dir: Path) -> dict[str, object]:
    files = release_files(repo)
    source_sha256 = worktree_digest(repo, files)
    snapshot_path = snapshot_dir / f"{repo.name}.tar.gz"
    snapshot_sha256 = write_snapshot(repo, files, snapshot_path)
    status = _git(repo, "status", "--porcelain=v1", "-z")
    return {
        "head_sha": _git(repo, "rev-parse", "HEAD").decode().strip(),
        "dirty": bool(status),
        "file_count": len(files),
        "include_prefixes": list(REPOSITORY_INCLUDE_PREFIXES.get(repo.name, ())),
        "exclude_prefixes": list(REPOSITORY_EXCLUDE_PREFIXES.get(repo.name, ())),
        "source_sha256": source_sha256,
        "snapshot": snapshot_path.name,
        "snapshot_sha256": snapshot_sha256,
    }


def create_manifest(
    workspace: Path,
    release_version: str,
    output: Path,
    snapshot_dir: Path,
) -> dict[str, object]:
    repositories: dict[str, object] = {}
    for name in REPOSITORIES:
        repo = workspace / name
        if not (repo / ".git").exists():
            raise RuntimeError(f"Required repository is missing: {repo}")
        repositories[name] = repository_record(repo, snapshot_dir)

    ui_source_sha = str(repositories["marty-ui"]["source_sha256"])
    manifest: dict[str, object] = {
        "schema_version": 1,
        "release_version": release_version,
        "mip_version": "0.3.1",
        "source_kind": "local-worktree-snapshot",
        "marty_ui_sha": ui_source_sha[:40],
        "marty_ui_source_sha256": ui_source_sha,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mixed_versions_supported": False,
        "promotion_eligible": False,
        "release_ready": False,
        "snapshot_directory": os.path.relpath(snapshot_dir, output.parent),
        "repositories": repositories,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(workspace: Path, manifest_path: Path) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    repositories = manifest.get("repositories")
    if not isinstance(repositories, dict) or set(repositories) != set(REPOSITORIES):
        raise RuntimeError("Source manifest repository set does not match release inputs")

    snapshot_directory = manifest.get("snapshot_directory")
    if not isinstance(snapshot_directory, str) or not snapshot_directory:
        raise RuntimeError("Source manifest is missing its snapshot directory")
    snapshot_root = (manifest_path.parent / snapshot_directory).resolve()
    if not snapshot_root.is_relative_to(manifest_path.parent.resolve()):
        raise RuntimeError("Snapshot directory must stay under the artifact directory")

    verified: dict[str, object] = {}
    for name in REPOSITORIES:
        record = repositories[name]
        if not isinstance(record, dict):
            raise RuntimeError(f"Invalid repository record: {name}")
        repo = workspace / name
        if not (repo / ".git").exists():
            raise RuntimeError(f"Required repository is missing: {repo}")
        files = release_files(repo)
        actual_source = worktree_digest(repo, files)
        expected_source = record.get("source_sha256")
        if actual_source != expected_source:
            raise RuntimeError(f"Worktree changed after snapshot: {name}")

        snapshot_name = record.get("snapshot")
        if not isinstance(snapshot_name, str) or Path(snapshot_name).name != snapshot_name:
            raise RuntimeError(f"Invalid snapshot name: {name}")
        snapshot = snapshot_root / snapshot_name
        if not snapshot.is_file():
            raise RuntimeError(f"Snapshot is missing: {snapshot}")
        actual_snapshot = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        if actual_snapshot != record.get("snapshot_sha256"):
            raise RuntimeError(f"Snapshot checksum mismatch: {name}")
        verified[name] = {
            "file_count": len(files),
            "source_sha256": actual_source,
            "snapshot_sha256": actual_snapshot,
        }

    ui_source = str(repositories["marty-ui"]["source_sha256"])
    if manifest.get("marty_ui_source_sha256") != ui_source:
        raise RuntimeError("UI source digest does not match repository record")
    if manifest.get("marty_ui_sha") != ui_source[:40]:
        raise RuntimeError("UI source ID does not match repository digest")
    return verified


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--release-version")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--verify-manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_manifest:
            verified = verify_manifest(
                args.workspace.resolve(),
                args.verify_manifest.resolve(),
            )
            print(json.dumps({"verified": list(verified)}))
            return 0
        if not args.release_version or not args.output or not args.snapshot_dir:
            raise RuntimeError(
                "Creation requires --release-version, --output, and --snapshot-dir"
            )
        manifest = create_manifest(
            args.workspace.resolve(),
            args.release_version,
            args.output.resolve(),
            args.snapshot_dir.resolve(),
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Local release manifest failed: {exc}")
        return 1
    print(json.dumps({
        "release_version": manifest["release_version"],
        "marty_ui_sha": manifest["marty_ui_sha"],
        "manifest": str(args.output.resolve()),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
