#!/usr/bin/env python3
"""Export the frozen product/Core Git objects for a local KMS-only build.

This produces immutable source inputs and a reviewed recipe. It neither creates
a compiler/target volume nor runs Cargo, Docker, beta, or an official suite.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import subprocess

import scoped_native_build as build
from scoped_native_runtime import read_ref, ref, require

PRODUCT = "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f"
CORE = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
FREEZE_SHA256 = "b77d6883f51bc1d3cf19d6cfa76fe567477c7d27e32134e05007c9104e49c941"
LATEST_PROFILE = "oid4vc-latest-maintenance-all-services"
LATEST_PRODUCT = "852dbb5cc0cca79cfe0bbbed5cb8fb94cda0ad34"
LATEST_CORE = CORE
SOURCE_METADATA_RECEIPT_SHA256 = "a834fa325f4a7b517a1a98218b87dfc8e125dcffc3f68cd5bf8310f8a99dc5f1"
LATEST_FREEZE_SHA256 = "075a9bafaf27bd31acfe8372c3172e04cf584120882018ff327e71044b69a5c1"
OPERATOR_NAMES = ("scoped_native_build.py", "scoped_native_profiles.py",
                  "scoped_native_runtime.py", "scoped_linux_journal.py",
                  "prepare_local_official_native_build.py",
                  "seed_local_official_native_target.py",
                  "run_local_official_native_build.py", "desktop_journal_transport.py",
                  "ci/check_core_localized_lock.py", "build-rust-service-binaries.sh")
ORIGINS = {"ui": "https://github.com/ElevenID/marty-ui.git",
           "core": "https://github.com/ElevenID/marty-core.git"}


def git_command(repo: Path, *args: str) -> list[str]:
    # Explicit paths are required before repository setup: a command-line -c
    # cannot repair a primary checkout whose core.worktree is a Linux path.
    repo = repo.resolve(strict=True)
    metadata = repo / ".git"
    if metadata.is_file():
        line = metadata.read_text(encoding="utf-8").strip()
        require(line.startswith("gitdir: ") and "\n" not in line, "GIT_METADATA_FILE_CHANGED")
        directory = Path(line.removeprefix("gitdir: "))
        metadata = directory if directory.is_absolute() else repo / directory
    require(metadata.is_dir(), "GIT_METADATA_DIRECTORY_REQUIRED")
    return ["git", "--git-dir=" + str(metadata.resolve(strict=True)),
            "--work-tree=" + str(repo), *args]


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(git_command(repo, *args))


def safe_member(name: str, kind: bytes) -> Path:
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and "\0" not in name and "\r" not in name and "\n" not in name,
            "SOURCE_ARCHIVE_PATH_UNSAFE")
    require(kind in (b"0", b"5"), "SOURCE_ARCHIVE_LINK_OR_DEVICE_REFUSED")
    return Path(*path.parts)


def source_metadata(receipt: Path | None, profile: str, repositories: dict[str, Path]) -> dict:
    if receipt is None:
        return {}
    require(profile == LATEST_PROFILE and receipt.is_file() and not receipt.is_symlink()
            and hashlib.sha256(receipt.read_bytes()).hexdigest() == SOURCE_METADATA_RECEIPT_SHA256,
            "KNOWN_SOURCE_METADATA_RECEIPT_REQUIRED")
    previous = json.loads(receipt.read_bytes())
    require(previous["state"] == "SOURCE_EXPORTED_NO_COMPILER"
            and previous["buildProfile"] == build.OFFICIAL_PROFILE,
            "KNOWN_SOURCE_METADATA_RECEIPT_REQUIRED")
    result = {}
    for name, revision in (("ui", PRODUCT), ("core", CORE)):
        source = previous["sources"][name]
        require(source["revision"] == revision, "SOURCE_METADATA_REVISION_CHANGED")
        directory = Path(source["directory"]).resolve(strict=True)
        require(directory.is_dir() and directory.is_relative_to((Path.home() / ".codex/private").resolve()),
                "SOURCE_METADATA_DIRECTORY_CHANGED")
        rows = json.loads(read_ref(source["inventory"], 4 * 1024**2).read_bytes())
        files = {row["path"]: row for row in rows}
        require(len(files) == len(rows) == source["fileCount"], "SOURCE_METADATA_INVENTORY_CHANGED")
        modes = {}
        for record in git(repositories[name], "ls-tree", "-rz", "-r", revision).split(b"\0"):
            if record:
                header, raw_name = record.split(b"\t", 1)
                mode, kind, _oid = header.split()
                require(kind == b"blob" and mode in (b"100644", b"100755"),
                        "SOURCE_METADATA_GIT_MODE_CHANGED")
                modes[raw_name.decode("utf-8")] = int(mode, 8)
        require(set(modes) == set(files), "SOURCE_METADATA_GIT_PATHS_CHANGED")
        files = {name: {**row, "mode": modes[name]} for name, row in files.items()}
        result[name] = {"directory": directory, "files": files, "inventory": source["inventory"]}
    return result


def reuse_timestamp(destination: Path, name: str, size: int, digest: str,
                   previous: dict | None, mode: int) -> bool:
    if previous is None:
        return False
    row = previous["files"].get(name)
    if row is None or row["bytes"] != size or row["sha256"] != digest or row["mode"] != mode:
        return False
    root = previous["directory"]
    cached = root / safe_member(name, b"0")
    require(cached.is_file() and not cached.is_symlink()
            and cached.resolve(strict=True).is_relative_to(root)
            and cached.stat().st_size == size
            and hashlib.sha256(cached.read_bytes()).hexdigest() == digest,
            "PRIOR_SOURCE_BYTES_CHANGED")
    stamp = cached.stat().st_mtime_ns
    require(destination.is_file() and not destination.is_symlink(), "SOURCE_METADATA_DESTINATION_CHANGED")
    os.utime(destination, ns=(stamp, stamp))
    return True


def export(repo: Path, revision: str, destination: Path, previous: dict | None = None) -> dict:
    tree = git(repo, "ls-tree", "-rz", "-r", revision)
    expected = {}
    for item in tree.split(b"\0"):
        if not item:
            continue
        header, path = item.split(b"\t", 1)
        mode, kind, oid = header.split()
        require(mode in (b"100644", b"100755") and kind == b"blob",
                "SOURCE_LINK_OR_GITLINK_UNSUPPORTED")
        name = path.decode("utf-8")
        safe_member(name, b"0")
        expected[name] = (oid.decode(), int(mode, 8))
    require(expected and not destination.exists(), "SOURCE_EXPORT_TARGET_EXISTS_OR_EMPTY")
    destination.mkdir()
    # Git for Windows applies checkout CRLF filters to `git archive`, so an
    # archive is not necessarily byte-identical to its tracked Git blobs.
    # Stream exact objects through one cat-file process without a checkout.
    process = subprocess.Popen(git_command(repo, "cat-file", "--batch"),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None
    rows = []
    reused_timestamps = 0
    try:
        for name, (oid, mode) in sorted(expected.items()):
            relative = safe_member(name, b"0")
            process.stdin.write((oid + "\n").encode())
            process.stdin.flush()
            header = process.stdout.readline().split()
            require(len(header) == 3 and header[0].decode() == oid
                    and header[1] == b"blob" and header[2].isdigit(),
                    "SOURCE_OBJECT_HEADER_CHANGED")
            remaining = int(header[2])
            digest = hashlib.sha1(b"blob " + str(remaining).encode() + b"\0")
            sha256 = hashlib.sha256()
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as output:
                while remaining:
                    block = process.stdout.read(min(remaining, 4 * 1024 * 1024))
                    require(block, "SOURCE_OBJECT_TRUNCATED")
                    output.write(block)
                    digest.update(block)
                    sha256.update(block)
                    remaining -= len(block)
            require(process.stdout.read(1) == b"\n" and digest.hexdigest() == oid,
                    "SOURCE_EXPORT_BLOB_CHANGED")
            os.chmod(path, 0o755 if mode == 0o100755 else 0o644)
            reused_timestamps += reuse_timestamp(path, name, int(header[2]), sha256.hexdigest(), previous, mode)
            rows.append({"path": name, "bytes": int(header[2]), "sha256": sha256.hexdigest()})
    finally:
        process.stdin.close()
        process.stdout.close()
    require(process.wait() == 0 and len(rows) == len(expected), "SOURCE_OBJECT_STREAM_INCOMPLETE")
    inventory = destination.parent / (destination.name + "-inventory.json")
    with inventory.open("x", encoding="utf-8") as output:
        json.dump(rows, output, separators=(",", ":"))
        output.write("\n")
    return {"repository": str(repo), "revision": revision, "directory": str(destination),
            "inventory": ref(inventory), "fileCount": len(rows),
            "tree": git(repo, "rev-parse", revision + "^{tree}").decode().strip(),
            **({"sourceTimestampReuse": {"unchangedFiles": reused_timestamps,
               "changedOrNewFiles": len(rows) - reused_timestamps,
               "sourceInventory": previous["inventory"],
               "scope": "SOURCE_TIMESTAMPS_ONLY_NO_ARTIFACT_QUALIFICATION"}} if previous is not None else {})}


def stage_operator(repo: Path, revision: str, name: str, destination: Path) -> dict:
    require(name in OPERATOR_NAMES, "REVIEWED_OPERATOR_NAME_REQUIRED")
    raw = git(repo, "show", revision + ":scripts/" + name)
    with destination.open("xb") as target:
        target.write(raw)
    require(destination.read_bytes() == raw, "OPERATOR_GIT_OBJECT_COPY_CHANGED")
    return ref(destination)


def selected_sources(profile: str) -> tuple[str, str, str]:
    if profile == build.OFFICIAL_PROFILE:
        return PRODUCT, CORE, FREEZE_SHA256
    require(profile == LATEST_PROFILE, "UNKNOWN_REVIEWED_BUILD_PROFILE")
    return LATEST_PRODUCT, LATEST_CORE, LATEST_FREEZE_SHA256


def producer_identity(directory: Path, profile: str, repository: Path | None = None,
                      revision: str | None = None) -> tuple[Path, str]:
    explicit = repository is not None or revision is not None
    require(not explicit or (profile == LATEST_PROFILE and repository is not None
                             and revision is not None), "EXPLICIT_PRODUCER_REQUIRES_LATEST_PROFILE")
    producer = repository.resolve(strict=True) if repository is not None else directory.parent
    if revision is None:
        revision = git(producer, "rev-parse", "HEAD").decode().strip()
        require(not git(producer, "status", "--porcelain", "--untracked-files=all").strip(),
                "REVIEWED_BUILD_TOOL_SOURCE_CHANGED")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", revision)), "EXACT_PRODUCER_REVISION_REQUIRED")
    require(git(producer, "remote", "get-url", "origin").decode().strip() == ORIGINS["ui"]
            and git(producer, "cat-file", "-t", revision).decode().strip() == "commit",
            "CANONICAL_PRODUCER_COMMIT_REQUIRED")
    # Explicit latest-source preparation reads reviewed Git objects only. The
    # primary worktree/HEAD may contain user work; none of those bytes are used.
    names = OPERATOR_NAMES if explicit else ("build-rust-service-binaries.sh",)
    for name in names:
        path = directory / name
        require(path.is_file() and not path.is_symlink()
                and path.read_bytes() == git(producer, "show", revision + ":scripts/" + name),
                "REVIEWED_BUILD_TOOL_SOURCE_CHANGED")
    return producer, revision


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-repo", type=Path, required=True)
    parser.add_argument("--core-repo", type=Path, required=True)
    parser.add_argument("--freeze-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-profile", choices=(build.OFFICIAL_PROFILE, LATEST_PROFILE),
                        default=build.OFFICIAL_PROFILE)
    parser.add_argument("--producer-repository", type=Path)
    parser.add_argument("--producer-revision")
    parser.add_argument("--reuse-source-metadata-receipt", type=Path)
    args = parser.parse_args()
    product_revision, core_revision, freeze_sha = selected_sources(args.build_profile)
    output = args.output.resolve()
    private = (Path.home() / ".codex/private").resolve()
    require(output.is_relative_to(private) and not output.exists()
            and output.parent.is_dir() and not output.is_symlink(),
            "NEW_OWNED_PRIVATE_OUTPUT_REQUIRED")
    freeze = args.freeze_receipt.resolve(strict=True)
    require(freeze.is_file() and not freeze.is_symlink()
            and hashlib.sha256(freeze.read_bytes()).hexdigest() == freeze_sha,
            "FROZEN_SOURCE_RECEIPT_CHANGED")
    frozen = json.loads(freeze.read_text(encoding="utf-8"))
    require(frozen["productRevision"] == product_revision and frozen["coreRevision"] == core_revision,
            "FROZEN_SOURCE_SELECTION_CHANGED")
    repositories = {"ui": args.product_repo.resolve(strict=True),
                    "core": args.core_repo.resolve(strict=True)}
    for name, repo in repositories.items():
        require(git(repo, "remote", "get-url", "origin").decode().strip() == ORIGINS[name],
                "SOURCE_ORIGIN_CHANGED")
        revision = product_revision if name == "ui" else core_revision
        require(git(repo, "cat-file", "-t", revision).decode().strip() == "commit",
                "SOURCE_COMMIT_MISSING")
    product = repositories["ui"]
    require(git(product, "rev-parse", "HEAD").decode().strip() == product_revision
            and not git(product, "status", "--porcelain", "--untracked-files=all").strip(),
            "FROZEN_PRODUCT_CHECKOUT_CHANGED")
    producer, producer_revision = producer_identity(Path(__file__).resolve().parent,
        args.build_profile, args.producer_repository, args.producer_revision)
    previous = source_metadata(args.reuse_source_metadata_receipt, args.build_profile, repositories)
    output.mkdir()
    sources = {name: export(repo, product_revision if name == "ui" else core_revision,
                            output / (name + "-source"), previous.get(name)) for name, repo in repositories.items()}
    require(sources["ui"]["tree"] == frozen["productTree"], "PRODUCT_TREE_CHANGED")
    recipe = output / "build.sh"
    with recipe.open("x", encoding="utf-8", newline="\n") as target:
        target.write(build.render_recipe(args.build_profile))
    operator_directory = output / "operator"
    operator_directory.mkdir()
    operator_files = {}
    for name in OPERATOR_NAMES:
        source = Path(__file__).parent / name
        target = operator_directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(source.is_file() and not source.is_symlink(), "OPERATOR_SOURCE_MISSING")
        operator_files[name] = stage_operator(producer, producer_revision, name, target)
    (output / "output").mkdir()
    receipt = {"schema": "marty.local-official-native-source-export/v1",
               "state": "SOURCE_EXPORTED_NO_COMPILER", "freeze": ref(freeze),
               "sources": sources, "recipe": ref(recipe), "buildProfile": args.build_profile,
               "operatorFiles": operator_files,
               "producerRevision": producer_revision,
               "producerRepository": str(producer.resolve()),
               "producerTree": git(producer, "rev-parse", producer_revision + "^{tree}").decode().strip(),
               "buildTool": operator_files["build-rust-service-binaries.sh"],
               "lockGuard": operator_files["ci/check_core_localized_lock.py"],
               "imagesBuilt": False, "releaseQualified": False,
               **({"sourceMetadataReuse": ref(args.reuse_source_metadata_receipt)} if previous else {})}
    with (output / "source-export-receipt.json").open("x", encoding="utf-8") as target:
        json.dump(receipt, target, indent=2)
        target.write("\n")
    print(json.dumps({"state": receipt["state"], "product": product_revision,
                      "core": core_revision, "uiFiles": sources["ui"]["fileCount"],
                      "coreFiles": sources["core"]["fileCount"]}))


if __name__ == "__main__":
    main()
