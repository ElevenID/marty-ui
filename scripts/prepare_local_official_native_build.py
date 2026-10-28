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
from pathlib import Path, PurePosixPath
import subprocess

import scoped_native_build as build
from scoped_native_runtime import ref, require

PRODUCT = "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f"
CORE = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
FREEZE_SHA256 = "b77d6883f51bc1d3cf19d6cfa76fe567477c7d27e32134e05007c9104e49c941"
ORIGINS = {"ui": "https://github.com/ElevenID/marty-ui.git",
           "core": "https://github.com/ElevenID/marty-core.git"}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def safe_member(name: str, kind: bytes) -> Path:
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and "\0" not in name and "\r" not in name and "\n" not in name,
            "SOURCE_ARCHIVE_PATH_UNSAFE")
    require(kind in (b"0", b"5"), "SOURCE_ARCHIVE_LINK_OR_DEVICE_REFUSED")
    return Path(*path.parts)


def export(repo: Path, revision: str, destination: Path) -> dict:
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
    process = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None
    rows = []
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
            "tree": git(repo, "rev-parse", revision + "^{tree}").decode().strip()}


def stage_operator(repo: Path, revision: str, name: str, destination: Path) -> dict:
    require(name in ("scoped_native_build.py", "scoped_native_profiles.py",
                     "scoped_native_runtime.py", "scoped_linux_journal.py",
                     "prepare_local_official_native_build.py",
                     "seed_local_official_native_target.py",
                     "run_local_official_native_build.py",
                     "build-rust-service-binaries.sh"), "REVIEWED_OPERATOR_NAME_REQUIRED")
    raw = git(repo, "show", revision + ":scripts/" + name)
    with destination.open("xb") as target:
        target.write(raw)
    require(destination.read_bytes() == raw, "OPERATOR_GIT_OBJECT_COPY_CHANGED")
    return ref(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-repo", type=Path, required=True)
    parser.add_argument("--core-repo", type=Path, required=True)
    parser.add_argument("--freeze-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    private = (Path.home() / ".codex/private").resolve()
    require(output.is_relative_to(private) and not output.exists()
            and output.parent.is_dir() and not output.is_symlink(),
            "NEW_OWNED_PRIVATE_OUTPUT_REQUIRED")
    freeze = args.freeze_receipt.resolve(strict=True)
    require(freeze.is_file() and not freeze.is_symlink()
            and hashlib.sha256(freeze.read_bytes()).hexdigest() == FREEZE_SHA256,
            "FROZEN_SOURCE_RECEIPT_CHANGED")
    frozen = json.loads(freeze.read_text(encoding="utf-8"))
    require(frozen["productRevision"] == PRODUCT and frozen["coreRevision"] == CORE,
            "FROZEN_SOURCE_SELECTION_CHANGED")
    repositories = {"ui": args.product_repo.resolve(strict=True),
                    "core": args.core_repo.resolve(strict=True)}
    for name, repo in repositories.items():
        require(git(repo, "remote", "get-url", "origin").decode().strip() == ORIGINS[name],
                "SOURCE_ORIGIN_CHANGED")
        revision = PRODUCT if name == "ui" else CORE
        require(git(repo, "cat-file", "-t", revision).decode().strip() == "commit",
                "SOURCE_COMMIT_MISSING")
    product = repositories["ui"]
    require(git(product, "rev-parse", "HEAD").decode().strip() == PRODUCT
            and not git(product, "status", "--porcelain", "--untracked-files=all").strip(),
            "FROZEN_PRODUCT_CHECKOUT_CHANGED")
    producer = Path(__file__).resolve().parents[1]
    producer_revision = git(producer, "rev-parse", "HEAD").decode().strip()
    require(not git(producer, "status", "--porcelain", "--untracked-files=all").strip()
            and git(producer, "show", producer_revision + ":scripts/build-rust-service-binaries.sh")
            == (producer / "scripts/build-rust-service-binaries.sh").read_bytes(),
            "REVIEWED_BUILD_TOOL_SOURCE_CHANGED")
    output.mkdir()
    sources = {name: export(repo, PRODUCT if name == "ui" else CORE,
                            output / (name + "-source")) for name, repo in repositories.items()}
    require(sources["ui"]["tree"] == frozen["productTree"], "PRODUCT_TREE_CHANGED")
    recipe = output / "build.sh"
    with recipe.open("x", encoding="utf-8", newline="\n") as target:
        target.write(build.render_recipe(build.OFFICIAL_PROFILE))
    operator_directory = output / "operator"
    operator_directory.mkdir()
    operator_files = {}
    for name in ("scoped_native_build.py", "scoped_native_profiles.py",
                 "scoped_native_runtime.py", "scoped_linux_journal.py",
                 "prepare_local_official_native_build.py",
                 "seed_local_official_native_target.py",
                 "run_local_official_native_build.py",
                 "build-rust-service-binaries.sh"):
        source = Path(__file__).with_name(name)
        target = operator_directory / name
        require(source.is_file() and not source.is_symlink(), "OPERATOR_SOURCE_MISSING")
        operator_files[name] = stage_operator(producer, producer_revision, name, target)
    (output / "output").mkdir()
    receipt = {"schema": "marty.local-official-native-source-export/v1",
               "state": "SOURCE_EXPORTED_NO_COMPILER", "freeze": ref(freeze),
               "sources": sources, "recipe": ref(recipe), "buildProfile": build.OFFICIAL_PROFILE,
               "operatorFiles": operator_files,
               "producerRevision": producer_revision,
               "producerTree": git(producer, "rev-parse", "HEAD^{tree}").decode().strip(),
               "buildTool": operator_files["build-rust-service-binaries.sh"],
               "imagesBuilt": False, "releaseQualified": False}
    with (output / "source-export-receipt.json").open("x", encoding="utf-8") as target:
        json.dump(receipt, target, indent=2)
        target.write("\n")
    print(json.dumps({"state": receipt["state"], "product": PRODUCT,
                      "core": CORE, "uiFiles": sources["ui"]["fileCount"],
                      "coreFiles": sources["core"]["fileCount"]}))


if __name__ == "__main__":
    main()
