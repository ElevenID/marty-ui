#!/usr/bin/env python3
"""Verify an independent product candidate archive without extracting it.

This checks the producer payload and identity on any Python 3.11+ host. It does
not authenticate GitHub attestations, inspect OCI images, or qualify a runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

SHA = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"[1-9][0-9]*\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
ROLES = {
    "marty-server": {"keycloak", "migrations", "openbao-didcomm", "services"},
    "marty-console": {"ui"},
}
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILES = 256
MAX_TOTAL = 64 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant: {value}")


def read_json(data: bytes) -> dict:
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    require(isinstance(value, dict), "JSON root must be an object")
    return value


def verify(archive: Path, checksum: Path, product: str, run_id: str,
           attempt: str, source_sha: str) -> dict:
    require(product in ROLES, "unknown product")
    require(RUN.fullmatch(run_id) is not None, "invalid producer run ID")
    require(RUN.fullmatch(attempt) is not None, "invalid producer attempt")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "invalid source commit")
    require(archive.is_file() and not archive.is_symlink()
            and checksum.is_file() and not checksum.is_symlink(),
            "candidate inputs must be regular files")
    require(0 < archive.stat().st_size <= MAX_ARCHIVE, "archive size is invalid")
    archive_hash = digest(archive.read_bytes())
    checksum_text = checksum.read_text(encoding="utf-8")
    require(checksum_text == f"{archive_hash}  product-package.tar.gz\n",
            "adjacent archive checksum differs")

    files: dict[str, bytes] = {}
    directories: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        require(0 < len(members) <= MAX_FILES, "unexpected member count")
        for item in members:
            name = item.name
            parts = PurePosixPath(name).parts
            require(bool(name) and not name.startswith("/") and "\\" not in name
                    and all(part not in ("", ".", "..") for part in parts)
                    and PurePosixPath(name).as_posix() == name,
                    "unsafe archive path")
            require(name not in files and name not in directories,
                    "duplicate archive member")
            require(item.uid == item.gid == item.mtime == 0
                    and item.uname == item.gname == "", "archive metadata changed")
            if item.isdir():
                require(item.mode == 0o755 and item.size == 0,
                        "directory metadata changed")
                directories.add(name)
            else:
                require(item.isfile() and item.mode ==
                        (0o755 if name.endswith(".sh") else 0o644),
                        "unsupported member or file mode")
                total += item.size
                require(total <= MAX_TOTAL, "archive payload exceeds bound")
                stream = bundle.extractfile(item)
                require(stream is not None, "archive file is unreadable")
                files[name] = stream.read()

    require("SHA256SUMS" in files and "product-package.json" in files
            and "build-plan.json" in files, "required archive files missing")
    inventory: dict[str, str] = {}
    lines = files["SHA256SUMS"].decode("utf-8").splitlines(keepends=True)
    require(bool(lines) and all(line.endswith("\n") and not line.endswith("\r\n")
                                for line in lines), "checksum inventory line endings changed")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n", line)
        require(match is not None, "malformed checksum inventory")
        value, name = match.groups()
        require(name not in inventory, "duplicate checksum inventory entry")
        inventory[name] = value
    require(list(inventory) == sorted(inventory), "checksum inventory is not sorted")
    require(set(inventory) == set(files) - {"SHA256SUMS"},
            "checksum inventory does not cover exact files")
    require(all(digest(files[name]) == value for name, value in inventory.items()),
            "archive file checksum differs")
    for name in files:
        parts = PurePosixPath(name).parts
        require(all("/".join(parts[:index]) in directories
                    for index in range(1, len(parts))),
                "archive parent directory missing")

    package = read_json(files["product-package.json"])
    plan = read_json(files["build-plan.json"])
    version = package.get("version")
    require(isinstance(version, str) and VERSION.fullmatch(version) is not None,
            "candidate version is invalid")
    require(package.get("schema") == "marty.product-package/v1"
            and package.get("product") == product
            and package.get("tag") ==
                ("server-v" if product == "marty-server" else "console-v") + version
            and package.get("support_state") == "experimental"
            and package.get("qualification") == "unqualified",
            "candidate package identity or qualification changed")
    require(package.get("source") == {"repository": "ElevenID/marty-ui",
                                      "commit": source_sha}
            and package.get("producer") == {
                "workflow": ".github/workflows/product-packages.yml",
                "run_id": run_id, "run_attempt": attempt},
            "candidate source or producer changed")
    require(package.get("api") == {"http": "v1", "mip": "0.5.0"}
            and package.get("platforms") == ["linux/amd64"],
            "candidate API or platform changed")
    require(plan.get("repository") == "ElevenID/marty-ui"
            and plan.get("source_sha") == source_sha
            and plan.get("product") == product
            and plan.get("version") == package["version"]
            and plan.get("tag") == package["tag"]
            and plan.get("qualification") == "unqualified",
            "build plan differs from package identity")
    canonical_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    require(package.get("build_plan_sha256") == "sha256:" + digest(canonical_plan),
            "build plan digest differs")
    images = package.get("images")
    require(isinstance(images, list) and len(images) == len(ROLES[product]),
            "image count differs")
    require({image.get("role") for image in images if isinstance(image, dict)}
            == ROLES[product], "image roles differ")
    planned = {image["role"]: image for image in plan["images"]}
    require(set(planned) == ROLES[product], "planned image roles differ")
    for image in images:
        role = image["role"]
        require(set(image) == {"role", "uri", "digest", "platform"}
                and image["uri"] == planned[role]["image"]
                and image["platform"] == "linux/amd64"
                and isinstance(image["digest"], str)
                and image["digest"].startswith("sha256:")
                and SHA.fullmatch(image["digest"][7:]) is not None,
                "image differs from plan or has invalid digest")
    runtime = plan.get("runtime_files")
    require(isinstance(runtime, list)
            and (len(runtime) == 27 if product == "marty-server" else not runtime),
            "runtime file count differs")
    runtime_paths = set()
    for item in runtime:
        require(set(item) == {"path", "sha256", "source_sha256"}
                and isinstance(item["path"], str), "runtime input changed")
        name = "runtime/" + item["path"]
        require(name in files and name not in runtime_paths
                and item["sha256"] == "sha256:" + digest(files[name]),
                "runtime payload differs from build plan")
        runtime_paths.add(name)
    require({name for name in files if name.startswith("runtime/")} == runtime_paths,
            "unexpected or missing runtime payload")
    require(("docker-compose.console.yml" in files) == (product == "marty-console"),
            "console composition boundary changed")
    return {
        "schema": "marty.product-candidate-payload-verification/v1",
        "product": product,
        "version": version,
        "source_sha": source_sha,
        "producer_run_id": run_id,
        "producer_run_attempt": attempt,
        "archive_sha256": "sha256:" + archive_hash,
        "package_sha256": "sha256:" + digest(files["product-package.json"]),
        "file_count": len(files),
        "runtime_file_count": len(runtime),
        "images": sorted(images, key=lambda image: image["role"]),
        "result": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksum", type=Path, required=True)
    parser.add_argument("--product", choices=ROLES, required=True)
    parser.add_argument("--producer-run-id", required=True)
    parser.add_argument("--producer-run-attempt", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.archive, args.checksum, args.product,
                    args.producer_run_id, args.producer_run_attempt, args.source_sha)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
