#!/usr/bin/env python3
"""Bind an unsigned local Signing Keys OCI archive for the opt-in installer test.

This command inspects existing inputs. It never builds, loads, tags, publishes,
or removes an image. Native Buildx metadata is local evidence, not a publisher
attestation. The Rust development harness separately imports the exact archive
and binds the image identity observed on its own rootless Docker daemon.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

# Inspecting the pinned checkout must not create an ignored __pycache__ before
# its own cleanliness check. This command only writes its explicit output.
sys.dont_write_bytecode = True
import build_verification_candidate as oci

SCHEMA = "elevenid.installer-development-signing-image/v1"
DOCKERFILE = "rust/services/signing-keys/Dockerfile"
MAX_METADATA_BYTES = 16 * 1024 * 1024
BUILD_TYPE = "https://mobyproject.org/buildkit@v1"
require = oci.require


def _stamp(path: Path, maximum: int) -> tuple[int, ...]:
    require(path.is_absolute() and path.resolve() == path, "input path is not canonical")
    value = path.lstat()
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_nlink == 1
        and value.st_uid == os.geteuid()
        and value.st_mode & 0o022 == 0
        and 0 < value.st_size <= maximum,
        "input must be a bounded, owned regular file",
    )
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        timeout=30,
    )
    require(result.returncode == 0, "clean pinned Git source is unavailable")
    require(len(result.stdout) <= MAX_METADATA_BYTES, "Git source record is too large")
    return result.stdout


def _source(root: Path, source_sha: str) -> tuple[str, bytes]:
    require(bool(oci.COMMIT.fullmatch(source_sha)), "source SHA must be full lowercase hex")
    require(
        Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() == root
        and _git(root, "rev-parse", "HEAD").decode().strip() == source_sha,
        "source checkout does not match the pinned commit",
    )
    require(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        )
        == b"",
        "source checkout must be clean, including ignored and untracked files",
    )
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    require(bool(oci.COMMIT.fullmatch(tree)), "source tree SHA is invalid")
    path = root / DOCKERFILE
    before = _stamp(path, 64 * 1024)
    contents = path.read_bytes()
    require(
        contents == _git(root, "show", f"{source_sha}:{DOCKERFILE}")
        and _stamp(path, 64 * 1024) == before,
        "canonical Dockerfile differs from the pinned source",
    )
    return tree, contents


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "build metadata contains duplicate JSON keys")
        value[key] = item
    return value


def _constant(_value: str) -> None:
    raise ValueError("build metadata contains a non-finite JSON value")


def _build_metadata(
    raw: bytes,
    image: dict[str, Any],
    source_sha: str,
    version: str,
    dockerfile: bytes,
) -> None:
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    require(isinstance(value, dict), "build metadata must contain an object")
    require(
        set(value)
        <= {
            "buildx.build.ref",
            "buildx.build.provenance",
            "buildx.build.warnings",
            "containerimage.config.digest",
            "containerimage.descriptor",
            "containerimage.digest",
            "image.name",
        },
        "build metadata contains unsupported fields",
    )
    if "image.name" in value:
        require(
            value["image.name"] in {
                f"{oci.SIGNING_KEYS_DEVELOPMENT_REPOSITORY}:{image['archive_tag']}",
                f"{oci.SIGNING_KEYS_DEVELOPMENT_REPOSITORY.removeprefix('docker.io/')}:{image['archive_tag']}",
            },
            "native build metadata contains another image name",
        )
    require(
        value.get("containerimage.config.digest") == image["config_digest"]
        and value.get("containerimage.digest")
        in {image["digest"], image["export_digest"]},
        "native build metadata does not identify the inspected OCI image",
    )
    if "containerimage.descriptor" in value:
        descriptor = value["containerimage.descriptor"]
        require(
            isinstance(descriptor, dict)
            and descriptor.get("digest") == value["containerimage.digest"]
            and descriptor.get("mediaType") in {oci.OCI_MANIFEST, oci.OCI_INDEX}
            and type(descriptor.get("size")) is int
            and 0 < descriptor["size"] <= MAX_METADATA_BYTES,
            "native build image descriptor changed",
        )
    reference = value.get("buildx.build.ref")
    require(
        isinstance(reference, str)
        and 0 < len(reference) <= 1024
        and not any(ord(character) < 32 for character in reference),
        "native build reference is missing or invalid",
    )
    provenance = value.get("buildx.build.provenance")
    require(isinstance(provenance, dict), "native max build provenance is required")
    # Buildx's default local v0.2 max metadata includes the actual Dockerfile
    # bytes. Bind those bytes, rather than trusting its possibly basename-only
    # filename or treating this unsigned record as a release attestation.
    require(provenance.get("buildType") == BUILD_TYPE, "native build provenance type differs")
    invocation = provenance.get("invocation")
    require(isinstance(invocation, dict), "native build invocation is missing")
    parameters = invocation.get("parameters")
    source = invocation.get("configSource")
    names = {DOCKERFILE, Path(DOCKERFILE).name}
    require(
        isinstance(source, dict) and source.get("entryPoint") in names,
        "native build Dockerfile differs",
    )
    record = provenance.get("metadata")
    require(isinstance(record, dict), "native build source metadata is missing")
    details = record.get(f"{BUILD_TYPE}#metadata")
    require(isinstance(details, dict), "native max build source details are missing")
    vcs = details.get("vcs")
    require(
        isinstance(vcs, dict) and vcs.get("revision") == source_sha,
        "native build did not use the clean pinned source commit",
    )
    source_details = details.get("source")
    require(isinstance(source_details, dict), "native build source details changed")
    infos = source_details.get("infos")
    require(isinstance(infos, list) and 0 < len(infos) <= 128, "native build source files differ")
    dockerfiles = [info for info in infos if isinstance(info, dict) and info.get("filename") in names]
    require(len(dockerfiles) == 1, "native build Dockerfile evidence is ambiguous")
    data = dockerfiles[0].get("data")
    require(
        isinstance(data, str)
        and len(data) <= 128 * 1024
        and base64.b64decode(data, validate=True) == dockerfile,
        "native build Dockerfile bytes differ from the pinned source",
    )
    require(isinstance(parameters, dict), "native build parameters are missing")
    arguments = parameters.get("args")
    require(isinstance(arguments, dict), "native build arguments are missing")
    require(
        dockerfile.startswith(b"# syntax=docker/dockerfile:1.7\n")
        and parameters.get("frontend") == "gateway.v0"
        and arguments.get("source") in {"docker/dockerfile:1.7", "docker.io/docker/dockerfile:1.7"}
        and arguments.get("cmdline") == arguments.get("source"),
        "native build frontend differs from the canonical Dockerfile",
    )
    expected = {
        "build-arg:CARGO_BUILD_JOBS": "1",
        "build-arg:MARTY_UI_SHA": source_sha,
        "build-arg:MARTY_RELEASE_VERSION": version,
    }
    require(
        {name: item for name, item in arguments.items() if name.startswith("build-arg:")}
        == expected
        and arguments.get("filename", source["entryPoint"]) in names
        and arguments.get("platform", "linux/amd64") == "linux/amd64"
        and arguments.get("target", "") == ""
        and arguments.get("vcs:revision", source_sha) == source_sha
        and parameters.get("secrets") in (None, [])
        and parameters.get("ssh") in (None, []),
        "native build source, arguments, platform or extra inputs differ",
    )


def prepare(
    *,
    source_root: Path,
    source_sha: str,
    archive: Path,
    build_metadata: Path,
    output: Path,
) -> dict[str, Any]:
    root = source_root.resolve(strict=True)
    archive = archive.absolute()
    build_metadata = build_metadata.absolute()
    output = output.absolute()
    require(root.is_dir(), "source root is not a directory")
    require(
        all(not path.resolve().is_relative_to(root) for path in (archive, build_metadata, output)),
        "build artifacts must be outside the clean source checkout",
    )
    source_tree, dockerfile = _source(root, source_sha)
    archive_stamp = _stamp(archive, oci.MAX_ARCHIVE_BYTES)
    metadata_stamp = _stamp(build_metadata, MAX_METADATA_BYTES)
    archive_digest = oci.file_digest(archive).removeprefix("sha256:")
    metadata = build_metadata.read_bytes()
    version = f"unsigned-installer-development-{source_sha}"
    image = oci.inspect_oci_archive(
        archive,
        commit=source_sha,
        version=version,
        profile=oci.SIGNING_KEYS_DEVELOPMENT_PROFILE,
    )
    _build_metadata(metadata, image, source_sha, version, dockerfile)
    require(
        _stamp(archive, oci.MAX_ARCHIVE_BYTES) == archive_stamp
        and oci.file_digest(archive).removeprefix("sha256:") == archive_digest
        and _stamp(build_metadata, MAX_METADATA_BYTES) == metadata_stamp
        and build_metadata.read_bytes() == metadata
        and _source(root, source_sha) == (source_tree, dockerfile),
        "source or build artifact changed during inspection",
    )
    receipt = {
        "schema": SCHEMA,
        "role": "signing-keys",
        "source_sha": source_sha,
        "source_tree_sha": source_tree,
        "dockerfile_sha256": hashlib.sha256(dockerfile).hexdigest(),
        "build_metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "archive_sha256": archive_digest,
        "archive_size": archive_stamp[6],
        "manifest_digest": image["digest"],
        "config_digest": image["config_digest"],
        "platform": "linux/amd64",
        "version": version,
        "archive_tag": image["archive_tag"],
    }
    require(output.parent.resolve(strict=True) == output.parent, "output parent is not canonical")
    parent = output.parent.stat()
    require(
        parent.st_uid == os.geteuid() and parent.st_mode & 0o022 == 0,
        "output parent is not privately controlled",
    )
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(oci.canonical_json(receipt) + b"\n")
        destination.flush()
        os.fsync(destination.fileno())
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--build-metadata", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = prepare(**vars(args))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"unsigned development image binding refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"classification": "UNSIGNED DEVELOPMENT ONLY", "source_sha": result["source_sha"], "binding": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
