#!/usr/bin/env python3
"""Fetch and authenticate one exact original package application publication.

Only the fixed successful Actions artifact is accepted. All downloaded files
remain inert, and the new destination appears after original receipt/image
verification and a final comparison with every byte extracted from the archive.
This intake does not establish backend compatibility or deployment authority.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import io
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import zipfile
import zlib

import application_provenance as application_proof
import application_release as application
import ui_release as ui
import web_auth as auth
import website_producer_policy as policy
import website_provenance as proof
import website_release as web

PLAN = "application-build-plan.json"
FULL_BASELINE = "application-source-closure.json"
PROOFS = (application.RECEIPT + ".sigstore.json", application.RECEIPT + ".provenance.jsonl", "image.provenance.jsonl")
FILES = (*application.ASSET_FILES, PLAN, FULL_BASELINE, *PROOFS)
FILE_LIMITS = {name: (application.ARCHIVE_LIMIT if name.endswith(".zip") else
                     proof.PROOF_LIMIT if name in PROOFS else application.JSON_LIMIT) for name in FILES}
MAX_ARCHIVE = auth.ARCHIVE_LIMIT
MAX_EXPANDED = sum(FILE_LIMITS.values())


def _selection(repository: str, run_id: str, attempt: str, source_sha: str) -> dict:
    ui.require(repository == ui.REPOSITORY, "package application requires its original public producer")
    return proof.validate_producer({"repository": repository, "workflow": ui.WORKFLOW, "ref": web.REF,
                                    "source_sha": web.full_sha(source_sha), "run_id": run_id,
                                    "run_attempt": attempt}, role="application")


def attempt_identity(value: dict, *, producer: dict) -> None:
    selected = policy.producer_policy(producer["repository"], role="application")
    ui.require(isinstance(value, dict), "application attempt metadata must be an object")
    repository = value.get("repository")
    ui.require(isinstance(repository, dict) and repository.get("full_name") == producer["repository"]
               and type(repository.get("id")) is int and repository["id"] == int(selected["repository_id"]),
               "application attempt repository differs")
    ui.require(type(value.get("id")) is int and value["id"] == int(producer["run_id"])
               and type(value.get("run_attempt")) is int and value["run_attempt"] == int(producer["run_attempt"])
               and value.get("status") == "completed" and value.get("conclusion") == "success"
               and value.get("event") == "workflow_dispatch" and value.get("head_branch") == "main"
               and value.get("head_sha") == producer["source_sha"]
               and value.get("path") in {ui.WORKFLOW, ui.WORKFLOW + "@main", ui.WORKFLOW + "@" + web.REF},
               "application attempt is not the selected successful protected-main publication")


def archive_selection(value: dict, *, producer: dict) -> dict:
    ui.require(isinstance(value, dict) and type(value.get("total_count")) is int and value["total_count"] == 1
               and isinstance(value.get("artifacts"), list) and len(value["artifacts"]) == 1,
               "one exact application release artifact is required")
    artifact = value["artifacts"][0]
    ui.require(isinstance(artifact, dict), "application artifact metadata must be an object")
    run = artifact.get("workflow_run")
    selected = policy.producer_policy(producer["repository"], role="application")
    ui.require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] == int(producer["run_id"])
               and run.get("head_sha") == producer["source_sha"] and run.get("head_branch") == "main"
               and type(run.get("repository_id")) is int and run["repository_id"] == int(selected["repository_id"]),
               "application artifact does not belong to the selected producer")
    ui.require(artifact.get("name") == f"application-release-{producer['run_id']}-{producer['run_attempt']}"
               and artifact.get("expired") is False and type(artifact.get("id")) is int and artifact["id"] > 0
               and type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE,
               "application release artifact identity or bounds differ")
    web.image_digest(artifact.get("digest"))
    return artifact


def _archive_layout(raw: bytes, archive: zipfile.ZipFile, entries: list[zipfile.ZipInfo]) -> None:
    """The pinned Actions uploader emits ordinary single-disk, non-ZIP64 ZIPs.

    Require the local and central records to describe the same closed payload,
    including streaming data descriptors. This rejects hidden records, prefixes,
    suffixes, ambiguous local names and inconsistent CRC/size declarations.
    ZipFile independently checks decompression, overlap and actual member CRCs.
    """
    ui.require(len(raw) >= 22, "application artifact is not an ordinary ZIP")
    end = struct.unpack("<4s4H2IH", raw[-22:])
    signature, disk, central_disk, disk_count, count, central_size, central_offset, comment_size = end
    ui.require(signature == b"PK\x05\x06" and disk == central_disk == comment_size == 0
               and disk_count == count == len(entries) and central_offset + central_size == len(raw) - 22
               and archive.start_dir == central_offset and not archive.comment,
               "application ZIP directory or trailing data is ambiguous")
    ordered = sorted(entries, key=lambda entry: entry.header_offset)
    position = 0
    for index, entry in enumerate(ordered):
        ui.require(entry.header_offset == position and position + 30 <= central_offset,
                   "application ZIP has hidden or overlapping records")
        header = struct.unpack("<4s5H3I2H", raw[position:position + 30])
        signature, _version, flags, method, _time, _date, crc, compressed, expanded, name_size, extra_size = header
        start = position + 30
        ui.require(signature == b"PK\x03\x04" and flags == entry.flag_bits and method == entry.compress_type
                   and raw[start:start + name_size] == entry.filename.encode("ascii") and extra_size == 0,
                   "application ZIP local header differs")
        position = start + name_size + entry.compress_size
        next_position = ordered[index + 1].header_offset if index + 1 < len(ordered) else central_offset
        if flags & 8:
            ui.require(crc in {0, entry.CRC} and compressed in {0, entry.compress_size}
                       and expanded in {0, entry.file_size}, "application ZIP streaming header differs")
            descriptor = raw[position:next_position]
            if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08":
                descriptor = descriptor[4:]
            ui.require(len(descriptor) == 12
                       and struct.unpack("<3I", descriptor) == (entry.CRC, entry.compress_size, entry.file_size),
                       "application ZIP data descriptor differs")
            position = next_position
        else:
            ui.require((crc, compressed, expanded) == (entry.CRC, entry.compress_size, entry.file_size)
                       and position == next_position, "application ZIP local size or CRC differs")
    ui.require(position == central_offset, "application ZIP payload closure differs")


def _extract_receipt(raw: bytes, destination: Path) -> dict:
    """Extract only into the caller's disposable private staging directory."""
    ui.require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE, "application archive exceeds limit")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            ui.require(len(entries) == len(FILES) and {entry.filename for entry in entries} == set(FILES),
                       "application archive contains unexpected, missing or duplicate members")
            for entry in entries:
                mode = entry.external_attr >> 16
                ui.require(entry.orig_filename == entry.filename and not entry.is_dir()
                           and mode in {0, 0o600, 0o644, stat.S_IFREG | 0o600, stat.S_IFREG | 0o644}
                           and not entry.external_attr & 0x10 and entry.create_system in {0, 3} and entry.volume == 0
                           and not entry.flag_bits & ~(8 | 0x800) and entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                           and not entry.extra and not entry.comment and 0 < entry.file_size <= FILE_LIMITS[entry.filename],
                           "application archive member is unsafe or exceeds its bound")
            ui.require(sum(entry.file_size for entry in entries) <= MAX_EXPANDED, "expanded application archive exceeds limit")
            _archive_layout(raw, archive, entries)
            destination.mkdir(mode=0o700)
            originals = {}
            for entry in entries:
                with archive.open(entry) as source:
                    value = source.read(FILE_LIMITS[entry.filename] + 1)
                ui.require(len(value) == entry.file_size, "application archive member size differs")
                target = destination / entry.filename
                with target.open("xb") as output:
                    target.chmod(0o600)
                    output.write(value)
                originals[entry.filename] = application.file_record(value)
            return originals
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, NotImplementedError, RuntimeError, struct.error, zlib.error):
        raise ValueError("invalid application release archive") from None


def _originals(directory: Path) -> dict:
    ui.require({path.name for path in directory.iterdir()} == set(FILES), "application intake file closure changed")
    result = {}
    for name in FILES:
        path = directory / name
        proof.verifier.local_file(path, private=True, maximum=FILE_LIMITS[name])
        ui.require(stat.S_IMODE(path.stat().st_mode) == 0o600, "application intake file mode changed")
        result[name] = application.file_record(application.read_bytes(path, FILE_LIMITS[name]))
    return result


def _validate_retained(directory: Path, release: dict) -> None:
    raw = application.read_bytes(directory / PLAN)
    ui.require(application.parse(raw) == release["build_plan"] and ui.digest(raw) == release["build_plan_sha256"],
               "retained application build plan differs from its signed receipt")
    raw = application.read_bytes(directory / FULL_BASELINE)
    profile = application.read(directory / "application-profile-source-closure.json")
    dependency = profile.get("dependency_profile")
    ui.require(isinstance(dependency, dict) and dependency.get("name") == "application",
               "retained profile omits its full-source baseline")
    baseline = dependency.get("baseline_report")
    ui.require(isinstance(baseline, dict)
               and {key: baseline.get(key) for key in ("bytes", "sha256")} == application.file_record(raw),
               "retained full-source baseline differs from its signed profile pin")
    report = application.parse(raw)
    plan = report.get("plan")
    ui.require(isinstance(plan, dict) and isinstance(plan.get("source"), dict), "retained baseline source is invalid")
    source = plan["source"]
    bun = release["build_plan"]["schema"] == application.BUN_PLAN_SCHEMA
    version = 6 if bun else 4
    ui.require(report.get("schema") == f"marty.application-source-closure-rehearsal/v{version}" and report.get("status") == "passed"
               and report.get("fixture", False) is False and plan.get("schema") == f"marty.application-source-closure-plan/v{version}"
               and not plan.get("dependency_profile") and source.get("commit") == release["source_sha"]
               and source.get("working_tree_dirty") is False and source.get("git_status") == [],
               "retained full-source baseline belongs to a different qualification")
    if not bun:
        return  # Preserve the original v1 receipt / v4 full-baseline contract.

    build, installed = report.get("build"), report.get("dependency_install")
    ui.require(isinstance(build, dict) and isinstance(installed, dict), "retained Bun installation is missing")
    ui.require(all(value.get("package_manager") == application.BUN_PACKAGE_MANAGER for value in (plan, build, installed)),
               "retained full-source package manager differs")
    ui.require(build.get("dependency_mode") == "fresh-bun-frozen" and build.get("dependency_profile") == "full"
               and build.get("effective_source_sha") == release["source_sha"]
               and installed.get("mode") == "fresh-bun-frozen" and installed.get("status") == "passed"
               and installed.get("dependency_profile") == "full"
               and installed.get("bun_version") == application.BUN_PACKAGE_MANAGER["version"]
               and installed.get("bun_lock_selected") is True
               and installed.get("independent_dependency_installation") is True,
               "retained full-source Bun installation differs")
    profile_plan, files = profile.get("plan"), source.get("files")
    ui.require(isinstance(profile_plan, dict) and source == profile_plan.get("source")
               and isinstance(files, list) and files and all(isinstance(row, dict) for row in files)
               and source.get("input_inventory_sha256") == ui.digest(application.compact(files)),
               "retained full-source inventory differs from its application profile")
    # The full baseline uses the original full locks. The release plan instead
    # binds the smaller application lock materialized into its source package.
    for name, field in (("ui/bun.lock", "dependency_lock_sha256"), ("ui/package-lock.json", "package_lock_sha256")):
        locks = [row for row in files if row.get("path") == name]
        ui.require(len(locks) == 1, "retained full-source lock inventory is ambiguous")
        ui.require(web.image_digest(locks[0].get("sha256")) == build.get(field), "retained full-source lock differs")


def _publish_directory(source: Path, destination: Path) -> None:
    """Linux publication is atomic and must never replace a concurrent output."""
    ui.require(sys.platform == "linux", "atomic application intake is qualified only on Linux")
    source_bytes, destination_bytes = os.fsencode(source), os.fsencode(destination)
    ui.require(b"\0" not in source_bytes and b"\0" not in destination_bytes,
               "application intake paths cannot contain NUL bytes")
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise ValueError("atomic application intake requires renameat2 without replacement") from None
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # Both paths are absolute. AT_FDCWD=-100; RENAME_NOREPLACE=1. There is no
    # check-then-replacing-rename fallback on unsupported kernels/filesystems.
    if rename(-100, source_bytes, -100, destination_bytes, 1) != 0:
        if ctypes.get_errno() in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ValueError("application intake destination appeared during verification")
        raise ValueError("atomic application intake publication failed")


def fetch(*, run_id: str, attempt: str, source_sha: str, destination: Path, gh: Path, cosign: Path,
          repository: str = ui.REPOSITORY, github_token_env: str = "GH_TOKEN", reader: auth.GitHubReader | None = None,
          runner: proof.verifier.Run = proof.verifier.command) -> dict:
    producer = _selection(repository, run_id, attempt, source_sha)
    destination, gh, cosign = destination.absolute(), gh.absolute(), cosign.absolute()
    ui.require(not os.path.lexists(destination), "application intake destination already exists")
    for tool in (gh, cosign):
        proof.verifier.local_file(tool)
    if reader is None:
        reader = auth.GitHubReader(gh=gh, repository=repository, run_id=run_id, attempt=attempt,
                                  kind="package-application", token_env=github_token_env)
    attempt_identity(proof.parse_verified_json(reader.attempt()), producer=producer)
    artifact = archive_selection(proof.parse_verified_json(reader.artifacts()), producer=producer)
    raw = reader.archive(artifact["id"], maximum=artifact["size_in_bytes"])
    ui.require(type(raw) is bytes and len(raw) == artifact["size_in_bytes"] and ui.digest(raw) == artifact["digest"],
               "application artifact bytes differ from GitHub metadata")
    with tempfile.TemporaryDirectory(prefix=".application-intake-", dir=destination.parent) as temporary:
        held = Path(temporary) / "assets"
        originals = _extract_receipt(raw, held)
        release = application.validate_release(application.read(held / application.RECEIPT), source_sha=source_sha)
        ui.require(release["producer"] == producer, "application receipt belongs to another selected producer attempt")
        _validate_retained(held, release)
        authenticated = application_proof.verify_package_application(held, gh=gh, cosign=cosign,
                                                                      source_sha=source_sha, runner=runner)
        ui.require(authenticated == release and _originals(held) == originals, "application originals changed during intake")
        ui.require(not os.path.lexists(destination), "application intake destination appeared during verification")
        _publish_directory(held, destination)
    return release


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", choices=(ui.REPOSITORY,), default=ui.REPOSITORY)
    for name in ("run-id", "run-attempt", "source-sha"):
        parser.add_argument("--" + name, required=True)
    for name in ("assets", "gh", "cosign"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--github-token-env", choices=("GH_TOKEN", "GITHUB_TOKEN"), default="GH_TOKEN")
    args = parser.parse_args()
    fetch(repository=args.repository, run_id=args.run_id, attempt=args.run_attempt, source_sha=args.source_sha,
          destination=args.assets, gh=args.gh, cosign=args.cosign, github_token_env=args.github_token_env)


if __name__ == "__main__":
    main()
