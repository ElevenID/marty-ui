"""Acquire exact staged nightly installer inputs from one pinned build artifact.

This controller transport step does not authenticate installer signatures or
authorize a guest. The initial signed grant receiver must do that afterward.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import struct
import time
import zipfile

import installer_candidate_dispatch as dispatch
import installer_candidate_grant_receive as archive_transport
import installer_candidate_public_release as public_release
import installer_candidate_rendezvous as transport
import installer_promote as promotion
import installer_release as release
from installer_candidate_authorize import write_exclusive

ARCHIVE_MAX = 1024 * 1024 * 1024
EXPANDED_MAX = 1024 * 1024 * 1024
DIRECTORY_MAX = 128 * 1024


def preflight_zip(fd: int, size: int) -> None:
    """Bound metadata before ZipFile allocates one object per central entry."""
    release.require(22 <= size <= ARCHIVE_MAX, "staged ZIP size invalid")
    end = os.pread(fd, 22, size - 22)
    release.require(len(end) == 22 and end[:4] == b"PK\x05\x06",
                    "staged ZIP needs a fixed terminal directory")
    disk, directory_disk, disk_count, count, directory_size, directory_offset, comment = (
        struct.unpack_from("<HHHHIIH", end, 4))
    release.require(disk == directory_disk == 0 and disk_count == count
                    and 0 < count <= 100 and comment == 0
                    and 0 < directory_size <= DIRECTORY_MAX
                    and directory_offset + directory_size == size - 22,
                    "staged ZIP directory exceeds bound or uses ZIP64")
    release.require(size < 42 or os.pread(fd, 4, size - 42) != b"PK\x06\x07",
                    "staged ZIP64 locator refused")
    raw = os.pread(fd, directory_size, directory_offset)
    release.require(len(raw) == directory_size, "staged ZIP directory truncated")
    position = 0
    for _ in range(count):
        release.require(position + 46 <= len(raw) and raw[position:position + 4] == b"PK\x01\x02",
                        "staged ZIP central entry differs")
        filename, extra, member_comment, start_disk = struct.unpack_from("<HHHH", raw, position + 28)
        compressed_size, expanded_size = struct.unpack_from("<II", raw, position + 20)
        local_offset = struct.unpack_from("<I", raw, position + 42)[0]
        release.require(0 < filename <= 128 and start_disk == 0,
                        "staged ZIP central entry exceeds bound")
        release.require(0xffffffff not in (compressed_size, expanded_size, local_offset),
                        "staged ZIP64 member refused")
        extra_bytes = raw[position + 46 + filename:position + 46 + filename + extra]
        extra_position = 0
        while extra_position < len(extra_bytes):
            release.require(extra_position + 4 <= len(extra_bytes),
                            "staged ZIP extra field truncated")
            field_id, field_size = struct.unpack_from("<HH", extra_bytes, extra_position)
            release.require(field_id != 1 and extra_position + 4 + field_size <= len(extra_bytes),
                            "staged ZIP64 or malformed extra field refused")
            extra_position += 4 + field_size
        position += 46 + filename + extra + member_comment
        release.require(position <= len(raw), "staged ZIP central entry truncated")
    release.require(position == len(raw), "staged ZIP central directory differs")


def extract_selected(stream, output: Path, parent_fd: int) -> None:
    limits = public_release.expected_assets()
    release.require(not output.exists(), "staged asset output already exists")
    os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
    os.fsync(parent_fd)
    held = dispatch._directory(output)
    try:
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            release.require(0 < len(entries) <= 100 and len(set(names)) == len(names)
                            and set(limits) <= set(names), "staged artifact member closure differs")
            total = 0
            for entry in entries:
                name = entry.filename
                mode = entry.external_attr >> 16
                release.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                                and not entry.is_dir() and not entry.flag_bits & 1
                                and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                                and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                                and 0 < entry.file_size <= (limits[name] if name in limits else 128 * 1024 * 1024),
                                "staged artifact member differs")
                total += entry.file_size
                release.require(total <= EXPANDED_MAX, "staged artifact expansion exceeds bound")
            for name in sorted(limits):
                entry = archive.getinfo(name)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=held)
                try:
                    os.fsync(held)
                    copied = 0
                    with archive.open(entry, "r") as source, os.fdopen(fd, "wb", closefd=False) as target:
                        while True:
                            chunk = source.read(min(65536, limits[name] + 1 - copied))
                            if not chunk:
                                break
                            copied += len(chunk)
                            release.require(copied <= entry.file_size and copied <= limits[name],
                                            "staged installer member exceeds bound")
                            target.write(chunk)
                        target.flush()
                        os.fsync(fd)
                    release.require(copied == entry.file_size, "staged installer member truncated")
                finally:
                    os.close(fd)
        os.fsync(held)
        dispatch.registry_unchanged(held, output)
        release.require({path.name for path in output.iterdir()} == set(limits),
                        "staged installer selection differs")
    finally:
        os.close(held)


def acquire(*, client, output: Path, gh: Path, source_sha: str, release_tag: str,
            build_run_id: int, build_run_attempt: int,
            downloader=archive_transport.download_archive, clock=time.time) -> dict:
    release.require(os.name == "posix", "Linux controller required")
    release.identity(source_sha, release_tag, build_run_id, build_run_attempt)
    release.require(release.classify_release_tag(release_tag)[0] == "nightly",
                    "staged build must be a nightly")
    def checked_run():
        promotion.check_run(client.request("GET", transport.REPO + "/actions/runs/" + str(build_run_id)),
            run_id=build_run_id, attempt=build_run_attempt,
            workflow=".github/workflows/nightly-release.yml", source=source_sha)
    checked_run()
    name = f"nightly-publication-assets-{build_run_id}"
    def chosen():
        listing = client.request("GET", transport.REPO
                                 + f"/actions/runs/{build_run_id}/artifacts?per_page=100")
        item = archive_transport.selected_artifact(listing, run_id=build_run_id,
            run_attempt=build_run_attempt, harness_source_sha=source_sha,
            name=name, maximum=ARCHIVE_MAX)
        release.require(item is not None, "nightly publication artifact missing")
        return item
    item = chosen()
    parent = dispatch._directory(output.parent)
    try:
        dispatch.registry_unchanged(parent, output.parent)
        archive = Path(str(output) + ".archive.zip")
        record = Path(str(output) + ".verified.json")
        release.require(not output.exists() and not archive.exists() and not record.exists(),
                        "staged asset acquisition already exists")
        downloader(gh, client.token, item["id"], archive, parent, maximum=ARCHIVE_MAX, timeout=900)
        dispatch.registry_unchanged(parent, output.parent)
        fd = os.open(archive.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            release.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_size == item["size_in_bytes"],
                            "staged archive identity differs")
            digest, size = archive_transport.hash_fd(fd, ARCHIVE_MAX)
            release.require(size == item["size_in_bytes"] and "sha256:" + digest == item["digest"],
                            "staged archive digest differs")
            preflight_zip(fd, size)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                stream.seek(0)
                extract_selected(stream, output, parent)
            again, again_size = archive_transport.hash_fd(fd, ARCHIVE_MAX)
            release.require(again == digest and again_size == size and os.fstat(fd).st_size == size,
                            "staged archive changed during extraction")
        finally:
            os.close(fd)
        limits = public_release.expected_assets()
        snapshot = {name: dispatch.private_file(output / name, limits[name]) for name in sorted(limits)}
        release.require(chosen() == item, "staged artifact identity changed")
        checked_run()
        dispatch.registry_unchanged(parent, output.parent)
        release.require({name: dispatch.private_file(output / name, limits[name])
                         for name in sorted(limits)} == snapshot,
                        "staged installer inputs changed")
        result = dict(schema="elevenid.installer-controller-staged-assets/v1",
                      scope="controller-transport-only", source_sha=source_sha,
                      release_tag=release_tag, build_run_id=build_run_id,
                      build_run_attempt=build_run_attempt, artifact=item,
                      archive_sha256=digest, selected_files=len(limits),
                      acquired_at=int(clock()), signatures_authenticated=False,
                      guest_dispatched=False, acceptance=False)
        write_exclusive(record, release.encode(result))
        dispatch.registry_unchanged(parent, output.parent)
        return result
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "gh"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, type=int, required=True)
    try:
        acquire(**vars(parser.parse_args(argv)), client=transport.Client(os.environ.get("GH_TOKEN")))
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        parser.exit(1, "Staged controller asset acquisition refused or uncertain; preserve staging.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
