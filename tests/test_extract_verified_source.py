from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "extract_verified_source.py"
SPEC = importlib.util.spec_from_file_location("extract_verified_source", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
source_archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_archive)
SourceArchiveError = source_archive.SourceArchiveError
extract_verified_source = source_archive.extract_verified_source


def _archive(path: Path, members: list[tuple[str, bytes | None, bytes | None]]) -> str:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, typeflag in members:
            member = tarfile.TarInfo(name)
            if typeflag is not None:
                member.type = typeflag
            if content is None:
                member.type = tarfile.DIRTYPE
                member.size = 0
                member.mode = 0o755
                archive.addfile(member)
            else:
                member.size = len(content)
                member.mode = 0o755 if name.endswith(".sh") else 0o644
                archive.addfile(member, io.BytesIO(content))
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def test_extracts_one_verified_regular_file_tree(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    digest = _archive(
        archive,
        [
            ("marty-integration-tests-1.2.79", None, None),
            ("marty-integration-tests-1.2.79/scripts", None, None),
            ("marty-integration-tests-1.2.79/scripts/gate.sh", b"#!/bin/sh\n", None),
            ("marty-integration-tests-1.2.79/README.md", b"verified\n", None),
        ],
    )
    destination = tmp_path / "integration-tests"

    extract_verified_source(
        archive,
        destination,
        expected_root="marty-integration-tests-1.2.79",
        expected_sha256=digest,
    )

    assert (destination / "README.md").read_text(encoding="utf-8") == "verified\n"
    if os.name != "nt":
        assert (destination / "scripts/gate.sh").stat().st_mode & 0o111


@pytest.mark.parametrize(
    ("name", "typeflag", "message"),
    [
        ("../escape", None, "archive path is unsafe"),
        ("wrong-root/file", None, "archive root changed"),
        ("marty-integration-tests-1.2.79\\file", None, "archive path is invalid"),
        (
            "marty-integration-tests-1.2.79/link",
            tarfile.SYMTYPE,
            "archive contains a non-file member",
        ),
    ],
)
def test_rejects_unsafe_members(
    tmp_path: Path, name: str, typeflag: bytes | None, message: str
) -> None:
    archive = tmp_path / "source.tar.gz"
    digest = _archive(archive, [(name, b"content", typeflag)])

    with pytest.raises(SourceArchiveError, match=message):
        extract_verified_source(
            archive,
            tmp_path / "output",
            expected_root="marty-integration-tests-1.2.79",
            expected_sha256=digest,
        )


def test_rejects_duplicate_paths(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    name = "marty-integration-tests-1.2.79/duplicate"
    digest = _archive(archive, [(name, b"one", None), (name, b"two", None)])

    with pytest.raises(SourceArchiveError, match="archive path is duplicated"):
        extract_verified_source(
            archive,
            tmp_path / "output",
            expected_root="marty-integration-tests-1.2.79",
            expected_sha256=digest,
        )


def test_rejects_digest_change_and_existing_destination(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    digest = _archive(
        archive,
        [("marty-integration-tests-1.2.79/file", b"content", None)],
    )
    destination = tmp_path / "output"

    with pytest.raises(SourceArchiveError, match="source archive digest changed"):
        extract_verified_source(
            archive,
            destination,
            expected_root="marty-integration-tests-1.2.79",
            expected_sha256="sha256:" + "0" * 64,
        )

    destination.mkdir()
    with pytest.raises(SourceArchiveError, match="source destination already exists"):
        extract_verified_source(
            archive,
            destination,
            expected_root="marty-integration-tests-1.2.79",
            expected_sha256=digest,
        )


def test_bounds_member_count_and_expanded_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "source.tar.gz"
    root = "marty-integration-tests-1.2.79"
    digest = _archive(
        archive,
        [(f"{root}/one", b"12", None), (f"{root}/two", b"34", None)],
    )

    monkeypatch.setattr(source_archive, "MAX_MEMBERS", 1)
    with pytest.raises(SourceArchiveError, match="too many members"):
        extract_verified_source(
            archive,
            tmp_path / "members",
            expected_root=root,
            expected_sha256=digest,
        )

    monkeypatch.setattr(source_archive, "MAX_MEMBERS", 5_000)
    monkeypatch.setattr(source_archive, "MAX_EXPANDED_BYTES", 3)
    with pytest.raises(SourceArchiveError, match="expands beyond its limit"):
        extract_verified_source(
            archive,
            tmp_path / "expanded",
            expected_root=root,
            expected_sha256=digest,
        )
