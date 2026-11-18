"""Bounded producer receipt checks; consumer admission is not enabled."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

from scripts import record_selfhost_public_kms_helper as helper

SOURCE = "a" * 40


def _elf() -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<H", header, 18, 62)
    return bytes(header) + b"bounded synthetic helper"


def _linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helper.platform, "system", lambda: "Linux")
    monkeypatch.setattr(helper.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        helper.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"},
    )


def test_receipt_binds_exact_bytes_source_run_and_linux_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _linux(monkeypatch)
    binary = tmp_path / "public-kms-jwk"
    binary.write_bytes(_elf())
    receipt = helper.record(binary, SOURCE, "123")
    assert receipt == {
        "schema": helper.SCHEMA,
        "source_sha": SOURCE,
        "run_id": "123",
        "platform": "linux-amd64-ubuntu-24.04",
        "binary": "public-kms-jwk",
        "sha256": hashlib.sha256(_elf()).hexdigest(),
        "size": len(_elf()),
        "qualification": "producer-only-unqualified",
    }
    binary.write_bytes(_elf() + b"changed")
    assert helper.record(binary, SOURCE, "123")["sha256"] != receipt["sha256"]


def test_receipt_rejects_wrong_identity_platform_file_and_elf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _linux(monkeypatch)
    binary = tmp_path / "public-kms-jwk"
    binary.write_bytes(_elf())
    for source, run in (
        ("A" * 40, "123"),
        (SOURCE, "one"),
        (SOURCE, "0"),
        (SOURCE, "\u0661\u0662\u0663"),
    ):
        with pytest.raises(ValueError, match="identity"):
            helper.record(binary, source, run)
    with monkeypatch.context() as patch:
        patch.setattr(helper.platform, "machine", lambda: "aarch64")
        with pytest.raises(ValueError, match="baseline"):
            helper.record(binary, SOURCE, "123")
    with monkeypatch.context() as patch:
        patch.setattr(
            helper.platform,
            "freedesktop_os_release",
            lambda: {"ID": "ubuntu", "VERSION_ID": "22.04"},
        )
        with pytest.raises(ValueError, match="baseline"):
            helper.record(binary, SOURCE, "123")
    with monkeypatch.context() as patch:
        original_is_symlink = Path.is_symlink
        patch.setattr(
            Path, "is_symlink", lambda path: path == binary or original_is_symlink(path)
        )
        with pytest.raises(ValueError, match="ordinary file"):
            helper.record(binary, SOURCE, "123")
    binary.write_bytes(b"not ELF" + b"x" * 64)
    with pytest.raises(ValueError, match="ELF"):
        helper.record(binary, SOURCE, "123")
    wrong_arch = bytearray(_elf())
    struct.pack_into("<H", wrong_arch, 18, 183)
    binary.write_bytes(wrong_arch)
    with pytest.raises(ValueError, match="ELF"):
        helper.record(binary, SOURCE, "123")


def test_receipt_output_is_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _linux(monkeypatch)
    binary = tmp_path / "public-kms-jwk"
    binary.write_bytes(_elf())
    output = tmp_path / "receipt.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "record",
            "--binary",
            str(binary),
            "--source-sha",
            SOURCE,
            "--run-id",
            "123",
            "--output",
            str(output),
        ],
    )
    helper.main()
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        helper.main()
    assert output.read_bytes() == original
