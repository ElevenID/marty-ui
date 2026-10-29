"""Synthetic rollback-copy preparation checks; no VM or package action."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release  # noqa: E402
import installer_test_vm_rootless_rollback_copy as copy  # noqa: E402
import installer_test_vm_rootless_stopped_snapshot as stopped  # noqa: E402

VM = "11111111-2222-4333-8444-555555555555"
BOOT = "22222222-3333-4444-8555-666666666666"


def pending_records():
    intent = {"schema": stopped.SCHEMA, "phase": "stop_intent",
              "vm_id": VM, "setup_readiness_sha256": "a" * 64,
              "launch_sha256": "b" * 64, "pid": 2345,
              "start_ticks": "12345", "boot_id": BOOT,
              "runtime_uid": 994, "runtime_gid": 994,
              "disk_device": 12, "disk_inode": 34,
              "qmp_device": 12, "qmp_inode": 35,
              "requested_at": 123456, "stopped": False,
              "snapshot_qualified": False,
              "package_install_authorized": False,
              "product_dispatch_authorized": False}
    raw = release.encode(intent)
    pending = {"schema": stopped.SCHEMA,
               "phase": "snapshot_pending_rollback_test", "vm_id": VM,
               "intent_sha256": release.digest(raw), "pid": 2345,
               "start_ticks": "12345", "boot_id": BOOT,
               "disk_device": 12, "disk_inode": 34,
               "disk_bytes": 1234, "disk_sha256": "c" * 64,
               "snapshot_bytes": 1234, "snapshot_sha256": "c" * 64,
               "snapshot_directory_device": 12,
               "snapshot_directory_inode": 36,
               "snapshot_device": 12, "snapshot_inode": 37,
               "observed_at": 123457, "stopped": True,
               "snapshot_qualified": False,
               "package_install_authorized": False,
               "product_dispatch_authorized": False}
    return raw, intent, release.encode(pending), pending


def test_pending_evidence_is_closed_and_cannot_claim_authority():
    intent_raw, intent, pending_raw, pending = pending_records()
    copy._exact_pending(intent_raw, intent, pending_raw, pending, VM)
    for key in ("snapshot_qualified", "package_install_authorized",
                "product_dispatch_authorized"):
        changed = dict(pending, **{key: True})
        with pytest.raises(ValueError):
            copy._exact_pending(intent_raw, intent, release.encode(changed),
                                changed, VM)
    changed = dict(pending, unexpected="canary")
    with pytest.raises(ValueError):
        copy._exact_pending(intent_raw, intent, release.encode(changed),
                            changed, VM)
    changed = dict(pending, disk_bytes=copy.restart.MAX_MUTABLE_DISK_BYTES + 1,
                   snapshot_bytes=copy.restart.MAX_MUTABLE_DISK_BYTES + 1)
    with pytest.raises(ValueError):
        copy._exact_pending(intent_raw, intent, release.encode(changed),
                            changed, VM)


def test_copy_exact_uses_new_inode_and_rejects_changed_bytes(tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    contents = b"owned synthetic stopped disk" * 300
    source.write_bytes(contents)
    expected = hashlib.sha256(contents).hexdigest()
    with source.open("rb") as reader, target.open("wb") as writer:
        copy._copy_exact(reader.fileno(), writer.fileno(), len(contents), expected)
    assert target.read_bytes() == contents
    assert source.stat().st_ino != target.stat().st_ino
    source.write_bytes(contents + b"changed")
    with source.open("rb") as reader, (tmp_path / "refused").open("wb") as writer:
        with pytest.raises(ValueError, match="source digest differs"):
            copy._copy_exact(reader.fileno(), writer.fileno(), len(contents), expected)


def test_copy_exact_refuses_concurrent_source_growth(tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    contents = b"synthetic" * 200
    source.write_bytes(contents)
    original = os.pread
    grown = False
    def growing(fd, count, offset):
        nonlocal grown
        block = original(fd, count, offset)
        if not grown and count > 1:
            grown = True
            with source.open("ab") as writer:
                writer.write(b"late")
        return block
    with source.open("rb") as reader, target.open("wb") as writer, \
         mock.patch.object(copy.os, "pread", side_effect=growing):
        with pytest.raises(ValueError, match="source digest differs"):
            copy._copy_exact(reader.fileno(), writer.fileno(), len(contents),
                             hashlib.sha256(contents).hexdigest())


def test_special_or_linked_snapshot_refuses_before_read(tmp_path):
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.mkfifo(tmp_path / "special", 0o600)
        info = (tmp_path / "special").lstat()
        with pytest.raises(ValueError, match="source inode differs"):
            copy._held_regular(parent, "special", owner=os.getuid(),
                               group=os.getgid(), mode=0o600,
                               device=info.st_dev, inode=info.st_ino, size=0)
        (tmp_path / "link").symlink_to("special")
        link = (tmp_path / "link").lstat()
        with pytest.raises(ValueError, match="source inode differs"):
            copy._held_regular(parent, "link", owner=os.getuid(),
                               group=os.getgid(), mode=0o777,
                               device=link.st_dev, inode=link.st_ino,
                               size=link.st_size)
    finally:
        os.close(parent)


def test_nonroot_or_same_uuid_refuses_before_source_access(tmp_path):
    with mock.patch.object(copy.create, "verify_source") as source:
        with pytest.raises(ValueError, match="request invalid"):
            copy.prepare_copy(source=tmp_path / "source",
                              registry=tmp_path / "registry",
                              vm_parent=tmp_path / "vm",
                              runtime_parent=tmp_path / "runtime",
                              vm_id=VM, copy_vm_id=VM, copy_port=22024)
    source.assert_not_called()
