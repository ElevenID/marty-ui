"""Synthetic exact cleanup boundaries; never signal or delete a real VM."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_rollback_cleanup as cleanup  # noqa: E402

VM = "11111111-2222-4333-8444-555555555555"
COPY = "33333333-4444-4555-8666-777777777777"


def test_cleanup_prior_record_refuses(tmp_path):
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        (tmp_path / (COPY + cleanup.RESULT_SUFFIX)).write_bytes(b"old")
        with pytest.raises(ValueError, match="already attempted"):
            cleanup._unused(parent, COPY)
    finally:
        os.close(parent)


def test_named_file_replacement_refuses_before_unlink(tmp_path):
    path = tmp_path / "disk.qcow2"
    path.write_bytes(b"original")
    stamp = path.stat()
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        cleanup._same_named_file(parent, "disk.qcow2", stamp)
        path.unlink()
        path.write_bytes(b"replacement")
        with pytest.raises(ValueError, match="changed before unlink"):
            cleanup._same_named_file(parent, "disk.qcow2", stamp)
        assert path.read_bytes() == b"replacement"
    finally:
        os.close(parent)


def test_cleanup_intent_precedes_fixed_qmp_and_no_removal_on_uncertainty(
        tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    runtime = tmp_path / "runtime"
    directory = runtime / COPY
    registry.mkdir()
    directory.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind("runtime/" + COPY + "/qmp.sock")
        binding = {"vm_id": VM, "copy_vm_id": COPY,
                   "runtime_uid": os.getuid(), "runtime_gid": os.getgid(),
                   "disk_device": 1, "disk_inode": 2, "pid": 1699,
                   "start_ticks": "12345",
                   "boot_id": "22222222-3333-4444-8555-666666666666",
                   "port": 22024, "launch_sha256": "a" * 64,
                   "prepared_sha256": "b" * 64}
        class Lease:
            parent = 20
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
        events = []
        def write(_parent, name, _record):
            events.append(("intent", name))
            return b"intent\n"
        def refuse_qmp(*_args, **_kwargs):
            events.append(("qmp", None))
            raise ValueError("uncertain QMP")
        with mock.patch.object(cleanup.os, "geteuid", return_value=0), \
             mock.patch.object(cleanup, "ControllerLease",
                               return_value=Lease()), \
             mock.patch.object(cleanup.launched, "bound_live_copy",
                               return_value=binding), \
             mock.patch.object(cleanup, "_baseline",
                               return_value=(b"baseline\n", {})), \
             mock.patch.object(cleanup, "_unused"), \
             mock.patch.object(cleanup.create, "_write", side_effect=write), \
             mock.patch.object(cleanup.stopped, "_qmp_powerdown",
                               side_effect=refuse_qmp):
            with pytest.raises(ValueError, match="uncertain QMP"):
                cleanup.cleanup_copy(source=tmp_path / "source",
                    registry=registry, runtime_parent=runtime,
                    vm_id=VM, copy_vm_id=COPY)
        assert events == [("intent", COPY + cleanup.INTENT_SUFFIX),
                          ("qmp", None)]
        assert (directory / "qmp.sock").exists()
