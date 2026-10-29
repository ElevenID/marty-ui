"""Synthetic stop boundary checks; these never signal a real QEMU process."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import threading
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_stopped_snapshot as stopped


def _record(_parent, name):
    if name.endswith(".runtime-receipt.json"):
        return b"runtime\n", {"runtime_uid": os.getuid(),
                               "runtime_gid": os.getgid()}
    if name.endswith(stopped.setup.SETUP_READINESS_SUFFIX):
        return b"setup\n", {}
    raise AssertionError("unexpected record")


def test_qmp_sends_only_fixed_powerdown_to_exact_peer(tmp_path):
    path = tmp_path / "qmp.sock"
    ready = threading.Event()
    commands = []

    def server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            ready.set()
            connection, _ = listener.accept()
            with connection, connection.makefile("rwb") as stream:
                stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\n')
                stream.flush()
                for ident in (1, 2):
                    request = stream.readline(4096)
                    commands.append(request)
                    stream.write((f'{{"return":{{}},"id":{ident}}}\n').encode())
                    stream.flush()

    worker = threading.Thread(target=server)
    worker.start()
    assert ready.wait(2)
    info = path.lstat()
    with mock.patch.object(stopped.observer, "qmp") as observed, \
         mock.patch.object(stopped.restart, "_original_still_live",
                           return_value=True):
        stopped._qmp_powerdown(path, tmp_path / "disk.qcow2", pid=os.getpid(),
                               uid=os.getuid(), start_ticks="123",
                               boot_id="11111111-2222-4333-8444-555555555555",
                               socket_device=info.st_dev,
                               socket_inode=info.st_ino)
    worker.join(2)
    assert not worker.is_alive()
    assert observed.call_count == 1
    assert commands == [b'{"execute":"qmp_capabilities","id":1}\n',
                        b'{"execute":"system_powerdown","id":2}\n']


def test_qmp_wrong_peer_refuses_before_powerdown(tmp_path):
    path = tmp_path / "qmp.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)
        info = path.lstat()
        with mock.patch.object(stopped.observer, "qmp"), \
             mock.patch.object(stopped.restart, "_original_still_live",
                               return_value=True):
            with pytest.raises(ValueError, match="QMP peer changed"):
                stopped._qmp_powerdown(path, tmp_path / "disk.qcow2",
                                       pid=os.getpid() + 10000, uid=os.getuid(),
                                       start_ticks="123",
                                       boot_id="11111111-2222-4333-8444-555555555555",
                                       socket_device=info.st_dev,
                                       socket_inode=info.st_ino)


def test_stop_intent_is_written_before_qmp_and_never_retried(tmp_path, monkeypatch):
    vm_id = "11111111-2222-4333-8444-555555555555"
    runtime = tmp_path / "runtime"
    (runtime / vm_id).mkdir(parents=True)
    path = runtime / vm_id / "qmp.sock"
    monkeypatch.chdir(tmp_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind("runtime/" + vm_id + "/qmp.sock")
        class Lease:
            parent = 20
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
        binding = {"vm_id": vm_id, "pid": 1600, "start_ticks": "123",
                   "boot_id": "11111111-2222-4333-8444-555555555555",
                   "port": 22020, "disk_device": 1, "disk_inode": 2,
                   "readiness_sha256": stopped.release.digest(b"setup\n"),
                   "launch_sha256": "b" * 64}
        calls = []
        def write(_parent, name, _record):
            calls.append(("intent", name))
            return b"intent\n"
        def fail_qmp(*_, **__):
            calls.append(("qmp", None))
            raise ValueError("uncertain QMP result")
        with mock.patch.object(stopped.os, "geteuid", return_value=0), \
             mock.patch.object(stopped, "ControllerLease", return_value=Lease()), \
             mock.patch.object(stopped.setup, "bound_setup_fixture",
                               return_value=binding), \
             mock.patch.object(stopped.create, "_read_record",
                               side_effect=_record), \
             mock.patch.object(stopped.create, "verify_source",
                               return_value={}), \
             mock.patch.object(stopped.restart, "_original_still_live",
                               return_value=True), \
             mock.patch.object(stopped.create, "_write", side_effect=write), \
             mock.patch.object(stopped, "_qmp_powerdown", side_effect=fail_qmp):
            with pytest.raises(ValueError, match="uncertain QMP"):
                stopped.stop_and_snapshot(source=tmp_path / "source",
                    registry=tmp_path / "registry", vm_parent=tmp_path / "vm",
                    runtime_parent=runtime, vm_id=vm_id)
        assert calls == [("intent", vm_id + stopped.INTENT_SUFFIX),
                         ("qmp", None)]


def test_existing_stop_intent_refuses_before_qmp(tmp_path, monkeypatch):
    vm_id = "11111111-2222-4333-8444-555555555555"
    runtime = tmp_path / "runtime"
    (runtime / vm_id).mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind("runtime/" + vm_id + "/qmp.sock")
        class Lease:
            parent = 20
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
        binding = {"vm_id": vm_id, "pid": 1600, "start_ticks": "123",
                   "boot_id": "11111111-2222-4333-8444-555555555555",
                   "port": 22020, "disk_device": 1, "disk_inode": 2,
                   "readiness_sha256": stopped.release.digest(b"setup\n"),
                   "launch_sha256": "b" * 64}
        with mock.patch.object(stopped.os, "geteuid", return_value=0), \
             mock.patch.object(stopped, "ControllerLease", return_value=Lease()), \
             mock.patch.object(stopped.setup, "bound_setup_fixture",
                               return_value=binding), \
             mock.patch.object(stopped.create, "_read_record",
                               side_effect=_record), \
             mock.patch.object(stopped.create, "verify_source",
                               return_value={}), \
             mock.patch.object(stopped.restart, "_original_still_live",
                               return_value=True), \
             mock.patch.object(stopped.create, "_write",
                               side_effect=FileExistsError), \
             mock.patch.object(stopped, "_qmp_powerdown") as qmp:
            with pytest.raises(FileExistsError):
                stopped.stop_and_snapshot(source=tmp_path / "source",
                    registry=tmp_path / "registry", vm_parent=tmp_path / "vm",
                    runtime_parent=runtime, vm_id=vm_id)
        qmp.assert_not_called()
