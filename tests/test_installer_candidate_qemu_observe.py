"""QMP peer binding for the diagnostic-only owned-VM observer."""
import json
import os
from pathlib import Path
import socket
import sys
import threading

import pytest

if sys.platform != "linux":
    pytest.skip("QMP peer credentials require Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_qemu_observe as observer


def test_qmp_refuses_wrong_peer_pid_and_socket_owner(tmp_path):
    path = tmp_path / "qmp.sock"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen(1)
        server.settimeout(5)

        def accept_once():
            with server.accept()[0]:
                pass

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            with pytest.raises(ValueError, match="monitor peer differs"):
                observer.qmp(path, tmp_path / "disk.qcow2", pid=os.getpid() + 1,
                             uid=os.getuid())
            with pytest.raises(ValueError, match="monitor socket differs"):
                observer.qmp(path, tmp_path / "disk.qcow2", pid=os.getpid(),
                             uid=os.getuid() + 1)
        finally:
            thread.join(timeout=5)
        assert not thread.is_alive()


def test_qmp_accepts_exact_peer_and_writable_disk(tmp_path):
    path = tmp_path / "qmp.sock"
    disk = tmp_path / "disk.qcow2"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen(1)
        server.settimeout(5)

        def respond():
            with server.accept()[0] as connection:
                with connection.makefile("rwb") as stream:
                    stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\n')
                    stream.flush()
                    for _ in range(3):
                        request = json.loads(stream.readline())
                        name = request["execute"]
                        result = ({"running": True, "status": "running"}
                                  if name == "query-status" else
                                  [{"inserted": {"file": str(disk), "drv": "qcow2", "ro": False}}]
                                  if name == "query-block" else {})
                        stream.write(json.dumps({"id": request["id"], "return": result}).encode()
                                     + b"\n")
                        stream.flush()

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        try:
            observer.qmp(path, disk, pid=os.getpid(), uid=os.getuid())
        finally:
            thread.join(timeout=5)
        assert not thread.is_alive()


def test_held_disk_requires_exact_live_writable_descriptor(tmp_path):
    disk = tmp_path / "disk.qcow2"
    process = Path("/proc") / str(os.getpid())
    descriptor = os.open(disk, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        expected = disk.stat()
        assert observer.held_writable_disk(process, disk, expected) == descriptor
        replacement = tmp_path / "replacement.qcow2"
        replacement.write_bytes(b"new disk")
        os.replace(replacement, disk)
        with pytest.raises(ValueError, match="writable disk descriptor differs"):
            observer.held_writable_disk(process, disk, disk.stat())
    finally:
        os.close(descriptor)


def test_held_disk_refuses_read_only_descriptor(tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"qcow2")
    descriptor = os.open(disk, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="selected writable disk"):
            observer.held_writable_disk(Path("/proc") / str(os.getpid()), disk, disk.stat())
    finally:
        os.close(descriptor)
