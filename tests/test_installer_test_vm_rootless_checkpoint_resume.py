"""Synthetic one-shot resume ordering; no QEMU process is started."""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_checkpoint_resume as resumed  # noqa: E402

VM = "11111111-2222-4333-8444-555555555555"
COPY = "33333333-4444-4555-8666-777777777777"
BOOT = "22222222-3333-4444-8555-666666666666"


def test_prior_resume_leaf_refuses_without_spawn(tmp_path):
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        (tmp_path / (VM + resumed.PID_SUFFIX)).write_bytes(b"prior")
        with pytest.raises(ValueError, match="already attempted"):
            resumed._unused(directory, VM)
    finally:
        os.close(directory)


def test_resume_intent_precedes_fixed_unprivileged_spawn(tmp_path):
    registry, runtime_parent = tmp_path / "registry", tmp_path / "runtime"
    registry.mkdir()
    runtime_parent.mkdir()
    runtime_dir = runtime_parent / VM
    runtime_dir.mkdir()
    disk = runtime_dir / "disk.qcow2"
    disk.write_bytes(b"synthetic")
    (runtime_dir / "seed.iso").write_bytes(b"seed")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    args = ["/usr/bin/qemu-system-x86_64", "-m", "2048"]
    provenance = {"image_path": "/private/factory"}
    pending = {"intent_sha256": resumed.release.digest(b"stop"),
               "disk_device": 4, "disk_inode": 5, "disk_bytes": 32,
               "disk_sha256": "a" * 64, "snapshot_bytes": 32}
    prior = {"pending_sha256": resumed.release.digest(
                 resumed.release.encode(pending)),
             "disk_sha256": "a" * 64, "snapshot_sha256": "a" * 64,
             "copy_vm_id": COPY, "cleanup_result_sha256": "c" * 64,
             "admission_result_sha256": "d" * 64}
    checked = {"stopped_pid": 1777, "stopped_start_ticks": "17",
               "disk_device": 4, "disk_inode": 5, "snapshot_bytes": 32}
    original_receipt = b"historical launch"
    records = {
        VM + resumed.proof.stopped.INTENT_SUFFIX:
            (b"stop", {"pid": 1777, "start_ticks": "17",
                       "runtime_uid": 994, "runtime_gid": 994,
                       "launch_sha256": resumed.release.digest(original_receipt)}),
        VM + resumed.proof.stopped.PENDING_SUFFIX:
            (resumed.release.encode(pending), pending),
        VM + ".launch-intent.json":
            (b"launch", {"ssh_port": port, "args": args}),
        VM + ".launch-receipt.json": (original_receipt, {}),
        VM + ".creation-receipt.json":
            (b"creation", {"image": provenance, "virtual_gib": 32}),
        VM + ".seed-receipt.json":
            (b"seed", {"ssh_port": port}),
    }
    events = []
    class Lease:
        def __enter__(self):
            self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
            return self
        def __exit__(self, *_):
            os.close(self.parent)
    class Process:
        pid = 1888
        def poll(self):
            return None
    def read(_fd, name):
        return records[name]
    def write(_fd, name, value):
        events.append(("write", name))
        raw = resumed.release.encode(value)
        records[name] = raw, value
        return raw
    def spawn(argv, **opts):
        events.append(("spawn", argv, opts))
        return Process()
    patches = [
        mock.patch.object(resumed.os, "geteuid", return_value=0),
        mock.patch.object(resumed, "ControllerLease", return_value=Lease()),
        mock.patch.object(resumed.proof, "inspect_proof", return_value=prior),
        mock.patch.object(resumed, "_checkpoint", return_value=(b"ck", checked)),
        mock.patch.object(resumed.create, "_read_record", side_effect=read),
        mock.patch.object(resumed.create, "_write", side_effect=write),
        mock.patch.object(resumed.create, "verify_source", return_value=provenance),
        mock.patch.object(resumed.launch, "_trusted_tool", return_value="f" * 64),
        mock.patch.object(resumed.launch, "_kvm_group", return_value=999),
        mock.patch.object(resumed.launch, "_host_headroom"),
        mock.patch.object(resumed.launch, "_arguments", return_value=args),
        mock.patch.object(resumed.launch, "_seed_media"),
        mock.patch.object(resumed.launch, "_same_path"),
        mock.patch.object(resumed.launch, "_boot_id", return_value=BOOT),
        mock.patch.object(resumed.launch, "_start_ticks", return_value="18"),
        mock.patch.object(resumed.launch, "_live",
                          return_value={"pid": 1888, "start_ticks": "18",
                                        "disk_fd": 12}),
        mock.patch.object(resumed.observer, "open_vm_dir",
                          side_effect=lambda *_:
                          os.open(runtime_dir, os.O_RDONLY | os.O_DIRECTORY)),
        mock.patch.object(resumed.restart, "_disk_fd",
                          side_effect=lambda *_: os.open(disk, os.O_RDONLY)),
        mock.patch.object(resumed.restart, "_mutable_digest",
                          return_value=(32, "a" * 64, 1, 1)),
        mock.patch.object(resumed.restart, "_mutable_image_info"),
        mock.patch.object(resumed.subprocess, "Popen", side_effect=spawn),
    ]
    with ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        result = resumed.resume(source=tmp_path, registry=registry,
                                runtime_parent=runtime_parent, vm_id=VM,
                                copy_vm_id=COPY)
    assert [row[0] for row in events] == ["write", "spawn", "write", "write"]
    assert events[0][1] == VM + resumed.INTENT_SUFFIX
    assert events[-1][1] == VM + resumed.RECEIPT_SUFFIX
    assert result["package_install_authorized"] is False
    assert events[1][1][:12] == [
        "/usr/bin/setpriv", "--reuid", "994", "--regid", "994",
        "--groups", "999", "--bounding-set=-all", "--inh-caps=-all",
        "--ambient-caps=-all", "--no-new-privs", "--"]
    assert events[1][2]["close_fds"] is True
