#!/usr/bin/env python3
"""Record a held-lease process/disk observation of an exact v2 VM launch.

This is diagnostic evidence. It does not approve a candidate, inspect the guest,
consume a nonce or authorize installer dispatch. The booted overlay is mutable;
its original content digest is evidence of creation, not a live byte predicate.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
from installer_candidate_vm_create import _bytes, _read_record, _write
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_launch as launcher
from installer_candidate_vm_runtime import _identity, _named_disk, _same_path
from installer_candidate_vm_launch_evidence import bind_provisioned_launch
from installer_candidate_vm_guest_readiness import pinned_guest
import installer_release as release

SCHEMA = "elevenid.installer-vm-live-process-observation/v1"
GUEST_SCHEMA = "elevenid.installer-vm-guest-readiness/v1"
RECORDS = (
    "creation-intent", "creation-receipt", "runtime-intent", "runtime-receipt",
    "seed-intent", "seed-receipt", "launch-intent", "launch-pid",
    "launch-receipt",
)


def observe(registry: Path, runtime_parent: Path, *, vm_id: str,
            guest_readiness: bool = False) -> dict:
    """Observe only the existing process named in root-held launch records."""
    release.require(os.geteuid() == 0 and type(vm_id) is str
                    and str(uuid.UUID(vm_id)) == vm_id
                    and uuid.UUID(vm_id).version == 4,
                    "root exact VM observer and canonical ID required")
    with ControllerLease(registry) as lease:
        raw = {name.replace("-", "_"): _read_record(
            lease.parent, vm_id + "." + name + ".json")[0]
            for name in RECORDS}
        records = {name: release.decode(value) for name, value in raw.items()}
        boot_id = launcher._boot_id()
        bound = bind_provisioned_launch(**raw, boot_id=boot_id)
        runtime = records["runtime_receipt"]
        seed = records["seed_receipt"]
        intent = records["launch_intent"]
        spawned = records["launch_pid"]
        launch_receipt = records["launch_receipt"]
        runtime_dir = runtime_parent / vm_id
        control_dir = registry / (vm_id + ".control")
        disk = runtime_dir / "disk.qcow2"
        release.require(str(runtime_dir) == intent["runtime_dir"]
                        and str(control_dir) == intent["control_dir"]
                        and intent["args"] == launcher._arguments(
                            runtime_dir, vm_id, seed["ssh_port"])
                        and intent["qemu_sha256"] == launcher._trusted_tool(
                            launcher.QEMU)
                        and intent["kvm_gid"] == launcher._kvm_group()
                        and runtime["runtime_account"] == _identity(
                            vm_id, runtime["runtime_uid"], runtime["runtime_gid"])
                        and launch_receipt["pid"] == spawned["pid"]
                        and launch_receipt["start_ticks"] == spawned["start_ticks"],
                        "VM launch policy or selected process differs")
        runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
        try:
            control_fd = _directory(control_dir)
            try:
                release.require(
                    (os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                    == (runtime["runtime_dir_device"],
                        runtime["runtime_dir_inode"])
                    and (os.fstat(control_fd).st_dev,
                         os.fstat(control_fd).st_ino)
                    == (seed["control_dir_device"], seed["control_dir_inode"]),
                    "VM held directories differ",
                )
                for name, expected, maximum in (
                    ("controller_ed25519", seed["controller_private_sha256"], 8192),
                    ("known_hosts", seed["known_hosts_sha256"], 4096),
                    ("guest_host_ed25519", seed["guest_host_private_sha256"], 8192),
                    ("seed.iso", seed["seed_sha256"], 16 * 1024 * 1024),
                ):
                    release.require(
                        release.digest(_bytes(control_dir / name, maximum)) == expected,
                        "VM control material differs",
                    )
                launcher._seed_media(runtime_fd, seed, runtime["runtime_gid"])
                disk_fd = os.open("disk.qcow2", os.O_RDONLY | os.O_NONBLOCK
                                  | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=runtime_fd)
                try:
                    _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"],
                                runtime["runtime_gid"])
                    first = launcher._live(
                        spawned["pid"], intent["args"], intent["uid"],
                        intent["gid"], intent["kvm_gid"], disk,
                        runtime["disk_device"], runtime["disk_inode"],
                        intent["qemu_sha256"],
                    )
                    release.require(
                        first == {"pid": spawned["pid"],
                                  "start_ticks": spawned["start_ticks"],
                                  "disk_fd": launch_receipt["disk_fd"]},
                        "VM process differs from exact launch receipt",
                    )
                    guest = None
                    if guest_readiness:
                        guest = pinned_guest(
                            control_dir, port=seed["ssh_port"],
                            user=seed["guest_user"], packages=seed["packages"],
                            key_sha256=seed["controller_private_sha256"],
                            known_hosts_sha256=seed["known_hosts_sha256"],
                        )
                    _same_path(runtime_dir, runtime_fd,
                               lambda path: observer.open_vm_dir(
                                   path, runtime["runtime_uid"]))
                    _same_path(control_dir, control_fd, _directory)
                    _same_path(registry, lease.parent, _directory)
                    release.require(all(_read_record(
                        lease.parent, vm_id + "." + name + ".json")[0]
                        == raw[name.replace("-", "_")]
                        for name in RECORDS), "VM registry records changed")
                    _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"],
                                runtime["runtime_gid"])
                    second = launcher._live(
                        spawned["pid"], intent["args"], intent["uid"],
                        intent["gid"], intent["kvm_gid"], disk,
                        runtime["disk_device"], runtime["disk_inode"],
                        intent["qemu_sha256"],
                    )
                    release.require(first == second,
                                    "VM process changed during observation")
                    launcher._seed_media(runtime_fd, seed,
                                         runtime["runtime_gid"])
                    release.require(all(_read_record(
                        lease.parent, vm_id + "." + name + ".json")[0]
                        == raw[name.replace("-", "_")]
                        for name in RECORDS),
                        "VM registry records changed before observation write")
                    observed = dict(
                        schema=GUEST_SCHEMA if guest_readiness else SCHEMA,
                        phase="guest-ready" if guest_readiness
                        else "process-observed", vm_id=vm_id,
                        controller_boot_id=boot_id, process_pid=first["pid"],
                        process_start_ticks=first["start_ticks"],
                        process_disk_fd=first["disk_fd"],
                        disk_device=runtime["disk_device"],
                        disk_inode=runtime["disk_inode"],
                        runtime_dir_device=runtime["runtime_dir_device"],
                        runtime_dir_inode=runtime["runtime_dir_inode"],
                        control_dir_device=seed["control_dir_device"],
                        control_dir_inode=seed["control_dir_inode"],
                        record_sha256=bound, observed_at=int(time.time()),
                        qualified=False, dispatch_authorized=False,
                    )
                    if guest_readiness:
                        observed["guest"] = guest
                    _same_path(runtime_dir, runtime_fd,
                               lambda path: observer.open_vm_dir(
                                   path, runtime["runtime_uid"]))
                    _same_path(control_dir, control_fd, _directory)
                    _same_path(registry, lease.parent, _directory)
                    for name, expected, maximum in (
                        ("controller_ed25519", seed["controller_private_sha256"], 8192),
                        ("known_hosts", seed["known_hosts_sha256"], 4096),
                        ("guest_host_ed25519", seed["guest_host_private_sha256"], 8192),
                        ("seed.iso", seed["seed_sha256"], 16 * 1024 * 1024),
                    ):
                        release.require(
                            release.digest(_bytes(control_dir / name, maximum)) == expected,
                            "VM control material changed before observation write",
                        )
                    name = ("guest-readiness" if guest_readiness else
                            "live-process-observation")
                    _write(lease.parent, vm_id + "." + name + ".json", observed)
                    _same_path(registry, lease.parent, _directory)
                    return observed
                finally:
                    os.close(disk_fd)
            finally:
                os.close(control_fd)
        finally:
            os.close(runtime_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--runtime-parent", type=Path, required=True)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--guest-readiness", action="store_true")
    args = parser.parse_args()
    try:
        result = observe(args.registry, args.runtime_parent, vm_id=args.vm_id,
                         guest_readiness=args.guest_readiness)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError):
        parser.exit(1, "VM live observation refused or uncertain; retain evidence.\n")
    print(release.encode(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
