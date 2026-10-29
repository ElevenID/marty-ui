#!/usr/bin/env python3
"""Read-only binding for a fresh disposable rootless-test guest.

The guest setup Engine is infrastructure. Nothing here authorizes product
dispatch, package installation, daemon setup, or release qualification.
"""
from __future__ import annotations

import os
from pathlib import Path
from contextlib import ExitStack
import stat

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_launch_evidence as evidence
import installer_candidate_vm_runtime as runtime
import installer_candidate_vm_seed as seed
import installer_release as release
import installer_test_vm_rootless_fixture as fixture

CHAIN_NAMES = (
    "creation-intent", "creation-receipt", "runtime-intent", "runtime-receipt",
    "seed-intent", "seed-receipt", "launch-intent", "launch-pid",
    "launch-receipt",
)


def bound_fixture(*, source: Path, registry: Path, vm_parent: Path,
                  runtime_parent: Path, vm_id: str) -> dict:
    """Bind exact root-owned records, signed source, and live QEMU disk FD.

    A root-private admitted controller must call this before and after every
    guest observation. The returned private binding must not be serialized.
    """
    fixture._uuid4(vm_id)
    release.require(os.geteuid() == 0 and all(p.is_absolute() for p in
                    (source, registry, vm_parent, runtime_parent)),
                    "fixture observation request invalid")
    provenance = create.verify_source(source)
    with ControllerLease(registry) as lease:
        intent_raw, intent = create._read_record(lease.parent,
                                                vm_id + fixture.RECORD_SUFFIX)
        result_raw, result = create._read_record(lease.parent,
                                                vm_id + fixture.RESULT_SUFFIX)
        raw = {name.replace("-", "_"): create._read_record(
            lease.parent, vm_id + "." + name + ".json")
            for name in CHAIN_NAMES}
        chain = evidence.bind_provisioned_launch(
            **{name: item[0] for name, item in raw.items()},
            boot_id=launch._boot_id())
        created = raw["creation_receipt"][1]
        transferred = raw["runtime_receipt"][1]
        seeded = raw["seed_receipt"][1]
        launch_intent = raw["launch_intent"][1]
        launched = raw["launch_receipt"][1]
        release.require(intent["schema"] == result["schema"] == fixture.SCHEMA
                        and intent["phase"] == "intent"
                        and result["phase"] == "prepared"
                        and intent["vm_id"] == result["vm_id"] == vm_id
                        and result["intent_sha256"] == release.digest(intent_raw)
                        and result["creation_sha256"] == chain["creation_receipt_sha256"]
                        and result["transfer_sha256"] == chain["runtime_receipt_sha256"]
                        and result["seed_sha256"] == chain["seed_receipt_sha256"]
                        and created["image"] == provenance
                        and all(provenance[key] == intent["source_" + key] for key in
                                ("image_sha256", "manifest_sha256",
                                 "signature_sha256", "keyring_sha256"))
                        and intent["vm_parent"] == str(vm_parent)
                        and intent["runtime_parent"] == str(runtime_parent)
                        and created["vm_dir"] == str(vm_parent / vm_id)
                        and transferred["target_path"] == str(
                            runtime_parent / vm_id / "disk.qcow2")
                        and intent["virtual_gib"] == created["virtual_gib"]
                        == fixture.VIRTUAL_GIB
                        and intent["runtime_uid"] == result["runtime_uid"]
                        == transferred["runtime_uid"]
                        and intent["runtime_gid"] == result["runtime_gid"]
                        == transferred["runtime_gid"]
                        and intent["ssh_port"] == seeded["ssh_port"]
                        and intent["guest_profile"] == result["guest_profile"]
                        == seeded.get("fixture_profile")
                        == seed.ROOTLESS_FIXTURE_PROFILE
                        and seeded["packages"] == seed.ROOTLESS_FIXTURE_PACKAGES
                        and launch_intent["memory_mib"]
                        == launch.ROOTLESS_FIXTURE_MEMORY_MIB
                        and launch_intent["args"] == launch._arguments(
                            runtime_parent / vm_id, vm_id, seeded["ssh_port"],
                            launch.ROOTLESS_FIXTURE_MEMORY_MIB)
                        and all(value is False for value in
                                (intent["qualified"], intent["launch_authorized"],
                                 intent["product_dispatch_authorized"],
                                 result["qualified"], result["launch_authorized"],
                                 result["product_dispatch_authorized"],
                                 result["rootless_daemon_ready"],
                                 launched["qualified"],
                                 launched["dispatch_authorized"])),
                        "fixture source or historical chain differs")
        control_dir = registry / (vm_id + ".control")
        with ExitStack() as stack:
            vm_fd = _directory(vm_parent)
            stack.callback(os.close, vm_fd)
            runtime_parent_fd = runtime._runtime_parent(runtime_parent)
            stack.callback(os.close, runtime_parent_fd)
            runtime_fd = observer.open_vm_dir(runtime_parent / vm_id,
                                              transferred["runtime_uid"])
            stack.callback(os.close, runtime_fd)
            control_fd = _directory(control_dir)
            stack.callback(os.close, control_fd)
            release.require((os.fstat(vm_fd).st_dev, os.fstat(vm_fd).st_ino)
                            == (intent["vm_parent_device"],
                                intent["vm_parent_inode"])
                            and (os.fstat(runtime_parent_fd).st_dev,
                                 os.fstat(runtime_parent_fd).st_ino)
                            == (intent["runtime_parent_device"],
                                intent["runtime_parent_inode"])
                            and (os.fstat(runtime_fd).st_dev,
                                 os.fstat(runtime_fd).st_ino)
                            == (transferred["runtime_dir_device"],
                                transferred["runtime_dir_inode"])
                            and (os.fstat(control_fd).st_dev,
                                 os.fstat(control_fd).st_ino)
                            == (seeded["control_dir_device"],
                                seeded["control_dir_inode"]),
                            "fixture directory identity differs")
            launch._seed_media(runtime_fd, seeded, transferred["runtime_gid"])
            live = launch._live(
                launched["pid"], launch_intent["args"], transferred["runtime_uid"],
                transferred["runtime_gid"], launch_intent["kvm_gid"],
                runtime_parent / vm_id / "disk.qcow2", created["disk_device"],
                created["disk_inode"], launch_intent["qemu_sha256"])
            release.require(live == {"pid": launched["pid"],
                                     "start_ticks": launched["start_ticks"],
                                     "disk_fd": launched["disk_fd"]}
                            and launch_intent["qemu_sha256"] ==
                                launch._trusted_tool(launch.QEMU),
                            "fixture live process differs")
            for name, maximum, digest_key in (
                ("controller_ed25519", 8192, "controller_private_sha256"),
                ("guest_host_ed25519", 8192, "guest_host_private_sha256"),
                ("known_hosts", 4096, "known_hosts_sha256"),
                ("user-data", 65536, "user_data_sha256"),
                ("meta-data", 4096, "metadata_sha256"),
                ("seed.iso", 16 * 1024 * 1024, "seed_sha256"),
            ):
                info = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
                release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                                and info.st_nlink == 1
                                and stat.S_IMODE(info.st_mode) == 0o600
                                and release.digest(seed._bytes(control_dir / name,
                                                                maximum))
                                == seeded[digest_key],
                                "fixture control material differs")
            create._rebind_directory(vm_parent, vm_fd)
            runtime._same_path(runtime_parent, runtime_parent_fd,
                               runtime._runtime_parent)
            create._rebind_directory(control_dir, control_fd)
            create._rebind_directory(registry, lease.parent)
            release.require(all(create._read_record(
                            lease.parent, vm_id + "." + name.replace("_", "-")
                            + ".json")[0] == item[0]
                            for name, item in raw.items())
                            and create._read_record(lease.parent,
                                vm_id + fixture.RECORD_SUFFIX)[0] == intent_raw
                            and create._read_record(lease.parent,
                                vm_id + fixture.RESULT_SUFFIX)[0] == result_raw,
                            "fixture records changed during observation")
            release.require(create.verify_source(source) == provenance,
                            "fixture signed factory source changed")
            return {"vm_id": vm_id, "pid": launched["pid"],
                    "start_ticks": launched["start_ticks"],
                    "boot_id": launch_intent["controller_boot_id"],
                    "disk_device": created["disk_device"],
                    "disk_inode": created["disk_inode"],
                    "control_dir": control_dir, "port": seeded["ssh_port"],
                    "key_sha256": seeded["controller_private_sha256"],
                    "known_hosts_sha256": seeded["known_hosts_sha256"],
                    "seed_sha256": chain["seed_receipt_sha256"],
                    "launch_sha256": chain["launch_receipt_sha256"],
                    "guest_user": "installer", "setup_user": "fixture-admin",
                    "qualified": False, "product_dispatch_authorized": False}
