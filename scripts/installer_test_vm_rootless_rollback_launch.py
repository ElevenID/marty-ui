#!/usr/bin/env python3
"""Dedicated one-shot QEMU launch for a prepared rollback-copy disk.

This never invents pristine VM creation/transfer receipts. All output remains
test-infrastructure evidence, with package/product authority false. No live
caller or CLI exists; an intent-only or PID-only launch is not retried.
"""
from __future__ import annotations

import os
from pathlib import Path
import json
import shlex
import socket
import stat
import subprocess
import time
import uuid

from installer_candidate_controller import ControllerLease
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_runtime as runtime
import installer_candidate_vm_seed as seed_module
import installer_release as release
import installer_test_vm_probe as probe
import installer_test_vm_rootless_package_admission_controller as admission_controller
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_setup as setup

SCHEMA = "elevenid.installer-only-rootless-rollback-launch/v1"
PID_SCHEMA = "elevenid.installer-only-rootless-rollback-pid/v1"
INTENT_SUFFIX = ".rootless-rollback-launch-intent.json"
PID_SUFFIX = ".rootless-rollback-launch-pid.json"
RECEIPT_SUFFIX = ".rootless-rollback-launch-receipt.json"
BASELINE_SUFFIX = ".rootless-rollback-baseline.json"
BASELINE_SCHEMA = "elevenid.installer-only-rootless-rollback-baseline/v1"
OBSERVE_SECONDS = 45


def _canonical_uuid(value: str) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _unused(parent: int, copy_vm_id: str) -> None:
    for suffix in (INTENT_SUFFIX, PID_SUFFIX, RECEIPT_SUFFIX):
        try:
            os.stat(copy_vm_id + suffix, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("fixture rollback launch already attempted")


def _held_mutable_disk(directory: int, *, uid: int, gid: int,
                       device: int, inode: int) -> int:
    """Classify the live qcow2 without reading or pinning its changing size."""
    held = os.open("disk.qcow2", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=directory)
    try:
        before = os.fstat(held)
        named = os.stat("disk.qcow2", dir_fd=directory,
                        follow_symlinks=False)
        release.require(stat.S_ISREG(before.st_mode)
                        and before.st_nlink == named.st_nlink == 1
                        and (before.st_dev, before.st_ino)
                        == (named.st_dev, named.st_ino) == (device, inode)
                        and (before.st_uid, before.st_gid)
                        == (named.st_uid, named.st_gid) == (uid, gid)
                        and stat.S_IMODE(before.st_mode)
                        == stat.S_IMODE(named.st_mode) == 0o600
                        and 0 < before.st_size <= copy.restart.MAX_MUTABLE_DISK_BYTES
                        and 0 < named.st_size <= copy.restart.MAX_MUTABLE_DISK_BYTES,
                        "fixture rollback live disk identity differs")
        return held
    except BaseException:
        os.close(held)
        raise


def launch_copy(*, source: Path, registry: Path, runtime_parent: Path,
                vm_id: str, copy_vm_id: str) -> dict:
    """Launch only a revalidated new copy inode; never the original snapshot."""
    release.require(os.geteuid() == 0, "fixture rollback launch needs root controller")
    with ControllerLease(registry) as lease:
        before = copy.bound_prepared_copy(
            source=source, registry=registry, runtime_parent=runtime_parent,
            vm_id=vm_id, copy_vm_id=copy_vm_id, _lease=lease)
        _unused(lease.parent, copy_vm_id)
        runtime_dir = before["runtime_dir"]
        disk_path = runtime_dir / "disk.qcow2"
        uid, gid = before["runtime_uid"], before["runtime_gid"]
        kvm_gid = launch._kvm_group()
        qemu_sha = launch._trusted_tool(launch.QEMU)
        setpriv_sha = launch._trusted_tool(launch.SETPRIV)
        launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        args = launch._arguments(runtime_dir, copy_vm_id,
                                 before["copy_port"],
                                 launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        # The source snapshot path never appears in these fixed QEMU arguments.
        release.require(str(disk_path) in args[args.index("-drive") + 1]
                        and all("rootless-stopped-snapshot" not in arg
                                for arg in args),
                        "fixture rollback QEMU disk selection differs")
        runtime_fd = observer.open_vm_dir(runtime_dir, uid)
        try:
            disk_fd = copy._held_regular(
                runtime_fd, "disk.qcow2", owner=uid, group=gid, mode=0o600,
                device=before["disk_device"], inode=before["disk_inode"],
                size=before["disk_bytes"])
            try:
                release.require(copy.restart._mutable_digest(disk_fd)[:2]
                                == (before["disk_bytes"],
                                    before["disk_sha256"]),
                                "fixture rollback disk changed before launch")
                launch._seed_media(runtime_fd, before, gid)
                boot = launch._boot_id()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                    reserved.bind(("127.0.0.1", before["copy_port"]))
                    current = copy.bound_prepared_copy(
                        source=source, registry=registry,
                        runtime_parent=runtime_parent, vm_id=vm_id,
                        copy_vm_id=copy_vm_id, _lease=lease)
                    release.require(current == before,
                                    "fixture rollback-copy binding changed")
                    intent = {"schema": SCHEMA, "phase": "launch_intent",
                              "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                              "prepared_sha256": before["prepared_sha256"],
                              "pending_sha256": before["pending_sha256"],
                              "runtime_uid": uid, "runtime_gid": gid,
                              "runtime_directory_device":
                                  before["runtime_directory_device"],
                              "runtime_directory_inode":
                                  before["runtime_directory_inode"],
                              "disk_device": before["disk_device"],
                              "disk_inode": before["disk_inode"],
                              "disk_sha256": before["disk_sha256"],
                              "seed_device": before["seed_device"],
                              "seed_inode": before["seed_inode"],
                              "seed_sha256": before["seed_sha256"],
                              "ssh_port": before["copy_port"],
                              "memory_mib": launch.ROOTLESS_FIXTURE_MEMORY_MIB,
                              "kvm_gid": kvm_gid, "args": args,
                              "qemu_sha256": qemu_sha,
                              "setpriv_sha256": setpriv_sha,
                              "controller_boot_id": boot,
                              "requested_at": int(time.time()),
                              "rollback_qualified": False,
                              "package_install_authorized": False,
                              "product_dispatch_authorized": False}
                    intent_raw = create._write(
                        lease.parent, copy_vm_id + INTENT_SUFFIX, intent)
                # Intent is durable before any guest process can start.
                current = copy.bound_prepared_copy(
                    source=source, registry=registry,
                    runtime_parent=runtime_parent, vm_id=vm_id,
                    copy_vm_id=copy_vm_id, _lease=lease)
                release.require(current == before
                                and launch._boot_id() == boot
                                and launch._trusted_tool(launch.QEMU) == qemu_sha
                                and launch._trusted_tool(launch.SETPRIV) == setpriv_sha,
                                "fixture rollback launch inputs changed")
                launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
                command = [str(launch.SETPRIV), "--reuid", str(uid),
                           "--regid", str(gid), "--groups", str(kvm_gid),
                           "--bounding-set=-all", "--inh-caps=-all",
                           "--ambient-caps=-all", "--no-new-privs", "--", *args]
                process = subprocess.Popen(
                    command, cwd="/", env=launch.ENV,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                    close_fds=True)
                # No automatic kill/retry if observation or receipt fails.
                start_ticks = launch._start_ticks(process.pid)
                pid_raw = create._write(lease.parent, copy_vm_id + PID_SUFFIX,
                    {"schema": PID_SCHEMA, "phase": "spawned",
                     "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                     "intent_sha256": release.digest(intent_raw),
                     "pid": process.pid, "start_ticks": start_ticks,
                     "controller_boot_id": boot,
                     "spawned_at": int(time.time())})
                live = None
                deadline = time.monotonic() + OBSERVE_SECONDS
                while time.monotonic() < deadline:
                    release.require(process.poll() is None,
                                    "fixture rollback QEMU exited before observation")
                    try:
                        live = launch._live(
                            process.pid, args, uid, gid, kvm_gid,
                            disk_path, before["disk_device"],
                            before["disk_inode"], qemu_sha)
                        break
                    except (FileNotFoundError, ConnectionRefusedError,
                            socket.timeout, observer.DiskNotOpenedYet):
                        time.sleep(0.25)
                release.require(live is not None
                                and live["start_ticks"] == start_ticks,
                                "fixture rollback QEMU observation timed out")
                release.require(launch._live(
                                process.pid, args, uid, gid, kvm_gid,
                                disk_path, before["disk_device"],
                                before["disk_inode"], qemu_sha) == live
                                and create._read_record(
                                    lease.parent, copy_vm_id + INTENT_SUFFIX)[0]
                                    == intent_raw
                                and create._read_record(
                                    lease.parent, copy_vm_id + PID_SUFFIX)[0]
                                    == pid_raw,
                                "fixture rollback QEMU changed before receipt")
                receipt = {**intent, "phase": "launched",
                           "intent_sha256": release.digest(intent_raw),
                           "pid_record_sha256": release.digest(pid_raw),
                           "pid": process.pid, "start_ticks": start_ticks,
                           "disk_fd": live["disk_fd"],
                           "observed_at": int(time.time())}
                create._write(lease.parent, copy_vm_id + RECEIPT_SUFFIX,
                              receipt)
                return receipt
            finally:
                os.close(disk_fd)
        finally:
            os.close(runtime_fd)


def bound_live_copy(*, source: Path, registry: Path, runtime_parent: Path,
                    vm_id: str, copy_vm_id: str,
                    _lease: ControllerLease | None = None) -> dict:
    """Rebind exact rollback launch, process and copied disk, without authority."""
    from contextlib import nullcontext
    release.require(os.geteuid() == 0, "fixture live-copy binding needs root")
    with (ControllerLease(registry) if _lease is None else nullcontext(_lease)) as lease:
        create._rebind_directory(registry, lease.parent)
        intent_raw, intent = create._read_record(
            lease.parent, copy_vm_id + INTENT_SUFFIX)
        pid_raw, spawned = create._read_record(
            lease.parent, copy_vm_id + PID_SUFFIX)
        receipt_raw, receipt = create._read_record(
            lease.parent, copy_vm_id + RECEIPT_SUFFIX)
        prepared_raw, prepared = create._read_record(
            lease.parent, copy_vm_id + copy.PREPARED_SUFFIX)
        copy_intent_raw, copy_intent = create._read_record(
            lease.parent, copy_vm_id + copy.INTENT_SUFFIX)
        release.exact(copy_intent, copy.INTENT_FIELDS,
                      "fixture rollback-copy intent")
        release.exact(prepared, copy.PREPARED_FIELDS,
                      "fixture rollback-copy prepared")
        fields = {"schema", "phase", "vm_id", "copy_vm_id",
                  "prepared_sha256", "pending_sha256", "runtime_uid",
                  "runtime_gid", "runtime_directory_device",
                  "runtime_directory_inode", "disk_device", "disk_inode",
                  "disk_sha256", "seed_device", "seed_inode", "seed_sha256",
                  "ssh_port", "memory_mib", "kvm_gid", "args",
                  "qemu_sha256", "setpriv_sha256", "controller_boot_id",
                  "requested_at", "rollback_qualified",
                  "package_install_authorized", "product_dispatch_authorized"}
        release.exact(intent, fields, "fixture rollback launch intent")
        release.exact(spawned, {"schema", "phase", "vm_id", "copy_vm_id",
                                "intent_sha256", "pid", "start_ticks",
                                "controller_boot_id", "spawned_at"},
                      "fixture rollback launch PID")
        release.exact(receipt, fields | {"intent_sha256",
                                         "pid_record_sha256", "pid",
                                         "start_ticks", "disk_fd",
                                         "observed_at"},
                      "fixture rollback launch receipt")
        release.require(intent["schema"] == receipt["schema"] == SCHEMA
                        and spawned["schema"] == PID_SCHEMA
                        and intent["phase"] == "launch_intent"
                        and spawned["phase"] == "spawned"
                        and receipt["phase"] == "launched"
                        and all(receipt[key] == value for key, value in
                                intent.items() if key != "phase")
                        and intent["vm_id"] == spawned["vm_id"] == vm_id
                        and intent["copy_vm_id"] == spawned["copy_vm_id"]
                        == copy_vm_id
                        and spawned["intent_sha256"]
                        == receipt["intent_sha256"] == release.digest(intent_raw)
                        and receipt["pid_record_sha256"]
                        == release.digest(pid_raw)
                        and receipt["pid"] == spawned["pid"]
                        and receipt["start_ticks"] == spawned["start_ticks"]
                        and type(spawned["pid"]) is int and spawned["pid"] > 4
                        and type(spawned["start_ticks"]) is str
                        and spawned["start_ticks"].isascii()
                        and spawned["start_ticks"].isdecimal()
                        and spawned["controller_boot_id"]
                        == intent["controller_boot_id"] == launch._boot_id()
                        and intent["prepared_sha256"]
                        == release.digest(prepared_raw)
                        and intent["pending_sha256"] == prepared["pending_sha256"]
                        and all(intent[key] == prepared[key] for key in
                                ("runtime_uid", "runtime_gid",
                                 "runtime_directory_device",
                                 "runtime_directory_inode", "disk_device",
                                 "disk_inode", "disk_sha256", "seed_device",
                                 "seed_inode", "seed_sha256"))
                        and intent["ssh_port"] == prepared["copy_port"]
                        and intent["memory_mib"]
                        == launch.ROOTLESS_FIXTURE_MEMORY_MIB
                        and all(value is False for value in
                                (intent["rollback_qualified"],
                                 intent["package_install_authorized"],
                                 intent["product_dispatch_authorized"]))
                        and copy_intent["copy_vm_id"] == copy_vm_id
                        and prepared["intent_sha256"]
                        == release.digest(copy_intent_raw)
                        and all(value is False for value in
                                (copy_intent["rollback_qualified"],
                                 copy_intent["package_install_authorized"],
                                 copy_intent["product_dispatch_authorized"],
                                 prepared["rollback_qualified"],
                                 prepared["package_install_authorized"],
                                 prepared["product_dispatch_authorized"])),
                        "fixture rollback launch record chain differs")
        provenance = create.verify_source(source)
        release.require(all(copy_intent["source_" + key] == provenance[key]
                            for key in ("image_sha256", "manifest_sha256",
                                        "signature_sha256", "keyring_sha256"))
                        and intent["qemu_sha256"]
                        == launch._trusted_tool(launch.QEMU)
                        and intent["setpriv_sha256"]
                        == launch._trusted_tool(launch.SETPRIV)
                        and intent["kvm_gid"] == launch._kvm_group(),
                        "fixture rollback launch source differs")
        runtime_dir = runtime_parent / copy_vm_id
        args = launch._arguments(runtime_dir, copy_vm_id,
                                 intent["ssh_port"],
                                 launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        release.require(intent["args"] == args,
                        "fixture rollback QEMU arguments differ")
        parent_fd = runtime._runtime_parent(runtime_parent)
        held = disk_fd = seed_fd = control_fd = None
        try:
            held = observer.open_vm_dir(runtime_dir, intent["runtime_uid"])
            release.require((os.fstat(parent_fd).st_dev,
                             os.fstat(parent_fd).st_ino)
                            == (copy_intent["runtime_parent_device"],
                                copy_intent["runtime_parent_inode"]),
                            "fixture rollback live parent differs")
            release.require((os.fstat(held).st_dev, os.fstat(held).st_ino)
                            == (intent["runtime_directory_device"],
                                intent["runtime_directory_inode"]),
                            "fixture rollback live directory differs")
            with os.scandir(held) as entries:
                release.require({entry.name for entry in entries}
                                == {"disk.qcow2", "seed.iso", "qmp.sock"},
                                "fixture rollback live directory differs")
            disk_fd = _held_mutable_disk(
                held, uid=intent["runtime_uid"], gid=intent["runtime_gid"],
                device=intent["disk_device"], inode=intent["disk_inode"])
            seed_fd = copy._held_regular(
                held, "seed.iso", owner=0, group=intent["runtime_gid"],
                mode=0o440, device=intent["seed_device"],
                inode=intent["seed_inode"], size=prepared["seed_bytes"])
            release.require(copy.restart._mutable_digest(seed_fd)[:2]
                            == (prepared["seed_bytes"],
                                prepared["seed_sha256"]),
                            "fixture rollback seed changed")
            live = launch._live(
                receipt["pid"], args, intent["runtime_uid"],
                intent["runtime_gid"], intent["kvm_gid"],
                runtime_dir / "disk.qcow2", intent["disk_device"],
                intent["disk_inode"], intent["qemu_sha256"])
            release.require(live == {"pid": receipt["pid"],
                                     "start_ticks": receipt["start_ticks"],
                                     "disk_fd": receipt["disk_fd"]},
                            "fixture rollback live QEMU differs")
            seed_raw, seed = create._read_record(
                lease.parent, vm_id + ".seed-receipt.json")
            release.require(release.digest(seed_raw)
                            == copy_intent["seed_sha256"],
                            "fixture rollback control seed differs")
            setup_raw, setup_record = create._read_record(
                lease.parent, vm_id + setup.SETUP_READINESS_SUFFIX)
            release.exact(setup_record, {"schema", "phase", "vm_id",
                                         "launch_sha256", "seed_sha256", "pid",
                                         "start_ticks", "boot_id", "setup_engine_id",
                                         "ordinary_uid", "ordinary_gid",
                                         "ordinary_home", "setup_uid", "setup_gid",
                                         "setup_home", "setup_principal_distinct",
                                         "ordinary_no_sudo_or_docker_group",
                                         "setup_socket_denied_to_installer",
                                         "setup_engine_stopped",
                                         "rootless_engine_observed", "rootless_ready",
                                         "qualified", "product_dispatch_authorized",
                                         "observed_at"},
                          "fixture rollback original setup readiness")
            release.require(release.digest(setup_raw)
                            == copy_intent["setup_readiness_sha256"]
                            and setup_record["schema"] == setup.SETUP_READINESS_SCHEMA
                            and setup_record["phase"] == "setup_engine_observed"
                            and setup_record["vm_id"] == vm_id
                            and type(setup_record["ordinary_uid"]) is int
                            and setup_record["ordinary_uid"] > 0
                            and type(setup_record["setup_uid"]) is int
                            and setup_record["setup_uid"] > 0
                            and setup_record["ordinary_uid"]
                            != setup_record["setup_uid"]
                            and setup_record["ordinary_home"] == "/home/installer"
                            and setup_record["setup_home"]
                            == "/home/fixture-admin"
                            and setup_record["setup_principal_distinct"] is True
                            and all(setup_record[key] is False for key in
                                    ("setup_engine_stopped",
                                     "rootless_engine_observed",
                                     "rootless_ready", "qualified",
                                     "product_dispatch_authorized")),
                            "fixture rollback original setup evidence differs")
            control_dir = registry / (vm_id + ".control")
            control_fd = copy._directory(control_dir)
            release.require((os.fstat(control_fd).st_dev,
                             os.fstat(control_fd).st_ino)
                            == (seed["control_dir_device"],
                                seed["control_dir_inode"])
                            and release.digest(seed_module._bytes(
                                control_dir / "controller_ed25519", 8192))
                            == seed["controller_private_sha256"]
                            and release.digest(seed_module._bytes(
                                control_dir / "known_hosts", 4096))
                            == seed["known_hosts_sha256"],
                            "fixture rollback SSH control changed")
            create._rebind_directory(control_dir, control_fd)
            launch._same_path(
                runtime_dir, held,
                lambda path: observer.open_vm_dir(path, intent["runtime_uid"]))
            runtime._same_path(runtime_parent, parent_fd,
                               runtime._runtime_parent)
            create._rebind_directory(registry, lease.parent)
            release.require(create._read_record(
                            lease.parent, copy_vm_id + INTENT_SUFFIX)[0]
                            == intent_raw
                            and create._read_record(
                            lease.parent, copy_vm_id + PID_SUFFIX)[0]
                            == pid_raw
                            and create._read_record(
                            lease.parent, copy_vm_id + RECEIPT_SUFFIX)[0]
                            == receipt_raw
                            and create.verify_source(source) == provenance,
                            "fixture rollback live records changed")
            return {"vm_id": vm_id, "copy_vm_id": copy_vm_id,
                    "pid": receipt["pid"],
                    "start_ticks": receipt["start_ticks"],
                    "boot_id": intent["controller_boot_id"],
                    "runtime_uid": intent["runtime_uid"],
                    "runtime_gid": intent["runtime_gid"],
                    "runtime_dir": runtime_dir,
                    "disk_device": intent["disk_device"],
                    "disk_inode": intent["disk_inode"],
                    "port": intent["ssh_port"],
                    "control_dir": control_dir,
                    "key_sha256": seed["controller_private_sha256"],
                    "known_hosts_sha256": seed["known_hosts_sha256"],
                    "ordinary_uid": setup_record["ordinary_uid"],
                    "setup_uid": setup_record["setup_uid"],
                    "setup_engine_id": setup_record["setup_engine_id"],
                    "launch_sha256": release.digest(receipt_raw),
                    "prepared_sha256": release.digest(prepared_raw),
                    "package_install_authorized": False,
                    "product_dispatch_authorized": False}
        finally:
            for fd in (control_fd, seed_fd, disk_fd, held, parent_fd):
                if fd is not None:
                    os.close(fd)


def observe_baseline(*, source: Path, registry: Path, runtime_parent: Path,
                     vm_id: str, copy_vm_id: str,
                     expected_engine_id: str,
                     expected_status_sha256: str,
                     admission_result_sha256: str) -> dict:
    """Record only fixed SSH boot baseline; caller assertions grant no authority."""
    release.require(type(expected_engine_id) is str
                    and type(expected_status_sha256) is str
                    and type(admission_result_sha256) is str
                    and len(expected_status_sha256) == 64
                    and len(admission_result_sha256) == 64
                    and all(c in "0123456789abcdef" for c in
                            expected_status_sha256 + admission_result_sha256)
                    and _canonical_uuid(expected_engine_id),
                    "fixture rollback expected baseline invalid")
    with ControllerLease(registry) as lease:
        before = bound_live_copy(source=source, registry=registry,
                                 runtime_parent=runtime_parent, vm_id=vm_id,
                                 copy_vm_id=copy_vm_id, _lease=lease)
        ordinary = setup._decode_installer(setup._ssh_as(
            before, "installer", setup._installer_command(), limit=2048))
        admin = setup._decode_admin(setup._ssh_as(
            before, "fixture-admin", setup._admin_identity_command(),
            limit=512), ordinary["uid"])
        release.require(ordinary["uid"] == before["ordinary_uid"]
                        and admin["uid"] == before["setup_uid"],
                        "fixture rollback principals changed")
        raw_engine = setup._ssh_as(before, "fixture-admin",
                                    setup.SETUP_ENGINE_COMMAND, limit=256)
        engine = json.loads(raw_engine)
        release.require(engine == expected_engine_id
                        == before["setup_engine_id"],
                        "fixture rollback setup Engine differs")
        script = ("/usr/bin/python3 -I -B -c "
                  + shlex.quote(admission_controller.STATUS_SCRIPT))
        raw_status = probe._ssh(before, script,
                                limit=admission_controller.admission.MAX_STATUS,
                                timeout=30)
        status_sha = release.digest(raw_status)
        release.require(status_sha == expected_status_sha256,
                        "fixture rollback dpkg status differs")
        after = bound_live_copy(source=source, registry=registry,
                                runtime_parent=runtime_parent, vm_id=vm_id,
                                copy_vm_id=copy_vm_id, _lease=lease)
        release.require(after == before
                        and setup._decode_installer(setup._ssh_as(
                            after, "installer", setup._installer_command(),
                            limit=2048)) == ordinary
                        and setup._decode_admin(setup._ssh_as(
                            after, "fixture-admin",
                            setup._admin_identity_command(),
                            limit=512), ordinary["uid"]) == admin
                        and setup._ssh_as(after, "fixture-admin",
                                          setup.SETUP_ENGINE_COMMAND,
                                          limit=256) == raw_engine
                        and release.digest(probe._ssh(
                            after, script,
                            limit=admission_controller.admission.MAX_STATUS,
                            timeout=30)) == status_sha,
                        "fixture rollback baseline changed")
        result = {"schema": BASELINE_SCHEMA, "phase": "baseline_observed",
                  "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                  "launch_sha256": before["launch_sha256"],
                  "prepared_sha256": before["prepared_sha256"],
                  "admission_result_sha256": admission_result_sha256,
                  "setup_engine_id": engine,
                  "dpkg_status_sha256": status_sha,
                  "pid": before["pid"],
                  "start_ticks": before["start_ticks"],
                  "boot_id": before["boot_id"],
                  "observed_at": int(time.time()),
                  "rollback_qualified": False,
                  "package_install_authorized": False,
                  "product_dispatch_authorized": False}
        create._write(lease.parent, copy_vm_id + BASELINE_SUFFIX, result)
        return result
