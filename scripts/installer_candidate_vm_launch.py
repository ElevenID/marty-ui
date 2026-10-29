#!/usr/bin/env python3
"""Launch one seeded engineering guest under its dedicated unprivileged identity.

This produces a process observation, not installation acceptance or release authority.
An exclusive intent survives any failure after the final prelaunch checks; it is
never reused for an automatic second spawn.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
from installer_candidate_vm_create import _bytes, _disk_digest, _read_record, _write
from installer_candidate_vm_runtime import _named_disk, _same_path
from installer_candidate_vm_seed import ROOTLESS_FIXTURE_PROFILE, verify_seed
import installer_release as release

SCHEMA = "elevenid.installer-vm-launch/v1"
PID_SCHEMA = "elevenid.installer-vm-pid/v2"
QEMU = Path("/usr/bin/qemu-system-x86_64")
SETPRIV = Path("/usr/bin/setpriv")
MEMORY_MIB = 4096
ROOTLESS_FIXTURE_MEMORY_MIB = 2048
CPUS = 2
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}


def _host_headroom(memory_mib: int = MEMORY_MIB) -> int:
    release.require(memory_mib in (MEMORY_MIB, ROOTLESS_FIXTURE_MEMORY_MIB),
                    "VM memory profile unsupported")
    raw = Path("/proc/meminfo").read_bytes()
    release.require(len(raw) <= 65536, "VM host memory inventory oversized")
    values = [
        line.split() for line in raw.splitlines() if line.startswith(b"MemAvailable:")
    ]
    release.require(
        len(values) == 1
        and len(values[0]) == 3
        and values[0][1].isdigit()
        and values[0][2] == b"kB",
        "VM host memory unavailable",
    )
    available = int(values[0][1]) * 1024
    # Engineering trial only; the independent 32GiB/20GiB release gate stays.
    release.require(
        available >= (memory_mib + 2048) * 1024 * 1024,
        "VM engineering host memory headroom insufficient",
    )
    return available


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    release.require(
        str(uuid.UUID(value)) == value, "VM controller boot identity invalid"
    )
    return value


def _safe_runtime_path(path: Path) -> None:
    value = str(path)
    release.require(
        path.is_absolute()
        and ".." not in path.parts
        and not any(
            character == "," or ord(character) < 32 or ord(character) == 127
            for character in value
        ),
        "VM runtime path is unsafe for QEMU arguments",
    )


def _trusted_tool(path: Path) -> str:
    info = path.lstat()
    release.require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and bool(info.st_mode & 0o111),
        "VM launch tool custody invalid",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held = os.fstat(fd)
        release.require(
            (held.st_dev, held.st_ino, held.st_size)
            == (info.st_dev, info.st_ino, info.st_size)
            and 0 < held.st_size <= 256 * 1024 * 1024,
            "VM launch tool changed",
        )
        digest = hashlib.sha256()
        while block := os.read(fd, 65536):
            digest.update(block)
        release.require(
            os.fstat(fd).st_size == info.st_size and path.lstat().st_ino == info.st_ino,
            "VM launch tool changed",
        )
        return digest.hexdigest()
    finally:
        os.close(fd)


def _idle_uid(uid: int) -> None:
    release.require(type(uid) is int and uid > 0, "VM runtime identity invalid")
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                if entry.stat().st_uid == uid:
                    raise ValueError("VM runtime identity has an existing process")
            except FileNotFoundError:
                continue


def _kvm_group() -> int:
    device = Path("/dev/kvm").lstat()
    group = grp.getgrnam("kvm")
    release.require(
        stat.S_ISCHR(device.st_mode)
        and device.st_uid == 0
        and device.st_gid == group.gr_gid
        and device.st_mode & stat.S_IRGRP
        and device.st_mode & stat.S_IWGRP,
        "VM KVM device custody invalid",
    )
    return group.gr_gid


def _arguments(runtime_dir: Path, vm_id: str, port: int,
               memory_mib: int = MEMORY_MIB) -> list[str]:
    release.require(memory_mib in (MEMORY_MIB, ROOTLESS_FIXTURE_MEMORY_MIB),
                    "VM memory profile unsupported")
    _safe_runtime_path(runtime_dir)
    disk = runtime_dir / "disk.qcow2"
    seed = runtime_dir / "seed.iso"
    qmp = runtime_dir / "qmp.sock"
    return [
        str(QEMU),
        "-name",
        "marty-" + vm_id,
        "-machine",
        "q35,accel=kvm",
        "-m",
        str(memory_mib),
        "-smp",
        str(CPUS),
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-serial",
        "null",
        "-monitor",
        "none",
        "-no-reboot",
        "-drive",
        "file=" + str(disk) + ",if=virtio,format=qcow2,cache=none",
        "-drive",
        "file=" + str(seed) + ",if=virtio,media=cdrom,format=raw,readonly=on",
        "-netdev",
        "user,id=net0,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-qmp",
        "unix:" + str(qmp) + ",server=on,wait=off",
    ]


def _process_credentials(pid: int, uid: int, gid: int, kvm_gid: int) -> None:
    raw = (Path("/proc") / str(pid) / "status").read_bytes()
    release.require(len(raw) <= 65536, "VM process credential inventory oversized")
    fields: dict[bytes, list[bytes]] = {}
    for line in raw.splitlines():
        if b":" in line:
            name, value = line.split(b":", 1)
            release.require(name not in fields, "VM process status duplicated")
            fields[name] = value.split()
    release.require(
        fields.get(b"Uid") == [str(uid).encode()] * 4
        and fields.get(b"Gid") == [str(gid).encode()] * 4
        and fields.get(b"Groups") == [str(kvm_gid).encode()]
        and fields.get(b"NoNewPrivs") == [b"1"],
        "VM process privilege identity differs",
    )
    for name in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        value = fields.get(name)
        release.require(
            value is not None and len(value) == 1 and int(value[0], 16) == 0,
            "VM process retains capabilities",
        )


def _seed_media(runtime_fd: int, seed: dict, gid: int) -> None:
    media = os.open(
        "seed.iso",
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=runtime_fd,
    )
    try:
        info = os.fstat(media)
        named = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
        release.require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and (info.st_dev, info.st_ino)
            == (named.st_dev, named.st_ino)
            == (seed["seed_device"], seed["seed_inode"])
            and info.st_uid == named.st_uid == 0
            and info.st_gid == named.st_gid == gid
            and stat.S_IMODE(info.st_mode) == stat.S_IMODE(named.st_mode) == 0o440
            and info.st_size == named.st_size == seed["seed_bytes"]
            and info.st_size <= 16 * 1024 * 1024,
            "VM launch seed identity differs",
        )
        digest = hashlib.sha256()
        left = info.st_size
        while left:
            block = os.read(media, min(left, 1024 * 1024))
            release.require(bool(block), "VM launch seed truncated")
            digest.update(block)
            left -= len(block)
        final = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
        release.require(
            (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            and digest.hexdigest() == seed["seed_sha256"],
            "VM launch seed changed",
        )
    finally:
        os.close(media)


def _live(
    pid: int,
    args: list[str],
    uid: int,
    gid: int,
    kvm_gid: int,
    disk: Path,
    disk_device: int,
    disk_inode: int,
    executable_sha256: str,
) -> dict:
    process = Path("/proc") / str(pid)
    cmdline = (process / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    release.require(
        cmdline == args
        and process.stat().st_uid == uid
        and os.readlink(process / "exe") == str(QEMU)
        and observer.executable_digest(process) == executable_sha256,
        "VM launch process identity differs",
    )
    _process_credentials(pid, uid, gid, kvm_gid)
    start_ticks = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
    disk_info = disk.lstat()
    release.require(
        (disk_info.st_dev, disk_info.st_ino) == (disk_device, disk_inode)
        and disk_info.st_uid == uid
        and disk_info.st_nlink == 1,
        "VM launch writable disk differs",
    )
    fd_number = observer.held_writable_disk(process, disk, disk_info)
    observer.qmp(disk.parent / "qmp.sock", disk, pid=pid, uid=uid)
    release.require(
        (process / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0") == args
        and (process / "stat").read_text().rsplit(")", 1)[1].split()[19] == start_ticks
        and process.stat().st_uid == uid,
        "VM process changed during monitor observation",
    )
    _process_credentials(pid, uid, gid, kvm_gid)
    observer.held_writable_disk(process, disk, disk_info)
    return {"pid": pid, "start_ticks": start_ticks, "disk_fd": fd_number}


def launch(
    source: Path, registry: Path, vm_parent: Path, runtime_parent: Path, *, vm_id: str
) -> dict:
    release.require(os.geteuid() == 0, "root VM controller required")
    seed = verify_seed(source, registry, vm_parent, runtime_parent, vm_id=vm_id)
    qemu_sha256 = _trusted_tool(QEMU)
    _trusted_tool(SETPRIV)
    kvm_gid = _kvm_group()
    with ControllerLease(registry) as lease:
        seed_raw, current_seed = _read_record(
            lease.parent, vm_id + ".seed-receipt.json"
        )
        runtime_raw, runtime = _read_record(
            lease.parent, vm_id + ".runtime-receipt.json"
        )
        release.require(
            current_seed == seed
            and release.digest(runtime_raw) == seed["runtime_receipt_sha256"],
            "VM seed chain changed before launch",
        )
        control_dir = registry / (vm_id + ".control")
        control_fd = _directory(control_dir)
        try:
            runtime_dir = runtime_parent / vm_id
            _safe_runtime_path(runtime_dir)
            runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
            try:
                return _launch_held(
                    lease.parent,
                    control_fd,
                    runtime_fd,
                    registry,
                    control_dir,
                    runtime_dir,
                    vm_id,
                    seed,
                    seed_raw,
                    runtime,
                    runtime_raw,
                    qemu_sha256,
                    kvm_gid,
                )
            finally:
                os.close(runtime_fd)
        finally:
            os.close(control_fd)


def _launch_held(
    registry_fd: int,
    control_fd: int,
    runtime_fd: int,
    registry: Path,
    control_dir: Path,
    runtime_dir: Path,
    vm_id: str,
    seed: dict,
    seed_raw: bytes,
    runtime: dict,
    runtime_raw: bytes,
    qemu_sha256: str,
    kvm_gid: int,
) -> dict:
    def rebind() -> None:
        _same_path(
            runtime_dir,
            runtime_fd,
            lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]),
        )
        _same_path(control_dir, control_fd, _directory)
        _same_path(registry, registry_fd, _directory)

    release.require(
        (os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
        == (seed["control_dir_device"], seed["control_dir_inode"])
        and (os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
        == (runtime["runtime_dir_device"], runtime["runtime_dir_inode"]),
        "VM launch directories differ",
    )
    disk_fd = os.open(
        "disk.qcow2",
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=runtime_fd,
    )
    try:
        _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"], runtime["runtime_gid"])
        release.require(
            _disk_digest(disk_fd) == (runtime["disk_bytes"], runtime["disk_sha256"]),
            "VM launch pristine disk differs",
        )
        disk_info = os.fstat(disk_fd)
        release.require(
            (disk_info.st_dev, disk_info.st_ino)
            == (runtime["disk_device"], runtime["disk_inode"]),
            "VM launch disk identity differs",
        )
        _seed_media(runtime_fd, seed, runtime["runtime_gid"])
        _idle_uid(runtime["runtime_uid"])
        memory_mib = (ROOTLESS_FIXTURE_MEMORY_MIB
                      if seed.get("fixture_profile") == ROOTLESS_FIXTURE_PROFILE
                      else MEMORY_MIB)
        _host_headroom(memory_mib)
        boot_id = _boot_id()
        release.require(
            not (runtime_dir / "qmp.sock").exists(), "VM monitor path already exists"
        )
        args = _arguments(runtime_dir, vm_id, seed["ssh_port"], memory_mib)
        reserve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            reserve.bind(("127.0.0.1", seed["ssh_port"]))
            rebind()
            _named_disk(
                runtime_fd, disk_fd, runtime["runtime_uid"], runtime["runtime_gid"]
            )
            _seed_media(runtime_fd, seed, runtime["runtime_gid"])
            release.require(
                _read_record(registry_fd, vm_id + ".seed-receipt.json")[0] == seed_raw
                and _read_record(registry_fd, vm_id + ".runtime-receipt.json")[0]
                == runtime_raw,
                "VM receipt chain changed before launch",
            )
            intent = {
                "schema": SCHEMA,
                "phase": "intent",
                "vm_id": vm_id,
                "seed_receipt_sha256": release.digest(seed_raw),
                "runtime_dir": str(runtime_dir),
                "control_dir": str(control_dir),
                "runtime_dir_device": runtime["runtime_dir_device"],
                "runtime_dir_inode": runtime["runtime_dir_inode"],
                "control_dir_device": seed["control_dir_device"],
                "control_dir_inode": seed["control_dir_inode"],
                "disk_device": runtime["disk_device"],
                "disk_inode": runtime["disk_inode"],
                "seed_device": seed["seed_device"],
                "seed_inode": seed["seed_inode"],
                "uid": runtime["runtime_uid"],
                "gid": runtime["runtime_gid"],
                "kvm_gid": kvm_gid,
                "ssh_port": seed["ssh_port"],
                "memory_mib": memory_mib,
                "cpus": CPUS,
                "args": args,
                "qemu_sha256": qemu_sha256,
                "controller_boot_id": boot_id,
                "started_at": int(time.time()),
                "qualified": False,
                "dispatch_authorized": False,
            }
            intent_raw = _write(registry_fd, vm_id + ".launch-intent.json", intent)
        finally:
            reserve.close()
        rebind()
        _host_headroom(memory_mib)
        _idle_uid(runtime["runtime_uid"])
        _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"], runtime["runtime_gid"])
        _seed_media(runtime_fd, seed, runtime["runtime_gid"])
        release.require(
            _read_record(registry_fd, vm_id + ".launch-intent.json")[0] == intent_raw
            and _read_record(registry_fd, vm_id + ".seed-receipt.json")[0] == seed_raw
            and _read_record(registry_fd, vm_id + ".runtime-receipt.json")[0]
            == runtime_raw,
            "VM launch inputs changed before spawn",
        )
        command = [
            str(SETPRIV),
            "--reuid",
            str(runtime["runtime_uid"]),
            "--regid",
            str(runtime["runtime_gid"]),
            "--groups",
            str(kvm_gid),
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--",
            *args,
        ]
        process = subprocess.Popen(
            command,
            cwd="/",
            env=ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        rebind()
        spawn_ticks = _start_ticks(process.pid)
        _write(
            registry_fd,
            vm_id + ".launch-pid.json",
            {
                "schema": PID_SCHEMA,
                "phase": "spawned",
                "vm_id": vm_id,
                "intent_sha256": release.digest(intent_raw),
                "pid": process.pid,
                "start_ticks": spawn_ticks,
                "controller_boot_id": boot_id,
                "spawned_at": int(time.time()),
            },
        )
        live = None
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            release.require(
                process.poll() is None, "VM process exited before observation"
            )
            try:
                if os.readlink(Path("/proc") / str(process.pid) / "exe") == str(
                    SETPRIV
                ):
                    time.sleep(0.1)
                    continue
                live = _live(
                    process.pid,
                    args,
                    runtime["runtime_uid"],
                    runtime["runtime_gid"],
                    kvm_gid,
                    runtime_dir / "disk.qcow2",
                    runtime["disk_device"],
                    runtime["disk_inode"],
                    qemu_sha256,
                )
                break
            except (
                FileNotFoundError,
                ConnectionRefusedError,
                socket.timeout,
                observer.DiskNotOpenedYet,
            ):
                time.sleep(0.25)
        release.require(live is not None, "VM process observation timed out")
        release.require(
            live["start_ticks"] == spawn_ticks, "VM process start changed since spawn"
        )
        rebind()
        release.require(
            _live(
                process.pid,
                args,
                runtime["runtime_uid"],
                runtime["runtime_gid"],
                kvm_gid,
                runtime_dir / "disk.qcow2",
                runtime["disk_device"],
                runtime["disk_inode"],
                qemu_sha256,
            )
            == live,
            "VM process changed before receipt",
        )
        receipt = {
            **intent,
            "phase": "launched",
            "intent_sha256": release.digest(intent_raw),
            "pid": live["pid"],
            "start_ticks": live["start_ticks"],
            "disk_fd": live["disk_fd"],
            "observation_route": "initial",
            "pid_authentication": "exact_boot_and_start_ticks",
            "observed_at": int(time.time()),
        }
        _write(registry_fd, vm_id + ".launch-receipt.json", receipt)
        rebind()
        return receipt
    finally:
        os.close(disk_fd)


def _start_ticks(pid: int) -> str:
    value = (
        (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
    )
    release.require(
        value.isdecimal() and int(value) > 0, "VM process start ticks invalid"
    )
    return value


def _spawn_time(pid: int) -> float:
    ticks = int(_start_ticks(pid))
    lines = [
        line
        for line in Path("/proc/stat").read_text().splitlines()
        if line.startswith("btime ")
    ]
    release.require(
        len(lines) == 1 and len(lines[0].split()) == 2,
        "VM process boot time unavailable",
    )
    return int(lines[0].split()[1]) + ticks / os.sysconf("SC_CLK_TCK")


def observe_existing(registry: Path, runtime_parent: Path, *, vm_id: str) -> dict:
    """Observe only the process named in the existing one-time PID record."""
    release.require(os.geteuid() == 0, "root VM controller required")
    with ControllerLease(registry) as lease:
        seed_raw, seed = _read_record(lease.parent, vm_id + ".seed-receipt.json")
        runtime_raw, runtime = _read_record(
            lease.parent, vm_id + ".runtime-receipt.json"
        )
        intent_raw, intent = _read_record(lease.parent, vm_id + ".launch-intent.json")
        pid_raw, spawned = _read_record(lease.parent, vm_id + ".launch-pid.json")
        release.require(
            not (registry / (vm_id + ".launch-receipt.json")).exists(),
            "VM launch already observed",
        )
        legacy_pid = spawned.get("schema") == SCHEMA
        release.exact(
            spawned,
            {"schema", "phase", "vm_id", "intent_sha256", "pid", "spawned_at"}
            | (set() if legacy_pid else {"start_ticks", "controller_boot_id"}),
            "VM launch PID record",
        )
        release.exact(
            intent,
            {
                "schema",
                "phase",
                "vm_id",
                "seed_receipt_sha256",
                "runtime_dir",
                "control_dir",
                "runtime_dir_device",
                "runtime_dir_inode",
                "control_dir_device",
                "control_dir_inode",
                "disk_device",
                "disk_inode",
                "seed_device",
                "seed_inode",
                "uid",
                "gid",
                "kvm_gid",
                "ssh_port",
                "memory_mib",
                "cpus",
                "args",
                "qemu_sha256",
                "controller_boot_id",
                "started_at",
                "qualified",
                "dispatch_authorized",
            },
            "VM launch intent",
        )
        runtime_dir = runtime_parent / vm_id
        control_dir = registry / (vm_id + ".control")
        _safe_runtime_path(runtime_dir)
        release.require(
            intent["schema"] == SCHEMA
            and spawned["schema"] in (SCHEMA, PID_SCHEMA)
            and intent["phase"] == "intent"
            and spawned["phase"] == "spawned"
            and intent["vm_id"] == spawned["vm_id"] == vm_id
            and intent["seed_receipt_sha256"] == release.digest(seed_raw)
            and seed["runtime_receipt_sha256"] == release.digest(runtime_raw)
            and spawned["intent_sha256"] == release.digest(intent_raw)
            and intent["runtime_dir"] == str(runtime_dir)
            and intent["control_dir"] == str(control_dir)
            and (intent["runtime_dir_device"], intent["runtime_dir_inode"])
            == (runtime["runtime_dir_device"], runtime["runtime_dir_inode"])
            and (intent["control_dir_device"], intent["control_dir_inode"])
            == (seed["control_dir_device"], seed["control_dir_inode"])
            and (intent["disk_device"], intent["disk_inode"])
            == (runtime["disk_device"], runtime["disk_inode"])
            and (intent["seed_device"], intent["seed_inode"])
            == (seed["seed_device"], seed["seed_inode"])
            and (intent["uid"], intent["gid"])
            == (runtime["runtime_uid"], runtime["runtime_gid"])
            and intent["kvm_gid"] == _kvm_group()
            and intent["ssh_port"] == seed["ssh_port"]
            and intent["memory_mib"] == (ROOTLESS_FIXTURE_MEMORY_MIB
                                        if seed.get("fixture_profile") == ROOTLESS_FIXTURE_PROFILE
                                        else MEMORY_MIB)
            and intent["cpus"] == CPUS
            and intent["args"] == _arguments(runtime_dir, vm_id, seed["ssh_port"],
                                             intent["memory_mib"])
            and intent["qemu_sha256"] == _trusted_tool(QEMU)
            and intent["controller_boot_id"] == _boot_id()
            and intent["qualified"] is False
            and intent["dispatch_authorized"] is False
            and type(intent["started_at"]) is int
            and type(spawned["spawned_at"]) is int
            and 0 < intent["started_at"] <= spawned["spawned_at"]
            and spawned["spawned_at"] <= int(time.time()) + 5
            and type(spawned["pid"]) is int
            and spawned["pid"] > 4,
            "VM launch recovery records disagree",
        )
        process_start = _spawn_time(spawned["pid"])
        release.require(
            abs(process_start - spawned["spawned_at"]) <= 5,
            "VM launch PID start differs",
        )
        if not legacy_pid:
            release.require(
                spawned["controller_boot_id"] == intent["controller_boot_id"]
                and spawned["start_ticks"] == _start_ticks(spawned["pid"]),
                "VM launch exact PID identity differs",
            )
        control_fd = _directory(control_dir)
        try:
            runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
            try:
                release.require(
                    (os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
                    == (seed["control_dir_device"], seed["control_dir_inode"])
                    and (os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                    == (runtime["runtime_dir_device"], runtime["runtime_dir_inode"]),
                    "VM launch recovery directories differ",
                )
                for name, digest, maximum in (
                    ("controller_ed25519", seed["controller_private_sha256"], 8192),
                    ("guest_host_ed25519", seed["guest_host_private_sha256"], 8192),
                    ("known_hosts", seed["known_hosts_sha256"], 4096),
                    ("user-data", seed["user_data_sha256"], 65536),
                    ("meta-data", seed["metadata_sha256"], 4096),
                    ("seed.iso", seed["seed_sha256"], 16 * 1024 * 1024),
                ):
                    release.require(
                        release.digest(_bytes(control_dir / name, maximum)) == digest,
                        "VM launch control material differs",
                    )
                _seed_media(runtime_fd, seed, runtime["runtime_gid"])
                live = _live(
                    spawned["pid"],
                    intent["args"],
                    intent["uid"],
                    intent["gid"],
                    intent["kvm_gid"],
                    runtime_dir / "disk.qcow2",
                    runtime["disk_device"],
                    runtime["disk_inode"],
                    intent["qemu_sha256"],
                )
                release.require(
                    _spawn_time(spawned["pid"]) == process_start,
                    "VM process start changed during recovery",
                )
                _same_path(
                    runtime_dir,
                    runtime_fd,
                    lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]),
                )
                _same_path(control_dir, control_fd, _directory)
                _same_path(registry, lease.parent, _directory)
                release.require(
                    _read_record(lease.parent, vm_id + ".seed-receipt.json")[0]
                    == seed_raw
                    and _read_record(lease.parent, vm_id + ".runtime-receipt.json")[0]
                    == runtime_raw
                    and _read_record(lease.parent, vm_id + ".launch-intent.json")[0]
                    == intent_raw
                    and _read_record(lease.parent, vm_id + ".launch-pid.json")[0]
                    == pid_raw,
                    "VM launch recovery records changed",
                )
                release.require(
                    _live(
                        spawned["pid"],
                        intent["args"],
                        intent["uid"],
                        intent["gid"],
                        intent["kvm_gid"],
                        runtime_dir / "disk.qcow2",
                        runtime["disk_device"],
                        runtime["disk_inode"],
                        intent["qemu_sha256"],
                    )
                    == live,
                    "VM launch process changed before recovery receipt",
                )
                _same_path(
                    runtime_dir,
                    runtime_fd,
                    lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]),
                )
                _same_path(control_dir, control_fd, _directory)
                _same_path(registry, lease.parent, _directory)
                receipt = {
                    **intent,
                    "phase": "launched",
                    "intent_sha256": release.digest(intent_raw),
                    "pid": live["pid"],
                    "start_ticks": live["start_ticks"],
                    "disk_fd": live["disk_fd"],
                    "observation_route": "existing",
                    "pid_authentication": (
                        "bounded_seconds_engineering_only"
                        if legacy_pid
                        else "exact_boot_and_start_ticks"
                    ),
                    "observed_at": int(time.time()),
                }
                _write(lease.parent, vm_id + ".launch-receipt.json", receipt)
                _same_path(
                    runtime_dir,
                    runtime_fd,
                    lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]),
                )
                _same_path(control_dir, control_fd, _directory)
                _same_path(registry, lease.parent, _directory)
                return receipt
            finally:
                os.close(runtime_fd)
        finally:
            os.close(control_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--observe-existing", action="store_true")
    args = parser.parse_args()
    try:
        if args.observe_existing:
            observe_existing(args.registry, args.runtime_parent, vm_id=args.vm_id)
        else:
            launch(
                args.source,
                args.registry,
                args.vm_parent,
                args.runtime_parent,
                vm_id=args.vm_id,
            )
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        parser.exit(
            1,
            "VM launch refused or uncertain; retain all intent and process evidence.\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
