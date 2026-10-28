"""One guarded, installer-only restart of a previously powered-off test VM.

Historical launch/readiness records remain historical. A durable restart intent
is never retried after an uncertain spawn. This module grants no candidate
dispatch, release qualification, or application-deployment authority.
"""
from __future__ import annotations

import argparse
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
from installer_candidate_vm_create import _bytes, _read_record, _write, verify_source
from installer_candidate_vm_guest_readiness import SSH
from installer_candidate_vm_launch_evidence import bind_provisioned_launch
from installer_candidate_vm_runtime import _identity, _named_disk, _same_path
from installer_candidate_vm_seed import _cloud_config, _private_key, _public_key
from installer_candidate_vm_policy import GUEST_USER
from installer_host_probe import command
import installer_candidate_vm_launch as launcher
import installer_release as release

SCHEMA = "elevenid.installer-test-vm-restart/v1"
PID_SCHEMA = "elevenid.installer-test-vm-restart-pid/v1"
READINESS_SCHEMA = "elevenid.installer-test-vm-restart-readiness/v1"
HISTORICAL = (
    "creation-intent", "creation-receipt", "runtime-intent", "runtime-receipt",
    "seed-intent", "seed-receipt", "launch-intent", "launch-pid", "launch-receipt",
)
MAX_MUTABLE_DISK_BYTES = 4 * 1024 * 1024 * 1024
QEMU_IMG = Path("/usr/bin/qemu-img")
INSTALLER_ONLY_MEMORY_MIB = (2048, 4096)
INSTALLER_ONLY_RESERVE_MIB = 2048
INSTALLER_ONLY_PURPOSE = "installer_only_trial"


def _memory_profile(guest_memory_mib: int) -> None:
    release.require(type(guest_memory_mib) is int
                    and guest_memory_mib in INSTALLER_ONLY_MEMORY_MIB,
                    "VM installer-only memory profile unsupported")


def _restart_args(runtime_dir: Path, vm_id: str, port: int,
                  historical_args: list[str], guest_memory_mib: int) -> list[str]:
    _memory_profile(guest_memory_mib)
    original = launcher._arguments(runtime_dir, vm_id, port)
    release.require(historical_args == original and original.count("-m") == 1,
                    "VM historical memory policy differs")
    memory_index = original.index("-m") + 1
    release.require(original[memory_index] == str(launcher.MEMORY_MIB)
                    and launcher.MEMORY_MIB == 4096,
                    "VM first-launch memory policy differs")
    selected = list(original)
    selected[memory_index] = str(guest_memory_mib)
    return selected


def _headroom_from_meminfo(raw: bytes, guest_memory_mib: int) -> int:
    _memory_profile(guest_memory_mib)
    release.require(0 < len(raw) <= 65536, "VM host memory inventory oversized")
    rows = [line.split() for line in raw.splitlines()
            if line.startswith(b"MemAvailable:")]
    release.require(len(rows) == 1 and len(rows[0]) == 3
                    and rows[0][1].isdigit() and rows[0][2] == b"kB",
                    "VM host memory unavailable")
    available_kib = int(rows[0][1])
    release.require(available_kib >= (guest_memory_mib + INSTALLER_ONLY_RESERVE_MIB)
                    * 1024, "VM installer-only host memory headroom insufficient")
    return available_kib


def _installer_headroom(guest_memory_mib: int) -> int:
    return _headroom_from_meminfo(Path("/proc/meminfo").read_bytes(),
                                  guest_memory_mib)


def _guest_mem_total(raw: str, guest_memory_mib: int) -> int:
    _memory_profile(guest_memory_mib)
    match = re.fullmatch(r"MemTotal:[ \t]+([1-9][0-9]*)[ \t]+kB", raw)
    release.require(match is not None, "VM retained guest memory invalid")
    total = int(match.group(1))
    release.require((guest_memory_mib - 512) * 1024 <= total
                    <= guest_memory_mib * 1024,
                    "VM retained guest memory differs")
    return total


def _uuid4(value: str) -> None:
    release.require(type(value) is str and str(uuid.UUID(value)) == value
                    and uuid.UUID(value).version == 4, "VM restart ID invalid")


def _record_set(parent: int, vm_id: str) -> tuple[dict[str, bytes], dict[str, dict]]:
    raw = {name.replace("-", "_"): _read_record(parent, vm_id + "." + name + ".json")[0]
           for name in HISTORICAL}
    records = {name: release.decode(value) for name, value in raw.items()}
    release.require(all(release.encode(records[name]) == value
                        for name, value in raw.items()), "VM restart records not canonical")
    bind_provisioned_launch(**raw,
                            boot_id=records["launch_intent"]["controller_boot_id"])
    return raw, records


def _poweroff(parent: int, vm_id: str, records: dict[str, dict]) -> tuple[bytes, bytes]:
    intent_raw, intent = _read_record(parent, vm_id + ".scope-retirement-poweroff-intent.json")
    result_raw, result = _read_record(parent, vm_id + ".scope-retirement-poweroff-result.json")
    release.require(release.encode(intent) == intent_raw and release.encode(result) == result_raw,
                    "VM poweroff records not canonical")
    release.exact(intent, {"acceptance", "disk_retained", "pid", "reason",
                           "requested_at", "start_ticks", "vm_id"},
                  "VM poweroff intent")
    release.exact(result, {"acceptance", "disk_retained", "observed_at",
                           "original_pid", "original_process_absent",
                           "original_start_ticks", "request_error_type", "vm_id"},
                  "VM poweroff result")
    launch = records["launch_receipt"]
    release.require(
        intent.get("vm_id") == result.get("vm_id") == vm_id
        and intent.get("pid") == result.get("original_pid") == launch["pid"]
        and intent.get("start_ticks") == result.get("original_start_ticks") == launch["start_ticks"]
        and result.get("original_process_absent") is True
        and result.get("request_error_type") is None
        and result.get("disk_retained") is True
        and result.get("acceptance") is False
        and intent["disk_retained"] is True
        and intent["acceptance"] is False
        and type(intent["reason"]) is str and 0 < len(intent["reason"]) <= 256
        and type(intent["requested_at"]) is int
        and type(result.get("observed_at")) is int
        and launch["observed_at"] <= intent["requested_at"] <= result["observed_at"],
        "VM poweroff evidence differs",
    )
    return intent_raw, result_raw


def _no_prior_attempt(parent: int, vm_id: str) -> None:
    # A discovered intent is never re-used. All restart records are fixed-name
    # and one-shot, so unknown partial attempts block before a new mutation.
    for suffix in ("restart-intent", "restart-pid", "restart-receipt",
                   "restart-readiness"):
        try:
            os.stat(vm_id + "." + suffix + ".json", dir_fd=parent,
                    follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("VM restart attempt already recorded")


def _status_uids(raw: bytes) -> tuple[int, int, int, int]:
    release.require(0 < len(raw) <= 65536, "VM process status inventory invalid")
    lines = [line.split(b":", 1)[1].split() for line in raw.splitlines()
             if line.startswith(b"Uid:")]
    release.require(len(lines) == 1 and len(lines[0]) == 4
                    and all(item.isascii() and item.isdigit() for item in lines[0]),
                    "VM process UID inventory invalid")
    return tuple(int(item) for item in lines[0])


def _process_start(proc: Path) -> str:
    with (proc / "stat").open("rb") as stream:
        raw = stream.read(65537)
    release.require(0 < len(raw) <= 65536 and b") " in raw,
                    "VM process start inventory invalid")
    fields = raw.rsplit(b") ", 1)[1].split()
    release.require(len(fields) >= 20 and fields[19].isdigit(),
                    "VM process start inventory invalid")
    return fields[19].decode("ascii")


def _actor_is_uid(proc: Path, uid: int) -> bool:
    with (proc / "status").open("rb") as stream:
        return uid in _status_uids(stream.read(65537))


def _original_still_live(old_pid: int, old_start: str, old_boot: str) -> bool:
    old = Path("/proc") / str(old_pid)
    if old.exists() and launcher._boot_id() == old_boot:
        try:
            return _process_start(old) == old_start
        except FileNotFoundError:
            release.require(not old.exists(), "VM original PID changed during inventory")
    return False


def _scan_descriptors(proc: Path, disk: os.stat_result) -> None:
    # Keep the scandir DIR descriptor open while statting each yielded entry.
    # Listing it first closes /proc/self/fd's own enumeration descriptor.
    count = 0
    with os.scandir(proc / "fd") as descriptors:
        for descriptor in descriptors:
            count += 1
            release.require(count <= 4096, "VM descriptor census oversized")
            try:
                held = descriptor.stat()
                if (held.st_dev, held.st_ino) == (disk.st_dev, disk.st_ino):
                    release.require(
                        int(proc.name) == os.getpid()
                        and fcntl.fcntl(int(descriptor.name), fcntl.F_GETFL)
                        & os.O_ACCMODE == os.O_RDONLY,
                        "VM disk has a live process holder")
            except FileNotFoundError:
                release.require(not proc.exists(), "VM descriptor inventory changed")
                break


def _no_live_owner(uid: int, old_pid: int, old_start: str, old_boot: str,
                   runtime_dir: Path, port: int) -> None:
    # PID absence alone does not prove shutdown. Refuse any actor under the
    # dedicated account, a disk holder, a QMP endpoint, or a bound SSH port.
    release.require(not _original_still_live(old_pid, old_start, old_boot),
                    "VM original process still exists")
    try:
        (runtime_dir / "qmp.sock").lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("VM monitor endpoint still exists")
    disk = (runtime_dir / "disk.qcow2").lstat()
    processes = list(Path("/proc").iterdir())
    release.require(len(processes) <= 65536, "VM process census oversized")
    for proc in processes:
        if not proc.name.isdecimal():
            continue
        try:
            start = _process_start(proc)
            release.require(not _actor_is_uid(proc, uid),
                            "VM runtime identity has an existing process")
            _scan_descriptors(proc, disk)
            release.require(_process_start(proc) == start,
                            "VM process changed during inventory")
        except FileNotFoundError:
            release.require(not proc.exists(), "VM process changed during inventory")
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", port))


def _mutable_digest(fd: int) -> tuple[int, str, int, int]:
    before = os.fstat(fd)
    release.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 < before.st_size <= MAX_MUTABLE_DISK_BYTES,
                    "VM mutable disk bounds invalid")
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    left = before.st_size
    while left:
        block = os.read(fd, min(left, 1024 * 1024))
        release.require(bool(block), "VM mutable disk truncated")
        digest.update(block)
        left -= len(block)
    after = os.fstat(fd)
    release.require((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                     stat.S_IMODE(before.st_mode), before.st_nlink, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                        stat.S_IMODE(after.st_mode), after.st_nlink, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns),
                    "VM mutable disk changed during digest")
    return before.st_size, digest.hexdigest(), before.st_mtime_ns, before.st_ctime_ns


def _disk_fd(runtime_fd: int, uid: int, gid: int,
             device: int, inode: int) -> int:
    """Classify the held inode before any content-capable open."""
    path_fd = os.open("disk.qcow2", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=runtime_fd)
    try:
        info = os.fstat(path_fd)
        release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and (info.st_dev, info.st_ino) == (device, inode)
                        and (info.st_uid, info.st_gid) == (uid, gid)
                        and stat.S_IMODE(info.st_mode) == 0o600,
                        "VM disk held metadata differs")
        _named_disk(runtime_fd, path_fd, uid, gid)
        readable = os.open(f"/proc/self/fd/{path_fd}",
                           os.O_RDONLY | os.O_CLOEXEC)
        try:
            again = os.fstat(readable)
            release.require((again.st_dev, again.st_ino, again.st_uid, again.st_gid,
                             stat.S_IMODE(again.st_mode), again.st_nlink)
                            == (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                                stat.S_IMODE(info.st_mode), info.st_nlink),
                            "VM disk changed during safe reopen")
            _named_disk(runtime_fd, readable, uid, gid)
            return readable
        except BaseException:
            os.close(readable)
            raise
    finally:
        os.close(path_fd)


def _header_backing(fd: int, expected_base: str, expected_virtual_bytes: int) -> None:
    """Reject unsafe qcow2 names/features before any image parser opens them."""
    header = os.pread(fd, 112, 0)
    u32 = lambda offset: int.from_bytes(header[offset:offset + 4], "big")
    u64 = lambda offset: int.from_bytes(header[offset:offset + 8], "big")
    release.require(len(header) == 112 and header[:4] == b"QFI\xfb"
                    and u32(4) == 3 and 9 <= u32(20) <= 21
                    and u64(24) == expected_virtual_bytes
                    and u32(32) == 0 and u64(72) == 0
                    and not u64(88) & 2,
                    "VM qcow2 header differs")
    cluster = 1 << u32(20)
    backing_offset, backing_size = u64(8), u32(16)
    header_length = u32(100)
    release.require(104 <= header_length <= backing_offset
                    and header_length % 8 == 0
                    and 0 < backing_size <= 1023
                    and backing_offset + backing_size <= cluster,
                    "VM qcow2 backing bounds differ")
    first_cluster = os.pread(fd, cluster, 0)
    release.require(len(first_cluster) == cluster
                    and first_cluster[backing_offset:backing_offset + backing_size]
                    == expected_base.encode("ascii"),
                    "VM qcow2 backing name differs")
    at = header_length
    ended = False
    backing_format = None
    while at + 8 <= backing_offset:
        kind = int.from_bytes(first_cluster[at:at + 4], "big")
        size = int.from_bytes(first_cluster[at + 4:at + 8], "big")
        if kind == 0:
            release.require(size == 0, "VM qcow2 extension terminator invalid")
            ended = True
            break
        next_at = at + 8 + ((size + 7) & ~7)
        release.require(next_at <= backing_offset, "VM qcow2 extension bounds differ")
        value = first_cluster[at + 8:at + 8 + size]
        release.require(kind != 0x44415441, "VM qcow2 external data file refused")
        if kind == 0xe2792aca:
            release.require(backing_format is None and value == b"qcow2",
                            "VM qcow2 backing format differs")
            backing_format = value
        at = next_at
    release.require(ended, "VM qcow2 extension terminator missing")


def _qemu_info_unprivileged(disk: Path, uid: int, gid: int) -> bytes:
    launcher._trusted_tool(launcher.SETPRIV)
    launcher._trusted_tool(QEMU_IMG)
    argv = [str(launcher.SETPRIV), "--reuid", str(uid), "--regid", str(gid),
            "--clear-groups", "--bounding-set=-all", "--inh-caps=-all",
            "--ambient-caps=-all", "--no-new-privs", "--", str(QEMU_IMG),
            "info", "-f", "qcow2", "--output=json", str(disk)]
    process = subprocess.Popen(argv, cwd="/", env=launcher.ENV, close_fds=True,
                               start_new_session=True, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    result = bytearray()
    deadline = time.monotonic() + 30
    try:
        while True:
            remaining = deadline - time.monotonic()
            release.require(remaining > 0, "VM image inspection timed out")
            readable, _, _ = select.select([process.stdout], [], [], min(remaining, 0.5))
            if not readable:
                continue
            block = os.read(process.stdout.fileno(), 8192)
            if not block:
                break
            result.extend(block)
            release.require(len(result) <= 65536, "VM image inspection oversized")
        release.require(process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                        "VM image inspection failed")
        return bytes(result)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()


def _mutable_image_info(disk: Path, fd: int, uid: int, gid: int,
                        expected_base: str, expected_virtual_bytes: int) -> None:
    _header_backing(fd, expected_base, expected_virtual_bytes)
    raw = _qemu_info_unprivileged(disk, uid, gid)
    info = json.loads(raw)
    def data_file(value: object) -> bool:
        if type(value) is dict:
            return any(key.startswith("data-file") or data_file(item)
                       for key, item in value.items())
        if type(value) is list:
            return any(data_file(item) for item in value)
        return False
    release.require(type(info) is dict and info.get("format") == "qcow2"
                    and info.get("filename") == str(disk)
                    and info.get("backing-filename") == expected_base
                    and info.get("full-backing-filename", expected_base) == expected_base
                    and info.get("backing-filename-format") in (None, "qcow2")
                    and info.get("virtual-size") == expected_virtual_bytes
                    and not data_file(info),
                    "VM mutable image backing differs")


def _historical_guest(parent: int, vm_id: str,
                      historical: dict[str, bytes]) -> tuple[bytes, str, int]:
    raw, record = _read_record(parent, vm_id + ".guest-readiness.json")
    release.require(release.encode(record) == raw and record.get("vm_id") == vm_id
                    and record.get("phase") == "guest-ready"
                    and record.get("qualified") is False
                    and record.get("dispatch_authorized") is False
                    and record.get("record_sha256")
                    == {name + "_sha256": release.digest(value)
                        for name, value in historical.items()}
                    and type(record.get("guest")) is dict
                    and type(record["guest"].get("docker_engine_id")) is str
                    and bool(record["guest"]["docker_engine_id"])
                    and type(record["guest"].get("guest_uid")) is int
                    and record["guest"]["guest_uid"] > 0
                    and record["guest"].get("guest_user") == GUEST_USER,
                    "VM historical guest observation differs")
    return raw, record["guest"]["docker_engine_id"], record["guest"]["guest_uid"]


def _retained_guest(control_dir: Path, *, port: int, seed: dict,
                    guest_memory_mib: int) -> dict:
    """Read current pinned guest identity without demanding an empty Docker state."""
    release.require(seed["guest_user"] == GUEST_USER and 1024 <= port <= 65535,
                    "VM retained guest selection invalid")
    ssh_info = SSH.lstat()
    release.require(stat.S_ISREG(ssh_info.st_mode) and ssh_info.st_uid == 0
                    and not ssh_info.st_mode & 0o022,
                    "VM retained SSH client untrusted")
    key = control_dir / "controller_ed25519"
    hosts = control_dir / "known_hosts"
    def pinned() -> None:
        release.require(release.digest(_bytes(key, 8192))
                        == seed["controller_private_sha256"]
                        and release.digest(_bytes(hosts, 4096))
                        == seed["known_hosts_sha256"],
                        "VM retained SSH identity changed")
    options = [str(SSH), "-F", "/dev/null", "-i", str(key),
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(hosts),
               "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "IdentityAgent=none",
               "-o", "IdentitiesOnly=yes", "-o", "ProxyCommand=none",
               "-o", "ProxyJump=none", "-o", "ForwardAgent=no",
               "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=5",
               "-o", "ConnectionAttempts=1", "-p", str(port),
               GUEST_USER + "@127.0.0.1"]
    def guest(script: str) -> str:
        pinned()
        value = command([*options, script], timeout=15, limit=65536,
                        env=launcher.ENV).decode("ascii").strip()
        pinned()
        return value
    account = guest("/usr/bin/id -u; /usr/bin/id -un; "
                    "/usr/bin/stat -c '%u:%a:%F' /home/installer").splitlines()
    release.require(len(account) == 3 and account[0].isdecimal()
                    and int(account[0]) > 0 and account[1] == GUEST_USER
                    and account[2] == account[0] + ":700:directory",
                    "VM retained guest account differs")
    engine = json.loads(guest("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
                              "/usr/bin/docker --host unix:///var/run/docker.sock "
                              "info --format '{{json .ID}}'"))
    release.require(guest("/usr/bin/systemctl is-active docker") == "active"
                    and guest("/usr/bin/uname -m") == "x86_64"
                    and type(engine) is str and bool(engine),
                    "VM retained guest Engine unavailable")
    release.require(json.loads(guest("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
                                     "/usr/bin/docker --host unix:///var/run/docker.sock "
                                     "info --format '{{json .ID}}'")) == engine,
                    "VM retained guest Engine changed")
    mem_total_kib = _guest_mem_total(
        guest("/usr/bin/grep '^MemTotal:' /proc/meminfo"), guest_memory_mib)
    return {"guest_uid": int(account[0]), "guest_user": GUEST_USER,
            "guest_architecture": "x86_64", "docker_engine_id": engine,
            "guest_mem_total_kib": mem_total_kib}


def _recheck_before_spawn(source: Path, registry: Path, runtime_parent: Path, vm_id: str,
                          lease: ControllerLease, intent: dict,
                          context: dict) -> bytes:
    """Rebind the named disk and exact durable intent immediately before spawn."""
    _same_path(registry, lease.parent, _directory)
    raw, current = _read_record(lease.parent, vm_id + ".restart-intent.json")
    release.require(current == intent and release.encode(current) == raw,
                    "VM restart intent changed")
    runtime = context["records"]["runtime_receipt"]
    seed = context["records"]["seed_receipt"]
    runtime_dir = runtime_parent / vm_id
    control_dir = registry / (vm_id + ".control")
    control_fd = _directory(control_dir)
    try:
        release.require((os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
                        == (intent["control_dir_device"], intent["control_dir_inode"]),
                        "VM restart control changed")
        _source_and_control(source, registry, context["records"], control_fd)
    finally:
        os.close(control_fd)
    release.require(all(_read_record(lease.parent, vm_id + "." + name.replace("_", "-")
                                     + ".json")[0] == value
                        for name, value in context["raw"].items())
                    and release.digest(_read_record(
                        lease.parent, vm_id + ".scope-retirement-poweroff-intent.json")[0])
                    == intent["poweroff_intent_sha256"]
                    and release.digest(_read_record(
                        lease.parent, vm_id + ".scope-retirement-poweroff-result.json")[0])
                    == intent["poweroff_result_sha256"]
                    and release.digest(_read_record(
                        lease.parent, vm_id + ".guest-readiness.json")[0])
                    == intent["historical_guest_readiness_sha256"],
                    "VM restart historical evidence changed before spawn")
    runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
    try:
        release.require((os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                        == (intent["runtime_dir_device"], intent["runtime_dir_inode"]),
                        "VM restart runtime changed")
        disk_fd = _disk_fd(runtime_fd, runtime["runtime_uid"],
                           runtime["runtime_gid"], intent["disk_device"],
                           intent["disk_inode"])
        try:
            _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"], runtime["runtime_gid"])
            info = os.fstat(disk_fd)
            release.require((info.st_dev, info.st_ino)
                            == (intent["disk_device"], intent["disk_inode"])
                            and _mutable_digest(disk_fd)
                            == (intent["mutable_disk_bytes"], intent["mutable_disk_sha256"],
                                intent["mutable_disk_mtime_ns"], intent["mutable_disk_ctime_ns"]),
                            "VM mutable disk changed before spawn")
            _mutable_image_info(
                runtime_dir / "disk.qcow2", disk_fd, runtime["runtime_uid"],
                runtime["runtime_gid"],
                context["records"]["creation_intent"]["image"]["image_path"],
                context["records"]["creation_receipt"]["virtual_gib"] * 1024**3)
            release.require(_mutable_digest(disk_fd)
                            == (intent["mutable_disk_bytes"], intent["mutable_disk_sha256"],
                                intent["mutable_disk_mtime_ns"], intent["mutable_disk_ctime_ns"]),
                            "VM mutable disk changed during image inspection")
            _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"], runtime["runtime_gid"])
            launcher._seed_media(runtime_fd, seed, runtime["runtime_gid"])
            _same_path(runtime_dir, runtime_fd,
                       lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]))
            _same_path(registry, lease.parent, _directory)
            release.require(_read_record(lease.parent, vm_id + ".restart-intent.json")[0]
                            == raw, "VM restart intent changed before spawn")
            return raw
        finally:
            os.close(disk_fd)
    finally:
        os.close(runtime_fd)


def _source_and_control(source: Path, registry: Path, records: dict[str, dict],
                        control_fd: int) -> None:
    creation = records["creation_intent"]
    seed = records["seed_receipt"]
    release.require(verify_source(source) == creation["image"],
                    "VM signed source differs")
    control_dir = registry / (creation["vm_id"] + ".control")
    release.require((os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
                    == (seed["control_dir_device"], seed["control_dir_inode"]),
                    "VM control directory differs")
    # verify the complete seed recipe; never expose secret bytes in records.
    controller_private = _bytes(control_dir / "controller_ed25519", 8192)
    controller_public = _public_key(_bytes(control_dir / "controller_ed25519.pub", 1024))
    host_private = _private_key(_bytes(control_dir / "guest_host_ed25519", 8192))
    host_public = _public_key(_bytes(control_dir / "guest_host_ed25519.pub", 1024))
    expected = {
        "controller_ed25519": (seed["controller_private_sha256"], 8192),
        "guest_host_ed25519": (seed["guest_host_private_sha256"], 8192),
        "known_hosts": (seed["known_hosts_sha256"], 4096),
        "user-data": (seed["user_data_sha256"], 65536),
        "meta-data": (seed["metadata_sha256"], 4096),
        "seed.iso": (seed["seed_sha256"], 16 * 1024 * 1024),
    }
    for name, (digest, maximum) in expected.items():
        release.require(release.digest(_bytes(control_dir / name, maximum)) == digest,
                        "VM control material differs")
        info = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
        release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                        "VM control material custody differs")
    release.require(
        _bytes(control_dir / "user-data", 65536)
        == _cloud_config(controller_public, host_public, host_private)
        and release.digest(controller_private) == seed["controller_private_sha256"],
        "VM control recipe differs",
    )


def _prepare_restart(source: Path, registry: Path, runtime_parent: Path,
                     vm_id: str, nonce: str, guest_memory_mib: int,
                     lease: ControllerLease) -> tuple[dict, dict]:
    """Read-only exact preflight; callers must repeat it before any intent."""
    parent = lease.parent
    release.require(parent is not None and lease.owner_pid == os.getpid(),
                    "VM controller lease not held")
    _memory_profile(guest_memory_mib)
    _same_path(registry, parent, _directory)
    _no_prior_attempt(parent, vm_id)
    raw, records = _record_set(parent, vm_id)
    power_intent, power_result = _poweroff(parent, vm_id, records)
    historical_guest_raw, historical_engine, historical_uid = _historical_guest(
        parent, vm_id, raw)
    runtime = records["runtime_receipt"]
    seed = records["seed_receipt"]
    launch = records["launch_intent"]
    runtime_dir = runtime_parent / vm_id
    control_dir = registry / (vm_id + ".control")
    release.require(str(runtime_dir) == launch["runtime_dir"]
                    and str(control_dir) == launch["control_dir"]
                    and runtime["runtime_account"] == _identity(
                        vm_id, runtime["runtime_uid"], runtime["runtime_gid"])
                    and launch["args"] == launcher._arguments(
                        runtime_dir, vm_id, seed["ssh_port"])
                    and launch["qemu_sha256"] == launcher._trusted_tool(launcher.QEMU)
                    and launch["kvm_gid"] == launcher._kvm_group(),
                    "VM restart launch policy differs")
    selected_args = _restart_args(runtime_dir, vm_id, seed["ssh_port"],
                                  launch["args"], guest_memory_mib)
    _no_live_owner(runtime["runtime_uid"], records["launch_pid"]["pid"],
                   records["launch_pid"]["start_ticks"],
                   records["launch_pid"]["controller_boot_id"],
                   runtime_dir, seed["ssh_port"])
    runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
    try:
        control_fd = _directory(control_dir)
        try:
            release.require((os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                            == (runtime["runtime_dir_device"], runtime["runtime_dir_inode"]),
                            "VM runtime directory differs")
            _source_and_control(source, registry, records, control_fd)
            launcher._seed_media(runtime_fd, seed, runtime["runtime_gid"])
            disk_fd = _disk_fd(runtime_fd, runtime["runtime_uid"],
                               runtime["runtime_gid"], runtime["disk_device"],
                               runtime["disk_inode"])
            try:
                _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"],
                            runtime["runtime_gid"])
                disk_info = os.fstat(disk_fd)
                release.require((disk_info.st_dev, disk_info.st_ino)
                                == (runtime["disk_device"], runtime["disk_inode"]),
                                "VM disk identity differs")
                _mutable_image_info(
                    runtime_dir / "disk.qcow2", disk_fd, runtime["runtime_uid"],
                    runtime["runtime_gid"],
                    records["creation_intent"]["image"]["image_path"],
                    records["creation_receipt"]["virtual_gib"] * 1024**3)
                first = _mutable_digest(disk_fd)
                _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"],
                            runtime["runtime_gid"])
                available_kib = _installer_headroom(guest_memory_mib)
                _no_live_owner(runtime["runtime_uid"], records["launch_pid"]["pid"],
                               records["launch_pid"]["start_ticks"],
                               records["launch_pid"]["controller_boot_id"],
                               runtime_dir, seed["ssh_port"])
                _same_path(runtime_dir, runtime_fd,
                           lambda path: observer.open_vm_dir(path, runtime["runtime_uid"]))
                _same_path(control_dir, control_fd, _directory)
                _same_path(registry, parent, _directory)
                release.require(all(_read_record(parent, vm_id + "." + name.replace("_", "-")
                                                 + ".json")[0] == value
                                    for name, value in raw.items())
                                and _read_record(parent, vm_id + ".scope-retirement-poweroff-intent.json")[0]
                                == power_intent
                                and _read_record(parent, vm_id + ".scope-retirement-poweroff-result.json")[0]
                                == power_result
                                and _read_record(parent, vm_id + ".guest-readiness.json")[0]
                                == historical_guest_raw
                                and _mutable_digest(disk_fd) == first,
                                "VM restart inputs changed")
                _named_disk(runtime_fd, disk_fd, runtime["runtime_uid"],
                            runtime["runtime_gid"])
                intent = {
                    "schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
                    "attempt_nonce": nonce, "controller_boot_id": launcher._boot_id(),
                    "historical_sha256": {name: release.digest(value)
                                          for name, value in raw.items()},
                    "poweroff_intent_sha256": release.digest(power_intent),
                    "poweroff_result_sha256": release.digest(power_result),
                    "historical_guest_readiness_sha256": release.digest(historical_guest_raw),
                    "historical_docker_engine_id": historical_engine,
                    "historical_guest_uid": historical_uid,
                    "runtime_dir_device": runtime["runtime_dir_device"],
                    "runtime_dir_inode": runtime["runtime_dir_inode"],
                    "control_dir_device": seed["control_dir_device"],
                    "control_dir_inode": seed["control_dir_inode"],
                    "disk_device": runtime["disk_device"],
                    "disk_inode": runtime["disk_inode"],
                    "mutable_disk_bytes": first[0], "mutable_disk_sha256": first[1],
                    "mutable_disk_mtime_ns": first[2], "mutable_disk_ctime_ns": first[3],
                    "runtime_uid": runtime["runtime_uid"],
                    "runtime_gid": runtime["runtime_gid"],
                    "ssh_port": seed["ssh_port"], "args": selected_args,
                    "guest_memory_mib": guest_memory_mib,
                    "controller_reserve_mib": INSTALLER_ONLY_RESERVE_MIB,
                    "purpose": INSTALLER_ONLY_PURPOSE,
                    "host_mem_available_kib_at_preflight": available_kib,
                    "qemu_sha256": launch["qemu_sha256"],
                    "qualified": False, "dispatch_authorized": False,
                    "application_deployment_authorized": False,
                    "started_at": int(time.time()),
                }
                return intent, {"records": records, "raw": raw,
                                "runtime_dir": runtime_dir, "control_dir": control_dir}
            finally:
                os.close(disk_fd)
        finally:
            os.close(control_fd)
    finally:
        os.close(runtime_fd)


def restart(source: Path, registry: Path, runtime_parent: Path, *, vm_id: str,
            attempt_nonce: str, guest_memory_mib: int = 2048) -> dict:
    """Spawn one isolated QEMU process and persist its exact live observation."""
    release.require(os.geteuid() == 0, "root VM controller required")
    _uuid4(vm_id)
    _uuid4(attempt_nonce)
    _memory_profile(guest_memory_mib)
    qemu_sha = launcher._trusted_tool(launcher.QEMU)
    launcher._trusted_tool(launcher.SETPRIV)
    kvm_gid = launcher._kvm_group()
    with ControllerLease(registry) as lease:
        intent, context = _prepare_restart(source, registry, runtime_parent,
                                           vm_id, attempt_nonce, guest_memory_mib, lease)
        _installer_headroom(guest_memory_mib)
        # Exclusive record publication is the irreversible attempt boundary.
        intent_raw = _write(lease.parent, vm_id + ".restart-intent.json", intent)
        release.require(_read_record(lease.parent, vm_id + ".restart-intent.json")[0]
                        == intent_raw, "VM restart intent changed after publication")
        runtime_dir = context["runtime_dir"]
        runtime = context["records"]["runtime_receipt"]
        _same_path(registry, lease.parent, _directory)
        previous = context["records"]["launch_pid"]
        _no_live_owner(runtime["runtime_uid"], previous["pid"],
                       previous["start_ticks"], previous["controller_boot_id"],
                       runtime_dir, intent["ssh_port"])
        release.require(qemu_sha == intent["qemu_sha256"],
                        "VM QEMU changed before restart")
        intent_raw = _recheck_before_spawn(source, registry, runtime_parent, vm_id,
                                          lease, intent, context)
        _installer_headroom(guest_memory_mib)
        process = subprocess.Popen(
            [str(launcher.SETPRIV), "--reuid", str(runtime["runtime_uid"]),
             "--regid", str(runtime["runtime_gid"]), "--groups", str(kvm_gid),
             "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
             "--no-new-privs", "--", *intent["args"]],
            cwd="/", env=launcher.ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
        ticks = launcher._start_ticks(process.pid)
        _write(lease.parent, vm_id + ".restart-pid.json", {
            "schema": PID_SCHEMA, "phase": "spawned", "vm_id": vm_id,
            "attempt_nonce": attempt_nonce, "intent_sha256": release.digest(intent_raw),
            "controller_boot_id": intent["controller_boot_id"],
            "pid": process.pid, "start_ticks": ticks, "spawned_at": int(time.time()),
        })
        live = None
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            release.require(process.poll() is None, "VM restart exited before observation")
            try:
                if os.readlink(Path("/proc") / str(process.pid) / "exe") == str(launcher.SETPRIV):
                    time.sleep(0.1)
                    continue
                live = launcher._live(
                    process.pid, intent["args"], runtime["runtime_uid"],
                    runtime["runtime_gid"], kvm_gid, runtime_dir / "disk.qcow2",
                    intent["disk_device"], intent["disk_inode"], qemu_sha)
                break
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout,
                    observer.DiskNotOpenedYet):
                time.sleep(0.25)
        release.require(live is not None and live["start_ticks"] == ticks,
                        "VM restart live identity unavailable")
        release.require(launcher._live(
            process.pid, intent["args"], runtime["runtime_uid"],
            runtime["runtime_gid"], kvm_gid, runtime_dir / "disk.qcow2",
            intent["disk_device"], intent["disk_inode"], qemu_sha) == live,
            "VM restart process changed")
        receipt = {**intent, "phase": "launched", "intent_sha256": release.digest(intent_raw),
                   "pid": live["pid"], "start_ticks": live["start_ticks"],
                   "disk_fd": live["disk_fd"], "observed_at": int(time.time())}
        _write(lease.parent, vm_id + ".restart-receipt.json", receipt)
        return receipt


def inspect(source: Path, registry: Path, runtime_parent: Path, *, vm_id: str,
            attempt_nonce: str, guest_memory_mib: int = 2048) -> dict:
    """Rehearse exact static checks without consuming an attempt or authorizing use."""
    release.require(os.geteuid() == 0, "root VM controller required")
    _uuid4(vm_id)
    _uuid4(attempt_nonce)
    _memory_profile(guest_memory_mib)
    with ControllerLease(registry) as lease:
        _prepare_restart(source, registry, runtime_parent, vm_id, attempt_nonce,
                         guest_memory_mib, lease)
    return {"vm_id": vm_id, "attempt_nonce": attempt_nonce, "phase": "preflight",
            "guest_memory_mib": guest_memory_mib,
            "controller_reserve_mib": INSTALLER_ONLY_RESERVE_MIB,
            "purpose": INSTALLER_ONLY_PURPOSE,
            "read_only": True, "qualified": False, "dispatch_authorized": False,
            "application_deployment_authorized": False}


def current_readiness(source: Path, registry: Path, runtime_parent: Path, *, vm_id: str) -> dict:
    """Observe the restarted process and pinned guest afresh; do not use old readiness."""
    release.require(os.geteuid() == 0, "root VM controller required")
    _uuid4(vm_id)
    with ControllerLease(registry) as lease:
        raw, records = _record_set(lease.parent, vm_id)
        intent_raw, intent = _read_record(lease.parent, vm_id + ".restart-intent.json")
        pid_raw, spawned = _read_record(lease.parent, vm_id + ".restart-pid.json")
        receipt_raw, receipt = _read_record(lease.parent, vm_id + ".restart-receipt.json")
        release.exact(intent, {
            "schema", "phase", "vm_id", "attempt_nonce", "controller_boot_id",
            "historical_sha256", "poweroff_intent_sha256", "poweroff_result_sha256",
            "historical_guest_readiness_sha256", "historical_docker_engine_id",
            "historical_guest_uid",
            "runtime_dir_device", "runtime_dir_inode", "control_dir_device",
            "control_dir_inode", "disk_device", "disk_inode", "mutable_disk_bytes",
            "mutable_disk_sha256", "mutable_disk_mtime_ns", "mutable_disk_ctime_ns",
            "runtime_uid", "runtime_gid", "ssh_port", "args", "qemu_sha256",
            "guest_memory_mib", "controller_reserve_mib", "purpose",
            "host_mem_available_kib_at_preflight",
            "qualified", "dispatch_authorized", "application_deployment_authorized",
            "started_at",
        }, "VM restart intent")
        release.exact(spawned, {"schema", "phase", "vm_id", "attempt_nonce",
                                "intent_sha256", "controller_boot_id", "pid",
                                "start_ticks", "spawned_at"}, "VM restart PID")
        release.exact(receipt, set(intent) | {"intent_sha256", "pid", "start_ticks",
                                                  "disk_fd", "observed_at"},
                      "VM restart receipt")
        release.require(intent["schema"] == receipt["schema"] == SCHEMA
                        and spawned["schema"] == PID_SCHEMA
                        and (intent["phase"], spawned["phase"], receipt["phase"])
                        == ("intent", "spawned", "launched")
                        and intent["vm_id"] == spawned["vm_id"] == receipt["vm_id"] == vm_id
                        and intent["attempt_nonce"] == spawned["attempt_nonce"]
                        == receipt["attempt_nonce"]
                        and all(receipt[key] == value for key, value in intent.items()
                                if key != "phase")
                        and intent["historical_sha256"] == {name: release.digest(value)
                        for name, value in raw.items()}
                        and spawned["intent_sha256"] == receipt["intent_sha256"]
                        == release.digest(intent_raw)
                        and receipt["pid"] == spawned["pid"]
                        and receipt["start_ticks"] == spawned["start_ticks"]
                        and intent["controller_boot_id"] == spawned["controller_boot_id"]
                        == launcher._boot_id()
                        and receipt["qualified"] is False
                        and receipt["dispatch_authorized"] is False
                        and receipt["application_deployment_authorized"] is False,
                        "VM restart receipt chain differs")
        release.require(
            release.digest(_read_record(
                lease.parent, vm_id + ".scope-retirement-poweroff-intent.json")[0])
            == intent["poweroff_intent_sha256"]
            and release.digest(_read_record(
                lease.parent, vm_id + ".scope-retirement-poweroff-result.json")[0])
            == intent["poweroff_result_sha256"]
            and release.digest(_read_record(
                lease.parent, vm_id + ".guest-readiness.json")[0])
            == intent["historical_guest_readiness_sha256"],
            "VM restart historical evidence changed")
        runtime = records["runtime_receipt"]
        seed = records["seed_receipt"]
        runtime_dir = runtime_parent / vm_id
        _uuid4(intent["attempt_nonce"])
        _memory_profile(intent["guest_memory_mib"])
        release.require(str(runtime_dir) == records["launch_intent"]["runtime_dir"]
                        and intent["args"] == _restart_args(
                            runtime_dir, vm_id, seed["ssh_port"],
                            records["launch_intent"]["args"], intent["guest_memory_mib"])
                        and intent["controller_reserve_mib"] == INSTALLER_ONLY_RESERVE_MIB
                        and intent["purpose"] == INSTALLER_ONLY_PURPOSE
                        and type(intent["host_mem_available_kib_at_preflight"]) is int
                        and intent["host_mem_available_kib_at_preflight"]
                        >= (intent["guest_memory_mib"] + INSTALLER_ONLY_RESERVE_MIB) * 1024
                        and intent["qemu_sha256"] == launcher._trusted_tool(launcher.QEMU)
                        and intent["runtime_uid"] == runtime["runtime_uid"]
                        and intent["runtime_gid"] == runtime["runtime_gid"]
                        and intent["disk_device"] == runtime["disk_device"]
                        and intent["disk_inode"] == runtime["disk_inode"]
                        and intent["ssh_port"] == seed["ssh_port"]
                        and type(intent["mutable_disk_bytes"]) is int
                        and 0 < intent["mutable_disk_bytes"] <= MAX_MUTABLE_DISK_BYTES
                        and type(intent["mutable_disk_sha256"]) is str
                        and len(intent["mutable_disk_sha256"]) == 64,
                        "VM restart runtime path differs")
        control_dir = registry / (vm_id + ".control")
        def recheck_custody() -> None:
            _same_path(registry, lease.parent, _directory)
            control_fd = _directory(control_dir)
            try:
                release.require((os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
                                == (intent["control_dir_device"], intent["control_dir_inode"]),
                                "VM restart control directory differs")
                _source_and_control(source, registry, records, control_fd)
            finally:
                os.close(control_fd)
            runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
            try:
                release.require((os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                                == (intent["runtime_dir_device"], intent["runtime_dir_inode"]),
                                "VM restart runtime directory differs")
                launcher._seed_media(runtime_fd, seed, runtime["runtime_gid"])
            finally:
                os.close(runtime_fd)
        recheck_custody()
        first = launcher._live(
            spawned["pid"], intent["args"], runtime["runtime_uid"],
            runtime["runtime_gid"], records["launch_intent"]["kvm_gid"],
            runtime_dir / "disk.qcow2", runtime["disk_device"], runtime["disk_inode"],
            intent["qemu_sha256"])
        release.require(first == {"pid": spawned["pid"],
                                  "start_ticks": spawned["start_ticks"],
                                  "disk_fd": receipt["disk_fd"]},
                        "VM restarted process differs")
        guest = _retained_guest(control_dir, port=seed["ssh_port"], seed=seed,
                                guest_memory_mib=intent["guest_memory_mib"])
        release.require(guest["docker_engine_id"] == intent["historical_docker_engine_id"],
                        "VM retained Docker Engine changed")
        release.require(guest["guest_uid"] == intent["historical_guest_uid"],
                        "VM retained guest account changed")
        recheck_custody()
        release.require(launcher._live(
            spawned["pid"], intent["args"], runtime["runtime_uid"],
            runtime["runtime_gid"], records["launch_intent"]["kvm_gid"],
            runtime_dir / "disk.qcow2", runtime["disk_device"], runtime["disk_inode"],
            intent["qemu_sha256"]) == first
            and all(_read_record(lease.parent, vm_id + "." + name.replace("_", "-")
                                 + ".json")[0] == value for name, value in raw.items())
            and _read_record(lease.parent, vm_id + ".restart-intent.json")[0] == intent_raw
            and _read_record(lease.parent, vm_id + ".restart-pid.json")[0] == pid_raw
            and _read_record(lease.parent, vm_id + ".restart-receipt.json")[0] == receipt_raw,
            "VM current readiness inputs changed")
        observed = {"schema": READINESS_SCHEMA, "phase": "guest-ready",
                    "vm_id": vm_id, "attempt_nonce": intent["attempt_nonce"],
                    "controller_boot_id": intent["controller_boot_id"],
                    "restart_receipt_sha256": release.digest(receipt_raw),
                    "pid": first["pid"], "start_ticks": first["start_ticks"],
                    "disk_device": runtime["disk_device"],
                    "disk_inode": runtime["disk_inode"],
                    "guest": guest, "observed_at": int(time.time()),
                    "guest_memory_mib": intent["guest_memory_mib"],
                    "controller_reserve_mib": INSTALLER_ONLY_RESERVE_MIB,
                    "purpose": INSTALLER_ONLY_PURPOSE,
                    "qualified": False, "dispatch_authorized": False,
                    "application_deployment_authorized": False}
        _write(lease.parent, vm_id + ".restart-readiness.json", observed)
        return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="root-custodied signed Ubuntu cloud-image directory")
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--runtime-parent", required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--guest-memory-mib", type=int,
                        choices=INSTALLER_ONLY_MEMORY_MIB, default=None,
                        help="installer-only guest RAM; defaults to 2048 MiB")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--restart-attempt-nonce")
    action.add_argument("--inspect-attempt-nonce")
    action.add_argument("--current-readiness", action="store_true")
    args = parser.parse_args()
    try:
        guest_memory_mib = 2048 if args.guest_memory_mib is None else args.guest_memory_mib
        if args.current_readiness:
            release.require(args.guest_memory_mib is None,
                            "VM readiness memory comes from restart intent")
            result = current_readiness(args.source, args.registry, args.runtime_parent,
                                       vm_id=args.vm_id)
        elif args.inspect_attempt_nonce is not None:
            result = inspect(args.source, args.registry, args.runtime_parent,
                             vm_id=args.vm_id,
                             attempt_nonce=args.inspect_attempt_nonce,
                             guest_memory_mib=guest_memory_mib)
        else:
            result = restart(args.source, args.registry, args.runtime_parent,
                             vm_id=args.vm_id,
                             attempt_nonce=args.restart_attempt_nonce,
                             guest_memory_mib=guest_memory_mib)
        print(json.dumps({"vm_id": result["vm_id"], "phase": result["phase"],
                          "attempt_nonce": result["attempt_nonce"],
                          "guest_memory_mib": result["guest_memory_mib"],
                          "controller_reserve_mib": result["controller_reserve_mib"],
                          "purpose": result["purpose"],
                          "qualified": False, "dispatch_authorized": False,
                          "application_deployment_authorized": False},
                         sort_keys=True))
        return 0
    except Exception:
        print("VM installer-only restart refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
