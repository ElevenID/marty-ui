"""Observe an owned QEMU trial guest for diagnostic capacity experiments.

Run on the trusted Linux controller as root. This reads only the owned VM and
guest Docker state. This experimental output must not authorize controller
nonce consumption, dispatch, or installed-journey acceptance. It does not prove
fresh image origin, trusted control-directory custody, or physical capacity.
Use one caller-allocated installation UUID for initial-empty, pre-dispatch,
and post-install identity observations. A VM restart requires separate policy;
this observer requires the original process lifetime throughout.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import time
import uuid
from typing import Callable

import installer_release as release
from installer_candidate_controller import _directory
from installer_host_probe import command


def private_file_at(parent: int, name: str, owner: int, maximum: int) -> bytes:
    release.require("/" not in name and name not in ("", ".", ".."),
                    "VM observation filename invalid")
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == owner
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and 0 < info.st_size <= maximum, "VM observation file differs")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        held = os.fstat(fd)
        release.require((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
                        "VM observation file changed")
        raw = os.read(fd, maximum + 1)
        again = os.stat(name, dir_fd=parent, follow_symlinks=False)
        release.require((again.st_dev, again.st_ino, again.st_size, again.st_mtime_ns)
                        == (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        and len(raw) == info.st_size, "VM observation file changed")
        return raw
    finally:
        os.close(fd)


def open_vm_dir(path: Path, expected_owner: int) -> int:
    release.require(path.is_absolute() and ".." not in path.parts
                    and type(expected_owner) is int and expected_owner >= 0,
                    "VM control directory path invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            release.require(info.st_uid in (0, expected_owner)
                            and (not info.st_mode & 0o022
                                 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                            "VM control ancestor is untrusted")
        child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fd)
        os.close(fd)
        fd = child
        info = os.fstat(fd)
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == expected_owner
                        and stat.S_IMODE(info.st_mode) == 0o700,
                        "VM control directory is not private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def qmp(socket_path: Path, disk: Path, *, pid: int, uid: int) -> None:
    info = socket_path.lstat()
    release.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid,
                    "VM monitor socket differs")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(socket_path))
        peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        release.require((peer_pid, peer_uid) == (pid, uid),
                        "VM monitor peer differs")
        with connection.makefile("rwb") as stream:
            release.require("QMP" in json.loads(stream.readline(65537)),
                            "VM monitor greeting differs")

            def query(name: str, ident: int):
                stream.write(release.encode({"execute": name, "id": ident}))
                stream.flush()
                for _ in range(20):
                    response = stream.readline(65537)
                    release.require(0 < len(response) <= 65536, "VM monitor response invalid")
                    decoded = release.decode(response)
                    if decoded.get("id") == ident:
                        release.require("return" in decoded, "VM monitor query failed")
                        return decoded["return"]
                raise ValueError("VM monitor response unavailable")

            query("qmp_capabilities", 1)
            state = query("query-status", 2)
            release.require(state.get("running") is True and state.get("status") == "running",
                            "VM is not running")
            blocks = query("query-block", 3)
            release.require(isinstance(blocks, list), "VM block inventory invalid")
            matching = [entry.get("inserted") for entry in blocks if isinstance(entry, dict)
                        and isinstance(entry.get("inserted"), dict)
                        and entry["inserted"].get("file") == str(disk)]
            release.require(len(matching) == 1 and matching[0].get("drv") == "qcow2"
                            and matching[0].get("ro") is False, "VM disk differs")


def held_writable_disk(process: Path, disk: Path, expected: os.stat_result) -> int:
    """Require a live process FD to hold this exact writable disk inode."""
    fd_root = process / "fd"
    names = os.listdir(fd_root)
    release.require(len(names) <= 4096 and all(name.isdecimal() for name in names),
                    "VM descriptor inventory invalid")
    matches = []
    for name in names:
        fd_path = fd_root / name
        try:
            target = os.readlink(fd_path)
        except FileNotFoundError:
            continue  # A non-disk descriptor closed during the inventory.
        if target != str(disk):
            continue
        info_path = process / "fdinfo" / name
        info_fd = os.open(info_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            raw = os.read(info_fd, 4097)
        finally:
            os.close(info_fd)
        release.require(len(raw) <= 4096, "VM disk descriptor metadata oversized")
        flags = [line.removeprefix(b"flags:").strip() for line in raw.splitlines()
                 if line.startswith(b"flags:")]
        release.require(len(flags) == 1 and flags[0]
                        and all(byte in b"01234567" for byte in flags[0]),
                        "VM disk descriptor flags invalid")
        access = int(flags[0], 8) & os.O_ACCMODE
        held = os.stat(fd_path)
        release.require(access == os.O_RDWR
                        and stat.S_ISREG(held.st_mode)
                        and (held.st_dev, held.st_ino) == (expected.st_dev, expected.st_ino)
                        and os.readlink(fd_path) == str(disk),
                        "VM does not hold the selected writable disk")
        matches.append(int(name))
    release.require(len(matches) == 1, "VM writable disk descriptor differs")
    return matches[0]


def validate_initial(initial: dict, installation_id: str) -> None:
    required = {"schema", "target", "observation_phase", "vm_boot_id",
                "vm_config_sha256", "controller_key_sha256", "known_hosts_sha256",
                "guest_user", "guest_uid", "observed_at", "vm_pid",
                "vm_start_ticks", "vm_disk_device", "vm_disk_inode", "vm_disk_fd",
                "vm_memory_mib", "vm_cpus", "initial_docker_clean",
                "capacity_qualified", "clean_host_qualified", "dispatch_authorized"}
    release.require(type(initial) is dict and set(initial) == required
                    and initial["schema"] == "elevenid.installer-qemu-trial-observation/v2"
                    and initial["observation_phase"] == "initial-empty"
                    and type(initial["target"]) is dict
                    and set(initial["target"]) == {"guest_id", "disk_id", "engine_id",
                                                    "installation_id"}
                    and initial["target"]["installation_id"] == installation_id
                    and initial["initial_docker_clean"] is True
                    and initial["dispatch_authorized"] is False
                    and initial["clean_host_qualified"] is False
                    and initial["capacity_qualified"] is False,
                    "initial VM observation invalid")
    release.require(all(type(initial["target"][field]) is str
                        and initial["target"][field]
                        for field in ("guest_id", "disk_id", "engine_id", "installation_id"))
                    and type(initial["guest_user"]) is str
                    and initial["guest_user"].isidentifier()
                    and type(initial["guest_uid"]) is int and initial["guest_uid"] > 0
                    and all(type(initial[field]) is int and initial[field] >= 0
                            for field in ("vm_pid", "vm_disk_device", "vm_disk_inode",
                                          "vm_disk_fd"))
                    and type(initial["vm_start_ticks"]) is str
                    and initial["vm_start_ticks"].isdecimal(),
                    "initial VM observation invalid")


def require_same_vm(initial: dict, current: dict) -> None:
    for field in ("target", "guest_user", "guest_uid", "vm_boot_id",
                  "vm_pid", "vm_start_ticks",
                  "vm_disk_device", "vm_disk_inode", "vm_disk_fd",
                  "vm_config_sha256", "controller_key_sha256", "known_hosts_sha256"):
        release.require(initial.get(field) == current[field],
                        "VM changed after initial observation")


def require_clean_docker(phase: str, guest: Callable[[str], str], docker: str) -> None:
    if phase == "post-install":
        return
    for docker_query in ("ps -aq", "images -q", "volume ls -q"):
        release.require(guest(docker + " " + docker_query) == "",
                        "guest Docker is not initially clean")
    release.require(set(guest(docker + " network ls --format '{{.Name}}'").splitlines())
                    == {"bridge", "host", "none"},
                    "guest Docker network inventory differs")


def write_observation(parent: int, name: str, raw: bytes) -> None:
    release.require(name.endswith("-observation.json") and "/" not in name
                    and len(raw) <= 65536, "observation output invalid")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        os.fsync(parent)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent)
    finally:
        os.close(fd)


def _observe(vm_dir: Path, vm_parent: int, output_dir: Path, output_parent: int, *, guest_user: str,
             ssh_host: str, installation_id: str, phase: str, expected_vm_uid: int,
             ssh_bin: Path) -> dict:
    release.require(os.geteuid() == 0 and vm_dir.is_absolute() and output_dir.is_absolute()
                    and vm_dir.resolve() == vm_dir and output_dir.resolve() == output_dir,
                    "trusted absolute controller paths required")
    release.require(guest_user.isidentifier() and guest_user != "root"
                    and ssh_host == "127.0.0.1", "trial guest selection differs")
    release.require(phase in ("initial-empty", "pre-dispatch", "post-install")
                    and type(installation_id) is str
                    and str(uuid.UUID(installation_id)) == installation_id
                    and uuid.UUID(installation_id).version == 4,
                    "observation phase or installation identity differs")
    initial_name = installation_id + ".initial-observation.json"
    initial_bytes = None
    initial = None
    if phase != "initial-empty":
        initial_bytes = private_file_at(output_parent, initial_name, 0, 65536)
        initial = release.decode(initial_bytes)
        validate_initial(initial, installation_id)
    directory = os.fstat(vm_parent)
    release.require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700,
                    "VM control directory is not private")
    owner = directory.st_uid
    output = os.fstat(output_parent)
    release.require(stat.S_ISDIR(output.st_mode) and output.st_uid == 0
                    and stat.S_IMODE(output.st_mode) == 0o700,
                    "controller registry is not private")
    vm_bytes = private_file_at(vm_parent, "vm.json", owner, 65536)
    vm = release.decode(vm_bytes)
    release.require(isinstance(vm, dict) and type(vm.get("id")) is str
                    and str(uuid.UUID(vm["id"])) == vm["id"]
                    and uuid.UUID(vm["id"]).version == 4,
                    "VM identity differs")
    port = vm.get("ssh_port")
    release.require(type(port) is int and 1 <= port <= 65535
                    and type(vm.get("args")) is list
                    and all(type(arg) is str for arg in vm["args"]),
                    "VM launch record invalid")
    args = vm["args"]
    disk = vm_dir / "disk.qcow2"
    release.require(args[0] == "/usr/bin/qemu-system-x86_64"
                    and "file=" + str(disk) + ",if=virtio,format=qcow2" in args
                    and "unix:" + str(vm_dir / "qmp.sock") + ",server=on,wait=off" in args
                    and "user,id=net0,hostfwd=tcp:127.0.0.1:"
                    + str(port) + "-:22" in args,
                    "VM launch arguments differ")
    pid = int(private_file_at(vm_parent, "vm.pid", 0, 16))
    release.require(pid > 4, "VM PID invalid")
    process = Path("/proc") / str(pid)
    live_args = (process / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    release.require(live_args == args and process.stat().st_uid == owner
                    and os.readlink(process / "exe") == args[0],
                    "live VM process differs")
    start_ticks = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
    disk_info = disk.lstat()
    release.require(stat.S_ISREG(disk_info.st_mode) and disk_info.st_uid == owner
                    and disk_info.st_nlink == 1, "VM disk identity differs")
    qmp(vm_dir / "qmp.sock", disk, pid=pid, uid=owner)
    disk_fd = held_writable_disk(process, disk, disk_info)
    key = vm_dir / "controller_ed25519"
    known_hosts = vm_dir / "known_hosts"
    key_bytes = private_file_at(vm_parent, key.name, owner, 65536)
    known_hosts_bytes = private_file_at(vm_parent, known_hosts.name, owner, 65536)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    release.require(str(uuid.UUID(boot_id)) == boot_id, "controller boot identity invalid")
    # SSH consumes root-owned snapshots, never mutable VM-owner paths.
    with tempfile.TemporaryDirectory(prefix="observe-ssh-", dir=output_dir) as credentials:
        key = Path(credentials) / "controller_ed25519"
        known_hosts = Path(credentials) / "known_hosts"
        for path, raw in ((key, key_bytes), (known_hosts, known_hosts_bytes)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
        ssh_info = ssh_bin.lstat()
        release.require(stat.S_ISREG(ssh_info.st_mode) and ssh_info.st_uid == 0
                        and not ssh_info.st_mode & 0o022, "SSH client differs")
        options = [str(ssh_bin), "-F", "/dev/null", "-i", str(key), "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentityAgent=none",
                   "-o", "IdentitiesOnly=yes", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                   "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
                   "-o", "ConnectTimeout=5", "-p", str(port), guest_user + "@" + ssh_host]

        def guest(script: str) -> str:
            raw = command([*options, script], timeout=15, limit=65536,
                          env={"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"})
            return raw.decode("ascii").strip()

        account = guest("id -u; id -un; stat -c '%u:%a:%F' /home/" + guest_user).splitlines()
        release.require(len(account) == 3 and account[0].isdecimal() and int(account[0]) > 0
                        and account[1] == guest_user
                        and account[2] == account[0] + ":700:directory",
                        "guest account is not private")
        docker = ("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
                  "/usr/bin/docker --host unix:///var/run/docker.sock")
        engine_query = docker + " info --format '{{json .ID}}'"
        engine = json.loads(guest(engine_query))
        release.require(type(engine) is str and engine, "guest Docker Engine unavailable")
        release.require(guest("uname -m") == "x86_64" and
                        json.loads(guest(docker + " info --format '{{json .OSType}}'")) == "linux" and
                        json.loads(guest(docker + " info --format '{{json .Architecture}}'")) in ("x86_64", "amd64"),
                        "guest Docker platform differs")
        require_clean_docker(phase, guest, docker)
        release.require(json.loads(guest(engine_query)) == engine, "guest Docker Engine changed")
        again = disk.lstat()
        release.require((again.st_dev, again.st_ino) == (disk_info.st_dev, disk_info.st_ino)
                        and (process / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0") == args
                        and process.stat().st_uid == owner
                        and os.readlink(process / "exe") == args[0]
                        and (process / "stat").read_text().rsplit(")", 1)[1].split()[19] == start_ticks,
                        "VM changed during observation")
        rebound_vm = open_vm_dir(vm_dir, expected_vm_uid)
        try:
            final_directory = os.fstat(rebound_vm)
            release.require((final_directory.st_dev, final_directory.st_ino) ==
                            (directory.st_dev, directory.st_ino)
                            and private_file_at(vm_parent, "vm.json", owner, 65536) == vm_bytes,
                            "VM control root changed")
        finally:
            os.close(rebound_vm)
        qmp(vm_dir / "qmp.sock", disk, pid=pid, uid=owner)
        release.require(held_writable_disk(process, disk, disk_info) == disk_fd,
                        "VM disk descriptor changed during observation")
        release.require((process / "stat").read_text().rsplit(")", 1)[1].split()[19]
                        == start_ticks and os.readlink(process / "exe") == args[0],
                        "VM process changed after disk observation")
        disk_identity = release.digest(release.encode(dict(vm_id=vm["id"], path=str(disk),
                            device=disk_info.st_dev, inode=disk_info.st_ino)))
        target = dict(guest_id=vm["id"], disk_id=disk_identity, engine_id=engine,
                      installation_id=installation_id)
        evidence = dict(schema="elevenid.installer-qemu-trial-observation/v2", target=target,
                        observation_phase=phase, vm_boot_id=boot_id,
                        guest_user=guest_user, guest_uid=int(account[0]),
                        vm_config_sha256=release.digest(vm_bytes),
                        controller_key_sha256=release.digest(key_bytes),
                        known_hosts_sha256=release.digest(known_hosts_bytes),
                        observed_at=int(time.time()), vm_pid=pid, vm_start_ticks=start_ticks,
                        vm_disk_device=disk_info.st_dev, vm_disk_inode=disk_info.st_ino,
                        vm_disk_fd=disk_fd,
                        vm_memory_mib=vm.get("memory_mib"), vm_cpus=vm.get("cpus"),
                        capacity_qualified=False,
                        clean_host_qualified=False, dispatch_authorized=False)
        if phase == "initial-empty":
            evidence["initial_docker_clean"] = True
        else:
            release.require(initial is not None and initial_bytes is not None,
                            "initial VM observation unavailable")
            require_same_vm(initial, evidence)
            rebound_vm = open_vm_dir(vm_dir, expected_vm_uid)
            try:
                current_dir = os.fstat(rebound_vm)
                release.require(private_file_at(output_parent, initial_name, 0, 65536)
                                == initial_bytes
                                and (current_dir.st_dev, current_dir.st_ino)
                                == (directory.st_dev, directory.st_ino),
                                "initial observation or VM control root changed")
            finally:
                os.close(rebound_vm)
            evidence["initial_observation_sha256"] = release.digest(initial_bytes)
            if phase == "pre-dispatch":
                evidence["docker_clean_at_observation"] = True
        final_output = output_dir.lstat()
        release.require((final_output.st_dev, final_output.st_ino)
                        == (output.st_dev, output.st_ino),
                        "controller output root changed")
        suffix = (".initial-observation.json" if phase == "initial-empty"
                  else "." + phase + "-observation.json")
        write_observation(output_parent, installation_id + suffix, release.encode(evidence))
        rebound = _directory(output_dir)
        try:
            release.require((os.fstat(rebound).st_dev, os.fstat(rebound).st_ino)
                            == (output.st_dev, output.st_ino),
                            "controller output root changed after publication")
        finally:
            os.close(rebound)
    return evidence


def observe(vm_dir: Path, output_dir: Path, *, guest_user: str, ssh_host: str,
            installation_id: str, phase: str, expected_vm_uid: int,
            ssh_bin: Path = Path("/usr/bin/ssh")) -> dict:
    vm_parent = open_vm_dir(vm_dir, expected_vm_uid)
    try:
        parent = _directory(output_dir)
        try:
            return _observe(vm_dir, vm_parent, output_dir, parent,
                            guest_user=guest_user, ssh_host=ssh_host,
                            installation_id=installation_id, phase=phase,
                            expected_vm_uid=expected_vm_uid,
                            ssh_bin=ssh_bin)
        finally:
            os.close(parent)
    finally:
        os.close(vm_parent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--guest-user", required=True)
    parser.add_argument("--ssh-host", default="127.0.0.1")
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--phase", choices=("initial-empty", "pre-dispatch", "post-install"), required=True)
    parser.add_argument("--expected-vm-uid", type=int, required=True,
                        help="Diagnostic selection only; future dispatch needs independent approval")
    args = parser.parse_args()
    try:
        observe(args.vm_dir, args.output_dir, guest_user=args.guest_user,
                ssh_host=args.ssh_host, installation_id=args.installation_id,
                phase=args.phase, expected_vm_uid=args.expected_vm_uid)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, IndexError):
        parser.exit(1, "Owned VM observation refused; preserve all control records.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
