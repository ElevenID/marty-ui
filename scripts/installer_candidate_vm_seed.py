#!/usr/bin/env python3
"""Prepare one root-controlled cloud-init seed for an unlaunched trial VM.

The seed contains a disposable guest host key. It never contains a Marty
application, registry, GitHub, KMS or personal credential. Creation does not
authorize launch, dispatch, qualification, or release admission.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import time

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
from installer_candidate_vm_create import _bytes, _read_record, _write
from installer_candidate_vm_runtime import _runtime_parent, _same_path, verify_transfer
from installer_host_probe import command
import installer_release as release

SCHEMA = "elevenid.installer-vm-seed/v1"
GUEST_USER = "installer"
KEYGEN = Path("/usr/bin/ssh-keygen")
LOCALDS = Path("/usr/bin/cloud-localds")
CLOUD_INIT = Path("/usr/bin/cloud-init")
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}
# This is an engineering image policy. The later installed acceptance must
# record actual package identities and source before it may qualify a release.
PACKAGES = {
    "openssh-server": "1:9.6p1-3ubuntu13.20",
    "docker.io": "29.1.3-0ubuntu3~24.04.2",
    "docker-compose-v2": "2.40.3+ds1-0ubuntu1~24.04.1",
    "containerd": "2.2.1-0ubuntu1~24.04.4",
    "runc": "1.3.4-0ubuntu1~24.04.1",
}


def _tool(path: Path) -> None:
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and not info.st_mode & 0o022 and bool(info.st_mode & 0o111),
                    "VM seed tool custody invalid")


def _public_key(raw: bytes) -> str:
    line = raw.decode("ascii").strip().split()
    release.require(len(line) in (2, 3) and line[0] == "ssh-ed25519"
                    and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line[1]) is not None,
                    "VM SSH public key invalid")
    return line[0] + " " + line[1]


def _private_key(raw: bytes) -> str:
    value = raw.decode("ascii")
    release.require(value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                    and value.endswith("-----END OPENSSH PRIVATE KEY-----\n")
                    and 100 < len(raw) < 8192
                    and all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n- "
                            for character in value),
                    "VM SSH private key invalid")
    return value


def _write_bytes(parent: int, name: str, raw: bytes) -> None:
    release.require("/" not in name and name not in ("", ".", "..")
                    and 0 < len(raw) <= 16 * 1024 * 1024,
                    "VM seed file invalid")
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


def _sync_control(path: Path) -> None:
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and info.st_nlink == 1 and not info.st_mode & 0o022,
                    "VM control file custody invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        held = os.fstat(fd)
        release.require((held.st_dev, held.st_ino) == (info.st_dev, info.st_ino),
                        "VM control file changed")
        os.fsync(fd)
    finally:
        os.close(fd)


def _install_media(runtime_fd: int, raw: bytes, gid: int) -> tuple[int, os.stat_result]:
    """Keep the exclusive seed FD across write, ownership, hash and name checks."""
    fd = os.open("seed.iso", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=runtime_fd)
    try:
        os.fsync(runtime_fd)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o440)
        os.fsync(fd)
        os.fsync(runtime_fd)
        held = os.fstat(fd)
        named = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
        release.require(stat.S_ISREG(named.st_mode)
                        and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
                        and held.st_uid == named.st_uid == 0
                        and held.st_gid == named.st_gid == gid
                        and held.st_nlink == named.st_nlink == 1
                        and stat.S_IMODE(held.st_mode) == stat.S_IMODE(named.st_mode) == 0o440
                        and held.st_size == len(raw), "VM seed runtime media changed")
        os.lseek(fd, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) < len(raw):
            block = os.read(fd, min(1024 * 1024, len(raw) - len(observed)))
            release.require(bool(block), "VM seed media truncated")
            observed.extend(block)
        release.require(bytes(observed) == raw and os.fstat(fd).st_size == len(raw),
                        "VM seed media bytes differ")
        return fd, held
    except BaseException:
        os.close(fd)
        raise


def _cloud_config(controller_public: str, host_public: str, host_private: str) -> bytes:
    # All variable scalars are constrained by _public_key/_private_key.
    lines = ["#cloud-config", "users:", "  - name: installer",
             "    lock_passwd: true", "    sudo: ALL=(ALL) NOPASSWD:ALL",
             "    groups: docker", "    homedir: /home/installer",
             "    ssh_authorized_keys:", "      - " + controller_public,
             "ssh_pwauth: false", "disable_root: true",
             "allow_public_ssh_keys: false", "ssh_deletekeys: true",
             "ssh_genkeytypes: [ed25519]", "ssh_keys:", "  ed25519_private: |"]
    lines.extend("    " + line for line in host_private.splitlines())
    lines.extend(["  ed25519_public: " + host_public,
                  "package_update: true", "package_upgrade: false", "packages:"])
    lines.extend("  - [" + name + ", " + json.dumps(version) + "]"
                 for name, version in PACKAGES.items())
    lines.extend(["runcmd:", "  - [chmod, '0700', /home/installer]",
                  "  - [systemctl, enable, --now, docker]",
                  "  - [systemctl, enable, --now, ssh]", ""])
    raw = "\n".join(lines).encode("ascii")
    release.require(len(raw) <= 65536, "VM cloud-init configuration oversized")
    return raw


def _keypair(control: Path, basename: str) -> tuple[str, str]:
    destination = control / basename
    command([str(KEYGEN), "-q", "-t", "ed25519", "-N", "", "-f", str(destination)],
            env=ENV, timeout=30, limit=4096)
    _sync_control(destination)
    _sync_control(control / (basename + ".pub"))
    private = _bytes(destination, 8192)
    public = _bytes(control / (basename + ".pub"), 1024)
    _private_key(private)
    return _public_key(public), release.digest(private)


def prepare(source: Path, registry: Path, vm_parent: Path, runtime_parent: Path, *,
            vm_id: str, ssh_port: int) -> dict:
    release.require(os.geteuid() == 0 and type(ssh_port) is int
                    and 1024 <= ssh_port <= 65535, "VM seed request invalid")
    for path in (KEYGEN, LOCALDS, CLOUD_INIT):
        _tool(path)
    transfer = verify_transfer(source, registry, vm_parent, runtime_parent, vm_id=vm_id)
    with ControllerLease(registry) as lease:
        runtime_raw, live = _read_record(lease.parent, vm_id + ".runtime-receipt.json")
        release.require(live == transfer, "VM runtime receipt changed before seeding")
        runtime_dir = runtime_parent / vm_id
        runtime_fd = observer.open_vm_dir(runtime_dir, live["runtime_uid"])
        try:
            runtime_info = os.fstat(runtime_fd)
            release.require((runtime_info.st_dev, runtime_info.st_ino, runtime_info.st_uid)
                            == (live["runtime_dir_device"], live["runtime_dir_inode"],
                                live["runtime_uid"]), "VM runtime directory changed")
            parent_fd = _runtime_parent(runtime_parent)
            try:
                _same_path(runtime_parent, parent_fd, _runtime_parent)
                _same_path(registry, lease.parent, _directory)
                intent = dict(schema=SCHEMA, phase="intent", vm_id=vm_id,
                              runtime_receipt_sha256=release.digest(runtime_raw),
                              control_dir=str(registry / (vm_id + ".control")),
                              runtime_dir=str(runtime_dir), ssh_port=ssh_port,
                              guest_user=GUEST_USER, packages=PACKAGES,
                              started_at=int(time.time()), qualified=False,
                              launch_authorized=False)
                intent_raw = _write(lease.parent, vm_id + ".seed-intent.json", intent)
                _same_path(registry, lease.parent, _directory)
                control_name = vm_id + ".control"
                os.mkdir(control_name, 0o700, dir_fd=lease.parent)
                os.fsync(lease.parent)
                control_dir = registry / control_name
                control_fd = _directory(control_dir)
                try:
                    prior_umask = os.umask(0o077)
                    try:
                        controller_public, controller_private_hash = _keypair(
                            control_dir, "controller_ed25519")
                        host_public, host_private_hash = _keypair(
                            control_dir, "guest_host_ed25519")
                        host_private = _private_key(_bytes(control_dir / "guest_host_ed25519", 8192))
                        user_data = _cloud_config(controller_public, host_public, host_private)
                        metadata = ("instance-id: " + vm_id + "\nlocal-hostname: marty-vm-"
                                    + vm_id[:8] + "\n").encode("ascii")
                        known_hosts = ("[127.0.0.1]:" + str(ssh_port) + " "
                                       + host_public + "\n").encode("ascii")
                        for name, raw in (("user-data", user_data), ("meta-data", metadata),
                                          ("known_hosts", known_hosts)):
                            _write_bytes(control_fd, name, raw)
                        command([str(CLOUD_INIT), "schema", "--config-file",
                                 str(control_dir / "user-data")], env=ENV,
                                timeout=30, limit=4096)
                        command([str(LOCALDS), str(control_dir / "seed.iso"),
                                 str(control_dir / "user-data"), str(control_dir / "meta-data")],
                                env=ENV, timeout=60, limit=4096)
                        _sync_control(control_dir / "seed.iso")
                        os.fsync(control_fd)
                    finally:
                        os.umask(prior_umask)
                    seed = _bytes(control_dir / "seed.iso", 16 * 1024 * 1024)
                    _same_path(control_dir, control_fd, _directory)
                    _same_path(runtime_parent, parent_fd, _runtime_parent)
                    _same_path(registry, lease.parent, _directory)
                    seed_fd, held = _install_media(runtime_fd, seed, live["runtime_gid"])
                    try:
                        named = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
                        release.require(stat.S_ISREG(named.st_mode)
                                        and (named.st_dev, named.st_ino)
                                        == (held.st_dev, held.st_ino)
                                        and named.st_uid == 0
                                        and named.st_gid == live["runtime_gid"]
                                        and named.st_nlink == 1
                                        and stat.S_IMODE(named.st_mode) == 0o440,
                                        "VM seed runtime media changed")
                        release.require(_bytes(control_dir / "seed.iso", 16 * 1024 * 1024) == seed
                                        and _bytes(control_dir / "user-data", 65536) == user_data
                                        and _bytes(control_dir / "meta-data", 4096) == metadata
                                        and _bytes(control_dir / "known_hosts", 4096) == known_hosts
                                        and release.digest(_bytes(control_dir / "controller_ed25519", 8192))
                                        == controller_private_hash
                                        and release.digest(_bytes(control_dir / "guest_host_ed25519", 8192))
                                        == host_private_hash,
                                        "VM seed control material changed")
                        receipt = dict(intent, phase="seeded",
                                       intent_sha256=release.digest(intent_raw),
                                       control_dir_device=os.fstat(control_fd).st_dev,
                                       control_dir_inode=os.fstat(control_fd).st_ino,
                                       seed_device=held.st_dev, seed_inode=held.st_ino,
                                       seed_bytes=len(seed), seed_sha256=release.digest(seed),
                                       user_data_sha256=release.digest(user_data),
                                       metadata_sha256=release.digest(metadata),
                                       known_hosts_sha256=release.digest(known_hosts),
                                       controller_public_sha256=release.digest(controller_public.encode("ascii")),
                                       guest_host_public_sha256=release.digest(host_public.encode("ascii")),
                                       controller_private_sha256=controller_private_hash,
                                       guest_host_private_sha256=host_private_hash,
                                       seeded_at=int(time.time()))
                        _same_path(runtime_parent, parent_fd, _runtime_parent)
                        _same_path(runtime_dir, runtime_fd,
                                   lambda path: observer.open_vm_dir(path, live["runtime_uid"]))
                        _same_path(control_dir, control_fd, _directory)
                        _same_path(registry, lease.parent, _directory)
                        _write(lease.parent, vm_id + ".seed-receipt.json", receipt)
                        _same_path(registry, lease.parent, _directory)
                        return receipt
                    finally:
                        os.close(seed_fd)
                finally:
                    os.close(control_fd)
            finally:
                os.close(parent_fd)
        finally:
            os.close(runtime_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--ssh-port", required=True, type=int)
    args = parser.parse_args()
    try:
        prepare(args.source, args.registry, args.vm_parent, args.runtime_parent,
                vm_id=args.vm_id, ssh_port=args.ssh_port)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM seed refused or uncertain; retain all intent, media and keys.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
