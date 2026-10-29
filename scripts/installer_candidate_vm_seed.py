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
from installer_candidate_vm_policy import GUEST_USER, PACKAGES
from installer_candidate_vm_create import _bytes, _read_record, _write
from installer_candidate_vm_runtime import _runtime_parent, _same_path, verify_transfer
from installer_host_probe import command
import installer_release as release

SCHEMA = "elevenid.installer-vm-seed/v1"
KEYGEN = Path("/usr/bin/ssh-keygen")
LOCALDS = Path("/usr/bin/cloud-localds")
CLOUD_INIT = Path("/usr/bin/cloud-init")
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}
ROOTLESS_FIXTURE_PROFILE = "installer_only_rootless_fixture"
# The setup-phase Engine is confined to the new disposable guest. It is test
# infrastructure for the existing signed package admission chain, never the
# product installer's selected daemon. Product dispatch remains disabled until
# a later controller proves this service stopped and a distinct user-owned
# rootless Engine is bound to the ordinary installer account.
ROOTLESS_FIXTURE_PACKAGES = dict(PACKAGES)


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


def _cloud_config(controller_public: str, host_public: str, host_private: str,
                  profile: str | None = None) -> bytes:
    # All variable scalars are constrained by _public_key/_private_key.
    release.require(profile in (None, ROOTLESS_FIXTURE_PROFILE),
                    "VM seed profile unsupported")
    lines = ["#cloud-config", "users:", "  - name: installer",
             "    lock_passwd: true"]
    if profile is None:
        lines.extend(["    sudo: ALL=(ALL) NOPASSWD:ALL", "    groups: docker"])
    else:
        lines.extend(["    sudo: false", "    groups: installer"])
    lines.extend(["    homedir: /home/installer",
             "    ssh_authorized_keys:", "      - " + controller_public])
    if profile == ROOTLESS_FIXTURE_PROFILE:
        # Distinct guest-only infrastructure principal. The installer user has
        # no sudo/docker membership; this principal is never a product actor.
        lines.extend(["  - name: fixture-admin", "    lock_passwd: true",
                      "    sudo: ALL=(ALL) NOPASSWD:ALL",
                      "    homedir: /home/fixture-admin",
                      "    ssh_authorized_keys:", "      - " + controller_public])
    lines.extend([
             "ssh_pwauth: false", "disable_root: true",
             "allow_public_ssh_keys: false", "ssh_deletekeys: true",
             "ssh_genkeytypes: [ed25519]", "ssh_keys:", "  ed25519_private: |"])
    lines.extend("    " + line for line in host_private.splitlines())
    lines.extend(["  ed25519_public: " + host_public,
                  "package_update: true", "package_upgrade: false", "packages:"])
    packages = PACKAGES if profile is None else ROOTLESS_FIXTURE_PACKAGES
    lines.extend("  - [" + name + ", " + json.dumps(version) + "]"
                 for name, version in packages.items())
    lines.extend(["runcmd:", "  - [chmod, '0700', /home/installer]"])
    lines.append("  - [systemctl, enable, --now, docker]")
    lines.extend(["  - [systemctl, enable, --now, ssh]", ""])
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
            vm_id: str, ssh_port: int, profile: str | None = None) -> dict:
    release.require(os.geteuid() == 0 and type(ssh_port) is int
                    and 1024 <= ssh_port <= 65535
                    and profile in (None, ROOTLESS_FIXTURE_PROFILE),
                    "VM seed request invalid")
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
                              guest_user=GUEST_USER,
                              packages=PACKAGES if profile is None else ROOTLESS_FIXTURE_PACKAGES,
                              started_at=int(time.time()), qualified=False,
                              launch_authorized=False)
                if profile is not None:
                    intent["fixture_profile"] = profile
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
                        user_data = _cloud_config(controller_public, host_public,
                                                  host_private, profile)
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


def verify_seed(source: Path, registry: Path, vm_parent: Path,
                runtime_parent: Path, *, vm_id: str) -> dict:
    """Revalidate root control, read-only seed media and the pristine disk chain."""
    transfer = verify_transfer(source, registry, vm_parent, runtime_parent, vm_id=vm_id)
    with ControllerLease(registry) as lease:
        runtime_raw, current = _read_record(lease.parent, vm_id + ".runtime-receipt.json")
        intent_raw, intent = _read_record(lease.parent, vm_id + ".seed-intent.json")
        receipt_raw, receipt = _read_record(lease.parent, vm_id + ".seed-receipt.json")
        release.require(current == transfer, "VM runtime receipt changed before seed check")
        base = {"schema", "phase", "vm_id", "runtime_receipt_sha256", "control_dir",
                "runtime_dir", "ssh_port", "guest_user", "packages", "started_at",
                "qualified", "launch_authorized"}
        profile = intent.get("fixture_profile")
        release.require(profile in (None, ROOTLESS_FIXTURE_PROFILE),
                        "VM seed profile unsupported")
        if profile is not None:
            base.add("fixture_profile")
        release.exact(intent, base, "VM seed intent")
        release.exact(receipt, base | {"intent_sha256", "control_dir_device",
                                      "control_dir_inode", "seed_device", "seed_inode",
                                      "seed_bytes", "seed_sha256", "user_data_sha256",
                                      "metadata_sha256", "known_hosts_sha256",
                                      "controller_public_sha256", "guest_host_public_sha256",
                                      "controller_private_sha256", "guest_host_private_sha256",
                                      "seeded_at"}, "VM seed receipt")
        release.require(intent["schema"] == receipt["schema"] == SCHEMA
                        and intent["phase"] == "intent" and receipt["phase"] == "seeded"
                        and intent["vm_id"] == vm_id
                        and intent["runtime_receipt_sha256"] == release.digest(runtime_raw)
                        and intent["control_dir"] == str(registry / (vm_id + ".control"))
                        and intent["runtime_dir"] == str(runtime_parent / vm_id)
                        and type(intent["ssh_port"]) is int
                        and 1024 <= intent["ssh_port"] <= 65535
                        and intent["guest_user"] == GUEST_USER
                        and intent["packages"] == (PACKAGES if profile is None
                                                   else ROOTLESS_FIXTURE_PACKAGES)
                        and type(intent["started_at"]) is int
                        and type(receipt["seeded_at"]) is int
                        and 0 < intent["started_at"] <= receipt["seeded_at"]
                        and receipt["seeded_at"] <= int(time.time()) + 5
                        and intent["qualified"] is receipt["qualified"] is False
                        and intent["launch_authorized"] is receipt["launch_authorized"] is False
                        and receipt["intent_sha256"] == release.digest(intent_raw)
                        and all(receipt[key] == value for key, value in intent.items()
                                if key != "phase"), "VM seed records disagree")
        control_dir = registry / (vm_id + ".control")
        control_fd = _directory(control_dir)
        try:
            control_info = os.fstat(control_fd)
            release.require((control_info.st_dev, control_info.st_ino)
                            == (receipt["control_dir_device"], receipt["control_dir_inode"]),
                            "VM control directory differs")
            controller_private = _bytes(control_dir / "controller_ed25519", 8192)
            controller_public = _public_key(_bytes(control_dir / "controller_ed25519.pub", 1024))
            host_private = _private_key(_bytes(control_dir / "guest_host_ed25519", 8192))
            host_public = _public_key(_bytes(control_dir / "guest_host_ed25519.pub", 1024))
            user_data = _bytes(control_dir / "user-data", 65536)
            metadata = _bytes(control_dir / "meta-data", 4096)
            known_hosts = _bytes(control_dir / "known_hosts", 4096)
            control_seed = _bytes(control_dir / "seed.iso", 16 * 1024 * 1024)
            expected_hosts = ("[127.0.0.1]:" + str(intent["ssh_port"]) + " "
                              + host_public + "\n").encode("ascii")
            expected_meta = ("instance-id: " + vm_id + "\nlocal-hostname: marty-vm-"
                             + vm_id[:8] + "\n").encode("ascii")
            release.require(user_data == _cloud_config(controller_public, host_public,
                                                        host_private, profile)
                            and metadata == expected_meta and known_hosts == expected_hosts
                            and release.digest(controller_private)
                            == receipt["controller_private_sha256"]
                            and release.digest(host_private.encode("ascii"))
                            == receipt["guest_host_private_sha256"]
                            and release.digest(controller_public.encode("ascii"))
                            == receipt["controller_public_sha256"]
                            and release.digest(host_public.encode("ascii"))
                            == receipt["guest_host_public_sha256"]
                            and release.digest(user_data) == receipt["user_data_sha256"]
                            and release.digest(metadata) == receipt["metadata_sha256"]
                            and release.digest(known_hosts) == receipt["known_hosts_sha256"]
                            and release.digest(control_seed) == receipt["seed_sha256"]
                            and len(control_seed) == receipt["seed_bytes"],
                            "VM control seed differs")
            for name in ("controller_ed25519", "guest_host_ed25519", "user-data",
                         "meta-data", "known_hosts", "seed.iso"):
                info = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
                release.require(info.st_uid == 0 and info.st_nlink == 1
                                and stat.S_IMODE(info.st_mode) == 0o600,
                                "VM control file permissions differ")
            runtime_dir = runtime_parent / vm_id
            runtime_fd = observer.open_vm_dir(runtime_dir, current["runtime_uid"])
            try:
                directory = os.fstat(runtime_fd)
                release.require((directory.st_dev, directory.st_ino)
                                == (current["runtime_dir_device"],
                                    current["runtime_dir_inode"]),
                                "VM runtime directory differs")
                media_fd = os.open("seed.iso", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                                   | os.O_CLOEXEC, dir_fd=runtime_fd)
                try:
                    held = os.fstat(media_fd)
                    named = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
                    release.require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                                    and (held.st_dev, held.st_ino)
                                    == (named.st_dev, named.st_ino)
                                    == (receipt["seed_device"], receipt["seed_inode"])
                                    and held.st_uid == named.st_uid == 0
                                    and held.st_gid == named.st_gid == current["runtime_gid"]
                                    and stat.S_IMODE(held.st_mode)
                                    == stat.S_IMODE(named.st_mode) == 0o440
                                    and held.st_size == named.st_size == len(control_seed),
                                    "VM runtime seed identity differs")
                    observed = bytearray()
                    while len(observed) < held.st_size:
                        block = os.read(media_fd, min(1024 * 1024, held.st_size - len(observed)))
                        release.require(bool(block), "VM runtime seed truncated")
                        observed.extend(block)
                    release.require(bytes(observed) == control_seed
                                    and os.fstat(media_fd).st_size == held.st_size,
                                    "VM runtime seed bytes differ")
                    final = os.stat("seed.iso", dir_fd=runtime_fd, follow_symlinks=False)
                    again = os.fstat(media_fd)
                    release.require(stat.S_ISREG(final.st_mode)
                                    and (final.st_dev, final.st_ino)
                                    == (again.st_dev, again.st_ino)
                                    == (receipt["seed_device"], receipt["seed_inode"])
                                    and final.st_uid == again.st_uid == 0
                                    and final.st_gid == again.st_gid == current["runtime_gid"]
                                    and final.st_nlink == again.st_nlink == 1
                                    and stat.S_IMODE(final.st_mode)
                                    == stat.S_IMODE(again.st_mode) == 0o440
                                    and final.st_size == again.st_size == receipt["seed_bytes"],
                                    "VM runtime seed changed during verification")
                    _same_path(runtime_dir, runtime_fd,
                               lambda path: observer.open_vm_dir(path, current["runtime_uid"]))
                    _same_path(control_dir, control_fd, _directory)
                    _same_path(registry, lease.parent, _directory)
                    release.require(_read_record(lease.parent, vm_id + ".seed-intent.json")[0]
                                    == intent_raw
                                    and _read_record(lease.parent,
                                                     vm_id + ".seed-receipt.json")[0] == receipt_raw
                                    and _read_record(lease.parent,
                                                     vm_id + ".runtime-receipt.json")[0]
                                    == runtime_raw,
                                    "VM seed records changed during verification")
                    return receipt
                finally:
                    os.close(media_fd)
            finally:
                os.close(runtime_fd)
        finally:
            os.close(control_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            receipt = verify_seed(args.source, args.registry, args.vm_parent,
                                  args.runtime_parent, vm_id=args.vm_id)
            release.require(args.ssh_port is None or args.ssh_port == receipt["ssh_port"],
                            "VM seed SSH port differs")
        else:
            release.require(args.ssh_port is not None, "VM seed SSH port required")
            prepare(args.source, args.registry, args.vm_parent, args.runtime_parent,
                    vm_id=args.vm_id, ssh_port=args.ssh_port)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM seed refused or uncertain; retain all intent, media and keys.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
