"""Explicit one-shot recovery of a staged, unexecuted installer-only VM probe.

This is limited to the reviewed pre-execution failure in controller 0c72576.
It preserves the original intent and guest files, records a separate durable
recovery intent before changing the held staged operator, and never retries an
uncertain recovery. It grants no installation, dispatch or qualification right.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import time

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _read_record, _write
import installer_candidate_dispatch as dispatch
import installer_release as release
import installer_test_vm_probe as probe

SCHEMA = "elevenid.installer-only-vm-probe-recovery/v1"
ORIGINAL_CONTROLLER_SHA = "0c72576fdb6b4960a2e5c75b9cbff7b06e8767eb"
ORIGINAL_FAILURE = "VM probe guest home changed"
STAGE = "copied_mode_0600_before_first_controller_exec"
ADMISSION_SCHEMA = "elevenid.installer-only-vm-probe-recovery-source-admission/v1"

ORIGINAL_FIELDS = {
    "schema", "phase", "vm_id", "probe_id", "restart_readiness_sha256",
    "restart_pid", "restart_start_ticks", "controller_boot_id", "disk_device",
    "disk_inode", "engine_id", "guest_uid", "operator_sha256",
    "operator_bytes", "source_sha", "release_tag", "build_run_id",
    "build_run_attempt", "inventory_sha256", "acquisition_sha256",
    "guest_directory", "allowlist", "qualified", "dispatch_authorized",
    "application_deployment_authorized", "started_at",
}


def _absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("VM probe recovery record already exists")


def _admitted_controller(admission: Path) -> tuple[str, str]:
    """Bind the loaded module bytes to a separately Git-admitted root snapshot."""
    release.require(admission.is_absolute() and not admission.is_symlink(),
                    "VM probe recovery admission path invalid")
    module = Path(__file__).resolve(strict=True)
    release.require(not Path(__file__).is_symlink(),
                    "VM probe recovery module is linked")
    release.require(module.parent.name == "scripts"
                    and admission.parent == module.parent.parent,
                    "VM probe recovery admission is outside source snapshot")
    for path in (admission.parent, module.parent):
        item = path.stat(follow_symlinks=False)
        release.require(stat.S_ISDIR(item.st_mode) and item.st_uid == 0
                        and item.st_mode & 0o022 == 0,
                        "VM probe recovery source custody differs")
    def read(path: Path, maximum: int) -> bytes:
        held = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(held)
            release.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                            and before.st_nlink == 1 and before.st_mode & 0o022 == 0
                            and 0 < before.st_size <= maximum,
                            "VM probe recovery source file custody differs")
            fd = os.open(f"/proc/self/fd/{held}", os.O_RDONLY | os.O_CLOEXEC)
            try:
                chunks = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    release.require(bool(chunk), "VM probe recovery source read changed")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                release.require(os.read(fd, 1) == b"", "VM probe recovery source grew")
                after = os.fstat(fd)
                named = path.stat(follow_symlinks=False)
                fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                          "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                release.require(all(getattr(before, key) == getattr(after, key)
                                    == getattr(named, key) for key in fields),
                                "VM probe recovery source changed")
                return b"".join(chunks)
            finally:
                os.close(fd)
        finally:
            os.close(held)
    raw = read(admission, 4096)
    manifest = release.decode(raw)
    release.require(release.encode(manifest) == raw,
                    "VM probe recovery admission is not canonical")
    release.exact(manifest, {"schema", "source_sha", "module_sha256"},
                  "VM probe recovery source admission")
    release.require(manifest["schema"] == ADMISSION_SCHEMA
                    and isinstance(manifest["source_sha"], str)
                    and re.fullmatch(r"[0-9a-f]{40}", manifest["source_sha"])
                    and manifest["source_sha"] != ORIGINAL_CONTROLLER_SHA
                    and isinstance(manifest["module_sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", manifest["module_sha256"])
                    and hashlib.sha256(read(module, 131072)).hexdigest()
                    == manifest["module_sha256"],
                    "VM probe recovery source admission differs")
    return manifest["source_sha"], manifest["module_sha256"]


def _held_chmod(binding: dict, target: str, expected: dict,
                old_stamp: tuple[int, int, int, int, int, int]) -> None:
    """Change only the exact held 0600 inode, then rebind its named path."""
    code = (
        "import os,stat,sys;"
        "p=sys.argv[1];dev=int(sys.argv[2]);ino=int(sys.argv[3]);"
        "uid=int(sys.argv[4]);size=int(sys.argv[5]);"
        "f=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);a=os.fstat(f);"
        "assert stat.S_ISREG(a.st_mode) and (a.st_dev,a.st_ino,a.st_uid,a.st_nlink,"
        "a.st_size,stat.S_IMODE(a.st_mode))==(dev,ino,uid,1,size,0o600);"
        "r=os.open(\"/proc/self/fd/%d\"%f,os.O_RDONLY|os.O_CLOEXEC);"
        "b=os.fstat(r);"
        "assert (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size,"
        "a.st_mtime_ns,a.st_ctime_ns)=="
        "(b.st_dev,b.st_ino,b.st_uid,b.st_gid,b.st_mode,b.st_nlink,b.st_size,"
        "b.st_mtime_ns,b.st_ctime_ns);"
        "os.fchmod(r,0o700);c=os.fstat(r);n=os.stat(p,follow_symlinks=False);"
        "assert (c.st_dev,c.st_ino,c.st_uid,c.st_gid,c.st_nlink,c.st_size,"
        "c.st_mtime_ns,stat.S_IMODE(c.st_mode))=="
        "(n.st_dev,n.st_ino,n.st_uid,n.st_gid,n.st_nlink,n.st_size,"
        "n.st_mtime_ns,stat.S_IMODE(n.st_mode))=="
        "(dev,ino,uid,a.st_gid,1,size,a.st_mtime_ns,0o700)"
    )
    arguments = [target, str(old_stamp[0]), str(old_stamp[1]),
                 str(binding["guest_uid"]), str(expected["binary_bytes"])]
    command = "/usr/bin/python3 -I -B -c '" + code + "' " + " ".join(arguments)
    release.require(probe._ssh(binding, command) == b"",
                    "VM probe recovery held chmod differed")


def recover(*, source: Path, registry: Path, runtime_parent: Path, vm_id: str,
            probe_id: str, recovery_id: str, original_intent_sha256: str,
            controller_admission: Path,
            assets: Path, gh: Path, cosign: Path, client) -> dict:
    """Resume only the exact post-SCP/pre-chmod staged failure once."""
    release.require(os.geteuid() == 0, "root VM controller required")
    probe._uuid(vm_id)
    probe._uuid(probe_id)
    probe._uuid(recovery_id)
    release.require(re.fullmatch(r"[0-9a-f]{64}", original_intent_sha256) is not None,
                    "VM probe recovery original digest invalid")
    recovery_controller_source_sha, module_sha = _admitted_controller(controller_admission)
    release.require(all(path.is_absolute() for path in
                        (source, registry, runtime_parent, assets, gh, cosign)),
                    "VM probe recovery path must be absolute")
    with ControllerLease(registry) as lease:
        original_name = vm_id + ".installer-only-probe-intent.json"
        result_name = vm_id + ".installer-only-probe-result.json"
        recovery_name = vm_id + ".installer-only-probe-recovery-intent.json"
        _absent(lease.parent, result_name)
        _absent(lease.parent, recovery_name)
        original_raw, original = _read_record(lease.parent, original_name)
        release.exact(original, ORIGINAL_FIELDS, "VM original probe intent")
        release.require(release.encode(original) == original_raw
                        and hashlib.sha256(original_raw).hexdigest() == original_intent_sha256
                        and original["schema"] == probe.SCHEMA
                        and original["phase"] == "intent"
                        and original["vm_id"] == vm_id
                        and original["probe_id"] == probe_id
                        and original["guest_directory"] == probe._guest_dir(probe_id)
                        and original["allowlist"] == ["--build-identity", "--help"]
                        and original["qualified"] is False
                        and original["dispatch_authorized"] is False
                        and original["application_deployment_authorized"] is False,
                        "VM original probe intent differs")
        expected = probe._verified_assets(assets, gh, cosign, client)
        binding = probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
        comparisons = {
            "restart_readiness_sha256": binding["readiness_sha256"],
            "restart_pid": binding["pid"],
            "restart_start_ticks": binding["start_ticks"],
            "controller_boot_id": binding["boot_id"],
            "disk_device": binding["disk_device"],
            "disk_inode": binding["disk_inode"],
            "engine_id": binding["engine_id"],
            "guest_uid": binding["guest_uid"],
            "operator_sha256": expected["binary_sha256"],
            "operator_bytes": expected["binary_bytes"],
            "source_sha": expected["source_sha"],
            "release_tag": expected["release_tag"],
            "build_run_id": expected["build_run_id"],
            "build_run_attempt": expected["build_run_attempt"],
            "inventory_sha256": expected["inventory_sha256"],
            "acquisition_sha256": expected["acquisition_sha256"],
        }
        release.require(all(original[name] == value for name, value in comparisons.items()),
                        "VM probe recovery binding differs")
        directory = original["guest_directory"]
        target = directory + "/marty-deploy"
        release.require(probe._guest_home_stamp(binding) == binding["home_stamp"],
                        "VM probe recovery home changed")
        held_directory = probe._guest_stamp(binding, directory)
        only = probe._ssh(binding, "/usr/bin/find " + directory
                          + " -mindepth 1 -maxdepth 1 -printf '%f\\n'", limit=256)
        release.require(only == b"marty-deploy\n", "VM probe recovery directory content differs")
        staged = probe._guest_operator(binding, target, expected, mode=600)
        release.require(staged[0] == held_directory[0],
                        "VM probe recovery file mount differs")
        release.require(probe._guest_stamp(binding, directory) == held_directory
                        and probe._guest_home_stamp(binding) == binding["home_stamp"]
                        and _read_record(lease.parent, original_name)[0] == original_raw
                        and probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == binding,
                        "VM probe recovery preparation changed")
        recovery_intent = {
            "schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
            "probe_id": probe_id, "recovery_id": recovery_id,
            "original_controller_sha": ORIGINAL_CONTROLLER_SHA,
            "original_failure": ORIGINAL_FAILURE, "classified_stage": STAGE,
            "original_intent_sha256": original_intent_sha256,
            "recovery_controller_source_sha": recovery_controller_source_sha,
            "recovery_module_sha256": module_sha,
            "restart_readiness_sha256": binding["readiness_sha256"],
            "restart_pid": binding["pid"],
            "restart_start_ticks": binding["start_ticks"],
            "controller_boot_id": binding["boot_id"],
            "engine_id": binding["engine_id"],
            "operator_sha256": expected["binary_sha256"],
            "operator_bytes": expected["binary_bytes"],
            "guest_home_device": binding["home_stamp"][0],
            "guest_home_inode": binding["home_stamp"][1],
            "guest_directory_device": held_directory[0],
            "guest_directory_inode": held_directory[1],
            "guest_operator_device": staged[0],
            "guest_operator_inode": staged[1],
            "qualified": False, "dispatch_authorized": False,
            "application_deployment_authorized": False,
            "started_at": int(time.time()),
        }
        recovery_raw = _write(lease.parent, recovery_name, recovery_intent)
        release.require(_read_record(lease.parent, recovery_name)[0] == recovery_raw
                        and _admitted_controller(controller_admission)
                        == (recovery_controller_source_sha, module_sha)
                        and _read_record(lease.parent, original_name)[0] == original_raw
                        and probe._guest_operator(binding, target, expected, mode=600) == staged
                        and probe._guest_stamp(binding, directory) == held_directory,
                        "VM probe recovery intent or stage changed")
        _held_chmod(binding, target, expected, staged)
        executable = probe._guest_operator(binding, target, expected, mode=700)
        release.require(executable[:3] == staged[:3]
                        and executable[4:] == staged[4:]
                        and probe._guest_stamp(binding, directory) == held_directory
                        and probe._guest_home_stamp(binding) == binding["home_stamp"]
                        and probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == binding,
                        "VM probe recovery staged identity changed")
        identity = probe._execute_sealed(binding, target, expected, executable,
                                         "--build-identity")
        release.require(probe._guest_operator(binding, target, expected, mode=700)
                        == executable, "VM probe recovery operator changed")
        help_result = probe._execute_sealed(binding, target, expected, executable,
                                            "--help")
        release.require(probe._guest_operator(binding, target, expected, mode=700)
                        == executable
                        and probe._guest_stamp(binding, directory) == held_directory
                        and probe._guest_home_stamp(binding) == binding["home_stamp"]
                        and probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == binding
                        and _read_record(lease.parent, original_name)[0] == original_raw
                        and _read_record(lease.parent, recovery_name)[0] == recovery_raw,
                        "VM probe recovery observations changed")
        release.require(_admitted_controller(controller_admission)
                        == (recovery_controller_source_sha, module_sha),
                        "VM probe recovery controller changed")
        result = {
            "schema": probe.RESULT_SCHEMA, "phase": "observed", "vm_id": vm_id,
            "probe_id": probe_id, "intent_sha256": original_intent_sha256,
            "recovery_intent_sha256": release.digest(recovery_raw),
            "recovery_controller_source_sha": recovery_controller_source_sha,
            "recovery_module_sha256": module_sha,
            "operator_sha256": expected["binary_sha256"],
            "build_identity_matched": identity["matched"],
            "help_sha256": help_result["output_sha256"],
            "help_bytes": help_result["output_bytes"],
            "guest_directory_device": held_directory[0],
            "guest_directory_inode": held_directory[1],
            "guest_operator_inode": executable[1],
            "qualified": False, "dispatch_authorized": False,
            "application_deployment_authorized": False,
            "observed_at": int(time.time()),
        }
        _write(lease.parent, result_name, result)
        return result
