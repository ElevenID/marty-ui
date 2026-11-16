#!/usr/bin/env python3
"""Dormant host-side checkpoint record after exact disposable rollback proof.

The root-private bootstrap must authenticate this module and its import closure
before import. A caller must still admit the exact host-to-guest transfer and
confirmation; this code does not call the guest package executor or product.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time

from installer_candidate_controller import ControllerLease
import installer_candidate_vm_create as create
import installer_release as release
import installer_test_vm_rootless_package_admission as archive
import installer_test_vm_rootless_package_admission_controller as admission
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_rollback_proof as proof


SCHEMA = "elevenid.installer-only-vm-stopped-disk-checkpoint/v2"
SUFFIX = ".rootless-rollback-checkpoint.json"
CHILD_BOOTSTRAP = (
    "import json,sys; m,e=sys.stdin.buffer.read().split(b'\\x00',1); "
    "g={'__name__':'admitted_stage_recheck'}; "
    "exec(compile(m,'admitted-package-module','exec'),g); "
    "p=g['Path']; r=g['verify_staged_bundle'](p(sys.argv[1]),p(sys.argv[2]),"
    "p(sys.argv[3]),json.loads(e)); "
    "sys.stdout.write(json.dumps(r,sort_keys=True,separators=(',',':')))"
)


def _closed_directory(path: Path, expected: set[str], owner: int) -> int:
    held = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                   os.O_CLOEXEC)
    try:
        info = os.fstat(held)
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner
                        and stat.S_IMODE(info.st_mode) == 0o700,
                        "checkpoint package stage custody differs")
        copy._closed_names(held, expected)
        create._rebind_directory(path, held)
        return held
    except BaseException:
        os.close(held)
        raise


def _stage_recheck(result: dict, module_bytes: bytes) -> dict:
    stage = admission.STAGE_PARENT / (
        "package-admission-" + result["observation_id"])
    release.require(result["private_stage"] == str(stage),
                    "checkpoint package stage path differs")
    admission._private_parent(admission.STAGE_PARENT)
    stage_fd = bundle_fd = None
    try:
        stage_fd = _closed_directory(stage, {"status", "bundle"}, 65534)
        bundle = stage / "bundle"
        names = ({"solver"}
                 | {f"{pocket}.inrelease" for pocket in archive.POCKETS}
                 | {f"{pocket}.{component}.packages.xz"
                    for pocket in archive.POCKETS
                    for component in archive.COMPONENTS}
                 | {f"{name}.deb" for name in archive.TARGETS})
        bundle_fd = _closed_directory(bundle, names, 65534)
        status = stage / "status"
        status_stamp = admission._status_identity(status)
        release.require(archive.sha(archive.private_file(
                            status, archive.MAX_STATUS, uid=65534))
                        == result["dpkg_status_sha256"],
                        "checkpoint dpkg snapshot differs")
        expected = {"packages": result["packages"],
                    "archive_releases": result["archive_releases"],
                    "dpkg_status_sha256": result["dpkg_status_sha256"]}
        payload = module_bytes + b"\0" + release.encode(expected)
        release.require(len(payload) <= 1024 * 1024,
                        "checkpoint stage verifier input oversized")
        setpriv = archive.trusted_tool(Path("/usr/bin/setpriv"))
        python = archive.trusted_tool(Path("/usr/bin/python3"))
        argv = ["/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/python3",
                "-I", "-B", "-c", CHILD_BOOTSTRAP,
                str(bundle), str(status), str(archive.KEYRING)]
        done = archive.run_bounded(
            argv, input_bytes=payload, stdout_limit=16384,
            stderr_limit=4096, timeout=180,
            env={"PATH": "/usr/bin", "HOME": "/nonexistent", "LC_ALL": "C"})
        release.require(done.returncode == 0
                        and archive.trusted_tool(Path("/usr/bin/setpriv")) == setpriv
                        and archive.trusted_tool(Path("/usr/bin/python3")) == python,
                        "checkpoint unprivileged stage recheck refused")
        try:
            observed = json.loads(done.stdout)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("checkpoint stage recheck invalid") from exc
        release.exact(observed,
                      {"schema", "packages", "archive_releases",
                       "dpkg_status_sha256", "package_actions_authorized",
                       "installation_authorized"},
                      "checkpoint stage recheck")
        release.require(observed["schema"]
                        == "elevenid.installer-only-package-stage-recheck/v1"
                        and observed["packages"]
                        == [next(row for row in result["packages"]
                                 if row["package"] == name)
                            for name in archive.TARGETS]
                        and observed["archive_releases"]
                        == [next(row for row in result["archive_releases"]
                                 if row["pocket"] == pocket)
                            for pocket in archive.POCKETS]
                        and observed["dpkg_status_sha256"]
                        == result["dpkg_status_sha256"]
                        and observed["package_actions_authorized"] is False
                        and observed["installation_authorized"] is False,
                        "checkpoint stage recheck differs")
        release.require(admission._status_identity(status) == status_stamp,
                        "checkpoint dpkg snapshot changed")
        copy.create._rebind_directory(stage, stage_fd)
        copy.create._rebind_directory(bundle, bundle_fd)
        return observed
    finally:
        for fd in (bundle_fd, stage_fd):
            if fd is not None:
                os.close(fd)


def mint_checkpoint(*, source: Path, registry: Path, runtime_parent: Path,
                    vm_id: str, copy_vm_id: str) -> dict:
    """Write an O_EXCL historical checkpoint only after current proof checks.

    It has no guest transfer or package installation authority by itself.
    """
    release.require(os.geteuid() == 0 and all(path.is_absolute() for path in
                    (source, registry, runtime_parent)),
                    "checkpoint controller request invalid")
    with ControllerLease(registry) as lease:
        for name in (vm_id + SUFFIX,):
            try:
                os.stat(name, dir_fd=lease.parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("checkpoint already attempted")
        first = proof.inspect_proof(source=source, registry=registry,
                                    runtime_parent=runtime_parent, vm_id=vm_id,
                                    copy_vm_id=copy_vm_id, _lease=lease)
        admission_raw, result = create._read_record(
            lease.parent, vm_id + admission.RESULT_SUFFIX)
        release.require(release.digest(admission_raw)
                        == first["admission_result_sha256"],
                        "checkpoint admission result changed")
        module_bytes = archive.private_file(
            Path(archive.__file__), 1024 * 1024, uid=0)
        controller_bytes = archive.private_file(
            Path(admission.__file__), 1024 * 1024, uid=0)
        release.require(archive.sha(module_bytes) == result["module_sha256"]
                        and archive.sha(controller_bytes)
                        == result["controller_sha256"],
                        "checkpoint admitted source differs")
        stage = _stage_recheck(result, module_bytes)
        second = proof.inspect_proof(source=source, registry=registry,
                                     runtime_parent=runtime_parent, vm_id=vm_id,
                                     copy_vm_id=copy_vm_id, _lease=lease)
        release.require(second == first
                        and create._read_record(
                            lease.parent, vm_id + admission.RESULT_SUFFIX)[0]
                        == admission_raw
                        and archive.private_file(
                            Path(archive.__file__), 1024 * 1024, uid=0)
                        == module_bytes
                        and archive.private_file(
                            Path(admission.__file__), 1024 * 1024, uid=0)
                        == controller_bytes,
                        "checkpoint inputs changed before publication")
        pending_raw, pending = create._read_record(
            lease.parent, vm_id + proof.stopped.PENDING_SUFFIX)
        stop_raw, stop = create._read_record(
            lease.parent, vm_id + proof.stopped.INTENT_SUFFIX)
        release.require(release.digest(pending_raw) == first["pending_sha256"]
                        and pending["intent_sha256"] == release.digest(stop_raw),
                        "checkpoint stop record changed")
        record = {"schema": SCHEMA, "phase": "historical_rollback_observed",
                  "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                  "controller_boot_id": pending["boot_id"],
                  "stopped_pid": stop["pid"],
                  "stopped_start_ticks": stop["start_ticks"],
                  "disk_device": pending["disk_device"],
                  "disk_inode": pending["disk_inode"],
                  "disk_sha256": first["disk_sha256"],
                  "snapshot_sha256": first["snapshot_sha256"],
                  "snapshot_bytes": pending["snapshot_bytes"],
                  "rollback_test_sha256": first["cleanup_result_sha256"],
                  "admission_result_sha256": first["admission_result_sha256"],
                  "stage_recheck_sha256": release.digest(release.encode(stage)),
                  "source_module_sha256": result["module_sha256"],
                  "source_controller_sha256": result["controller_sha256"],
                  "created_at": int(time.time()), "stopped": True,
                  "package_install_authorized": False,
                  "product_dispatch_authorized": False}
        create._write(lease.parent, vm_id + SUFFIX, record)
        return record
