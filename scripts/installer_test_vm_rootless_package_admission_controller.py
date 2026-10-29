"""One-shot controller for read-only Ubuntu package admission on retained VM.

It stages only private archive data and an offline APT simulation. No package,
account, daemon, or guest application change is authorized by the result.
Root operation is forbidden until a separate root-private bootstrap has
authenticated this controller and its full import closure against exact Git
objects before Python imports them. Runtime hash checks below only detect
post-admission change; they do not retroactively authenticate imported code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _write
import installer_release as release
import installer_test_vm_probe as probe
import installer_test_vm_rootless_setup as fixture_setup
import installer_test_vm_rootless_package_admission as admission


SCHEMA = "elevenid.installer-only-vm-rootless-package-admission/v1"
INTENT_SUFFIX = ".installer-only-package-admission-intent.json"
RESULT_SUFFIX = ".installer-only-package-admission.json"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
STAGE_PARENT = Path("/var/tmp/marty-installer-package-admission")
STATUS_SCRIPT = r'''
import os,stat,sys
p='/var/lib/dpkg/status'; m=16777216
h=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 a=os.fstat(h)
 if not(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and not a.st_mode&0o022 and 0<a.st_size<=m):raise ValueError()
 r=os.open('/proc/self/fd/%d'%h,os.O_RDONLY|os.O_CLOEXEC)
 try:
  remain=a.st_size
  while remain:
   b=os.read(r,min(remain,65536))
   if not b:raise ValueError()
   sys.stdout.buffer.write(b);remain-=len(b)
  if os.read(r,1):raise ValueError()
  c=os.fstat(r);n=os.stat(p,follow_symlinks=False)
  if any(getattr(a,k)!=getattr(c,k) or getattr(a,k)!=getattr(n,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')):raise ValueError()
 finally:os.close(r)
finally:os.close(h)
'''
CHILD_BOOTSTRAP = ("import sys,json; g={'__name__':'admission_child'}; "
                   "exec(compile(sys.stdin.buffer.read(),'admitted-package-module','exec'),g); "
                   "print(json.dumps(g['child_main'](sys.argv[1:]),sort_keys=True))")


def _guest_status(binding: dict) -> bytes:
    command = "python3 -I -B -c " + shlex.quote(STATUS_SCRIPT)
    return probe._ssh(binding, command, limit=admission.MAX_STATUS, timeout=30)


def _private_parent(parent: Path) -> None:
    info = parent.lstat()
    outer = Path("/var/tmp").lstat()
    release.require(parent == STAGE_PARENT and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755
                    and stat.S_ISDIR(outer.st_mode) and outer.st_uid == 0
                    and stat.S_IMODE(outer.st_mode) == 0o1777,
                    "package admission parent custody invalid")


def _stage(parent: Path, observation_id: str, status: bytes) -> tuple[Path, Path, Path]:
    _private_parent(parent)
    leaf = "package-admission-" + observation_id
    stage = parent / leaf
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held_parent = os.fstat(parent_fd)
        release.require((held_parent.st_dev, held_parent.st_ino) ==
                        (parent.lstat().st_dev, parent.lstat().st_ino),
                        "package admission parent changed")
        os.mkdir(leaf, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        stage_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                           os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            status_fd = os.open("status", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=stage_fd)
            try:
                position = 0
                while position < len(status):
                    written = os.write(status_fd, status[position:position + 65536])
                    release.require(written > 0, "VM dpkg status staging stalled")
                    position += written
                os.fchown(status_fd, 65534, 65534)
                os.fsync(status_fd)
            finally:
                os.close(status_fd)
            os.mkdir("bundle", mode=0o700, dir_fd=stage_fd)
            os.chown("bundle", 65534, 65534, dir_fd=stage_fd,
                     follow_symlinks=False)
            os.fsync(stage_fd)
            # The root-owned nonwritable parent prevents the shared nobody UID
            # from replacing the top-level leaf after this final handoff.
            os.fchown(stage_fd, 65534, 65534)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    _private_parent(parent)
    status_path = stage / "status"
    bundle = stage / "bundle"
    return stage, status_path, bundle


def _child(module_bytes: bytes, bundle: Path, status: Path) -> dict:
    setpriv = admission.trusted_tool(Path("/usr/bin/setpriv"))
    python = admission.trusted_tool(Path("/usr/bin/python3"))
    args = ["/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
            "--clear-groups", "--no-new-privs", "--bounding-set=-all",
            "--inh-caps=-all", "--ambient-caps=-all",
            "/usr/bin/python3", "-I", "-B",
            "-c", CHILD_BOOTSTRAP, str(bundle), str(status), str(KEYRING)]
    try:
        done = admission.run_bounded(args, input_bytes=module_bytes,
                                     stdout_limit=65536, stderr_limit=4096,
                                     env={"PATH": "/usr/bin", "HOME": "/nonexistent",
                                          "LC_ALL": "C"}, timeout=240)
    except (OSError, admission.Refused) as exc:
        raise ValueError("package admission child unavailable") from exc
    release.require(done.returncode == 0 and len(done.stdout) <= 65536
                    and len(done.stderr) <= 4096,
                    "package admission child refused")
    release.require(admission.trusted_tool(Path("/usr/bin/setpriv")) == setpriv
                    and admission.trusted_tool(Path("/usr/bin/python3")) == python,
                    "package admission child tool changed")
    try:
        result = json.loads(done.stdout)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("package admission child result invalid") from exc
    release.require(type(result) is dict and set(result) == {
        "schema", "packages", "archive_releases", "status_sha256",
        "installed_docker_io_version", "new_package_actions",
        "transaction_simulated", "rootful_docker_package_simulated_change",
        "package_actions_authorized", "installation_authorized", "rootless_ready"}
                    and result.get("schema") == "elevenid.installer-only-rootless-package-child/v1"
                    and result.get("transaction_simulated") is True
                    and result.get("rootful_docker_package_simulated_change") is False
                    and result.get("package_actions_authorized") is False
                    and result.get("installation_authorized") is False
                    and result.get("rootless_ready") is False,
                    "package admission child result invalid")
    packages = result["packages"]
    release.require(type(packages) is list and len(packages) == len(admission.TARGETS)
                    and {row.get("package") for row in packages if type(row) is dict}
                        == set(admission.TARGETS),
                    "package admission child packages invalid")
    for row in packages:
        release.require(type(row) is dict and set(row) == {
            "package", "version", "sha256", "size", "pocket", "component"}
                        and row["version"] == admission.EXPECTED_VERSIONS[row["package"]]
                        and admission.HEX.fullmatch(row["sha256"]) is not None
                        and type(row["size"]) is int and 0 < row["size"] <= admission.MAX_DEB
                        and row["pocket"] in admission.POCKETS
                        and row["component"] in admission.COMPONENTS,
                        "package admission child package invalid")
    releases = result["archive_releases"]
    release.require(type(releases) is list and len(releases) == len(admission.POCKETS)
                    and {row.get("pocket") for row in releases if type(row) is dict}
                        == set(admission.POCKETS),
                    "package admission child releases invalid")
    for row in releases:
        release.require(type(row) is dict and set(row) == {
            "pocket", "base_url", "inrelease_sha256", "keyring_sha256",
            "signer_fingerprint", "date", "valid_until"}
                        and row["base_url"] == admission.POCKETS[row["pocket"]]
                        and row["signer_fingerprint"] == admission.ARCHIVE_FINGERPRINT
                        and admission.HEX.fullmatch(row["inrelease_sha256"]) is not None
                        and admission.HEX.fullmatch(row["keyring_sha256"]) is not None
                        and type(row["date"]) is str and len(row["date"]) <= 40
                        and (row["valid_until"] is None or type(row["valid_until"]) is str
                             and len(row["valid_until"]) <= 40),
                        "package admission child release invalid")
    actions = result["new_package_actions"]
    release.require(type(actions) is list and len(actions) <= len(admission.TARGETS)
                    and {row.get("package") for row in actions if type(row) is dict}
                        >= set(admission.REQUIRED),
                    "package admission child actions invalid")
    for row in actions:
        release.require(type(row) is dict and set(row) == {"package", "version"}
                        and row["package"] in admission.TARGETS
                        and row["version"] == admission.EXPECTED_VERSIONS[row["package"]],
                        "package admission child action invalid")
    release.require(len({row["package"] for row in actions}) == len(actions)
                    and admission.HEX.fullmatch(result["status_sha256"]) is not None
                    and type(result["installed_docker_io_version"]) is str
                    and admission.VERSION.fullmatch(result["installed_docker_io_version"])
                    is not None, "package admission child identity invalid")
    return result


def _rebind_stage(stage: Path, identity: tuple[int, int]) -> None:
    info = stage.lstat()
    release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 65534
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and (info.st_dev, info.st_ino) == identity,
                    "package admission stage identity changed")


def _status_identity(path: Path) -> tuple[int, int, int, int, int, int, int, int]:
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 65534
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    "package admission status custody invalid")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def observe(*, source: Path, registry: Path, runtime_parent: Path,
            stage_parent: Path, vm_id: str, observation_id: str,
            admitted_module_sha256: str, admitted_controller_sha256: str,
            vm_parent: Path | None = None) -> dict:
    release.require(os.geteuid() == 0, "root VM controller required")
    probe._uuid(vm_id)
    probe._uuid(observation_id)
    release.require(all(path.is_absolute() for path in
                        (source, registry, runtime_parent, stage_parent))
                    and (vm_parent is None or vm_parent.is_absolute()),
                    "package admission path must be absolute")
    def bound(lease: ControllerLease) -> dict:
        if vm_parent is None:
            return probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
        return fixture_setup.bound_setup_fixture(
            source=source, registry=registry, vm_parent=vm_parent,
            runtime_parent=runtime_parent, vm_id=vm_id, _lease=lease)
    _private_parent(stage_parent)
    module_bytes = admission.private_file(Path(admission.__file__), 1024 * 1024, uid=0)
    controller_bytes = admission.private_file(Path(__file__), 1024 * 1024, uid=0)
    release.require(hashlib.sha256(module_bytes).hexdigest() == admitted_module_sha256,
                    "package admission source differs from admitted code")
    release.require(hashlib.sha256(controller_bytes).hexdigest() ==
                    admitted_controller_sha256,
                    "package admission controller differs from admitted code")
    with ControllerLease(registry) as lease:
        intent_name = vm_id + INTENT_SUFFIX
        result_name = vm_id + RESULT_SUFFIX
        for name in (intent_name, result_name):
            try:
                os.stat(name, dir_fd=lease.parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("package admission attempt already exists")
        before = bound(lease)
        first = _guest_status(before)
        second = _guest_status(before)
        release.require(first == second and admission._installed_status(first),
                        "VM dpkg status unstable")
        release.require(bound(lease)
                        == before, "VM package admission binding changed")
        intent = {"schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
                  "observation_id": observation_id, "engine_id": before["engine_id"],
                  "readiness_sha256": before["readiness_sha256"],
                  "pid": before["pid"], "start_ticks": before["start_ticks"],
                  "dpkg_status_sha256": hashlib.sha256(first).hexdigest(),
                  "module_sha256": admitted_module_sha256,
                  "controller_sha256": admitted_controller_sha256,
                  "purpose": ("installer_only_rootless_package_admission"
                              if vm_parent is None else
                              "disposable_fixture_setup_package_admission"),
                  "package_actions_authorized": False,
                  "installation_authorized": False}
        intent_bytes = _write(lease.parent, intent_name, intent)
        stage, status_path, bundle = _stage(stage_parent, observation_id, first)
        stage_info = stage.lstat()
        stage_identity = (stage_info.st_dev, stage_info.st_ino)
        _rebind_stage(stage, stage_identity)
        bundle_info = bundle.lstat()
        bundle_identity = (bundle_info.st_dev, bundle_info.st_ino)
        _rebind_stage(bundle, bundle_identity)
        status_identity = _status_identity(status_path)
        child = _child(module_bytes, bundle, status_path)
        release.require(child["status_sha256"] == intent["dpkg_status_sha256"]
                        and child["installed_docker_io_version"] ==
                            admission._installed_status(first)["docker.io"],
                        "package admission child status differs")
        _rebind_stage(stage, stage_identity)
        _rebind_stage(bundle, bundle_identity)
        release.require(_status_identity(status_path) == status_identity,
                        "package admission status identity changed")
        release.require(admission.private_file(status_path, admission.MAX_STATUS) == first,
                        "VM dpkg snapshot changed")
        for row in child["packages"]:
            raw = admission.private_file(bundle / (row["package"] + ".deb"),
                                         admission.MAX_DEB, uid=65534)
            release.require(len(raw) == row["size"] and hashlib.sha256(raw).hexdigest()
                            == row["sha256"], "package admission archive changed")
        for row in child["archive_releases"]:
            raw = admission.private_file(bundle / (row["pocket"] + ".inrelease"),
                                         admission.MAX_INRELEASE, uid=65534)
            release.require(hashlib.sha256(raw).hexdigest() == row["inrelease_sha256"],
                            "package admission release changed")
        release.require(admission.private_file(Path(admission.__file__), 1024 * 1024, uid=0)
                        == module_bytes
                        and admission.private_file(Path(__file__), 1024 * 1024, uid=0)
                        == controller_bytes, "package admission source changed")
        release.require(bound(lease)
                        == before and _guest_status(before) == first,
                        "VM package admission source changed")
        result = {"schema": SCHEMA, "phase": "observed", "vm_id": vm_id,
                  "observation_id": observation_id,
                  "intent_sha256": hashlib.sha256(intent_bytes).hexdigest(),
                  "engine_id": before["engine_id"],
                  "readiness_sha256": before["readiness_sha256"],
                  "dpkg_status_sha256": intent["dpkg_status_sha256"],
                  "module_sha256": admitted_module_sha256,
                  "controller_sha256": admitted_controller_sha256,
                  "private_stage": str(stage),
                  "packages": child["packages"],
                  "archive_releases": child["archive_releases"],
                  "new_package_actions": child["new_package_actions"],
                  "transaction_simulated": True,
                  "rootful_docker_package_simulated_change": False,
                  "package_actions_authorized": False, "installation_authorized": False,
                  "account_or_subids_allocated": False,
                  "daemon_start_attempted_by_probe": False,
                  "rootless_ready": False, "qualified": False,
                  "application_deployment_authorized": False,
                  "observed_at": int(time.time())}
        _write(lease.parent, result_name, result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("vm-id", "observation-id", "admitted-module-sha256",
                 "admitted-controller-sha256"):
        parser.add_argument("--" + name, required=True)
    try:
        args = {key.replace("-", "_"): value for key, value in
                vars(parser.parse_args()).items()}
        result = observe(stage_parent=STAGE_PARENT, **args)
        print(json.dumps({"phase": result["phase"], "vm_id": result["vm_id"],
                          "rootless_ready": False, "qualified": False}, sort_keys=True))
        return 0
    except Exception:
        print("VM package admission refused", file=sys.stderr)
        return 1


# Deliberately no direct script entrypoint: a separate admitted root-private
# bootstrap must verify the exact source/import closure before importing and
# calling main(). Running this file from a checkout cannot attempt admission.
