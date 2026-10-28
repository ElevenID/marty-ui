"""Read-only package and local-account plan for a separate rootless VM fixture.

This does not install packages, allocate accounts/IDs, start a daemon, or alter
the retained rootful Docker Engine. Current metadata is not transaction proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _write
import installer_release as release
import installer_test_vm_probe as probe

SCHEMA = "elevenid.installer-only-vm-rootless-package-plan/v1"
GUEST_SCHEMA = "elevenid.installer-only-vm-rootless-local-policy/v1"
RESULT_SUFFIX = ".installer-only-rootless-package-plan.json"
PACKAGES = ("docker.io", "docker-ce", "docker-ce-rootless-extras", "uidmap", "rootlesskit",
            "slirp4netns", "fuse-overlayfs")
ROOTLESS_PATHS = ("/usr/bin/dockerd-rootless.sh",
                  "/usr/bin/dockerd-rootless-setuptool.sh", "/usr/bin/rootlesskit",
                  "/usr/bin/slirp4netns", "/usr/bin/fuse-overlayfs",
                  "/usr/bin/newuidmap", "/usr/bin/newgidmap")
ACCOUNT = "marty-rootless-test"
VERSION = re.compile(r"[A-Za-z0-9.+:~_-]{1,96}\Z")

# All commands are constructed solely from the fixed tuples above. No caller
# can supply a package, path, shell fragment, account name or apt action.
def _commands(package: str) -> tuple[str, str, str]:
    release.require(package in PACKAGES, "unsupported package observation")
    return ("LC_ALL=C /usr/bin/dpkg-query -W -f='${Status}\\n${Version}\\n' -- "
            + package,
            "LC_ALL=C /usr/bin/apt-cache policy " + package,
            "LC_ALL=C /usr/bin/apt-cache depends " + package)


def _file_list_command(package: str) -> str:
    release.require(package in PACKAGES, "unsupported package file list")
    return "LC_ALL=C /usr/bin/dpkg-query -L -- " + package


LOCAL_SCRIPT = r'''
import json,os,pwd,stat,sys
ACCOUNT="marty-rootless-test"
FILES=("/etc/passwd","/etc/group","/etc/subuid","/etc/subgid",
       "/etc/apt/sources.list.d/ubuntu.sources")
APPARMOR="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
def read(path,limit):
    try:
        h=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(h)
            if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or (path!=APPARMOR and a.st_size>limit):
                return None
            r=os.open("/proc/self/fd/%d"%h,os.O_RDONLY|os.O_CLOEXEC)
            try:
                chunks=[];remaining=limit+1
                while remaining:
                    part=os.read(r,min(8192,remaining))
                    if not part:break
                    chunks.append(part);remaining-=len(part)
                data=b"".join(chunks)
                b=os.fstat(r);n=os.stat(path,follow_symlinks=False)
                if (path!=APPARMOR and len(data)!=a.st_size) or len(data)>limit or any(getattr(a,k)!=getattr(b,k) or getattr(a,k)!=getattr(n,k)
                    for k in ("st_dev","st_ino","st_uid","st_gid","st_mode","st_size","st_mtime_ns","st_ctime_ns")):
                    return None
                return data
            finally:os.close(r)
        finally:os.close(h)
    except OSError:return None
def decoded(path,limit):
    data=read(path,limit)
    if data is None:return None
    try:return data.decode("ascii").splitlines()
    except UnicodeError:return None
def subids(lines):
    if lines is None:return {"status":"unknown","local_candidate_start":None,
                             "local_ranges_checked":0}
    occupied=[]
    for line in lines:
        part=line.split(":")
        if len(part)!=3 or not all(x.isdecimal() for x in part[1:]):
            return {"status":"unknown","local_candidate_start":None,"local_ranges_checked":0}
        start,count=map(int,part[1:])
        if start<1 or count<1 or start+count>4294967296:
            return {"status":"unknown","local_candidate_start":None,"local_ranges_checked":0}
        occupied.append((start,start+count))
    for start in range(100000,100000+65536*1024,65536):
        if all(start+65536<=left or right<=start for left,right in occupied):
            return {"status":"local_file_candidate","local_candidate_start":start,
                    "local_ranges_checked":min(len(occupied),65536)}
    return {"status":"no_local_gap_in_bound","local_candidate_start":None,
            "local_ranges_checked":min(len(occupied),65536)}
def local_account(passwd,group):
    if passwd is None or group is None:return {"status":"unknown","name_in_local_files":None,
                                               "local_uid_gid_candidate":None}
    try:
        users=[line.split(":") for line in passwd]
        groups=[line.split(":") for line in group]
        if any(len(x)<4 or not x[2].isdecimal() or not x[3].isdecimal() for x in users):raise ValueError()
        if any(len(x)<3 or not x[2].isdecimal() for x in groups):raise ValueError()
        if not any(x[0]=="installer" and int(x[2])==os.getuid() and int(x[3])==os.getgid()
                   for x in users):raise ValueError()
        names={x[0] for x in users}|{x[0] for x in groups}
        used={int(x[2]) for x in users}|{int(x[2]) for x in groups}
        free=next((n for n in range(2000,65000) if n not in used),None)
        return {"status":"local_files_observed","name_in_local_files":ACCOUNT in names,
                "local_uid_gid_candidate":free}
    except ValueError:return {"status":"unknown","name_in_local_files":None,
                              "local_uid_gid_candidate":None}
def apparmor():
    data=read(APPARMOR,128)
    if data is None:return None
    try:value=data.strip().decode("ascii")
    except UnicodeError:return None
    return int(value) if value in ("0","1") else None
try:
    assert os.getuid()!=0 and pwd.getpwuid(os.getuid()).pw_name=="installer"
    account=local_account(decoded("/etc/passwd",65536),decoded("/etc/group",65536))
    uid=subids(decoded("/etc/subuid",65536));gid=subids(decoded("/etc/subgid",65536))
    source=decoded("/etc/apt/sources.list.d/ubuntu.sources",16384)
    signed=None if source is None else any(line.strip()=="Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" for line in source)
    value={"schema":"elevenid.installer-only-vm-rootless-local-policy/v1",
           "account":account,"subuid":uid,"subgid":gid,
           "apparmor_unprivileged_userns_restrict":apparmor(),
           "ubuntu_signed_by_declaration_observed":signed,
           "external_nss_checked":False,"keyring_admitted":False}
    print(json.dumps(value,sort_keys=True,separators=(",",":")))
except Exception:
    print("rootless local policy observation refused",file=sys.stderr);sys.exit(1)
'''


def _local_command() -> str:
    return "/usr/bin/python3 -E -I -B -c " + shlex.quote(LOCAL_SCRIPT)


def _version(value: str) -> str | None:
    return value if VERSION.fullmatch(value) and value != "(none)" else None


def _package_status(raw: bytes | None) -> dict:
    if raw is None:
        return {"status": "not_observed", "installed_version": None}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        lines = []
    if len(lines) != 2 or lines[0] != "install ok installed":
        return {"status": "unknown", "installed_version": None}
    value = _version(lines[1])
    return {"status": "installed" if value else "unknown",
            "installed_version": value}


def _policy(raw: bytes | None, package: str) -> dict:
    result = {"status": "unknown", "installed_version": None,
              "candidate_version": None, "ubuntu_origin_metadata_observed": False}
    if raw is None:
        return result
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return result
    if not lines or lines[0] != package + ":":
        return result
    installed = [line.strip().removeprefix("Installed: ") for line in lines
                 if line.strip().startswith("Installed: ")]
    candidate = [line.strip().removeprefix("Candidate: ") for line in lines
                 if line.strip().startswith("Candidate: ")]
    if len(installed) != 1 or len(candidate) != 1:
        return result
    result["status"] = "metadata_observed"
    result["installed_version"] = _version(installed[0])
    result["candidate_version"] = _version(candidate[0])
    result["ubuntu_origin_metadata_observed"] = any(
        "release " in line and "o=Ubuntu" in line for line in lines)
    return result


def _depends(raw: bytes | None, package: str) -> dict:
    result = {"status": "unknown", "closed_package_dependencies": [],
              "other_dependency_lines": 0}
    if raw is None:
        return result
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return result
    if not lines or lines[0] != package:
        return result
    closed = set()
    count = 0
    for line in lines[1:]:
        if re.match(r"^\s*(?:PreDepends|Depends|Recommends):\s+", line):
            name = line.split(":", 1)[1].strip().strip("<>")
            if name in PACKAGES:
                closed.add(name)
            else:
                count += 1
    return {"status": "metadata_observed", "closed_package_dependencies": sorted(closed),
            "other_dependency_lines": min(count, 65536)}


def _file_list(raw: bytes | None) -> dict:
    if raw is None:
        return {"status": "unknown", "approved_paths_observed": []}
    try:
        paths = raw.decode("ascii").splitlines()
    except UnicodeError:
        return {"status": "unknown", "approved_paths_observed": []}
    if any(not path.startswith("/") or len(path) > 512 for path in paths):
        return {"status": "unknown", "approved_paths_observed": []}
    return {"status": "file_list_observed", "approved_paths_observed":
            sorted(set(paths) & set(ROOTLESS_PATHS))}


def _local_policy(raw: bytes) -> dict:
    value = release.decode(raw)
    release.require(release.encode(value) == raw and value.get("schema") == GUEST_SCHEMA,
                    "VM rootless local policy invalid")
    release.exact(value, {"schema", "account", "subuid", "subgid",
                          "apparmor_unprivileged_userns_restrict",
                          "ubuntu_signed_by_declaration_observed",
                          "external_nss_checked", "keyring_admitted"},
                  "VM rootless local policy")
    release.require(value["external_nss_checked"] is False
                    and value["keyring_admitted"] is False
                    and (value["apparmor_unprivileged_userns_restrict"] is None or
                         type(value["apparmor_unprivileged_userns_restrict"]) is int and
                         value["apparmor_unprivileged_userns_restrict"] in (0, 1))
                    and (value["ubuntu_signed_by_declaration_observed"] is None or
                         type(value["ubuntu_signed_by_declaration_observed"]) is bool),
                    "VM rootless policy authority invalid")
    release.exact(value["account"], {"status", "name_in_local_files",
                                     "local_uid_gid_candidate"}, "VM rootless local account")
    release.require(value["account"]["status"] in ("unknown", "local_files_observed")
                    and value["account"]["name_in_local_files"] in (None, True, False)
                    and (value["account"]["local_uid_gid_candidate"] is None or
                         type(value["account"]["local_uid_gid_candidate"]) is int and
                         2000 <= value["account"]["local_uid_gid_candidate"] < 65000),
                    "VM rootless account observation invalid")
    for key in ("subuid", "subgid"):
        item = value[key]
        release.exact(item, {"status", "local_candidate_start", "local_ranges_checked"},
                      "VM rootless local subordinate range")
        release.require(item["status"] in ("unknown", "local_file_candidate",
                                           "no_local_gap_in_bound")
                        and (item["local_candidate_start"] is None or
                             type(item["local_candidate_start"]) is int and
                             100000 <= item["local_candidate_start"] < 100000+65536*1024)
                        and type(item["local_ranges_checked"]) is int
                        and 0 <= item["local_ranges_checked"] <= 65536,
                        "VM rootless subordinate range invalid")
    return value


def _read_query(binding: dict, command: str, limit: int) -> bytes | None:
    try:
        return probe._ssh(binding, command, limit=limit, timeout=12)
    except (ValueError, OSError, TimeoutError):
        return None


def observe(*, source: Path, registry: Path, runtime_parent: Path,
            vm_id: str, observation_id: str) -> dict:
    release.require(os.geteuid() == 0, "root VM controller required")
    probe._uuid(vm_id)
    probe._uuid(observation_id)
    release.require(all(path.is_absolute() for path in (source, registry, runtime_parent)),
                    "VM rootless plan path must be absolute")
    with ControllerLease(registry) as lease:
        name = vm_id + RESULT_SUFFIX
        try:
            os.stat(name, dir_fd=lease.parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("VM rootless package plan already observed")
        before = probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
        packages = {}
        for package in PACKAGES:
            status_command, policy_command, depends_command = _commands(package)
            dpkg = _package_status(_read_query(before, status_command, 512))
            file_list = (_file_list(_read_query(before, _file_list_command(package), 65536))
                         if dpkg["status"] == "installed" else
                         {"status": "unknown", "approved_paths_observed": []})
            packages[package] = {
                "dpkg": dpkg,
                "apt_policy": _policy(_read_query(before, policy_command, 8192), package),
                "apt_depends": _depends(_read_query(before, depends_command, 4096), package),
                "filtered_file_list": file_list,
            }
        local = _local_policy(probe._ssh(before, _local_command(), limit=2048, timeout=20))
        release.require(probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == before, "VM rootless package plan live binding changed")
        result = {"schema": SCHEMA, "phase": "observed", "vm_id": vm_id,
                  "observation_id": observation_id,
                  "readiness_sha256": before["readiness_sha256"],
                  "pid": before["pid"], "start_ticks": before["start_ticks"],
                  "engine_id": before["engine_id"],
                  "packages": packages, "local_policy": local,
                  "dedicated_account_name": ACCOUNT,
                  "proposed_private_home": "/home/" + ACCOUNT,
                  "proposed_private_home_mode": "0700",
                  "proposed_private_runtime": "/run/user/<dedicated-uid>",
                  "proposed_private_runtime_mode": "0700",
                  "proposed_supplementary_groups": [],
                  "proposed_docker_group_membership": False,
                  "proposed_sudo_grants": False,
                  "proposed_subid_range_count": 65536,
                  "package_review_candidates": ["uidmap", "rootlesskit",
                                                "slirp4netns", "fuse-overlayfs"],
                  "rootless_script_provider": "unresolved",
                  "rootful_docker_package_changed_by_probe": False,
                  "docker_io_package_version_at_observation":
                      packages["docker.io"]["dpkg"]["installed_version"],
                  "rootful_docker_version_preservation_proven_for_install": False,
                  "package_source_key_trust_admitted": False,
                  "transaction_simulated": False,
                  "requires_reviewed_transaction_and_source_key": True,
                  "plan_complete": False,
                  "external_nss_checked": False,
                  "account_or_subids_allocated": False,
                  "packages_installed": False,
                  "package_actions_authorized": False,
                  "daemon_start_attempted_by_probe": False,
                  "rootless_ready": False, "qualified": False,
                  "installation_authorized": False,
                  "application_deployment_authorized": False,
                  "observed_at": int(time.time())}
        _write(lease.parent, name, result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("vm-id", "observation-id"):
        parser.add_argument("--" + name, required=True)
    try:
        value = observe(**{key.replace("-", "_"): v for key, v in vars(parser.parse_args()).items()})
        print(json.dumps({"phase": value["phase"], "vm_id": value["vm_id"],
                          "rootless_ready": False, "qualified": False}, sort_keys=True))
        return 0
    except Exception:
        print("VM rootless package plan refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
