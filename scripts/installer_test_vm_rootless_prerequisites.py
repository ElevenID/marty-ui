"""Observe fixed rootless prerequisites in a retained installer-only VM.

The current installer account has Docker and sudo access. This observational
record cannot authorize a rootless daemon, installation, or qualification.
"""
from __future__ import annotations

import argparse
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


SCHEMA = "elevenid.installer-only-vm-rootless-prerequisites/v1"
GUEST_SCHEMA = "elevenid.installer-only-vm-rootless-guest-observation/v1"
RESULT_SUFFIX = ".installer-only-rootless-prerequisites.json"
LOGINCTL_COMMAND = ("/usr/bin/loginctl show-user installer -p Linger -p State "
                    "-p RuntimePath --no-pager")
BINARY_NAMES = ("docker", "dockerd-rootless.sh", "dockerd-rootless-setuptool.sh",
                "rootlesskit", "slirp4netns", "fuse-overlayfs", "newuidmap",
                "newgidmap", "systemctl", "loginctl")

# The script accepts no paths, account names, flags, or input from the caller.
# It neither executes Docker nor probes its socket. All returned fields are
# bounded metadata; /etc/subuid and /etc/subgid content is never returned.
GUEST_SCRIPT = r'''
import grp,json,os,pwd,stat,sys
N=("docker","dockerd-rootless.sh","dockerd-rootless-setuptool.sh",
   "rootlesskit","slirp4netns","fuse-overlayfs","newuidmap","newgidmap",
   "systemctl","loginctl")
def binary(name):
    try:
        s=os.lstat("/usr/bin/"+name)
    except FileNotFoundError:
        return {"kind":"missing","root_owned":False,"not_writable":False,"setuid":False}
    except OSError:
        return {"kind":"unknown","root_owned":False,"not_writable":False,"setuid":False}
    k="regular" if stat.S_ISREG(s.st_mode) else "symlink" if stat.S_ISLNK(s.st_mode) else "other"
    return {"kind":k,"root_owned":s.st_uid==0,"not_writable":not bool(s.st_mode&0o022),
            "setuid":bool(s.st_mode&stat.S_ISUID)}
def fixed_bytes(path,limit):
    try:
        h=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(h)
            if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or a.st_size>limit:
                return None
            r=os.open("/proc/self/fd/%d"%h,os.O_RDONLY|os.O_CLOEXEC)
            try:
                data=os.read(r,limit+1)
                b=os.fstat(r)
                n=os.stat(path,follow_symlinks=False)
                if len(data)>limit or any(getattr(a,x)!=getattr(b,x) or getattr(a,x)!=getattr(n,x)
                    for x in ("st_dev","st_ino","st_uid","st_gid","st_mode","st_size","st_mtime_ns","st_ctime_ns")):
                    return None
                return data
            finally:os.close(r)
        finally:os.close(h)
    except OSError:
        return None
def subids(path,uid):
    data=fixed_bytes(path,65536)
    if data is None:return {"status":"unknown","account_entries":0,"sufficient_65536":False}
    try: lines=data.decode("ascii").splitlines()
    except UnicodeError:return {"status":"unknown","account_entries":0,"sufficient_65536":False}
    found=[]
    for line in lines:
        pieces=line.split(":")
        if len(pieces)!=3:continue
        if pieces[0] not in ("installer",str(uid)):continue
        if not all(v.isdecimal() for v in pieces[1:]):
            return {"status":"unknown","account_entries":0,"sufficient_65536":False}
        start,count=map(int,pieces[1:])
        if start<1 or count<1 or start+count>4294967296:
            return {"status":"unknown","account_entries":0,"sufficient_65536":False}
        found.append((start,count))
    return {"status":"observed","account_entries":min(len(found),65536),
            "sufficient_65536":any(count>=65536 for _,count in found)}
def decimal(path):
    data=fixed_bytes(path,128)
    if data is None:return None
    value=data.strip()
    return int(value) if value.isdecimal() and len(value)<20 else None
def groups():
    actual=set(os.getgroups())|{os.getgid()}
    result={}
    for name in ("docker","sudo"):
        try:result[name]=grp.getgrnam(name).gr_gid in actual
        except KeyError:result[name]=False
    return result
try:
    uid=os.getuid()
    assert uid!=0 and pwd.getpwuid(uid).pw_name=="installer"
    home=os.lstat("/home/installer")
    assert stat.S_ISDIR(home.st_mode) and home.st_uid==uid and stat.S_IMODE(home.st_mode)==0o700
    s=os.statvfs("/home/installer")
    mem=fixed_bytes("/proc/meminfo",8192)
    available=None
    if mem is not None:
        for line in mem.decode("ascii").splitlines():
            if line.startswith("MemAvailable:"):
                words=line.split()
                if len(words)==3 and words[1].isdecimal() and words[2]=="kB":
                    available=int(words[1])
                break
    controllers=fixed_bytes("/sys/fs/cgroup/cgroup.controllers",4096)
    control=None if controllers is None else controllers.decode("ascii").split()
    userns=decimal("/proc/sys/kernel/unprivileged_userns_clone")
    maximum=decimal("/proc/sys/user/max_user_namespaces")
    value={"schema":"elevenid.installer-only-vm-rootless-guest-observation/v1",
           "uid":uid,"gid":os.getgid(),"docker_group":groups()["docker"],
           "sudo_group":groups()["sudo"],"sudo_policy_known":False,
           "binaries":{name:binary(name) for name in N},
           "subuid":subids("/etc/subuid",uid),"subgid":subids("/etc/subgid",uid),
           "userns_clone":userns,"max_user_namespaces":maximum,
           "cgroup_v2_controllers":None if control is None else
                {name:name in control for name in ("cpu","memory","pids")},
           "mem_available_kib":available,
           "home_available_bytes":s.f_bavail*s.f_frsize,
           "home_total_bytes":s.f_blocks*s.f_frsize,
           "daemon_started":False,"rootless_ready":False}
    print(json.dumps(value,sort_keys=True,separators=(",",":")))
except Exception:
    print("rootless prerequisite observation refused",file=sys.stderr)
    sys.exit(1)
'''


def _guest_command() -> str:
    return "/usr/bin/python3 -E -I -B -c " + shlex.quote(GUEST_SCRIPT)


def _decode_guest(raw: bytes, expected_uid: int) -> dict:
    result = release.decode(raw)
    release.require(release.encode(result) == raw and result.get("schema") == GUEST_SCHEMA,
                    "VM rootless guest observation invalid")
    release.exact(result, {"schema", "uid", "gid", "docker_group", "sudo_group",
                           "sudo_policy_known", "binaries", "subuid", "subgid",
                           "userns_clone", "max_user_namespaces", "cgroup_v2_controllers",
                           "mem_available_kib", "home_available_bytes",
                           "home_total_bytes", "daemon_started", "rootless_ready"},
                  "VM rootless guest observation")
    release.require(type(result["uid"]) is int and result["uid"] == expected_uid
                    and type(result["gid"]) is int and result["gid"] >= 0
                    and all(type(result[k]) is bool for k in
                            ("docker_group", "sudo_group", "sudo_policy_known",
                             "daemon_started", "rootless_ready"))
                    and result["sudo_policy_known"] is False
                    and result["daemon_started"] is False
                    and result["rootless_ready"] is False,
                    "VM rootless guest identity or authority differs")
    release.require(type(result["binaries"]) is dict
                    and set(result["binaries"]) == set(BINARY_NAMES),
                    "VM rootless binary set differs")
    for value in result["binaries"].values():
        release.exact(value, {"kind", "root_owned", "not_writable", "setuid"},
                      "VM rootless binary observation")
        release.require(value["kind"] in ("missing", "unknown", "regular", "symlink", "other")
                        and all(type(value[k]) is bool for k in
                                ("root_owned", "not_writable", "setuid")),
                        "VM rootless binary metadata invalid")
    for key in ("subuid", "subgid"):
        value = result[key]
        release.exact(value, {"status", "account_entries", "sufficient_65536"},
                      "VM rootless subordinate ID observation")
        release.require(value["status"] in ("unknown", "observed")
                        and type(value["account_entries"]) is int
                        and 0 <= value["account_entries"] <= 65536
                        and type(value["sufficient_65536"]) is bool,
                        "VM rootless subordinate ID metadata invalid")
    for key in ("userns_clone", "max_user_namespaces", "mem_available_kib",
                "home_available_bytes", "home_total_bytes"):
        value = result[key]
        release.require(value is None or type(value) is int and 0 <= value <= 2**63,
                        "VM rootless numeric observation invalid")
    controllers = result["cgroup_v2_controllers"]
    release.require(controllers is None or (type(controllers) is dict
                    and set(controllers) == {"cpu", "memory", "pids"}
                    and all(type(v) is bool for v in controllers.values())),
                    "VM rootless cgroup observation invalid")
    return result


def _systemd_user(raw: bytes | None, expected_uid: int) -> dict:
    unknown = {"status": "unknown", "linger": None, "state": "unknown",
               "runtime_path_expected": None}
    if raw is None or len(raw) > 512:
        return unknown
    try:
        lines = raw.decode("ascii").splitlines()
        pairs = [line.split("=", 1) for line in lines]
        if len(pairs) != 3 or any(len(pair) != 2 for pair in pairs):
            return unknown
        value = dict(pairs)
        if set(value) != {"Linger", "State", "RuntimePath"}:
            return unknown
        if value["Linger"] not in ("yes", "no") or value["State"] not in (
                "active", "lingering", "closing", "offline"):
            return unknown
        return {"status": "observed", "linger": value["Linger"] == "yes",
                "state": value["State"],
                "runtime_path_expected": value["RuntimePath"]
                == "/run/user/" + str(expected_uid)}
    except (UnicodeError, ValueError):
        return unknown


def observe(*, source: Path, registry: Path, runtime_parent: Path,
            vm_id: str, observation_id: str) -> dict:
    release.require(os.geteuid() == 0, "root VM controller required")
    probe._uuid(vm_id)
    probe._uuid(observation_id)
    release.require(all(p.is_absolute() for p in (source, registry, runtime_parent)),
                    "VM rootless path must be absolute")
    with ControllerLease(registry) as lease:
        name = vm_id + RESULT_SUFFIX
        try:
            os.stat(name, dir_fd=lease.parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("VM rootless observation already recorded")
        before = probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
        guest = _decode_guest(probe._ssh(before, _guest_command(), limit=8192, timeout=20),
                              before["guest_uid"])
        try:
            systemd_user = _systemd_user(probe._ssh(before, LOGINCTL_COMMAND,
                                                      limit=512, timeout=10),
                                          before["guest_uid"])
        except (ValueError, OSError, TimeoutError):
            systemd_user = _systemd_user(None, before["guest_uid"])
        release.require(probe._bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == before, "VM rootless live binding changed")
        result = {"schema": SCHEMA, "phase": "observed", "vm_id": vm_id,
                  "observation_id": observation_id,
                  "readiness_sha256": before["readiness_sha256"],
                  "pid": before["pid"], "start_ticks": before["start_ticks"],
                  "engine_id": before["engine_id"], "guest": guest,
                  "systemd_user": systemd_user,
                  "daemon_started": False, "rootless_ready": False,
                  "qualified": False, "installation_authorized": False,
                  "application_deployment_authorized": False,
                  "current_installer_least_privileged": False,
                  "dedicated_fixture_account_required": True,
                  "tool_versions_admitted": False,
                  "live_rootless_daemon_tested": False,
                  "binary_search_limited_to_usr_bin": True,
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
        print("VM rootless prerequisite observation refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
