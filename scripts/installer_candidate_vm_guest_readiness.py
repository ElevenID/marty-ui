"""Pinned-SSH guest baseline probe for a root-controlled installer VM.

This observes a guest before installation. It neither approves a candidate nor
proves host/image provenance; the controller must bind it to a held live VM.
"""
from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import re
import shlex
import stat

from installer_host_probe import command, INFO_FORMAT
from installer_candidate_vm_policy import (
    GUEST_USER, PACKAGES, ROOTLESS_UID, ROOTLESS_DOCKER_HOST, ROOTLESS_PACKAGES,
    require_rootless_profile,
)
import installer_release as release

SSH = Path("/usr/bin/ssh")
DOCKER = ("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
          "/usr/bin/docker --host unix:///var/run/docker.sock")
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}
ROOTLESS_DOCKER = ("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
                   "/usr/bin/docker --host " + ROOTLESS_DOCKER_HOST)
ROOTLESS_SYSTEMCTL = (f"env -i HOME=/home/installer PATH=/usr/bin:/bin "
                     f"XDG_RUNTIME_DIR=/run/user/{ROOTLESS_UID} "
                     f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{ROOTLESS_UID}/bus "
                     "/usr/bin/systemctl --user")
ROOTLESS_DOCKER_ROOT = "/home/installer/.local/share/docker"
ROOTLESS_INFO_QUERY = ROOTLESS_DOCKER + " info --format " + shlex.quote(INFO_FORMAT)
ROOTLESS_SOCKET_QUERY = "/usr/bin/python3 -I -c " + shlex.quote("\n".join([
    "import json, os, pathlib, stat",
    f"uid={ROOTLESS_UID}",
    "assert os.getuid()==os.geteuid()==uid",
    "path=pathlib.Path('/run/user/'+str(uid)+'/docker.sock')",
    "assert path.resolve()==path",
    "for parent in path.parents:",
    "    info=parent.lstat()",
    "    assert stat.S_ISDIR(info.st_mode) and info.st_uid in (0,uid) and not info.st_mode&0o022",
    "directory=path.parent.lstat(); sock=path.lstat()",
    "assert directory.st_uid==uid and stat.S_IMODE(directory.st_mode)==0o700",
    "assert stat.S_ISSOCK(sock.st_mode) and sock.st_uid==uid and not sock.st_mode&0o007",
    "print(json.dumps(dict(runtime=dict(profile='rootless',uid=uid,docker_host='unix://'+str(path),socket_device=sock.st_dev,socket_inode=sock.st_ino),runtime_directory_device=directory.st_dev,runtime_directory_inode=directory.st_ino)))",
]))
ROOTLESS_RESOURCE_QUERY = "/usr/bin/python3 -I -c " + shlex.quote("\n".join([
    "import json, os, pathlib, re, stat",
    f"uid={ROOTLESS_UID}",
    f"path=pathlib.Path({ROOTLESS_DOCKER_ROOT!r})",
    "assert os.getuid()==os.geteuid()==uid and path.resolve()==path",
    "for parent in path.parents:",
    "    info=parent.lstat()",
    "    assert stat.S_ISDIR(info.st_mode) and info.st_uid in (0,uid) and not info.st_mode&0o022",
    "info=path.lstat(); assert stat.S_ISDIR(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022",
    "raw=pathlib.Path('/proc/meminfo').read_bytes(); assert len(raw)<=65536",
    "matches=re.findall(rb'^MemTotal:\\s+([0-9]+) kB$',raw,re.MULTILINE); assert len(matches)==1",
    "fs=os.statvfs(path)",
    "print(json.dumps(dict(guest_memory_bytes=int(matches[0])*1024,docker_data_filesystem=dict(device=info.st_dev,free_bytes=fs.f_bavail*fs.f_frsize))))",
]))
ROOTLESS_FACT_FIELDS = {
    "resource_profile", "runtime", "rootless_resource_controls",
    "guest_memory_bytes", "docker_memory_bytes", "docker_data_filesystem",
}


def validate_rootless_facts(value: dict, resource_profile: str) -> None:
    """Validate measured v2 facts; this confers no dispatch or readiness."""
    require_rootless_profile(resource_profile)
    release.require(value.get("resource_profile") == resource_profile,
                    "VM measured resource profile differs")
    runtime = release.exact(value.get("runtime"), {
        "profile", "uid", "docker_host", "socket_device", "socket_inode"},
        "VM rootless runtime")
    controls = release.exact(value.get("rootless_resource_controls"), {
        "cgroup_version", "cgroup_driver", "memory_limit"}, "VM rootless controls")
    disk = release.exact(value.get("docker_data_filesystem"), {"device", "free_bytes"},
                         "VM Docker filesystem")
    release.require(runtime["profile"] == "rootless"
                    and type(runtime["uid"]) is int and runtime["uid"] == ROOTLESS_UID
                    and runtime["docker_host"] == ROOTLESS_DOCKER_HOST
                    and all(type(runtime[key]) is int and runtime[key] >= 0
                            for key in ("socket_device", "socket_inode"))
                    and runtime["socket_inode"] > 0
                    and controls["cgroup_version"] == "2"
                    and controls["cgroup_driver"] == "systemd"
                    and controls["memory_limit"] is True
                    and all(type(value.get(key)) is int and value[key] >= 7 * 1024**3
                            for key in ("guest_memory_bytes", "docker_memory_bytes"))
                    and type(disk["device"]) is int and disk["device"] >= 0
                    and type(disk["free_bytes"]) is int and disk["free_bytes"] >= 20 * 1024**3,
                    "VM rootless runtime or measured capacity unavailable")


def same_rootless_guest(initial: dict, current: dict) -> None:
    profile = initial.get("resource_profile")
    for value in (initial, current):
        validate_rootless_facts(value, profile)
    # Free bytes are measurements, not identity. Both observations must meet
    # the floor and use the same filesystem; ordinary guest writes may occur.
    release.require(set(initial) == set(current)
                    and all(type(current[key]) is type(value) and current[key] == value
                            for key, value in initial.items() if key != "docker_data_filesystem")
                    and current["docker_data_filesystem"]["device"]
                    == initial["docker_data_filesystem"]["device"],
                    "VM rootless guest identity changed")


def inspect_guest(guest: Callable[[str], str], *, user: str,
                  packages: dict[str, str], resource_profile: str | None = None,
                  require_empty: bool = True) -> dict:
    """Require exact bootstrap facts and a still-empty Docker baseline."""
    rootless = resource_profile is not None
    release.require(type(require_empty) is bool and (require_empty or rootless),
                    "legacy VM readiness requires an empty baseline")
    if rootless:
        require_rootless_profile(resource_profile)
    release.require(user == GUEST_USER and packages == (ROOTLESS_PACKAGES if rootless else PACKAGES),
                    "guest seed package policy differs")
    account = guest("/usr/bin/id -u; /usr/bin/id -un; "
                    "/usr/bin/stat -c '%u:%a:%F' /home/installer").splitlines()
    release.require(len(account) == 3 and re.fullmatch(r"[1-9][0-9]*", account[0])
                    and account[1] == user
                    and account[2] == account[0] + ":700:directory",
                    "guest account is not private")
    if rootless:
        release.require(account[0] == str(ROOTLESS_UID), "rootless guest UID differs")
    status = json.loads(guest("/usr/bin/cloud-init status --format json"))
    release.require(type(status) is dict and status.get("status") == "done"
                    and status.get("extended_status") == "done"
                    and status.get("errors") in ([], {})
                    and status.get("recoverable_errors") in (None, [], {}),
                    "guest cloud-init is not complete and clean")
    versions = {}
    for name, expected in packages.items():
        release.require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is not None,
                        "guest package name invalid")
        package_state = guest(
            "/usr/bin/dpkg-query -W -f='${Status}\\t${Version}' " + name)
        release.require(package_state == "install ok installed\t" + expected,
                        "guest package installation or version differs")
        versions[name] = expected
    runtime = None
    info = None
    docker = ROOTLESS_DOCKER if rootless else DOCKER
    if rootless:
        release.require(guest(ROOTLESS_SYSTEMCTL + " is-active docker") == "active"
                        and guest(ROOTLESS_SYSTEMCTL + " is-enabled docker") == "enabled"
                        and guest("/usr/bin/loginctl show-user installer -p Linger --value") == "yes"
                        and guest("/usr/bin/systemctl show --property=ActiveState --value docker.service") == "inactive"
                        and guest("/usr/bin/systemctl show --property=ActiveState --value docker.socket") == "inactive",
                        "rootless user service boot policy unavailable")
        runtime = release.decode(guest(ROOTLESS_SOCKET_QUERY).encode("ascii"))
        release.exact(runtime, {"runtime", "runtime_directory_device", "runtime_directory_inode"},
                      "rootless guest socket identity")
        release.require(all(type(runtime[key]) is int and runtime[key] >= 0
                            for key in ("runtime_directory_device", "runtime_directory_inode"))
                        and runtime["runtime_directory_inode"] > 0,
                        "rootless guest runtime directory invalid")
        info = release.decode(guest(ROOTLESS_INFO_QUERY).encode("ascii"))
        release.exact(info, {"ID", "OSType", "Architecture", "SecurityOptions", "MemTotal",
                             "DockerRootDir", "ServerVersion", "CgroupVersion", "CgroupDriver",
                             "MemoryLimit"}, "rootless guest Docker information")
        security = info.get("SecurityOptions")
        release.require(type(security) is list and all(type(v) is str for v in security)
                        and security.count("name=rootless") == 1
                        and not any(v.startswith("name=rootless,") or v == "name=userns"
                                    or v.startswith("name=userns,") for v in security)
                        and info.get("CgroupVersion") == "2"
                        and info.get("CgroupDriver") == "systemd"
                        and info.get("MemoryLimit") is True
                        and info.get("DockerRootDir") == ROOTLESS_DOCKER_ROOT,
                        "guest Docker rootless resource controls unavailable")
    else:
        release.require(guest("/usr/bin/systemctl is-active docker") == "active",
                        "guest Docker service differs")
    release.require(guest("/usr/bin/uname -m") == "x86_64",
                    "guest Docker service or platform differs")
    engine = json.loads(guest(docker + " info --format '{{json .ID}}'"))
    release.require(type(engine) is str and engine
                    and json.loads(guest(docker + " info --format '{{json .OSType}}'"))
                    == "linux"
                    and json.loads(guest(
                        docker + " info --format '{{json .Architecture}}'"))
                    in ("x86_64", "amd64"),
                    "guest Docker Engine differs")
    if require_empty:
        for query in ("ps -aq", "image ls -aq", "volume ls -q"):
            release.require(guest(docker + " " + query) == "",
                            "guest Docker is not initially clean")
        networks = guest(docker + " network ls --format '{{.Name}}'").splitlines()
        release.require(len(networks) == 3
                        and set(networks) == {"bridge", "host", "none"},
                        "guest Docker network inventory differs")
        for name, expected in (("bridge", "bridge:local"),
                               ("host", "host:local"),
                               ("none", "null:local")):
            release.require(guest(docker + " network inspect --format "
                                  "'{{.Driver}}:{{.Scope}}' " + name) == expected,
                            "guest Docker default network differs")
    release.require(json.loads(guest(docker + " info --format '{{json .ID}}'"))
                    == engine, "guest Docker Engine changed")
    result = {"guest_uid": int(account[0]), "guest_user": user,
              "packages": versions, "cloud_init_status": "done",
              "docker_engine_id": engine, "docker_initially_empty": require_empty,
              "guest_architecture": "x86_64"}
    if rootless:
        resources = release.decode(guest(ROOTLESS_RESOURCE_QUERY).encode("ascii"))
        release.exact(resources, {"guest_memory_bytes", "docker_data_filesystem"},
                      "rootless guest resource measurements")
        release.require(info["ID"] == engine and info["OSType"] == "linux"
                        and info["Architecture"] in ("x86_64", "amd64")
                        and release.decode(guest(ROOTLESS_INFO_QUERY).encode("ascii")) == info
                        and release.decode(guest(ROOTLESS_SOCKET_QUERY).encode("ascii")) == runtime,
                        "rootless guest daemon or socket changed")
        result.update(resources, resource_profile=resource_profile, runtime=runtime["runtime"],
                      docker_memory_bytes=info["MemTotal"], rootless_resource_controls=dict(
                          cgroup_version="2", cgroup_driver="systemd", memory_limit=True))
        validate_rootless_facts(result, resource_profile)
    return result


def pinned_guest(control_dir: Path, *, port: int, user: str,
                 packages: dict[str, str], key_sha256: str,
                 known_hosts_sha256: str, resource_profile: str | None = None) -> dict:
    """Run only fixed read-only commands over a pinned loopback SSH identity."""
    release.require(os.geteuid() == 0 and type(port) is int
                    and 1024 <= port <= 65535 and user == GUEST_USER,
                    "guest SSH selection invalid")
    client = SSH.lstat()
    release.require(stat.S_ISREG(client.st_mode) and client.st_uid == 0
                    and not client.st_mode & 0o022,
                    "SSH client is not trusted")
    key = control_dir / "controller_ed25519"
    hosts = control_dir / "known_hosts"
    from installer_candidate_vm_create import _bytes
    def pinned() -> None:
        release.require(release.digest(_bytes(key, 8192)) == key_sha256
                        and release.digest(_bytes(hosts, 4096))
                        == known_hosts_sha256,
                        "guest SSH identity material changed")
    pinned()
    options = [str(SSH), "-F", "/dev/null", "-i", str(key),
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(hosts),
               "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "HostKeyAlgorithms=ssh-ed25519",
               "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
               "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
               "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
               "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
               "-p", str(port), user + "@127.0.0.1"]

    def guest(script: str) -> str:
        pinned()
        raw = command([*options, script], timeout=15, limit=65536, env=ENV)
        pinned()
        return raw.decode("ascii").strip()

    result = inspect_guest(guest, user=user, packages=packages, resource_profile=resource_profile)
    pinned()
    return result
