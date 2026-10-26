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
import stat

from installer_host_probe import command
from installer_candidate_vm_policy import GUEST_USER, PACKAGES
import installer_release as release

SSH = Path("/usr/bin/ssh")
DOCKER = ("env -i HOME=/nonexistent PATH=/usr/bin:/bin "
          "/usr/bin/docker --host unix:///var/run/docker.sock")
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}


def inspect_guest(guest: Callable[[str], str], *, user: str,
                  packages: dict[str, str]) -> dict:
    """Require exact bootstrap facts and a still-empty Docker baseline."""
    release.require(user == GUEST_USER and packages == PACKAGES,
                    "guest seed package policy differs")
    account = guest("/usr/bin/id -u; /usr/bin/id -un; "
                    "/usr/bin/stat -c '%u:%a:%F' /home/installer").splitlines()
    release.require(len(account) == 3 and re.fullmatch(r"[1-9][0-9]*", account[0])
                    and account[1] == user
                    and account[2] == account[0] + ":700:directory",
                    "guest account is not private")
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
    release.require(guest("/usr/bin/systemctl is-active docker") == "active"
                    and guest("/usr/bin/uname -m") == "x86_64",
                    "guest Docker service or platform differs")
    engine = json.loads(guest(DOCKER + " info --format '{{json .ID}}'"))
    release.require(type(engine) is str and engine
                    and json.loads(guest(DOCKER + " info --format '{{json .OSType}}'"))
                    == "linux"
                    and json.loads(guest(
                        DOCKER + " info --format '{{json .Architecture}}'"))
                    in ("x86_64", "amd64"),
                    "guest Docker Engine differs")
    for query in ("ps -aq", "image ls -aq", "volume ls -q"):
        release.require(guest(DOCKER + " " + query) == "",
                        "guest Docker is not initially clean")
    networks = guest(DOCKER + " network ls --format '{{.Name}}'").splitlines()
    release.require(len(networks) == 3
                    and set(networks) == {"bridge", "host", "none"},
                    "guest Docker network inventory differs")
    for name, expected in (("bridge", "bridge:local"),
                           ("host", "host:local"),
                           ("none", "null:local")):
        release.require(guest(DOCKER + " network inspect --format "
                              "'{{.Driver}}:{{.Scope}}' " + name) == expected,
                        "guest Docker default network differs")
    release.require(json.loads(guest(DOCKER + " info --format '{{json .ID}}'"))
                    == engine, "guest Docker Engine changed")
    return {"guest_uid": int(account[0]), "guest_user": user,
            "packages": versions, "cloud_init_status": "done",
            "docker_engine_id": engine, "docker_initially_empty": True,
            "guest_architecture": "x86_64"}


def pinned_guest(control_dir: Path, *, port: int, user: str,
                 packages: dict[str, str], key_sha256: str,
                 known_hosts_sha256: str) -> dict:
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

    result = inspect_guest(guest, user=user, packages=packages)
    pinned()
    return result
