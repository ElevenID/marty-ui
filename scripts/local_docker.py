"""Select a local Docker daemon without accepting remote/context overrides.

An existing current-user rootless socket takes precedence over the legacy local
rootful default. Endpoint selection is pinned for this process; a lost or
replaced rootless socket must fail rather than redirect later phases to another
daemon. This helper does not start a daemon or authorize any Docker mutation.
"""

from __future__ import annotations

from functools import lru_cache
import json
import os
from pathlib import Path
import stat
import subprocess


ROOTFUL_HOST = "unix:///var/run/docker.sock"


def _rootless_candidate() -> tuple[Path, int] | None:
    if os.name != "posix":
        return None
    uid = os.geteuid()
    if uid != os.getuid():
        raise ValueError("Local Docker requires matching real and effective user IDs")
    if uid == 0:
        return None
    return Path(f"/run/user/{uid}/docker.sock"), uid


def _checked_rootless_socket(path: Path, uid: int) -> tuple[int, int]:
    try:
        for parent in path.parents:
            info = parent.lstat()
            runtime = parent == path.parent
            if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid != (uid if runtime else 0)
                or (stat.S_IMODE(info.st_mode) != 0o700 if runtime
                    else info.st_mode & 0o022)):
                raise ValueError("Local rootless Docker runtime directory is unsafe")
        info = path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o007):
            raise ValueError("Local rootless Docker socket is unsafe")
        return info.st_dev, info.st_ino
    except OSError as exc:
        raise ValueError("Local rootless Docker socket is unavailable") from exc


@lru_cache(maxsize=1)
def _selected_endpoint() -> tuple[str, int | None, tuple[int, int] | None]:
    candidate = _rootless_candidate()
    if candidate is not None:
        path, uid = candidate
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ValueError("Local rootless Docker socket cannot be inspected") from exc
        else:
            identity = _checked_rootless_socket(path, uid)
            return f"unix://{path}", uid, identity
    return ROOTFUL_HOST, None, None


def local_docker_environment(environment: dict[str, str]) -> dict[str, str]:
    """Return a copy pinned to a verified local socket, stripping remote options."""
    host, uid, identity = _selected_endpoint()
    candidate = _rootless_candidate()
    if uid is not None:
        if (candidate is None or candidate[1] != uid
            or f"unix://{candidate[0]}" != host
            or _checked_rootless_socket(*candidate) != identity):
            raise ValueError("Selected local rootless Docker socket changed")
    elif (candidate is not None
          and environment.get("DOCKER_HOST") == f"unix://{candidate[0]}"):
        # A deliberately selected rootless daemon may be stopped. Never turn
        # that into permission to operate the unrelated rootful daemon.
        raise ValueError("Selected local rootless Docker socket is unavailable")
    local = environment.copy()
    local["DOCKER_HOST"] = host
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        local.pop(name, None)
    return local


def local_bind_mount_user(environment: dict[str, str]) -> str:
    """Map private host-owned binds through the verified local daemon.

    A current-user rootless daemon maps container root to its host owner.
    Numeric host UIDs inside that namespace instead map to subordinate users.
    The socket and daemon must agree before selecting that mapping.
    """
    selected = local_docker_environment(environment)
    fields = ('{"ID":{{json .ID}},"OSType":{{json .OSType}},'
              '"SecurityOptions":{{json .SecurityOptions}}}')
    try:
        result = subprocess.run(
            ["docker", "--host", selected["DOCKER_HOST"], "info", "--format", fields],
            env=selected, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", timeout=25, check=True,
        )
        if len(result.stdout) > 4096:
            raise ValueError("Local Docker daemon identity is oversized")
        daemon = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        raise ValueError("Local Docker daemon identity cannot be verified") from exc
    # A replaced endpoint must not turn a previously admitted inspection into
    # permission to select a user for another daemon.
    local_docker_environment(selected)
    if (not isinstance(daemon, dict) or set(daemon) != {"ID", "OSType", "SecurityOptions"}
        or not isinstance(daemon["ID"], str) or not 1 <= len(daemon["ID"]) <= 128
        or not all(33 <= ord(char) <= 126 for char in daemon["ID"])
        or daemon["OSType"] != "linux"
        or not isinstance(daemon["SecurityOptions"], list)
        or len(daemon["SecurityOptions"]) > 32
        or any(not isinstance(option, str) or not 1 <= len(option) <= 256
               for option in daemon["SecurityOptions"])):
        raise ValueError("Local Docker daemon identity is invalid")
    _, uid, _ = _selected_endpoint()
    rootless = "name=rootless" in daemon["SecurityOptions"]
    if rootless != (uid is not None):
        raise ValueError("Local Docker socket and daemon rootless identity differ")
    if rootless:
        return "0:0"
    return f"{os.getuid()}:{os.getgid()}" if os.name == "posix" else "1000:1000"
