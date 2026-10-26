#!/usr/bin/env python3
"""Read-only Linux Docker observations, NOT clean-host or acceptance evidence.

The sole local write is an ephemeral private empty Docker client config directory.
No credentials are read and no resources are created, pulled, stopped or removed.
The controller must independently establish VM origin, backing disk capacity,
source absence and credential absence; these limited observations cannot do so.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

LIMIT = 256 * 1024
MAX_RESOURCES = 512
SOCKET = Path("/var/run/docker.sock")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DEVTOOLS = ("git", "rustc", "cargo", "node", "npm", "gcc", "g++", "make")
INFO_FORMAT = '{' + ','.join('"' + key + '":{{json .' + key + '}}' for key in (
    "ID", "OSType", "Architecture", "SecurityOptions", "MemTotal", "DockerRootDir", "ServerVersion")) + '}'
NETWORK_FORMAT = '{"Id":{{json .Id}},"Name":{{json .Name}},"Driver":{{json .Driver}},"AttachedCount":{{len .Containers}}}'


def require(condition):
    if not condition:
        raise ValueError("host observation unavailable or invalid")


def command(argv, *, env, timeout=15, limit=LIMIT):
    """Bound both streams together; kill/reap the owned process group on failure."""
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, cwd=env["HOME"], start_new_session=True)
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        streams[key.fileobj].extend(chunk)
                        require(sum(map(len, streams.values())) <= limit)
            # Observe exit without reaping: reserve the leader PID while killing
            # any same-group descendants, even if they closed inherited pipes.
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                require(time.monotonic() < deadline)
                time.sleep(0.01)
            os.killpg(process.pid, signal.SIGKILL)
            require(process.wait() == 0)
        return bytes(streams[process.stdout])
    except BaseException as error:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if not isinstance(error, Exception):
            raise
        raise ValueError("host command observation failed") from None
    finally:
        if process is not None:
            process.stdout.close()
            process.stderr.close()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    return json.loads(raw, object_pairs_hook=unique)


def identifiers(raw, expression, *, deduplicate=False):
    require(isinstance(raw, bytes) and len(raw) <= LIMIT)
    values = raw.decode("ascii").splitlines()
    require(len(values) <= MAX_RESOURCES and (deduplicate or len(set(values)) == len(values)))
    require(all(re.fullmatch(expression, value) for value in values))
    return sorted(set(values))


class Filesystem:
    """Observation seams; production uses the local guest kernel only."""
    def ancestors(self, path):
        for parent in path.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)

    def config(self, path):
        info = path.lstat()
        require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
                and not any(path.iterdir()))

    def socket(self):
        require(SOCKET.resolve() == Path("/run/docker.sock"))
        self.ancestors(Path("/run/docker.sock"))
        info = SOCKET.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0)

    def executable(self, path):
        require(path.is_absolute())
        self.ancestors(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111
                and not info.st_mode & 0o022 and info.st_uid == 0)
        require(path.resolve() == path)

    def memory(self):
        # Linux labels these KiB counters "kB". Do not use advertised VM GB.
        with Path("/proc/meminfo").open("rb") as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536)
        matches = re.findall(rb"^MemTotal:\s+([0-9]+) kB$", raw, re.MULTILINE)
        require(len(matches) == 1)
        return int(matches[0]) * 1024

    def disk(self, root):
        path = Path(root)
        require(path.is_absolute() and path.resolve() == path)
        self.ancestors(path)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0)
        fs = os.statvfs(path)
        return {"device": info.st_dev, "free_bytes": fs.f_bavail * fs.f_frsize}

    def credential_files(self):
        import pwd
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        locations = {"docker_config": home / ".docker/config.json",
                     "containers_auth": home / ".config/containers/auth.json",
                     "runtime_containers_auth": Path(f"/run/user/{os.geteuid()}/containers/auth.json")}
        result = {}
        for name, path in locations.items():
            try:
                path.lstat()  # Presence only: never follow a link or read contents.
                result[name] = True
            except FileNotFoundError:
                result[name] = False
        return result

    def devtools(self):
        return {name: shutil.which(name, path=SAFE_PATH) is not None for name in DEVTOOLS}


def observe(docker, config, *, runner=command, filesystem=None, ambient=None):
    fs = filesystem or Filesystem()
    ambient = os.environ if ambient is None else ambient
    fs.socket()
    fs.executable(docker)
    fs.config(config)
    # Only this empty private temporary directory is visible as HOME/config.
    env = {"PATH": SAFE_PATH, "HOME": str(config), "LANG": "C", "LC_ALL": "C"}
    prefix = [str(docker), "--host", "unix:///var/run/docker.sock", "--config", str(config)]
    def run(*args):
        return runner(prefix + list(args), env=env)
    info = decode(run("info", "--format", INFO_FORMAT))
    require(isinstance(info, dict) and info.get("OSType") == "linux"
            and info.get("Architecture") in ("x86_64", "amd64"))
    security = info.get("SecurityOptions")
    require(isinstance(security, list) and all(isinstance(v, str) for v in security)
            and not any("rootless" in v or "userns" in v for v in security))
    engine = info.get("ID")
    require(isinstance(engine, str) and re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", engine))
    memory = info.get("MemTotal")
    require(type(memory) is int and memory > 0)
    root = info.get("DockerRootDir")
    require(isinstance(root, str) and len(root) <= 4096)
    disk = fs.disk(root)
    guest_memory = fs.memory()
    require(type(guest_memory) is int and guest_memory > 0)
    version = info.get("ServerVersion")
    compose = run("compose", "version", "--short").decode("ascii").strip()
    for value in (version, compose):
        require(isinstance(value, str) and len(value) <= 128
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.~-]+)?", value))
    containers = identifiers(run("ps", "-aq", "--no-trunc"), r"[0-9a-f]{64}")
    images = identifiers(run("image", "ls", "-q", "--no-trunc"), r"sha256:[0-9a-f]{64}", deduplicate=True)
    volumes = identifiers(run("volume", "ls", "-q"), r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
    network_ids = identifiers(run("network", "ls", "-q", "--no-trunc"), r"[0-9a-f]{64}")
    networks = []
    if network_ids:
        raw = run("network", "inspect", "--format", NETWORK_FORMAT, *network_ids)
        require(len(raw) <= LIMIT)
        records = [decode(line) for line in raw.splitlines()]
        require(len(records) == len(network_ids))
        for record in records:
            require(isinstance(record, dict) and record.get("Id") in network_ids)
            name, driver = record.get("Name"), record.get("Driver")
            require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", name)
                    and isinstance(driver, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", driver))
            attached = record.get("AttachedCount")
            require(type(attached) is int and 0 <= attached <= MAX_RESOURCES)
            networks.append({"id": record["Id"], "name": name, "driver": driver,
                             "attached_count": attached})
        require(sorted(v["id"] for v in networks) == network_ids)
    final = decode(run("info", "--format", INFO_FORMAT))
    require(final == info)  # Refuse observed daemon drift; not an atomic snapshot.
    credential_names = sorted(name for name in ambient if re.fullmatch(
        r"(?:GH_TOKEN|GITHUB_TOKEN|DOCKER_AUTH_CONFIG|DOCKER_CONFIG|REGISTRY_.*|AWS_.*|AZURE_.*|GOOGLE_APPLICATION_CREDENTIALS)", name))
    require(len(credential_names) <= 128 and all(len(v) <= 128 for v in credential_names))
    defaults = {"bridge": "bridge", "host": "host", "none": "null"}
    clean_networks = (len(networks) == 3 and {v["name"] for v in networks} == set(defaults)
                      and all(v["driver"] == defaults[v["name"]] and v["attached_count"] == 0 for v in networks))
    result = {"schema": "elevenid.installer-host-observation/v1", "acceptance": False,
              "engine_id": engine, "docker_version": version, "compose_version": compose,
              "docker_memory_bytes": memory, "guest_memory_bytes": guest_memory,
              "docker_data_filesystem": disk,
              "resources": {"containers": containers, "images": images, "volumes": volumes,
                            "networks": sorted(networks, key=lambda v: v["id"])},
              "resource_counts": {"containers": len(containers), "images": len(images),
                                  "volumes": len(volumes), "networks": len(networks)},
              "predicates": {"capacity": min(memory, guest_memory) >= 32 * 1024**3
                             and disk["free_bytes"] >= 20 * 1024**3,
                             "initial_docker_clean": not (containers or images or volumes) and clean_networks},
              "credential_file_presence": fs.credential_files(), "credential_environment_names": credential_names,
              "development_tool_presence": fs.devtools(),
              "limitations": ["not an atomic resource snapshot", "source absence not established",
                              "credential absence not established", "VM origin and backing capacity not established",
                              "controller must establish pre-pull timing", "Python is probe runtime, not a development-tool claim"]}
    require(len(json.dumps(result).encode()) <= LIMIT)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-bin", type=Path, default=Path("/usr/bin/docker"))
    args = parser.parse_args()
    try:
        require(sys.platform == "linux")
        with tempfile.TemporaryDirectory(prefix="installer-host-probe-") as directory:
            result = observe(args.docker_bin, Path(directory))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("host observation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
