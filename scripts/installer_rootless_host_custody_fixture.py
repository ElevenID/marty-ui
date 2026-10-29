#!/usr/bin/env python3
"""Disposable rootless UID-mapping observation; never an installer or release test.

The controller may invoke already-installed RootlessKit/newuidmap while starting
its own daemon. Docker clients run with no_new_privs. No rootful socket, sudo,
package installation, existing Docker context, or pre-existing state is used.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import socket
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid


TAG = "v1.1.263-nightly.20261027.40597099479"
SOURCE = "0aae5d6c03df0ccb2aa757d61fb022a24a962d14"
INVENTORY_SHA = "54b593a48bbf139838e6c0a79441e9eb1ebbe79faf7d2347cb775ff2140a9676"
IMAGE = ("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:"
         "f8832a8b325fc017d9d10baf6742bf692cd573fa9a3ec09cb6c976a2fde56c54")
CANARY = b"marty-rootless-owned-canary\n"
SET_PRIV = "/usr/bin/setpriv"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def write_record(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def run(argv, env, *, timeout=40, output_limit=65536, binary=False):
    require(type(argv) is list and all(type(a) is str for a in argv), "invalid command")
    require(0 < output_limit <= 64 * 1024 * 1024, "invalid command output bound")
    for parent in (Path("/usr"), Path("/usr/bin")):
        ancestor = parent.lstat()
        require(stat.S_ISDIR(ancestor.st_mode) and ancestor.st_uid == 0
                and ancestor.st_mode & 0o022 == 0,
                "no-new-privs launcher ancestor differs")
    m = Path(SET_PRIV).lstat()
    require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_mode & 0o022 == 0
            and m.st_mode & 0o6000 == 0 and m.st_mode & 0o111 != 0,
            "trusted no-new-privs launcher unavailable")
    try:
        capability = os.getxattr(SET_PRIV, "security.capability", follow_symlinks=False)
    except OSError as error:
        require(error.errno == errno.ENODATA, "setpriv capability metadata unavailable")
    else:
        require(not capability, "setpriv has file capabilities")
    proc = subprocess.Popen([SET_PRIV, "--no-new-privs", "--", *argv],
                            env=env, cwd="/", stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    chunks = {"out": bytearray(), "err": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "out")
    selector.register(proc.stderr, selectors.EVENT_READ, "err")
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "bounded command timeout")
            for key, _ in selector.select(min(remaining, 0.25)):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffer = chunks[key.data]
                limit = output_limit if key.data == "out" else 65536
                require(len(buffer) + len(data) <= limit, "bounded command output exceeded")
                buffer.extend(data)
        while True:
            state = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if state is not None:
                break
            require(time.monotonic() < deadline, "bounded command timeout")
            time.sleep(0.05)
    finally:
        selector.close()
        # Keep the exact leader PID reserved through group cleanup. A child
        # retaining a closed pipe cannot outlive this command.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()
    out, err = bytes(chunks["out"]), bytes(chunks["err"])
    require(proc.returncode == 0, "command refused: " + str(argv[:3]) + " stderr=" +
            err.decode("utf-8", "replace")[-300:])
    return out if binary else out.decode("utf-8", "strict").strip()


def proc_stamp(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return int(raw.rsplit(") ", 1)[1].split()[19])


def leader_exited(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def owned_context_processes(context):
    found = []
    needle = os.fsencode(str(context))
    for count, entry in enumerate(Path("/proc").iterdir(), start=1):
        require(count <= 8192, "process census exceeds bound")
        if not entry.name.isdecimal():
            continue
        try:
            if entry.stat().st_uid != os.geteuid():
                continue
            with (entry / "cmdline").open("rb") as stream:
                raw = stream.read(16385)
            require(len(raw) <= 16384, "owned process command exceeds bound")
        except FileNotFoundError:
            continue
        if needle in raw:
            found.append(int(entry.name))
    return found


def stop_daemon(daemon, stamp, socket_path, socket_identity, context):
    require(proc_stamp(daemon.pid) == stamp and os.getpgid(daemon.pid) == daemon.pid,
            "owned daemon changed; preserve fixture")
    try:
        os.killpg(daemon.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 10
    while not leader_exited(daemon.pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    # The zombie leader still reserves its PID, so the group cannot be reused.
    try:
        os.killpg(daemon.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while not leader_exited(daemon.pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    require(leader_exited(daemon.pid), "rootlesskit leader did not stop")
    try:
        named = socket_path.lstat()
    except FileNotFoundError:
        named = None
    if named is not None:
        require(stat.S_ISSOCK(named.st_mode)
                and (named.st_dev, named.st_ino, named.st_uid) == socket_identity,
                "rootless socket changed during daemon stop")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            outcome = probe.connect_ex(str(socket_path))
        require(outcome in (errno.ENOENT, errno.ECONNREFUSED),
                "rootless daemon socket still serves or cannot be classified")
    daemon.wait(timeout=5)
    require(not owned_context_processes(context),
            "owned rootless daemon descendant remains")


def mapped(uid_map, guest):
    matches = []
    for line in uid_map.splitlines():
        parts = line.split()
        require(len(parts) == 3 and all(p.isdecimal() for p in parts), "invalid uid_map")
        inner, outer, length = map(int, parts)
        if inner <= guest < inner + length:
            matches.append(outer + guest - inner)
    require(len(matches) == 1, "ambiguous or absent UID map")
    return matches[0]


def preflight(*, record=False, tool_dir=None):
    uid = os.geteuid()
    require(uid != 0 and os.getuid() == uid, "ordinary nonroot runner required")
    required = ("docker", "dockerd", "newuidmap", "newgidmap", "setpriv", "gpg", "gpgv", "dpkg-deb")
    extras = ("dockerd-rootless.sh", "rootlesskit")
    names = (*required, *extras)
    missing = [name for name in required if not shutil.which(name)]
    user = pwd.getpwuid(uid).pw_name
    ranges = {}
    for file in ("/etc/subuid", "/etc/subgid"):
        lines = Path(file).read_text().splitlines() if Path(file).exists() else []
        ranges[file] = [line for line in lines if line.split(":", 1)[0] in (user, str(uid))]
    allowed = all(any(len(parts := line.split(":")) == 3 and parts[2].isdecimal()
                      and int(parts[2]) >= 65536 for line in ranges[file]) for file in ranges)
    report = {"schema": "marty.rootless-fixture-preflight/v1", "uid": uid,
              "tool_presence": {n: shutil.which(n) is not None for n in names},
              "subordinate_ranges_present": allowed,
              "userns_max": Path("/proc/sys/user/max_user_namespaces").read_text().strip(),
              "daemon_started": False, "installer_executed": False}
    if not missing:
        clean = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
        report["docker_version"] = run([shutil.which("docker"), "--version"], clean)
        report["dockerd_version"] = run([shutil.which("dockerd"), "--version"], clean)
    if record:
        write_record(Path(os.environ["RUNNER_TEMP"]) / "marty-rootless-preflight.json", report)
    require(not missing and shutil.which("setpriv") == SET_PRIV,
            "missing preinstalled rootless tools: " + ",".join(missing))
    require(allowed, "no preconfigured >=65536 subordinate UID/GID range")
    tools = {n: shutil.which(n) for n in names}
    if tool_dir is not None:
        raw_directory = Path(tool_dir)
        require(raw_directory == Path(os.environ["RUNNER_TEMP"]) / "marty-rootless-tools",
                "rootless tool location differs")
        directory = raw_directory.resolve(strict=True)
        metadata = directory.lstat()
        require(directory == raw_directory and directory.is_dir() and metadata.st_uid == uid
                and stat.S_IMODE(metadata.st_mode) == 0o700,
                "private rootless tool directory differs")
        admission_path = Path(os.environ["RUNNER_TEMP"]) / "marty-rootless-admission.json"
        admission_meta = admission_path.lstat()
        require(stat.S_ISREG(admission_meta.st_mode) and admission_meta.st_uid == uid
                and stat.S_IMODE(admission_meta.st_mode) == 0o600
                and admission_meta.st_size <= 8192,
                "rootless admission record custody differs")
        admission = json.loads(admission_path.read_bytes())
        require(admission["schema"] == "marty.rootless-tool-admission/v1"
                and admission["uid"] == uid
                and admission["docker_version"] == report["dockerd_version"]
                and admission["system_install"] is False,
                "rootless tool admission differs")
        admitted = admission["member_sha256"]
        allowed_tools = {"dockerd-rootless.sh", "rootlesskit",
                         "rootlesskit-docker-proxy", "vpnkit"}
        require(type(admitted) is dict and set(admitted).issubset(
                    {"./usr/bin/" + name for name in allowed_tools})
                and {"./usr/bin/" + name for name in extras}.issubset(admitted),
                "admitted rootless tool set differs")
        expected_names = {"docker.gpg", "InRelease", "gnupg", "trusted.gpg",
                          "rootless-extras.deb"} | {name.removeprefix("./usr/bin/") for name in admitted}
        with os.scandir(directory) as listing:
            actual_names = []
            for entry in listing:
                actual_names.append(entry.name)
                require(len(actual_names) <= 10, "private tool directory exceeds bound")
        require(set(actual_names) == expected_names and len(actual_names) == len(expected_names),
                "private rootless tool directory has unknown entries")
        for member in allowed_tools:
            if "./usr/bin/" + member not in admitted:
                continue
            path = directory / member
            m = path.lstat()
            require(stat.S_ISREG(m.st_mode) and m.st_uid == uid
                    and stat.S_IMODE(m.st_mode) == 0o500 and m.st_nlink == 1
                    and 0 < m.st_size <= 16 * 1024 * 1024,
                    "admitted rootless tool custody differs")
            with path.open("rb") as stream:
                data = stream.read(m.st_size + 1)
            after = path.lstat()
            require(len(data) == m.st_size
                    and (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_size) ==
                    (m.st_dev, m.st_ino, m.st_uid, m.st_mode, m.st_size),
                    "admitted rootless tool changed")
            digest = hashlib.sha256(data).hexdigest()
            require(digest == admitted["./usr/bin/" + member],
                    "admitted rootless tool bytes differ")
            tools[member] = str(path)
    return {"uid": uid, "tools": tools,
            "subordinate_ranges_present": True,
            "userns_max": report["userns_max"]}


def authenticated_image(inventory):
    raw = inventory.read_bytes()
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == INVENTORY_SHA,
            "authenticated inventory bytes differ")
    obj = json.loads(raw)
    require(obj["schema"] == "elevenid.installer-inventory/v1"
            and obj["release_tag"] == TAG and obj["source_sha"] == SOURCE
            and obj["build_run_id"] == 40597188642 and obj["build_run_attempt"] == 1
            and obj["platform"] == "linux/amd64"
            and obj["images"]["openbao_didcomm_image"] == IMAGE,
            "authenticated image identity differs")


def require_exact_image_volumes(image):
    volumes = image["Config"]["Volumes"]
    require(IMAGE in image["RepoDigests"] and type(volumes) is dict
            and set(volumes) == {"/openbao/file", "/openbao/logs"}
            and all(value in ({}, None) for value in volumes.values()),
            "pulled image digest or declared volumes differ")


def container(docker_call, context, entry, command, image_id):
    name = entry["name"]
    cidfile = context / (name + ".cid")
    args = ["create", "--cidfile", str(cidfile),
            "--name", name, "--label", "com.elevenid.fixture.owner=" + context.name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
            "--security-opt", "no-new-privileges:true", "--user", "0:0",
            "--mount", f"type=bind,src={context / 'output'},dst=/out",
            "--mount", f"type=bind,src={context / 'state'},dst=/bao/data",
            "--mount", f"type=bind,src={context / 'volume_file'},dst=/openbao/file",
            "--mount", f"type=bind,src={context / 'volume_logs'},dst=/openbao/logs",
            "--entrypoint", "/bin/sh", IMAGE, "-ec", command]
    cid = docker_call(args, timeout=60)
    require(re.fullmatch(r"[0-9a-f]{64}", cid) is not None
            and cidfile.read_text().strip() == cid, "container ID uncertain")
    entry["id"] = cid
    write_record(context / (name + ".record.json"), {"id": cid, "name": name})
    inspect = json.loads(docker_call(["inspect", cid]))[0]
    require(inspect["Id"] == cid and inspect["Name"] == "/" + name
            and inspect["Config"]["Labels"]["com.elevenid.fixture.owner"] == context.name
            and inspect["Config"]["Image"] == IMAGE and inspect["Image"] == image_id
            and inspect["HostConfig"]["NetworkMode"] == "none"
            and inspect["HostConfig"]["ReadonlyRootfs"] is True
            and inspect["HostConfig"]["UsernsMode"] in ("", None)
            and inspect["HostConfig"]["Privileged"] is False
            and inspect["HostConfig"]["PidMode"] in ("", None)
            and inspect["HostConfig"]["Devices"] in ([], None)
            and set(inspect["HostConfig"]["CapDrop"]) == {"ALL"}
            and set(inspect["HostConfig"]["CapAdd"]) == {"CHOWN", "DAC_OVERRIDE"}
            and set(inspect["HostConfig"]["SecurityOpt"]) == {"no-new-privileges:true"}
            and inspect["Config"]["User"] == "0:0"
            and len(inspect["Mounts"]) == 4,
            "container ownership/sandbox differs")
    require(all(m["Type"] == "bind" and m["RW"] is True for m in inspect["Mounts"]),
            "container mount type/access differs")
    sources = {m["Destination"]: m["Source"] for m in inspect["Mounts"]}
    require(sources == {"/out": str(context / "output"), "/bao/data": str(context / "state"),
                        "/openbao/file": str(context / "volume_file"),
                        "/openbao/logs": str(context / "volume_logs")},
            "container mount sources differ")
    return cid


def observe_mapping(path, uid):
    first = inspect_owner(path, uid, 0o444)
    raw = path.read_bytes()
    after = inspect_owner(path, uid, 0o444)
    require((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "UID mapping file changed")
    require(len(raw) <= 4096, "UID mapping output exceeds bound")
    uid_map = raw.decode("ascii", "strict")
    require(mapped(uid_map, 0) == uid and mapped(uid_map, 100) not in (uid, 0),
            "container UID mapping differs")
    return {"uid_map": uid_map.strip(), "uid0_host": mapped(uid_map, 0),
            "uid100_host": mapped(uid_map, 100)}


def inspect_owner(path, uid, mode):
    m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and m.st_uid == uid and stat.S_IMODE(m.st_mode) == mode
            and m.st_nlink == 1 and 0 < m.st_size <= 4096,
            "host output custody differs")
    return m


def closed_names(path, limit):
    names = []
    with os.scandir(path) as listing:
        for entry in listing:
            names.append(entry.name)
            require(len(names) <= limit, "fixture directory exceeds bound")
    require(len(names) == len(set(names)), "fixture directory names repeat")
    return set(names)


def daemon_log_evidence(raw):
    # Raw daemon output remains in the private, unuploaded context. A digest
    # permits exact later comparison without publishing unknown log contents.
    require(len(raw) <= 4 * 1024 * 1024, "daemon log evidence exceeds bound")
    observed = raw.lower()
    patterns = ((b"newuidmap: write to uid_map failed", "newuidmap_write_failed"),
                (b"newgidmap: write to gid_map failed", "newgidmap_write_failed"),
                (b"slirp4netns: not found", "slirp4netns_not_found"),
                (b"rootlesskit: not found", "rootlesskit_not_found"),
                (b"operation not permitted", "operation_not_permitted_observed"),
                (b"permission denied", "permission_denied_observed"),
                (b"address already in use", "address_in_use_observed"))
    return {"captured_log_bytes": len(raw),
            "captured_log_sha256": hashlib.sha256(raw).hexdigest(),
            "observed_log_codes": [code for marker, code in patterns if marker in observed]}


def fixture(inventory, tool_dir):
    prerequisites = preflight(tool_dir=tool_dir)
    authenticated_image(inventory)
    base = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(base.is_dir() and not base.is_symlink(), "runner temp unavailable")
    context = Path(tempfile.mkdtemp(prefix="marty-rootless-custody-", dir=base))
    os.chmod(context, 0o700)
    for name in ("runtime", "data", "exec", "home", "config", "output", "state",
                 "volume_file", "volume_logs"):
        (context / name).mkdir(mode=0o700)
    foreign_child = context / "state" / "canary-root"
    foreign_child.mkdir(mode=0o700)
    parent_before = (context / "state").lstat()
    child_before = foreign_child.lstat()
    require(closed_names(context / "state", 1) == {"canary-root"}
            and closed_names(foreign_child, 1) == set(),
            "initial fixed state tree differs")
    docker = prerequisites["tools"]["docker"]
    host = "unix://" + str(context / "runtime" / "docker.sock")
    env = {"PATH": str(Path(tool_dir).resolve(strict=True)) + ":/usr/bin:/bin",
           "HOME": str(context / "home"),
           "USER": pwd.getpwuid(os.geteuid()).pw_name,
           "XDG_RUNTIME_DIR": str(context / "runtime"),
           "XDG_CONFIG_HOME": str(context / "config"),
           "DOCKER_CONFIG": str(context / "config"), "DOCKER_HOST": host}
    name = "marty-uid-" + uuid.uuid4().hex
    write_record(context / "intent.json", {"schema": "marty.rootless-fixture/v1",
                 "uid": os.geteuid(), "host": host, "image": IMAGE,
                 "name_prefix": name, "context": str(context), "inventory_sha256": INVENTORY_SHA})
    daemon = None
    stamp = None
    owned = []
    success_summary = None
    held_socket = None
    daemon_output = bytearray()
    daemon_log_overflow = [False]
    log_reader = None
    startup_phase = "before_daemon"
    socket_observed = False
    socket_lstat_error = None
    leader_exited_before_socket = None
    try:
        daemon = subprocess.Popen([prerequisites["tools"]["dockerd-rootless.sh"],
                                  "--host", host, "--data-root", str(context / "data"),
                                  "--exec-root", str(context / "exec")],
                                  env=env, cwd="/", stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        def drain_daemon_log():
            while data := os.read(daemon.stdout.fileno(), 8192):
                room = 4 * 1024 * 1024 - len(daemon_output)
                daemon_output.extend(data[:room])
                if len(data) > room:
                    daemon_log_overflow[0] = True
        log_reader = threading.Thread(target=drain_daemon_log, daemon=True)
        log_reader.start()
        stamp = proc_stamp(daemon.pid)
        write_record(context / "daemon.json", {"pid": daemon.pid, "start_ticks": stamp,
                    "pgid": os.getpgid(daemon.pid), "uid": os.geteuid()})
        deadline = time.monotonic() + 45
        startup_phase = "await_socket"
        while time.monotonic() < deadline:
            if (context / "runtime" / "docker.sock").exists():
                socket_observed = True
                break
            time.sleep(0.2)
        leader_exited_before_socket = leader_exited(daemon.pid)
        socket_path = context / "runtime" / "docker.sock"
        try:
            sock = socket_path.lstat()
        except FileNotFoundError:
            socket_lstat_error = "ENOENT"
            raise
        startup_phase = "socket_bound"
        require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == os.geteuid(),
                "owned rootless socket unavailable")
        held_socket = os.open(socket_path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        held = os.fstat(held_socket)
        require((held.st_dev, held.st_ino, held.st_uid) ==
                (sock.st_dev, sock.st_ino, sock.st_uid) and stat.S_ISSOCK(held.st_mode),
                "held rootless socket differs")
        def docker_call(args, *, timeout=40):
            named = socket_path.lstat()
            current = os.fstat(held_socket)
            require((named.st_dev, named.st_ino, named.st_uid) ==
                    (current.st_dev, current.st_ino, current.st_uid) ==
                    (sock.st_dev, sock.st_ino, sock.st_uid), "rootless socket replaced")
            value = run([docker, "--host", host, *args], env, timeout=timeout)
            named = socket_path.lstat()
            current = os.fstat(held_socket)
            require((named.st_dev, named.st_ino, named.st_uid) ==
                    (current.st_dev, current.st_ino, current.st_uid) ==
                    (sock.st_dev, sock.st_ino, sock.st_uid), "rootless socket replaced")
            return value
        info = json.loads(docker_call(["info", "--format", "{{json .}}"] ))
        require("name=rootless" in info["SecurityOptions"]
                and not any("name=userns" in s for s in info["SecurityOptions"])
                and info["ID"], "positive rootless Engine policy unavailable")
        write_record(context / "engine.json", {"id": info["ID"],
                     "security_options": info["SecurityOptions"],
                     "socket_dev": sock.st_dev, "socket_ino": sock.st_ino})
        docker_call(["pull", IMAGE], timeout=240)
        image = json.loads(docker_call(["image", "inspect", IMAGE]))[0]
        require_exact_image_volumes(image)
        first_entry = {"name": name + "-foreign", "id": None}
        owned.append(first_entry)
        first = container(docker_call, context, first_entry,
                          "umask 077; cat /proc/self/uid_map > /out/uid_map; chmod 0444 /out/uid_map; "
                          "printf 'marty-rootless-owned-canary\\n' > /out/payload; "
                          "chmod 0444 /out/payload; printf 'marty-rootless-owned-canary\\n' > /bao/data/canary-root/canary; "
                          "chown 100:100 /bao/data/canary-root/canary /bao/data/canary-root", image["Id"])
        docker_call(["start", first])
        require(docker_call(["wait", first], timeout=35) == "0",
                "foreign-owner fixture failed")
        exited = json.loads(docker_call(["inspect", first]))[0]["State"]
        require(exited["Running"] is False and exited["ExitCode"] == 0,
                "foreign-owner lifecycle differs")
        mapping = observe_mapping(context / "output" / "uid_map", os.geteuid())
        output = context / "output" / "payload"
        inspect_owner(output, os.geteuid(), 0o444)
        require(output.read_bytes() == CANARY, "UID0 output bytes differ")
        state = (context / "state").lstat()
        child = foreign_child.lstat()
        require((state.st_dev, state.st_ino, state.st_uid, stat.S_IMODE(state.st_mode)) ==
                (parent_before.st_dev, parent_before.st_ino, os.geteuid(), 0o700)
                and (child.st_dev, child.st_ino) == (child_before.st_dev, child_before.st_ino)
                and child.st_uid == mapping["uid100_host"]
                and stat.S_IMODE(child.st_mode) == 0o700,
                "UID100 child or unchanged parent custody differs")
        require(closed_names(context / "state", 1) == {"canary-root"},
                "state parent acquired unknown entries")
        try:
            (foreign_child / "canary").read_bytes()
        except PermissionError:
            pass
        else:
            raise RuntimeError("ordinary host user unexpectedly read foreign 0700 state")
        second_entry = {"name": name + "-restore", "id": None}
        owned.append(second_entry)
        second = container(docker_call, context, second_entry,
                           "cat /proc/self/uid_map > /out/restore_uid_map; chmod 0444 /out/restore_uid_map; "
                           "cat /bao/data/canary-root/canary > /out/recovered; chmod 0444 /out/recovered; "
                           "chown 0:0 /bao/data/canary-root/canary /bao/data/canary-root", image["Id"])
        docker_call(["start", second])
        require(docker_call(["wait", second], timeout=35) == "0",
                "rootless restore fixture failed")
        exited = json.loads(docker_call(["inspect", second]))[0]["State"]
        require(exited["Running"] is False and exited["ExitCode"] == 0,
                "rootless restore lifecycle differs")
        restore_map = observe_mapping(context / "output" / "restore_uid_map", os.geteuid())
        require(restore_map["uid_map"] == mapping["uid_map"], "helper UID map changed")
        inspect_owner(context / "output" / "recovered", os.geteuid(), 0o444)
        require((context / "output" / "recovered").read_bytes() == CANARY,
                "rootless helper readback differs")
        state_after = (context / "state").lstat()
        child_after = foreign_child.lstat()
        require((state_after.st_dev, state_after.st_ino, state_after.st_uid,
                 stat.S_IMODE(state_after.st_mode)) ==
                (parent_before.st_dev, parent_before.st_ino, os.geteuid(), 0o700)
                and (child_after.st_dev, child_after.st_ino, child_after.st_uid,
                     stat.S_IMODE(child_after.st_mode)) ==
                (child_before.st_dev, child_before.st_ino, os.geteuid(), 0o700),
                "parent/child ownership not restored")
        require(closed_names(context / "state", 1) == {"canary-root"}
                and closed_names(foreign_child, 1) == {"canary"},
                "restored state tree differs")
        marker = inspect_owner(foreign_child / "canary", os.geteuid(), 0o600)
        require(marker.st_size == len(CANARY)
                and (foreign_child / "canary").read_bytes() == CANARY,
                "restored canary bytes differ")
        final_info = json.loads(docker_call(["info", "--format", "{{json .}}"] ))
        require(final_info["ID"] == info["ID"]
                and final_info["SecurityOptions"] == info["SecurityOptions"],
                "rootless Engine changed during fixture")
        success_summary = {"schema": "marty.rootless-fixture-result/v1",
                     "engine_id": info["ID"], "mapping": mapping,
                     "container_ids": [entry["id"] for entry in owned],
                     "daemon_pid": daemon.pid, "daemon_start_ticks": stamp,
                     "socket_dev": sock.st_dev, "socket_ino": sock.st_ino,
                     "uid0_output_owner": os.geteuid(),
                     "uid100_inaccessible_to_host": True,
                     "rootless_helper_readback": True,
                     "installer_executed": False, "daemon_setup_outside_installer": True,
                     "product_fixed_socket_qualified": False}
        write_record(context / "result.json", success_summary)
        print("ROOTLESS_HOST_CUSTODY_OBSERVED")
    finally:
        cleanup_errors = []
        for entry in reversed(owned):
            cid = entry["id"]
            if cid is None:
                cidfile = context / (entry["name"] + ".cid")
                if cidfile.exists():
                    candidate = cidfile.read_text().strip()
                    if re.fullmatch(r"[0-9a-f]{64}", candidate):
                        cid = candidate
                if cid is None:
                    cleanup_errors.append("container ID uncertain: " + entry["name"])
                    continue
            try:
                obj = json.loads(docker_call(["inspect", cid]))[0]
                require(obj["Id"] == cid and obj["Name"] == "/" + entry["name"]
                        and obj["Config"]["Labels"]["com.elevenid.fixture.owner"] == context.name,
                        "owned container changed; preserve fixture")
                docker_call(["rm", "-f", cid])
            except (RuntimeError, OSError, ValueError, KeyError, IndexError) as error:
                cleanup_errors.append("exact container cleanup refused: " + str(error))
        if daemon is not None:
            try:
                require(stamp is not None, "daemon PID was not stamped")
                stop_daemon(daemon, stamp, context / "runtime" / "docker.sock",
                            (sock.st_dev, sock.st_ino, sock.st_uid) if held_socket is not None else None,
                            context)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append("exact daemon cleanup refused: " + str(error))
        if log_reader is not None:
            log_reader.join(timeout=10)
            if log_reader.is_alive():
                cleanup_errors.append("daemon output pipe still active")
        fd = os.open(context / "daemon.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(daemon_output)
            stream.flush()
            os.fsync(stream.fileno())
        if daemon_log_overflow[0]:
            cleanup_errors.append("daemon log exceeded evidence bound")
        if held_socket is not None:
            os.close(held_socket)
        if startup_phase == "await_socket":
            write_record(base / "marty-rootless-startup-diagnostic.json", {
                "schema": "marty.rootless-startup-diagnostic/v1",
                "phase": startup_phase, "daemon_pid": daemon.pid if daemon else None,
                "daemon_start_ticks": stamp, "socket_observed": socket_observed,
                "socket_lstat_error": socket_lstat_error,
                "leader_exited_before_socket": leader_exited_before_socket,
                "cleanup_error_count": len(cleanup_errors),
                "daemon_log_overflow": daemon_log_overflow[0],
                **daemon_log_evidence(daemon_output),
                "daemon_launch_attempted": daemon is not None,
                "extracted_daemon_script_spawned": daemon is not None,
                "installer_executed": False})
        require(not cleanup_errors, "; ".join(cleanup_errors))
        if success_summary is not None:
            write_record(base / "marty-rootless-custody-result.json", success_summary)
        # Keep the exact private context, daemon log, and result for review. The
        # hosted runner retires this disposable workspace; no recursive delete.


def main():
    require((len(sys.argv) == 3 and sys.argv[1] == "--preflight")
            or (len(sys.argv) == 4 and sys.argv[1] == "--run"),
            "fixed arguments only")
    if sys.argv[1] == "--preflight":
        print(json.dumps(preflight(record=True), sort_keys=True))
    else:
        fixture(Path(sys.argv[2]), Path(sys.argv[3]))


if __name__ == "__main__":
    main()
