#!/usr/bin/env python3
"""Disposable rootless UID-mapping observation; never an installer or release test.

The controller may invoke already-installed RootlessKit/newuidmap while starting
its own daemon. Docker clients run with no_new_privs. No rootful socket, sudo,
package installation, existing Docker context, or pre-existing state is used.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
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
PR_SET_NO_NEW_PRIVS = 38


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


def no_new_privs():
    require(ctypes.CDLL(None).prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
            "cannot set no_new_privs")


def run(argv, env, *, timeout=40, nnp=True):
    require(type(argv) is list and all(type(a) is str for a in argv), "invalid command")
    proc = subprocess.Popen(argv, env=env, cwd="/", stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True, preexec_fn=no_new_privs if nnp else None)
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
                require(len(buffer) + len(data) <= 65536, "bounded command output exceeded")
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
    return out.decode("utf-8", "strict").strip()


def proc_stamp(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return int(raw.rsplit(") ", 1)[1].split()[19])


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


def preflight(*, record=False):
    uid = os.geteuid()
    require(uid != 0 and os.getuid() == uid, "ordinary nonroot runner required")
    names = ("docker", "dockerd-rootless.sh", "rootlesskit", "newuidmap", "newgidmap")
    missing = [name for name in names if not shutil.which(name)]
    user = pwd.getpwuid(uid).pw_name
    ranges = {}
    for file in ("/etc/subuid", "/etc/subgid"):
        lines = Path(file).read_text().splitlines() if Path(file).exists() else []
        ranges[file] = [line for line in lines if line.split(":", 1)[0] in (user, str(uid))]
    allowed = all(any(len(parts := line.split(":")) == 3 and parts[2].isdecimal()
                      and int(parts[2]) >= 65536 for line in ranges[file]) for file in ranges)
    report = {"schema": "marty.rootless-fixture-preflight/v1", "uid": uid,
              "tool_presence": {n: n not in missing for n in names},
              "subordinate_ranges_present": allowed,
              "userns_max": Path("/proc/sys/user/max_user_namespaces").read_text().strip(),
              "daemon_started": False, "installer_executed": False}
    if record:
        write_record(Path(os.environ["RUNNER_TEMP"]) / "marty-rootless-preflight.json", report)
    require(not missing, "missing preinstalled rootless tools: " + ",".join(missing))
    require(allowed, "no preconfigured >=65536 subordinate UID/GID range")
    return {"uid": uid, "tools": {n: shutil.which(n) for n in names},
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
            and len(inspect["Mounts"]) == 2,
            "container ownership/sandbox differs")
    require(all(m["Type"] == "bind" and m["RW"] is True for m in inspect["Mounts"]),
            "container mount type/access differs")
    sources = {m["Destination"]: m["Source"] for m in inspect["Mounts"]}
    require(sources == {"/out": str(context / "output"), "/bao/data": str(context / "state")},
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


def fixture(inventory):
    prerequisites = preflight()
    authenticated_image(inventory)
    base = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(base.is_dir() and not base.is_symlink(), "runner temp unavailable")
    context = Path(tempfile.mkdtemp(prefix="marty-rootless-custody-", dir=base))
    os.chmod(context, 0o700)
    for name in ("runtime", "data", "exec", "home", "config", "output", "state"):
        (context / name).mkdir(mode=0o700)
    docker = prerequisites["tools"]["docker"]
    host = "unix://" + str(context / "runtime" / "docker.sock")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(context / "home"),
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
        while time.monotonic() < deadline:
            if (context / "runtime" / "docker.sock").exists():
                break
            time.sleep(0.2)
        socket_path = context / "runtime" / "docker.sock"
        sock = socket_path.lstat()
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
        require(IMAGE in image["RepoDigests"] and image["Config"]["Volumes"] in ({}, None),
                "pulled image digest differs or declares unowned implicit volumes")
        first_entry = {"name": name + "-foreign", "id": None}
        owned.append(first_entry)
        first = container(docker_call, context, first_entry,
                          "umask 077; cat /proc/self/uid_map > /out/uid_map; chmod 0444 /out/uid_map; "
                          "printf 'marty-rootless-owned-canary\\n' > /out/payload; "
                          "chmod 0444 /out/payload; printf 'marty-rootless-owned-canary\\n' > /bao/data/canary; "
                          "chown 100:100 /bao/data/canary /bao/data", image["Id"])
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
        require(state.st_uid == mapping["uid100_host"] and stat.S_IMODE(state.st_mode) == 0o700,
                "UID100 bind ownership differs")
        try:
            (context / "state" / "canary").read_bytes()
        except PermissionError:
            pass
        else:
            raise RuntimeError("ordinary host user unexpectedly read foreign 0700 state")
        second_entry = {"name": name + "-restore", "id": None}
        owned.append(second_entry)
        second = container(docker_call, context, second_entry,
                           "cat /proc/self/uid_map > /out/restore_uid_map; chmod 0444 /out/restore_uid_map; "
                           "cat /bao/data/canary > /out/recovered; chmod 0444 /out/recovered; "
                           "chown 0:0 /bao/data/canary /bao/data", image["Id"])
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
        require((context / "state").lstat().st_uid == os.geteuid(),
                "state ownership not restored")
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
                require(stamp is not None and proc_stamp(daemon.pid) == stamp
                        and os.getpgid(daemon.pid) == daemon.pid,
                        "owned daemon changed; preserve fixture")
                os.killpg(daemon.pid, signal.SIGKILL)
                daemon.wait(timeout=10)
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
        require(not cleanup_errors, "; ".join(cleanup_errors))
        if success_summary is not None:
            write_record(base / "marty-rootless-custody-result.json", success_summary)
        # Keep the exact private context, daemon log, and result for review. The
        # hosted runner retires this disposable workspace; no recursive delete.


def main():
    require(len(sys.argv) == 3 and sys.argv[1] in ("--preflight", "--run"), "fixed arguments only")
    if sys.argv[1] == "--preflight":
        print(json.dumps(preflight(record=True), sort_keys=True))
    else:
        fixture(Path(sys.argv[2]))


if __name__ == "__main__":
    main()
