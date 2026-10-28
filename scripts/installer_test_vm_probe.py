"""One-shot installer-only observation of an authenticated published operator.

This does not install, dispatch a candidate, qualify a release, or grant reuse of
historical VM approval. A durable intent is written before any guest mutation;
an uncertain attempt is never retried or cleaned up automatically.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
from installer_candidate_vm_create import _read_record, _write
import installer_candidate_dispatch as dispatch
import installer_candidate_public_bootstrap as bootstrap
import installer_candidate_public_release as published
import installer_candidate_published_assets as acquisition
import installer_candidate_rendezvous as transport
from installer_candidate_vm_guest_readiness import SSH
import installer_candidate_qemu_observe as observer
from installer_host_probe import command
import installer_release as release
import installer_test_vm_restart as restart
import verify_installer_provenance as provenance

SCHEMA = "elevenid.installer-only-vm-probe/v1"
RESULT_SCHEMA = "elevenid.installer-only-vm-probe-result/v1"
WORKFLOW = ".github/workflows/nightly-release.yml"
SCP = Path("/usr/bin/scp")
OPERATOR = "marty-deploy-linux-amd64"
MAX_HELP = 32768
MAX_PROBE_OPERATOR_BYTES = 64 * 1024 * 1024

# Sent as a fixed SSH argument. The named guest file is never executed. The
# verified bytes are copied to an executable sealed memfd, then that FD is the
# sole exec target. No guest Python source file or ambient environment is used.
GUEST_SEALED_EXEC = r"""
import fcntl,hashlib,json,os,selectors,signal,stat,subprocess,sys,time
try:
    assert len(sys.argv)==7
    path,expected_sha,size_text,uid_text,flag,identity=sys.argv[1:]
    assert flag in ("--build-identity","--help")
    assert len(expected_sha)==64 and all(c in "0123456789abcdef" for c in expected_sha)
    size=int(size_text);uid=int(uid_text)
    assert 0<size<=67108864 and uid>0
    source=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
    before=os.fstat(source)
    assert stat.S_ISREG(before.st_mode) and before.st_uid==uid
    assert stat.S_IMODE(before.st_mode)==0o700 and before.st_nlink==1
    assert before.st_size==size
    readable=os.open("/proc/self/fd/%d"%source,os.O_RDONLY|os.O_CLOEXEC)
    def stamp(value):
        return (value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,
                value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    assert stamp(before)==stamp(os.fstat(readable))
    sealed=os.memfd_create("marty-installer-only-probe",
                           os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    os.fchmod(sealed,0o700)
    digest=hashlib.sha256();remaining=size
    while remaining:
        block=os.read(readable,min(65536,remaining))
        assert block
        digest.update(block)
        view=memoryview(block)
        while view:
            written=os.write(sealed,view)
            assert written>0
            view=view[written:]
        remaining-=len(block)
    assert os.read(readable,1)==b"" and digest.hexdigest()==expected_sha
    assert stamp(before)==stamp(os.fstat(readable))==stamp(os.stat(path,follow_symlinks=False))
    mask=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
    fcntl.fcntl(sealed,fcntl.F_ADD_SEALS,mask)
    assert fcntl.fcntl(sealed,fcntl.F_GET_SEALS)&mask==mask
    assert os.fstat(sealed).st_size==size
    os.close(readable);os.close(source)
    child=subprocess.Popen(["/proc/self/fd/%d"%sealed,flag],pass_fds=(sealed,),
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        cwd="/",env={"HOME":"/nonexistent","PATH":"/usr/bin:/bin","LANG":"C"},
        start_new_session=True,close_fds=True)
    limit=32768 if flag=="--help" else 256
    streams={child.stdout:bytearray(),child.stderr:bytearray()}
    deadline=time.monotonic()+20
    try:
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                os.set_blocking(stream.fileno(),False)
                selector.register(stream,selectors.EVENT_READ)
            while selector.get_map():
                assert time.monotonic()<deadline
                for key,_ in selector.select(0.1):
                    block=os.read(key.fileobj.fileno(),8192)
                    if not block:selector.unregister(key.fileobj)
                    else:
                        streams[key.fileobj].extend(block)
                        assert sum(map(len,streams.values()))<=limit
            while os.waitid(os.P_PID,child.pid,
                            os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                assert time.monotonic()<deadline
                time.sleep(0.01)
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait()
    assert child.returncode==0
    output=bytes(streams[child.stdout])
    if flag=="--build-identity":
        assert output==(identity+"\n").encode("ascii")
    else:
        assert output.startswith(b"usage: marty-deploy.py ") and output
    print(json.dumps({"flag":flag,"operator_sha256":expected_sha,
                      "operator_device":before.st_dev,"operator_inode":before.st_ino,
                      "output_sha256":hashlib.sha256(output).hexdigest(),
                      "output_bytes":len(output),"matched":True},
                     sort_keys=True,separators=(",",":")))
except Exception:
    print("installer-only probe refused",file=sys.stderr)
    sys.exit(1)
"""


def _uuid(value: str) -> None:
    release.require(type(value) is str and str(uuid.UUID(value)) == value
                    and uuid.UUID(value).version == 4, "VM probe UUID invalid")


def _canonical(path: Path, maximum: int) -> tuple[bytes, dict]:
    raw = bootstrap.private_file(path, maximum)
    record = release.decode(raw)
    release.require(release.encode(record) == raw, "VM probe record noncanonical")
    return raw, record


def _verified_assets(assets: Path, gh: Path, cosign: Path, client) -> dict:
    """Revalidate a completed independent immutable-release acquisition."""
    held = bootstrap.private_directory(assets)
    try:
        base = assets.parent
        intent_raw, intent = _canonical(base / (assets.name + ".intent.json"), 65536)
        release_raw, observed = _canonical(base / (assets.name + ".release.json"), 65536)
        verified_raw, verified = _canonical(base / (assets.name + ".verified.json"), 65536)
        release.exact(intent, {"schema", "scope", "source_sha", "release_tag",
                               "build_run_id", "build_run_attempt", "release_id",
                               "release_observation_sha256", "started_at",
                               "guest_acquisition", "acceptance"}, "acquisition intent")
        release.exact(verified, set(intent) | {"inventory_sha256", "verified_at",
                                                   "artifact_count"}, "acquisition result")
        release.require(intent["schema"] == verified["schema"] == acquisition.SCHEMA
                        and intent["scope"] == "controller-acquisition-only"
                        and intent["guest_acquisition"] is False
                        and intent["acceptance"] is False
                        and all(verified[k] == value for k, value in intent.items())
                        and verified["release_observation_sha256"] == release.digest(release_raw)
                        and verified["release_id"] == observed["release_id"]
                        and verified["artifact_count"] == len(published.expected_assets()),
                        "VM published acquisition differs")
        release.identity(intent["source_sha"], intent["release_tag"],
                         intent["build_run_id"], intent["build_run_attempt"])
        def api(path: str) -> dict:
            return client.request("GET", transport.REPO + "/" + path)
        release.require(published.observe(api, intent["release_tag"],
                                          intent["source_sha"]) == observed,
                        "VM published release changed")
        published.verify_downloads(observed, assets)
        expected = dict(source_sha=intent["source_sha"],
                        release_tag=intent["release_tag"],
                        build_run_id=intent["build_run_id"],
                        build_run_attempt=intent["build_run_attempt"])
        inventory = release.verify_inventory_assets(assets, **expected)
        inventory_raw = bootstrap.private_file(assets / "installer-inventory.json", 65536)
        release.require(release.digest(inventory_raw) == verified["inventory_sha256"],
                        "VM published inventory changed")
        for name, tool in (("gh", gh), ("cosign", cosign)):
            release.require(dispatch.private_file(tool, dispatch.TOOLS[name][1],
                                                  executable=True) == dispatch.TOOLS[name],
                            "VM verifier tool differs")
        for subject in ("installer-inventory.json", OPERATOR):
            provenance.verify_subject(
                assets / subject, assets / (subject + ".provenance.jsonl"),
                gh=gh, cosign=cosign,
                signature_bundle=assets / (subject + ".sigstore.json"),
                workflow=WORKFLOW, source_sha=intent["source_sha"],
                run_id=intent["build_run_id"],
                run_attempt=intent["build_run_attempt"])
        binary = assets / OPERATOR
        entry = next(item for item in inventory["artifacts"] if item["name"] == OPERATOR)
        digest, size = dispatch.private_file(binary, release.ARTIFACT_MAX_BYTES[OPERATOR])
        release.require((digest, size) == (entry["sha256"], entry["size"]),
                        "VM operator digest differs")
        release.require(0 < size <= MAX_PROBE_OPERATOR_BYTES,
                        "VM probe operator exceeds bounded profile")
        bootstrap.same_directory(held, assets)
        release.require(_canonical(base / (assets.name + ".intent.json"), 65536)[0]
                        == intent_raw
                        and _canonical(base / (assets.name + ".release.json"), 65536)[0]
                        == release_raw
                        and _canonical(base / (assets.name + ".verified.json"), 65536)[0]
                        == verified_raw,
                        "VM published acquisition changed")
        return {"binary": binary, "binary_sha256": digest, "binary_bytes": size,
                "source_sha": intent["source_sha"], "release_tag": intent["release_tag"],
                "build_run_id": intent["build_run_id"],
                "build_run_attempt": intent["build_run_attempt"],
                "inventory_sha256": release.digest(inventory_raw),
                "acquisition_sha256": release.digest(verified_raw)}
    finally:
        os.close(held)


def _bound_vm(source: Path, registry: Path, runtime_parent: Path,
              vm_id: str, lease: ControllerLease) -> dict:
    raw, historical = restart._record_set(lease.parent, vm_id)
    intent_raw, intent = _read_record(lease.parent, vm_id + ".restart-intent.json")
    pid_raw, pid = _read_record(lease.parent, vm_id + ".restart-pid.json")
    receipt_raw, receipt = _read_record(lease.parent, vm_id + ".restart-receipt.json")
    ready_raw, ready = _read_record(lease.parent, vm_id + ".restart-readiness.json")
    release.require(all(release.encode(record) == value for record, value in
                        ((intent, intent_raw), (pid, pid_raw),
                         (receipt, receipt_raw), (ready, ready_raw))),
                    "VM probe evidence noncanonical")
    release.exact(intent, {
        "schema", "phase", "vm_id", "attempt_nonce", "controller_boot_id",
        "historical_sha256", "poweroff_intent_sha256", "poweroff_result_sha256",
        "historical_guest_readiness_sha256", "historical_docker_engine_id",
        "historical_guest_uid", "runtime_dir_device", "runtime_dir_inode",
        "control_dir_device", "control_dir_inode", "disk_device", "disk_inode",
        "mutable_disk_bytes", "mutable_disk_sha256", "mutable_disk_mtime_ns",
        "mutable_disk_ctime_ns", "runtime_uid", "runtime_gid", "ssh_port", "args",
        "qemu_sha256", "guest_memory_mib", "controller_reserve_mib", "purpose",
        "host_mem_available_kib_at_preflight", "qualified", "dispatch_authorized",
        "application_deployment_authorized", "started_at"}, "VM probe restart intent")
    release.exact(pid, {"schema", "phase", "vm_id", "attempt_nonce",
                        "intent_sha256", "controller_boot_id", "pid",
                        "start_ticks", "spawned_at"}, "VM probe restart PID")
    release.exact(receipt, set(intent) | {"intent_sha256", "pid", "start_ticks",
                                               "disk_fd", "observed_at"},
                  "VM probe restart receipt")
    release.exact(ready, {"schema", "phase", "vm_id", "attempt_nonce",
                          "controller_boot_id", "restart_receipt_sha256", "pid",
                          "start_ticks", "disk_device", "disk_inode", "guest",
                          "observed_at", "guest_memory_mib", "controller_reserve_mib",
                          "purpose", "qualified", "dispatch_authorized",
                          "application_deployment_authorized"}, "VM probe readiness")
    release.require(intent["schema"] == receipt["schema"] == restart.SCHEMA
                    and pid["schema"] == restart.PID_SCHEMA
                    and ready["schema"] == restart.READINESS_SCHEMA
                    and (intent["phase"], pid["phase"], receipt["phase"], ready["phase"])
                    == ("intent", "spawned", "launched", "guest-ready")
                    and intent["vm_id"] == pid["vm_id"] == receipt["vm_id"]
                    == ready["vm_id"] == vm_id
                    and intent["attempt_nonce"] == pid["attempt_nonce"]
                    == receipt["attempt_nonce"] == ready["attempt_nonce"]
                    and intent["historical_sha256"] == {name: release.digest(value)
                                                       for name, value in raw.items()}
                    and release.digest(_read_record(lease.parent, vm_id
                        + ".scope-retirement-poweroff-intent.json")[0])
                    == intent["poweroff_intent_sha256"]
                    and release.digest(_read_record(lease.parent, vm_id
                        + ".scope-retirement-poweroff-result.json")[0])
                    == intent["poweroff_result_sha256"]
                    and release.digest(_read_record(lease.parent, vm_id
                        + ".guest-readiness.json")[0])
                    == intent["historical_guest_readiness_sha256"]
                    and pid["intent_sha256"] == receipt["intent_sha256"]
                    == release.digest(intent_raw)
                    and ready["restart_receipt_sha256"] == release.digest(receipt_raw)
                    and receipt["pid"] == pid["pid"] == ready["pid"]
                    and receipt["start_ticks"] == pid["start_ticks"]
                    == ready["start_ticks"]
                    and all(receipt[k] == v for k, v in intent.items() if k != "phase")
                    and all(item["qualified"] is False
                            and item["dispatch_authorized"] is False
                            and item["application_deployment_authorized"] is False
                            for item in (intent, receipt, ready))
                    and intent["purpose"] == ready["purpose"]
                    == restart.INSTALLER_ONLY_PURPOSE
                    and intent["guest_memory_mib"] == ready["guest_memory_mib"]
                    and intent["controller_reserve_mib"] == ready["controller_reserve_mib"]
                    and intent["controller_boot_id"] == pid["controller_boot_id"]
                    == ready["controller_boot_id"] == restart.launcher._boot_id()
                    and ready["disk_device"] == intent["disk_device"]
                    and ready["disk_inode"] == intent["disk_inode"],
                    "VM probe restart evidence differs")
    runtime = historical["runtime_receipt"]
    seed = historical["seed_receipt"]
    launch = historical["launch_intent"]
    runtime_dir = runtime_parent / vm_id
    control_dir = registry / (vm_id + ".control")
    release.require(str(runtime_dir) == launch["runtime_dir"]
                    and intent["args"] == restart._restart_args(
                        runtime_dir, vm_id, seed["ssh_port"], launch["args"],
                        intent["guest_memory_mib"])
                    and intent["qemu_sha256"] == restart.launcher._trusted_tool(
                        restart.launcher.QEMU)
                    and intent["runtime_uid"] == runtime["runtime_uid"]
                    and intent["runtime_gid"] == runtime["runtime_gid"]
                    and intent["disk_device"] == runtime["disk_device"]
                    and intent["disk_inode"] == runtime["disk_inode"]
                    and intent["ssh_port"] == seed["ssh_port"],
                    "VM probe runtime binding differs")
    restart._same_path(registry, lease.parent, _directory)
    control_fd = _directory(control_dir)
    try:
        release.require((os.fstat(control_fd).st_dev, os.fstat(control_fd).st_ino)
                        == (intent["control_dir_device"], intent["control_dir_inode"]),
                        "VM probe control directory differs")
        restart._source_and_control(source, registry, historical, control_fd)
    finally:
        os.close(control_fd)
    runtime_fd = observer.open_vm_dir(runtime_dir, runtime["runtime_uid"])
    try:
        release.require((os.fstat(runtime_fd).st_dev, os.fstat(runtime_fd).st_ino)
                        == (intent["runtime_dir_device"], intent["runtime_dir_inode"]),
                        "VM probe runtime directory differs")
        restart.launcher._seed_media(runtime_fd, seed, runtime["runtime_gid"])
    finally:
        os.close(runtime_fd)
    current = restart.launcher._live(
        pid["pid"], intent["args"], runtime["runtime_uid"], runtime["runtime_gid"],
        launch["kvm_gid"], runtime_dir / "disk.qcow2",
        intent["disk_device"], intent["disk_inode"], intent["qemu_sha256"])
    release.require(current == {"pid": pid["pid"], "start_ticks": pid["start_ticks"],
                                "disk_fd": receipt["disk_fd"]},
                    "VM probe live process differs")
    guest = restart._retained_guest(control_dir, port=seed["ssh_port"], seed=seed,
                                    guest_memory_mib=intent["guest_memory_mib"])
    release.require(guest == ready["guest"]
                    and guest["docker_engine_id"] == intent["historical_docker_engine_id"]
                    and guest["guest_uid"] == intent["historical_guest_uid"],
                    "VM probe current guest differs")
    binding = {"readiness_sha256": release.digest(ready_raw), "pid": pid["pid"],
            "start_ticks": pid["start_ticks"], "boot_id": intent["controller_boot_id"],
            "disk_device": intent["disk_device"], "disk_inode": intent["disk_inode"],
            "engine_id": guest["docker_engine_id"], "guest_uid": guest["guest_uid"],
            "port": seed["ssh_port"], "key_sha256": seed["controller_private_sha256"],
            "known_hosts_sha256": seed["known_hosts_sha256"], "control_dir": control_dir}
    binding["home_stamp"] = _guest_home_stamp(binding)
    return binding


def _pinned(binding: dict) -> list[str]:
    key = binding["control_dir"] / "controller_ed25519"
    hosts = binding["control_dir"] / "known_hosts"
    release.require(release.digest(restart._bytes(key, 8192)) == binding["key_sha256"]
                    and release.digest(restart._bytes(hosts, 4096))
                    == binding["known_hosts_sha256"], "VM probe SSH identity changed")
    for tool in (SSH, SCP):
        info = tool.lstat()
        release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and not info.st_mode & 0o022,
                        "VM probe SSH executable untrusted")
    return ["-F", "/dev/null", "-i", str(key), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(hosts),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1"]


def _ssh(binding: dict, script: str, *, limit: int = 1024, timeout: int = 20) -> bytes:
    opts = _pinned(binding)
    output = command([str(SSH), *opts, "-p", str(binding["port"]),
                      "installer@127.0.0.1", script],
                     timeout=timeout, limit=limit, env=restart.launcher.ENV)
    _pinned(binding)
    return output


def _guest_dir(probe_id: str) -> str:
    _uuid(probe_id)
    return "/home/installer/.marty-installer-only-probe-" + probe_id


def _guest_stamp(binding: dict, directory: str) -> tuple[int, int, int, int, str, int]:
    raw = _ssh(binding, "/usr/bin/stat -c '%d:%i:%u:%a:%F:%h' -- " + directory)
    parts = raw.decode("ascii").strip().split(":")
    release.require(len(parts) == 6 and all(item.isdecimal() for item in
                                             (parts[0], parts[1], parts[2], parts[3], parts[5]))
                    and parts[4] == "directory", "VM probe guest directory differs")
    stamp = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]),
             parts[4], int(parts[5]))
    release.require(stamp[2] == binding["guest_uid"] and stamp[3] == 700
                    and stamp[5] == 2, "VM probe guest directory custody differs")
    return stamp


def _guest_home_stamp(binding: dict) -> tuple[int, int, int, int, str, int]:
    raw = _ssh(binding, "/usr/bin/stat -c '%d:%i:%u:%a:%F:%h' -- /home/installer")
    parts = raw.decode("ascii").strip().split(":")
    release.require(len(parts) == 6 and all(item.isdecimal() for item in
                    (parts[0], parts[1], parts[2], parts[3], parts[5]))
                    and parts[4] == "directory", "VM probe guest home invalid")
    stamp = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]),
             parts[4], int(parts[5]))
    release.require(stamp[2] == binding["guest_uid"] and stamp[3] == 700
                    and stamp[5] >= 2, "VM probe guest home custody differs")
    return stamp


def _guest_operator(binding: dict, target: str, expected: dict) -> tuple[int, int, int, int, int, int]:
    """Classify O_PATH, reopen that inode, hash it, and rebind the named path."""
    code = (
        "import hashlib,os,stat,sys;"
        "p=sys.argv[1];size=int(sys.argv[2]);"
        "f=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);"
        "a=os.fstat(f);"
        "assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and "
        "a.st_size==size and 0<size<=67108864;"
        "r=os.open(\"/proc/self/fd/%d\"%f,os.O_RDONLY|os.O_CLOEXEC);"
        "b=os.fstat(r);"
        "assert (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size,"
        "a.st_mtime_ns,a.st_ctime_ns)"
        "==(b.st_dev,b.st_ino,b.st_uid,b.st_gid,b.st_mode,b.st_nlink,b.st_size,"
        "b.st_mtime_ns,b.st_ctime_ns);"
        "left=size;h=hashlib.sha256()\n"
        "while left:\n"
        "    block=os.read(r,min(65536,left))\n"
        "    assert block\n"
        "    h.update(block);left-=len(block)\n"
        "assert os.read(r,1)==b\"\"\n"
        "c=os.fstat(r);n=os.stat(p,follow_symlinks=False);"
        "assert (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size,"
        "a.st_mtime_ns,a.st_ctime_ns)"
        "==(c.st_dev,c.st_ino,c.st_uid,c.st_gid,c.st_mode,c.st_nlink,c.st_size,"
        "c.st_mtime_ns,c.st_ctime_ns)"
        "==(n.st_dev,n.st_ino,n.st_uid,n.st_gid,n.st_mode,n.st_nlink,n.st_size,"
        "n.st_mtime_ns,n.st_ctime_ns);"
        "print(\"%d:%d:%d:%o:%d:%d:%s\"%(a.st_dev,a.st_ino,a.st_uid,"
        "stat.S_IMODE(a.st_mode),a.st_nlink,a.st_size,h.hexdigest()))"
    )
    raw = _ssh(binding, "/usr/bin/python3 -I -B -c '" + code + "' "
               + target + " " + str(expected["binary_bytes"]),
               limit=256, timeout=30)
    parts = raw.decode("ascii").strip().split(":")
    release.require(len(parts) == 7 and all(part.isdecimal() for part in parts[:6])
                    and re.fullmatch("[0-9a-f]{64}", parts[6]) is not None,
                    "VM probe operator observation invalid")
    stamp = tuple(int(part) for part in parts[:6])
    release.require(stamp[2] == binding["guest_uid"] and stamp[3] == 700
                    and stamp[4] == 1 and stamp[5] == expected["binary_bytes"]
                    and parts[6] == expected["binary_sha256"],
                    "VM probe guest operator differs")
    return stamp


def _execute_sealed(binding: dict, target: str, expected: dict,
                    stamp: tuple[int, int, int, int, int, int], flag: str) -> dict:
    release.require(flag in ("--build-identity", "--help"),
                    "VM probe command unsupported")
    identity = expected["source_sha"] + ":" + expected["release_tag"]
    release.identity(expected["source_sha"], expected["release_tag"],
                     expected["build_run_id"], expected["build_run_attempt"])
    args = [target, expected["binary_sha256"], str(expected["binary_bytes"]),
            str(binding["guest_uid"]), flag, identity]
    release.require(re.fullmatch(r"/home/installer/\.marty-installer-only-probe-"
                                 r"[0-9a-f-]{36}/marty-deploy", target) is not None,
                    "VM probe target invalid")
    script = ("/usr/bin/env -i HOME=/ PATH=/usr/bin:/bin LANG=C "
              "/usr/bin/python3 -E -I -B -c " + shlex.quote(GUEST_SEALED_EXEC)
              + " " + " ".join(shlex.quote(value) for value in args))
    raw = _ssh(binding, script, limit=1024, timeout=35)
    result = release.decode(raw)
    release.exact(result, {"flag", "operator_sha256", "operator_device",
                           "operator_inode", "output_sha256", "output_bytes",
                           "matched"}, "VM probe sealed execution")
    release.require(result["flag"] == flag
                    and result["operator_sha256"] == expected["binary_sha256"]
                    and result["operator_device"] == stamp[0]
                    and result["operator_inode"] == stamp[1]
                    and type(result["output_bytes"]) is int
                    and 0 < result["output_bytes"] <= (MAX_HELP if flag == "--help" else 256)
                    and re.fullmatch(r"[0-9a-f]{64}", result["output_sha256"]) is not None
                    and result["matched"] is True,
                    "VM probe sealed execution differs")
    return result


def _transport(binding: dict, binary: Path, expected: dict, probe_id: str) -> dict:
    directory = _guest_dir(probe_id)
    target = directory + "/marty-deploy"
    # The only variable in the remote shell commands is a canonical UUID.
    release.require(_guest_home_stamp(binding) == binding["home_stamp"],
                    "VM probe guest home changed")
    release.require(_ssh(binding, "umask 077; /usr/bin/mkdir -m 700 -- " + directory)
                    == b"", "VM probe guest directory creation differed")
    created = _guest_stamp(binding, directory)
    opts = _pinned(binding)
    command([str(SCP), *opts, "-P", str(binding["port"]), "--", str(binary),
             "installer@127.0.0.1:" + target],
            timeout=300, limit=4096, env=restart.launcher.ENV)
    _pinned(binding)
    release.require(_guest_home_stamp(binding) == binding["home_stamp"],
                    "VM probe guest home changed")
    release.require(_guest_stamp(binding, directory) == created,
                    "VM probe guest directory changed")
    release.require(_ssh(binding, "/usr/bin/chmod 700 -- " + target) == b"",
                    "VM probe operator mode change differed")
    operator = _guest_operator(binding, target, expected)
    release.require(_guest_stamp(binding, directory) == created,
                    "VM probe guest directory changed")
    return {"directory_stamp": created, "operator_stamp": operator, "target": target}


def probe(*, source: Path, registry: Path, runtime_parent: Path, vm_id: str,
          probe_id: str, assets: Path, gh: Path, cosign: Path, client) -> dict:
    release.require(os.geteuid() == 0, "root VM controller required")
    release.require(all(path.is_absolute() for path in
                        (source, registry, runtime_parent, assets, gh, cosign)),
                    "VM probe path must be absolute")
    _uuid(vm_id)
    _uuid(probe_id)
    with ControllerLease(registry) as lease:
        expected = _verified_assets(assets, gh, cosign, client)
        binding = _bound_vm(source, registry, runtime_parent, vm_id, lease)
        intent_name = vm_id + ".installer-only-probe-intent.json"
        result_name = vm_id + ".installer-only-probe-result.json"
        for name in (intent_name, result_name):
            try:
                os.stat(name, dir_fd=lease.parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("VM installer-only probe already attempted")
        release.require(dispatch.private_file(expected["binary"],
                        release.ARTIFACT_MAX_BYTES[OPERATOR])
                        == (expected["binary_sha256"], expected["binary_bytes"]),
                        "VM probe operator changed")
        intent = {"schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
                  "probe_id": probe_id, "restart_readiness_sha256": binding["readiness_sha256"],
                  "restart_pid": binding["pid"], "restart_start_ticks": binding["start_ticks"],
                  "controller_boot_id": binding["boot_id"],
                  "disk_device": binding["disk_device"], "disk_inode": binding["disk_inode"],
                  "engine_id": binding["engine_id"], "guest_uid": binding["guest_uid"],
                  "operator_sha256": expected["binary_sha256"],
                  "operator_bytes": expected["binary_bytes"],
                  "source_sha": expected["source_sha"],
                  "release_tag": expected["release_tag"],
                  "build_run_id": expected["build_run_id"],
                  "build_run_attempt": expected["build_run_attempt"],
                  "inventory_sha256": expected["inventory_sha256"],
                  "acquisition_sha256": expected["acquisition_sha256"],
                  "guest_directory": _guest_dir(probe_id),
                  "allowlist": ["--build-identity", "--help"],
                  "qualified": False, "dispatch_authorized": False,
                  "application_deployment_authorized": False,
                  "started_at": int(time.time())}
        intent_raw = _write(lease.parent, intent_name, intent)
        release.require(_read_record(lease.parent, intent_name)[0] == intent_raw,
                        "VM probe intent changed")
        transferred = _transport(binding, expected["binary"], expected, probe_id)
        release.require(_bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == binding, "VM probe live identity changed after transfer")
        release.require(dispatch.private_file(expected["binary"],
                        release.ARTIFACT_MAX_BYTES[OPERATOR])
                        == (expected["binary_sha256"], expected["binary_bytes"]),
                        "VM probe source operator changed after transfer")
        target = transferred["target"]
        release.require(_guest_operator(binding, target, expected)
                        == transferred["operator_stamp"],
                        "VM probe guest operator changed before build identity")
        release.require(_guest_home_stamp(binding) == binding["home_stamp"],
                        "VM probe guest home changed")
        identity = _execute_sealed(binding, target, expected,
                                   transferred["operator_stamp"], "--build-identity")
        release.require(_guest_operator(binding, target, expected)
                        == transferred["operator_stamp"],
                        "VM probe guest operator changed before help")
        release.require(_guest_home_stamp(binding) == binding["home_stamp"],
                        "VM probe guest home changed")
        help_result = _execute_sealed(binding, target, expected,
                                      transferred["operator_stamp"], "--help")
        release.require(_guest_stamp(binding, intent["guest_directory"])
                        == transferred["directory_stamp"]
                        and _guest_home_stamp(binding) == binding["home_stamp"]
                        and _guest_operator(binding, target, expected)
                        == transferred["operator_stamp"]
                        and _bound_vm(source, registry, runtime_parent, vm_id, lease)
                        == binding
                        and _read_record(lease.parent, intent_name)[0] == intent_raw,
                        "VM probe observations changed")
        result = {"schema": RESULT_SCHEMA, "phase": "observed", "vm_id": vm_id,
                  "probe_id": probe_id, "intent_sha256": release.digest(intent_raw),
                  "operator_sha256": expected["binary_sha256"],
                  "build_identity_matched": identity["matched"],
                  "help_sha256": help_result["output_sha256"],
                  "help_bytes": help_result["output_bytes"], "guest_directory_device":
                  transferred["directory_stamp"][0], "guest_directory_inode":
                  transferred["directory_stamp"][1],
                  "guest_operator_inode": transferred["operator_stamp"][1],
                  "qualified": False, "dispatch_authorized": False,
                  "application_deployment_authorized": False,
                  "observed_at": int(time.time())}
        _write(lease.parent, result_name, result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "runtime-parent", "assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("vm-id", "probe-id"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    try:
        result = probe(**{key.replace("-", "_"): value for key, value in args.items()},
                       client=transport.Client(os.environ.get("GH_TOKEN")))
        print(json.dumps({"phase": result["phase"], "vm_id": result["vm_id"],
                          "probe_id": result["probe_id"], "qualified": False,
                          "dispatch_authorized": False,
                          "application_deployment_authorized": False}, sort_keys=True))
        return 0
    except Exception:
        print("VM installer-only probe refused; retain intent and guest data", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
