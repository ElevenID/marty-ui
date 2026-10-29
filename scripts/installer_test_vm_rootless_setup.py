#!/usr/bin/env python3
"""Read-only binding for a fresh disposable rootless-test guest.

The guest setup Engine is infrastructure. Nothing here authorizes product
dispatch, package installation, daemon setup, or release qualification.
"""
from __future__ import annotations

import os
from pathlib import Path
from contextlib import ExitStack
import json
import re
import shlex
import stat
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_launch_evidence as evidence
import installer_candidate_vm_runtime as runtime
import installer_test_vm_probe as probe
from installer_host_probe import command
import installer_candidate_vm_seed as seed
import installer_release as release
import installer_test_vm_rootless_fixture as fixture

CHAIN_NAMES = (
    "creation-intent", "creation-receipt", "runtime-intent", "runtime-receipt",
    "seed-intent", "seed-receipt", "launch-intent", "launch-pid",
    "launch-receipt",
)
SETUP_READINESS_SUFFIX = ".rootless-fixture-setup-readiness.json"
SETUP_READINESS_SCHEMA = "elevenid.installer-only-rootless-fixture-setup-readiness/v1"
INSTALLER_GUEST_SCRIPT = r'''
import errno, grp, json, os, pwd, socket, stat
uid=os.getuid(); gid=os.getgid(); groups=set(os.getgroups())|{gid}
assert uid>0 and os.geteuid()==uid and pwd.getpwuid(uid).pw_name=='installer'
docker_gid=grp.getgrnam('docker').gr_gid
sudo_gid=grp.getgrnam('sudo').gr_gid
sock='/var/run/docker.sock'; info=os.lstat(sock)
assert stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==docker_gid
assert not (info.st_mode & 0o007) and docker_gid not in groups and sudo_gid not in groups
client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); client.settimeout(2)
try:
 try: client.connect(sock)
 except OSError as exc: assert exc.errno in (errno.EACCES,errno.EPERM)
 else: raise AssertionError('setup Engine socket accessible')
finally: client.close()
status=open('/proc/self/status',encoding='ascii').read(16384)
fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
assert fields.get('NoNewPrivs')=='1'
assert all(fields.get(key)=='0000000000000000' for key in ('CapEff','CapPrm','CapAmb'))
print(json.dumps({'schema':'elevenid.fixture-installer-account/v1','uid':uid,'gid':gid,
 'docker_group':False,'sudo_group':False,'setup_socket_denied':True,
 'no_new_privs':True,'effective_caps_zero':True},sort_keys=True,separators=(',',':')))
'''
SETUP_ENGINE_COMMAND = ("/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin "
                        "/usr/bin/sudo -n /usr/bin/docker --host "
                        "unix:///var/run/docker.sock info --format '{{json .ID}}'")
SETUP_SERVICE_COMMAND = "/usr/bin/systemctl is-active docker.service"
SETUP_CLOUD_INIT_COMMAND = "/usr/bin/cloud-init status --format json"


def _ssh_as(binding: dict, user: str, script: str, *, limit: int = 1024,
            timeout: int = 20) -> bytes:
    release.require((user, script) in (("installer", _installer_command()),
                                       ("fixture-admin", SETUP_ENGINE_COMMAND),
                                       ("fixture-admin", SETUP_SERVICE_COMMAND),
                                       ("fixture-admin", SETUP_CLOUD_INIT_COMMAND)),
                    "fixture guest command unsupported")
    opts = probe._pinned(binding)
    raw = command([str(probe.SSH), *opts, "-p", str(binding["port"]),
                   user + "@127.0.0.1", script],
                  env=launch.ENV, timeout=timeout, limit=limit)
    probe._pinned(binding)
    return raw


def _installer_command() -> str:
    return ("/usr/bin/setpriv --no-new-privs -- /usr/bin/python3 -E -I -B -c "
            + shlex.quote(INSTALLER_GUEST_SCRIPT))


def _decode_installer(raw: bytes) -> dict:
    value = release.decode(raw)
    release.exact(value, {"schema", "uid", "gid", "docker_group", "sudo_group",
                          "setup_socket_denied", "no_new_privs",
                          "effective_caps_zero"}, "fixture ordinary account")
    release.require(release.encode(value) == raw
                    and value["schema"] == "elevenid.fixture-installer-account/v1"
                    and type(value["uid"]) is int and value["uid"] > 0
                    and type(value["gid"]) is int and value["gid"] > 0
                    and value["docker_group"] is False
                    and value["sudo_group"] is False
                    and value["setup_socket_denied"] is True
                    and value["no_new_privs"] is True
                    and value["effective_caps_zero"] is True,
                    "fixture ordinary guest account differs")
    return value


def observe_setup_readiness(*, source: Path, registry: Path, vm_parent: Path,
                            runtime_parent: Path, vm_id: str) -> dict:
    """Record only the separate guest setup Engine and ordinary-user denial.

    The rootful setup Engine is not selected for product installation. A later
    controller must stop it and bind a distinct rootless Engine before any
    candidate invocation. This observation never starts or stops a service.
    """
    before = bound_fixture(source=source, registry=registry, vm_parent=vm_parent,
                           runtime_parent=runtime_parent, vm_id=vm_id)
    ordinary = _decode_installer(_ssh_as(before, "installer",
                                        _installer_command(), limit=2048))
    cloud_raw = _ssh_as(before, "fixture-admin", SETUP_CLOUD_INIT_COMMAND,
                        limit=4096)
    cloud = release.decode(cloud_raw)
    release.require(type(cloud) is dict and cloud.get("status") == "done"
                    and cloud.get("extended_status") == "done"
                    and cloud.get("errors") in ([], {})
                    and cloud.get("recoverable_errors") in (None, [], {}),
                    "fixture cloud-init incomplete")
    release.require(_ssh_as(before, "fixture-admin", SETUP_SERVICE_COMMAND,
                            limit=64) == b"active\n",
                    "fixture setup Engine service inactive")
    raw_engine = _ssh_as(before, "fixture-admin", SETUP_ENGINE_COMMAND,
                         limit=256)
    engine = json.loads(raw_engine)
    release.require(type(engine) is str and str(uuid.UUID(engine)) == engine,
                    "fixture setup Engine identity invalid")
    after = bound_fixture(source=source, registry=registry, vm_parent=vm_parent,
                          runtime_parent=runtime_parent, vm_id=vm_id)
    release.require(after == before
                    and _decode_installer(_ssh_as(after, "installer",
                                                  _installer_command(),
                                                  limit=2048)) == ordinary
                    and _ssh_as(after, "fixture-admin", SETUP_ENGINE_COMMAND,
                                limit=256) == raw_engine,
                    "fixture setup observation changed")
    result = {"schema": SETUP_READINESS_SCHEMA,
              "phase": "setup_engine_observed", "vm_id": vm_id,
              "launch_sha256": before["launch_sha256"],
              "seed_sha256": before["seed_sha256"],
              "pid": before["pid"], "start_ticks": before["start_ticks"],
              "boot_id": before["boot_id"],
              "setup_engine_id": engine,
              "ordinary_uid": ordinary["uid"],
              "ordinary_gid": ordinary["gid"],
              "ordinary_no_sudo_or_docker_group": True,
              "setup_socket_denied_to_installer": True,
              "setup_engine_stopped": False,
              "rootless_engine_observed": False,
              "rootless_ready": False, "qualified": False,
              "product_dispatch_authorized": False,
              "observed_at": int(time.time())}
    with ControllerLease(registry) as lease:
        create._write(lease.parent, vm_id + SETUP_READINESS_SUFFIX, result)
    return result


def bound_setup_fixture(*, source: Path, registry: Path, vm_parent: Path,
                        runtime_parent: Path, vm_id: str) -> dict:
    """Reobserve a prepared guest's exact setup Engine for package admission.

    This intentionally returns the old admission controller's private binding
    shape, while retaining false product/rootless authority. It never selects
    the setup Engine for a product invocation.
    """
    before = bound_fixture(source=source, registry=registry, vm_parent=vm_parent,
                           runtime_parent=runtime_parent, vm_id=vm_id)
    with ControllerLease(registry) as lease:
        raw, recorded = create._read_record(lease.parent,
                                            vm_id + SETUP_READINESS_SUFFIX)
    release.exact(recorded, {"schema", "phase", "vm_id", "launch_sha256",
                             "seed_sha256", "pid", "start_ticks", "boot_id",
                             "setup_engine_id", "ordinary_uid", "ordinary_gid",
                             "ordinary_no_sudo_or_docker_group",
                             "setup_socket_denied_to_installer",
                             "setup_engine_stopped", "rootless_engine_observed",
                             "rootless_ready", "qualified",
                             "product_dispatch_authorized", "observed_at"},
                  "fixture setup readiness")
    release.require(recorded["schema"] == SETUP_READINESS_SCHEMA
                    and recorded["phase"] == "setup_engine_observed"
                    and recorded["vm_id"] == vm_id
                    and recorded["launch_sha256"] == before["launch_sha256"]
                    and recorded["seed_sha256"] == before["seed_sha256"]
                    and recorded["pid"] == before["pid"]
                    and recorded["start_ticks"] == before["start_ticks"]
                    and recorded["boot_id"] == before["boot_id"]
                    and all(recorded[key] is True for key in
                            ("ordinary_no_sudo_or_docker_group",
                             "setup_socket_denied_to_installer"))
                    and all(recorded[key] is False for key in
                            ("setup_engine_stopped", "rootless_engine_observed",
                             "rootless_ready", "qualified",
                             "product_dispatch_authorized")),
                    "fixture setup readiness evidence invalid")
    ordinary = _decode_installer(_ssh_as(before, "installer",
                                        _installer_command(), limit=2048))
    release.require((ordinary["uid"], ordinary["gid"])
                    == (recorded["ordinary_uid"], recorded["ordinary_gid"])
                    and _ssh_as(before, "fixture-admin", SETUP_SERVICE_COMMAND,
                                limit=64) == b"active\n"
                    and json.loads(_ssh_as(before, "fixture-admin",
                                           SETUP_ENGINE_COMMAND, limit=256))
                    == recorded["setup_engine_id"],
                    "fixture setup Engine changed")
    after = bound_fixture(source=source, registry=registry, vm_parent=vm_parent,
                          runtime_parent=runtime_parent, vm_id=vm_id)
    release.require(after == before, "fixture launch changed")
    with ControllerLease(registry) as lease:
        release.require(create._read_record(lease.parent,
                        vm_id + SETUP_READINESS_SUFFIX)[0] == raw,
                        "fixture setup evidence changed")
    return {**before, "engine_id": recorded["setup_engine_id"],
            "readiness_sha256": release.digest(raw),
            "guest_uid": ordinary["uid"], "rootless_ready": False,
            "product_dispatch_authorized": False}


def bound_fixture(*, source: Path, registry: Path, vm_parent: Path,
                  runtime_parent: Path, vm_id: str) -> dict:
    """Bind exact root-owned records, signed source, and live QEMU disk FD.

    A root-private admitted controller must call this before and after every
    guest observation. The returned private binding must not be serialized.
    """
    fixture._uuid4(vm_id)
    release.require(os.geteuid() == 0 and all(p.is_absolute() for p in
                    (source, registry, vm_parent, runtime_parent)),
                    "fixture observation request invalid")
    provenance = create.verify_source(source)
    with ControllerLease(registry) as lease:
        intent_raw, intent = create._read_record(lease.parent,
                                                vm_id + fixture.RECORD_SUFFIX)
        result_raw, result = create._read_record(lease.parent,
                                                vm_id + fixture.RESULT_SUFFIX)
        raw = {name.replace("-", "_"): create._read_record(
            lease.parent, vm_id + "." + name + ".json")
            for name in CHAIN_NAMES}
        chain = evidence.bind_provisioned_launch(
            **{name: item[0] for name, item in raw.items()},
            boot_id=launch._boot_id())
        created = raw["creation_receipt"][1]
        transferred = raw["runtime_receipt"][1]
        seeded = raw["seed_receipt"][1]
        launch_intent = raw["launch_intent"][1]
        launched = raw["launch_receipt"][1]
        release.require(intent["schema"] == result["schema"] == fixture.SCHEMA
                        and intent["phase"] == "intent"
                        and result["phase"] == "prepared"
                        and intent["vm_id"] == result["vm_id"] == vm_id
                        and result["intent_sha256"] == release.digest(intent_raw)
                        and result["creation_sha256"] == chain["creation_receipt_sha256"]
                        and result["transfer_sha256"] == chain["runtime_receipt_sha256"]
                        and result["seed_sha256"] == chain["seed_receipt_sha256"]
                        and created["image"] == provenance
                        and all(provenance[key] == intent["source_" + key] for key in
                                ("image_sha256", "manifest_sha256",
                                 "signature_sha256", "keyring_sha256"))
                        and intent["vm_parent"] == str(vm_parent)
                        and intent["runtime_parent"] == str(runtime_parent)
                        and created["vm_dir"] == str(vm_parent / vm_id)
                        and transferred["target_path"] == str(
                            runtime_parent / vm_id / "disk.qcow2")
                        and intent["virtual_gib"] == created["virtual_gib"]
                        == fixture.VIRTUAL_GIB
                        and intent["runtime_uid"] == result["runtime_uid"]
                        == transferred["runtime_uid"]
                        and intent["runtime_gid"] == result["runtime_gid"]
                        == transferred["runtime_gid"]
                        and intent["ssh_port"] == seeded["ssh_port"]
                        and intent["guest_profile"] == result["guest_profile"]
                        == seeded.get("fixture_profile")
                        == seed.ROOTLESS_FIXTURE_PROFILE
                        and seeded["packages"] == seed.ROOTLESS_FIXTURE_PACKAGES
                        and launch_intent["memory_mib"]
                        == launch.ROOTLESS_FIXTURE_MEMORY_MIB
                        and launch_intent["args"] == launch._arguments(
                            runtime_parent / vm_id, vm_id, seeded["ssh_port"],
                            launch.ROOTLESS_FIXTURE_MEMORY_MIB)
                        and all(value is False for value in
                                (intent["qualified"], intent["launch_authorized"],
                                 intent["product_dispatch_authorized"],
                                 result["qualified"], result["launch_authorized"],
                                 result["product_dispatch_authorized"],
                                 result["rootless_daemon_ready"],
                                 launched["qualified"],
                                 launched["dispatch_authorized"])),
                        "fixture source or historical chain differs")
        control_dir = registry / (vm_id + ".control")
        with ExitStack() as stack:
            vm_fd = _directory(vm_parent)
            stack.callback(os.close, vm_fd)
            runtime_parent_fd = runtime._runtime_parent(runtime_parent)
            stack.callback(os.close, runtime_parent_fd)
            runtime_fd = observer.open_vm_dir(runtime_parent / vm_id,
                                              transferred["runtime_uid"])
            stack.callback(os.close, runtime_fd)
            control_fd = _directory(control_dir)
            stack.callback(os.close, control_fd)
            release.require((os.fstat(vm_fd).st_dev, os.fstat(vm_fd).st_ino)
                            == (intent["vm_parent_device"],
                                intent["vm_parent_inode"])
                            and (os.fstat(runtime_parent_fd).st_dev,
                                 os.fstat(runtime_parent_fd).st_ino)
                            == (intent["runtime_parent_device"],
                                intent["runtime_parent_inode"])
                            and (os.fstat(runtime_fd).st_dev,
                                 os.fstat(runtime_fd).st_ino)
                            == (transferred["runtime_dir_device"],
                                transferred["runtime_dir_inode"])
                            and (os.fstat(control_fd).st_dev,
                                 os.fstat(control_fd).st_ino)
                            == (seeded["control_dir_device"],
                                seeded["control_dir_inode"]),
                            "fixture directory identity differs")
            launch._seed_media(runtime_fd, seeded, transferred["runtime_gid"])
            live = launch._live(
                launched["pid"], launch_intent["args"], transferred["runtime_uid"],
                transferred["runtime_gid"], launch_intent["kvm_gid"],
                runtime_parent / vm_id / "disk.qcow2", created["disk_device"],
                created["disk_inode"], launch_intent["qemu_sha256"])
            release.require(live == {"pid": launched["pid"],
                                     "start_ticks": launched["start_ticks"],
                                     "disk_fd": launched["disk_fd"]}
                            and launch_intent["qemu_sha256"] ==
                                launch._trusted_tool(launch.QEMU),
                            "fixture live process differs")
            for name, maximum, digest_key in (
                ("controller_ed25519", 8192, "controller_private_sha256"),
                ("guest_host_ed25519", 8192, "guest_host_private_sha256"),
                ("known_hosts", 4096, "known_hosts_sha256"),
                ("user-data", 65536, "user_data_sha256"),
                ("meta-data", 4096, "metadata_sha256"),
                ("seed.iso", 16 * 1024 * 1024, "seed_sha256"),
            ):
                info = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
                release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                                and info.st_nlink == 1
                                and stat.S_IMODE(info.st_mode) == 0o600
                                and release.digest(seed._bytes(control_dir / name,
                                                                maximum))
                                == seeded[digest_key],
                                "fixture control material differs")
            create._rebind_directory(vm_parent, vm_fd)
            runtime._same_path(runtime_parent, runtime_parent_fd,
                               runtime._runtime_parent)
            create._rebind_directory(control_dir, control_fd)
            create._rebind_directory(registry, lease.parent)
            release.require(all(create._read_record(
                            lease.parent, vm_id + "." + name.replace("_", "-")
                            + ".json")[0] == item[0]
                            for name, item in raw.items())
                            and create._read_record(lease.parent,
                                vm_id + fixture.RECORD_SUFFIX)[0] == intent_raw
                            and create._read_record(lease.parent,
                                vm_id + fixture.RESULT_SUFFIX)[0] == result_raw,
                            "fixture records changed during observation")
            release.require(create.verify_source(source) == provenance,
                            "fixture signed factory source changed")
            return {"vm_id": vm_id, "pid": launched["pid"],
                    "start_ticks": launched["start_ticks"],
                    "boot_id": launch_intent["controller_boot_id"],
                    "disk_device": created["disk_device"],
                    "disk_inode": created["disk_inode"],
                    "control_dir": control_dir, "port": seeded["ssh_port"],
                    "key_sha256": seeded["controller_private_sha256"],
                    "known_hosts_sha256": seeded["known_hosts_sha256"],
                    "seed_sha256": chain["seed_receipt_sha256"],
                    "launch_sha256": chain["launch_receipt_sha256"],
                    "guest_user": "installer", "setup_user": "fixture-admin",
                    "qualified": False, "product_dispatch_authorized": False}
