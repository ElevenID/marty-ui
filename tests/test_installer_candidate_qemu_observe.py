"""QMP peer binding for the diagnostic-only owned-VM observer."""
import json
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import uuid

import pytest

if sys.platform != "linux":
    pytest.skip("QMP peer credentials require Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_qemu_observe as observer


def test_qmp_refuses_wrong_peer_pid_and_socket_owner(tmp_path):
    path = tmp_path / "qmp.sock"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen(1)
        server.settimeout(5)

        def accept_once():
            with server.accept()[0]:
                pass

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            with pytest.raises(ValueError, match="monitor peer differs"):
                observer.qmp(path, tmp_path / "disk.qcow2", pid=os.getpid() + 1,
                             uid=os.getuid())
            with pytest.raises(ValueError, match="monitor socket differs"):
                observer.qmp(path, tmp_path / "disk.qcow2", pid=os.getpid(),
                             uid=os.getuid() + 1)
        finally:
            thread.join(timeout=5)
        assert not thread.is_alive()


def test_qmp_accepts_exact_peer_and_writable_disk(tmp_path):
    path = tmp_path / "qmp.sock"
    disk = tmp_path / "disk.qcow2"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen(1)
        server.settimeout(5)

        def respond():
            with server.accept()[0] as connection:
                with connection.makefile("rwb") as stream:
                    stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\n')
                    stream.flush()
                    for _ in range(3):
                        request = json.loads(stream.readline())
                        name = request["execute"]
                        result = ({"running": True, "status": "running"}
                                  if name == "query-status" else
                                  [{"inserted": {"file": str(disk), "drv": "qcow2", "ro": False}}]
                                  if name == "query-block" else {})
                        stream.write(json.dumps({"id": request["id"], "return": result}).encode()
                                     + b"\n")
                        stream.flush()

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        try:
            observer.qmp(path, disk, pid=os.getpid(), uid=os.getuid())
        finally:
            thread.join(timeout=5)
        assert not thread.is_alive()


def test_held_disk_requires_exact_live_writable_descriptor(tmp_path):
    disk = tmp_path / "disk.qcow2"
    process = Path("/proc") / str(os.getpid())
    descriptor = os.open(disk, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        expected = disk.stat()
        assert observer.held_writable_disk(process, disk, expected) == descriptor
        replacement = tmp_path / "replacement.qcow2"
        replacement.write_bytes(b"new disk")
        os.replace(replacement, disk)
        with pytest.raises(observer.DiskNotOpenedYet):
            observer.held_writable_disk(process, disk, disk.stat())
    finally:
        os.close(descriptor)


def test_held_disk_refuses_read_only_descriptor(tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"qcow2")
    descriptor = os.open(disk, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="selected writable disk"):
            observer.held_writable_disk(Path("/proc") / str(os.getpid()), disk, disk.stat())
    finally:
        os.close(descriptor)


def initial_observation(installation_id):
    return dict(schema="elevenid.installer-qemu-trial-observation/v2",
                target=dict(guest_id=str(uuid.uuid4()), disk_id="disk", engine_id="engine",
                            installation_id=installation_id),
                observation_phase="initial-empty", vm_boot_id=str(uuid.uuid4()),
                vm_config_sha256="config", vm_executable_sha256="executable",
                controller_key_sha256="client-key",
                known_hosts_sha256="host-key", guest_user="installer", guest_uid=1000,
                vm_dir_path="/trusted/vm", vm_dir_device=1, vm_dir_inode=10,
                vm_uid=1000, vm_gid=1000, vm_disk_path="/trusted/vm/disk.qcow2",
                ssh_port=49000,
                observed_at=1, vm_pid=42, vm_start_ticks="100", vm_disk_device=1,
                vm_disk_inode=2, vm_disk_fd=3, vm_memory_mib=4096, vm_cpus=2,
                initial_docker_clean=True, capacity_qualified=False,
                clean_host_qualified=False, dispatch_authorized=False)


def test_reobservation_refuses_target_or_process_substitution():
    installation_id = str(uuid.uuid4())
    initial = initial_observation(installation_id)
    observer.validate_initial(initial, installation_id)
    observer.require_same_vm(initial, dict(initial))
    for field, replacement in (("vm_boot_id", str(uuid.uuid4())),
                               ("guest_user", "different"), ("guest_uid", 1001),
                               ("vm_pid", 43), ("vm_start_ticks", "101"),
                               ("vm_disk_inode", 4), ("vm_config_sha256", "different"),
                               ("vm_dir_inode", 11), ("vm_uid", 1001),
                               ("ssh_port", 49001),
                               ("vm_executable_sha256", "different"),
                               ("controller_key_sha256", "different"),
                               ("known_hosts_sha256", "different")):
        changed = dict(initial, **{field: replacement})
        with pytest.raises(ValueError, match="VM changed"):
            observer.require_same_vm(initial, changed)
    for target_field in ("guest_id", "disk_id", "engine_id", "installation_id"):
        changed = dict(initial, target=dict(initial["target"], **{target_field: "different"}))
        with pytest.raises(ValueError, match="VM changed"):
            observer.require_same_vm(initial, changed)


def test_reobservation_refuses_untrusted_initial_record():
    installation_id = str(uuid.uuid4())
    initial = initial_observation(installation_id)
    for changed in (dict(initial, dispatch_authorized=True),
                    dict(initial, initial_docker_clean=False),
                    dict(initial, observation_phase="post-install"),
                    dict(initial, extra="forged"),
                    dict(initial, vm_pid=True),
                    dict(initial, target=dict(initial["target"], installation_id=str(uuid.uuid4())))):
        with pytest.raises(ValueError, match="initial VM observation invalid"):
            observer.validate_initial(changed, installation_id)


def test_populated_docker_refuses_clean_phases_but_not_identity_reobservation():
    queries = []

    def populated(script):
        queries.append(script)
        return "container-1"

    for phase in ("initial-empty", "pre-dispatch"):
        with pytest.raises(ValueError, match="not initially clean"):
            observer.require_clean_docker(phase, populated, "docker")
    assert len(queries) == 2
    observer.require_clean_docker("post-install", populated, "docker")
    assert len(queries) == 2


def test_observation_output_is_exclusive_and_bound_to_held_directory(tmp_path):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    parent = observer._directory(output)
    try:
        observer.write_observation(parent, "first.initial-observation.json", b"first\n")
        assert observer.private_file_at(parent, "first.initial-observation.json",
                                        os.getuid(), 65536) == b"first\n"
        (output / "alias.initial-observation.json").symlink_to("first.initial-observation.json")
        with pytest.raises(ValueError, match="observation file differs"):
            observer.private_file_at(parent, "alias.initial-observation.json",
                                     os.getuid(), 65536)
        with pytest.raises(FileExistsError):
            observer.write_observation(parent, "first.initial-observation.json", b"replacement\n")
        moved = tmp_path / "moved"
        output.rename(moved)
        output.mkdir(mode=0o700)
        observer.write_observation(parent, "second.post-install-observation.json", b"second\n")
        assert (moved / "second.post-install-observation.json").read_bytes() == b"second\n"
        assert not (output / "second.post-install-observation.json").exists()
    finally:
        os.close(parent)


def test_vm_control_reads_stay_in_held_private_directory(tmp_path):
    vm = tmp_path / "vm"
    vm.mkdir(mode=0o700)
    (vm / "vm.json").write_bytes(b"original\n")
    (vm / "vm.json").chmod(0o600)
    parent = observer.open_vm_dir(vm, os.getuid())
    try:
        moved = tmp_path / "moved"
        vm.rename(moved)
        vm.mkdir(mode=0o700)
        (vm / "vm.json").write_bytes(b"replacement\n")
        (vm / "vm.json").chmod(0o600)
        assert observer.private_file_at(parent, "vm.json", os.getuid(), 65536) == b"original\n"
        (tmp_path / "symlink").symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(OSError):
            observer.open_vm_dir(tmp_path / "symlink" / "vm", os.getuid())
    finally:
        os.close(parent)


def test_root_controller_accepts_only_selected_nonroot_vm_owner(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root controller identity requires root")
    owner = 65534
    ancestor = tmp_path / "vm-owner"
    vm = ancestor / "vm"
    ancestor.mkdir(mode=0o700)
    vm.mkdir(mode=0o700)
    os.chown(ancestor, owner, owner)
    os.chown(vm, owner, owner)
    parent = observer.open_vm_dir(vm, owner)
    os.close(parent)
    with pytest.raises(ValueError, match="untrusted"):
        observer.open_vm_dir(vm, owner + 1)


def test_live_executable_hash_is_bound_to_process_image():
    # Hosted Python may live in a runner-owned toolcache. QEMU is a root-owned
    # executable, so exercise the same production predicate with /usr/bin/sleep.
    executable = Path("/usr/bin/sleep")
    assert executable.lstat().st_uid == 0
    child = subprocess.Popen([str(executable), "30"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        process = Path("/proc") / str(child.pid)
        with (process / "exe").open("rb") as stream:
            expected = hashlib.file_digest(stream, "sha256").hexdigest()
        assert observer.executable_digest(process) == expected
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
