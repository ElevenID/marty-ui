"""Root-only custody transition tests for the fresh VM overlay."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid

import pytest

if sys.platform != "linux":
    pytest.skip("VM runtime custody requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_create as creation
import installer_candidate_vm_runtime as runtime
from test_installer_candidate_vm_create import root_trial as root_trial

VM_ID = "33333333-3333-4333-8333-333333333333"
UID = GID = 60000


@pytest.fixture
def runtime_parent(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="marty-runtime-test-", dir="/var/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o711)
        parent = root / "vms"
        parent.mkdir(mode=0o711)
        account = SimpleNamespace(pw_name="mvq_" + runtime.base64.b32encode(
            uuid.UUID(VM_ID).bytes).decode("ascii").rstrip("=").lower(),
                                  pw_gid=GID, pw_dir="/nonexistent",
                                  pw_shell="/usr/sbin/nologin")
        monkeypatch.setattr(runtime.pwd, "getpwuid", lambda uid: account)
        yield parent


def test_transfer_moves_only_disk_and_denies_qemu_controller_access(root_trial, runtime_parent,
                                                                    monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    receipt = runtime.transfer(source, registry, parent, runtime_parent,
                               vm_id=VM_ID, uid=UID, gid=GID)
    assert runtime.verify_transfer(source, registry, parent, runtime_parent,
                                   vm_id=VM_ID) == receipt
    disk = runtime_parent / VM_ID / "disk.qcow2"
    assert receipt["qualified"] is False and receipt["launch_authorized"] is False
    assert receipt["runtime_uid"] == UID and receipt["runtime_gid"] == GID
    assert not (parent / VM_ID / "disk.qcow2").exists()
    assert (disk.stat().st_uid, disk.stat().st_gid) == (UID, GID)
    assert stat.S_IMODE(disk.stat().st_mode) == 0o600
    assert stat.S_IMODE(disk.parent.stat().st_mode) == 0o700
    assert (registry / f"{VM_ID}.runtime-receipt.json").is_file()
    assert subprocess.run(["/usr/bin/setpriv", "--reuid=60000", "--regid=60000",
                           "--clear-groups", "/usr/bin/test", "-r", str(disk)],
                          check=False).returncode == 0
    assert subprocess.run(["/usr/bin/setpriv", "--reuid=60000", "--regid=60000",
                           "--clear-groups", "/usr/bin/test", "-r",
                           str(registry / f"{VM_ID}.runtime-receipt.json")],
                          check=False).returncode != 0
    with pytest.raises((FileNotFoundError, ValueError)):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)


def test_transfer_failure_retains_intent_without_completion(root_trial, runtime_parent,
                                                              monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    original = runtime.os.rename

    def refuse_disk(source_name, target_name, **kwargs):
        if source_name == target_name == "disk.qcow2":
            raise OSError("injected disk move failure")
        return original(source_name, target_name, **kwargs)

    monkeypatch.setattr(runtime.os, "rename", refuse_disk)
    with pytest.raises(OSError, match="injected disk move failure"):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)
    assert (registry / f"{VM_ID}.runtime-intent.json").is_file()
    assert not (registry / f"{VM_ID}.runtime-receipt.json").exists()
    assert (parent / VM_ID / "disk.qcow2").is_file()
    with pytest.raises(FileExistsError):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)


def test_transfer_rejects_non_dedicated_runtime_account(root_trial, runtime_parent,
                                                        monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    monkeypatch.setattr(runtime.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_name="nobody", pw_gid=GID, pw_dir="/nonexistent",
        pw_shell="/usr/sbin/nologin"))
    with pytest.raises(ValueError, match="not dedicated"):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)
    assert not (registry / f"{VM_ID}.runtime-intent.json").exists()


def test_base_must_be_traversable_and_readable(runtime_parent):
    image = runtime_parent / "public-image.qcow2"
    image.write_bytes(b"base")
    image.chmod(0o444)
    runtime._backing_readable(image)
    runtime_parent.chmod(0o700)
    with pytest.raises(ValueError, match="not traversable"):
        runtime._backing_readable(image)


def test_replaced_disk_after_runtime_ownership_never_completes(root_trial, runtime_parent,
                                                                monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    actual_chown = runtime.os.fchown
    replaced = False

    def replace_at_handoff(fd, uid, gid):
        nonlocal replaced
        actual_chown(fd, uid, gid)
        if stat.S_ISDIR(runtime.os.fstat(fd).st_mode) and not replaced:
            disk = runtime_parent / VM_ID / "disk.qcow2"
            prior = disk.with_name("prior-disk.qcow2")
            disk.rename(prior)
            shutil.copyfile(prior, disk)
            os.chown(disk, uid, gid)
            disk.chmod(0o600)
            replaced = True

    monkeypatch.setattr(runtime.os, "fchown", replace_at_handoff)
    with pytest.raises(ValueError, match="disk name differs"):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)
    assert replaced
    assert (registry / f"{VM_ID}.runtime-intent.json").is_file()
    assert not (registry / f"{VM_ID}.runtime-receipt.json").exists()
    assert (runtime_parent / VM_ID / "prior-disk.qcow2").is_file()


def test_registry_replacement_after_intent_never_completes(root_trial, runtime_parent,
                                                            monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    actual_write = runtime._write
    moved = registry.with_name("moved-registry")

    def replace_registry(fd, name, record):
        raw = actual_write(fd, name, record)
        if name.endswith(".runtime-intent.json"):
            registry.rename(moved)
            registry.mkdir(mode=0o700)
        return raw

    monkeypatch.setattr(runtime, "_write", replace_registry)
    with pytest.raises(ValueError, match="custody path changed"):
        runtime.transfer(source, registry, parent, runtime_parent,
                         vm_id=VM_ID, uid=UID, gid=GID)
    assert (moved / f"{VM_ID}.runtime-intent.json").is_file()
    assert not (moved / f"{VM_ID}.runtime-receipt.json").exists()
    assert (parent / VM_ID / "disk.qcow2").is_file()


def test_prelaunch_revalidation_refuses_modified_overlay(root_trial, runtime_parent,
                                                         monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent, vm_id=VM_ID,
                     uid=UID, gid=GID)
    disk = runtime_parent / VM_ID / "disk.qcow2"
    with disk.open("r+b") as stream:
        stream.seek(4096)
        original = stream.read(1)
        stream.seek(4096)
        stream.write(bytes([original[0] ^ 1]))
    with pytest.raises(ValueError, match="pristine bytes differ"):
        runtime.verify_transfer(source, registry, parent, runtime_parent,
                                vm_id=VM_ID)


def test_prelaunch_revalidation_refuses_replaced_overlay(root_trial, runtime_parent,
                                                         monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent, vm_id=VM_ID,
                     uid=UID, gid=GID)
    disk = runtime_parent / VM_ID / "disk.qcow2"
    prior = disk.with_name("prior-disk.qcow2")
    disk.rename(prior)
    shutil.copyfile(prior, disk)
    os.chown(disk, UID, GID)
    disk.chmod(0o600)
    with pytest.raises(ValueError, match="pristine bytes differ"):
        runtime.verify_transfer(source, registry, parent, runtime_parent,
                                vm_id=VM_ID)


def test_prelaunch_revalidation_refuses_changed_receipt(root_trial, runtime_parent,
                                                        monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent, vm_id=VM_ID,
                     uid=UID, gid=GID)
    receipt = registry / f"{VM_ID}.runtime-receipt.json"
    receipt.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        runtime.verify_transfer(source, registry, parent, runtime_parent,
                                vm_id=VM_ID)


def test_prelaunch_never_parses_mutable_runtime_path_as_root(root_trial, runtime_parent,
                                                              monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent, vm_id=VM_ID,
                     uid=UID, gid=GID)

    def forbidden(_path):
        raise AssertionError("root QEMU parsed UID-writable runtime disk")

    monkeypatch.setattr(creation, "_image_info", forbidden)
    runtime.verify_transfer(source, registry, parent, runtime_parent, vm_id=VM_ID)


def test_prelaunch_rechecks_creation_intent_at_end(root_trial, runtime_parent,
                                                    monkeypatch):
    source, registry, parent = root_trial
    monkeypatch.setattr(runtime, "_backing_readable", lambda _path: None)
    creation.create_overlay(source, registry, parent, vm_id=VM_ID, virtual_gib=20)
    runtime.transfer(source, registry, parent, runtime_parent, vm_id=VM_ID,
                     uid=UID, gid=GID)
    original = runtime._disk_digest
    changed = False

    def mutate_during_digest(fd):
        nonlocal changed
        result = original(fd)
        if not changed:
            (registry / f"{VM_ID}.creation-intent.json").write_bytes(b"changed")
            changed = True
        return result

    monkeypatch.setattr(runtime, "_disk_digest", mutate_during_digest)
    with pytest.raises(ValueError):
        runtime.verify_transfer(source, registry, parent, runtime_parent,
                                vm_id=VM_ID)
    assert changed
