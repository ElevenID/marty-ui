"""Fresh overlay creation keeps uncertain disks and never publishes false completion."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("QEMU overlay creation requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_create as creation
import installer_release as release


@pytest.fixture
def root_trial(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root controller trial required")
    source, registry, parent = [tmp_path / name for name in ("source", "registry", "vms")]
    source.mkdir(mode=0o755)
    registry.mkdir(mode=0o700)
    parent.mkdir(mode=0o700)
    image = source / creation.IMAGE
    subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", str(image), "2G"],
                   check=True, stdout=subprocess.DEVNULL)
    image.chmod(0o444)
    (source / "SHA256SUMS").write_bytes(b"mock signed manifest")
    (source / "SHA256SUMS.gpg").write_bytes(b"mock signature")
    provenance = dict(image_path=str(image), image_sha256=creation._digest_file(image, creation.MAX_IMAGE),
                      manifest_sha256=release.digest(b"mock signed manifest"),
                      signature_sha256=release.digest(b"mock signature"),
                      keyring_sha256=release.digest(creation._bytes(creation.KEYRING, 1024 * 1024)))
    # Failure-path tests start after signed-source verification; the real signed
    # source was exercised separately with the official Ubuntu image.
    monkeypatch.setattr(creation, "verify_source", lambda _source: provenance)
    return source, registry, parent


def test_disk_fsync_failure_retains_intent_without_completion(root_trial, monkeypatch):
    source, registry, parent = root_trial
    vm_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    real_fsync = creation.os.fsync

    def refuse_disk(fd):
        if os.readlink(f"/proc/self/fd/{fd}").endswith("/disk.qcow2"):
            raise OSError("injected disk flush failure")
        return real_fsync(fd)

    monkeypatch.setattr(creation.os, "fsync", refuse_disk)
    with pytest.raises(OSError, match="injected disk flush failure"):
        creation.create_overlay(source, registry, parent, vm_id=vm_id, virtual_gib=20)
    assert (registry / f"{vm_id}.creation-intent.json").is_file()
    assert not (registry / f"{vm_id}.creation-receipt.json").exists()
    assert (parent / vm_id / "disk.qcow2").is_file()


def test_parent_replacement_retains_partial_and_refuses_receipt(root_trial, monkeypatch):
    source, registry, parent = root_trial
    vm_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    real_command = creation.command
    moved = parent.with_name("moved-vms")

    def replace_after_create(argv, **kwargs):
        result = real_command(argv, **kwargs)
        if len(argv) > 1 and argv[1] == "create":
            parent.rename(moved)
            parent.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(creation, "command", replace_after_create)
    with pytest.raises(ValueError, match="controller directory changed"):
        creation.create_overlay(source, registry, parent, vm_id=vm_id, virtual_gib=20)
    assert (registry / f"{vm_id}.creation-intent.json").is_file()
    assert not (registry / f"{vm_id}.creation-receipt.json").exists()
    assert (moved / vm_id / "disk.qcow2").is_file()


def test_second_directory_acquisition_closes_first(root_trial, monkeypatch):
    source, registry, parent = root_trial
    opened = []
    real_directory = creation._directory

    def refuse_parent(path):
        if path == parent:
            raise ValueError("injected parent refusal")
        fd = real_directory(path)
        opened.append(fd)
        return fd

    monkeypatch.setattr(creation, "_directory", refuse_parent)
    with pytest.raises(ValueError, match="injected parent refusal"):
        creation.create_overlay(source, registry, parent,
                                vm_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", virtual_gib=20)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_duplicate_id_preserves_existing_receipt_and_disk(root_trial):
    source, registry, parent = root_trial
    vm_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    creation.create_overlay(source, registry, parent, vm_id=vm_id, virtual_gib=20)
    receipt = registry / f"{vm_id}.creation-receipt.json"
    disk = parent / vm_id / "disk.qcow2"
    before = (receipt.read_bytes(), disk.read_bytes())
    with pytest.raises(FileExistsError):
        creation.create_overlay(source, registry, parent, vm_id=vm_id, virtual_gib=20)
    assert (receipt.read_bytes(), disk.read_bytes()) == before


def test_base_with_backing_file_is_not_closed(tmp_path):
    if not Path("/usr/bin/qemu-img").is_file():
        pytest.skip("the required root VM-creation lane installs qemu-utils")
    base = tmp_path / "base.qcow2"
    image = tmp_path / "image.qcow2"
    subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", str(base), "2G"],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(base), str(image)], check=True, stdout=subprocess.DEVNULL)
    assert creation._external_reference(creation._image_info(image))
