"""Synthetic exact binding tests; no guest, VM, Docker or package action."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_launch as launch  # noqa: E402
import installer_candidate_vm_seed as seed  # noqa: E402
import installer_release as release  # noqa: E402
import installer_test_vm_rootless_fixture as fixture  # noqa: E402
import installer_test_vm_rootless_setup as setup  # noqa: E402
from test_installer_candidate_vm_launch_evidence import chain, refresh_links  # noqa: E402


def fixture_records(root: Path):
    entries, boot = chain()
    vm_id = entries["launch_intent"]["vm_id"]
    source = root / "source"
    registry = root / "registry"
    vm_parent = root / "vm"
    runtime_parent = root / "runtime"
    for path in (source, registry, vm_parent, runtime_parent,
                 runtime_parent / vm_id, registry / (vm_id + ".control")):
        path.mkdir()
    control_values = {"controller_ed25519": b"private",
                      "guest_host_ed25519": b"host-private",
                      "known_hosts": b"hosts", "user-data": b"user-data",
                      "meta-data": b"meta", "seed.iso": b"seed"}
    for name, value in control_values.items():
        path = registry / (vm_id + ".control") / name
        path.write_bytes(value)
        path.chmod(0o600)
    provenance = {"image_path": str(source / "noble-server-cloudimg-amd64.img"),
                  **{key: "a" * 64 for key in
                     ("image_sha256", "manifest_sha256", "signature_sha256",
                      "keyring_sha256")}}
    entries["creation_intent"].update(image=provenance, virtual_gib=20,
                                      vm_dir=str(vm_parent / vm_id),
                                      disk_path=str(vm_parent / vm_id / "disk.qcow2"))
    entries["creation_receipt"].update(image=provenance, virtual_gib=20,
                                       vm_dir=str(vm_parent / vm_id),
                                       disk_path=str(vm_parent / vm_id / "disk.qcow2"))
    entries["creation_receipt"]["intent_sha256"] = release.digest(
        release.encode(entries["creation_intent"]))
    for key in ("runtime_intent", "runtime_receipt"):
        entries[key]["source_path"] = entries["creation_receipt"]["disk_path"]
        entries[key]["target_path"] = str(runtime_parent / vm_id / "disk.qcow2")
    runtime_stat = (runtime_parent / vm_id).stat()
    control_stat = (registry / (vm_id + ".control")).stat()
    entries["runtime_receipt"].update(runtime_dir_device=runtime_stat.st_dev,
                                      runtime_dir_inode=runtime_stat.st_ino)
    entries["seed_intent"].update(runtime_dir=str(runtime_parent / vm_id),
                                  control_dir=str(registry / (vm_id + ".control")),
                                  packages=seed.ROOTLESS_FIXTURE_PACKAGES,
                                  fixture_profile=seed.ROOTLESS_FIXTURE_PROFILE)
    entries["seed_receipt"].update(runtime_dir=str(runtime_parent / vm_id),
                                   control_dir=str(registry / (vm_id + ".control")),
                                   packages=seed.ROOTLESS_FIXTURE_PACKAGES,
                                   fixture_profile=seed.ROOTLESS_FIXTURE_PROFILE,
                                   control_dir_device=control_stat.st_dev,
                                   control_dir_inode=control_stat.st_ino,
                                   controller_private_sha256=release.digest(b"private"),
                                   guest_host_private_sha256=release.digest(b"host-private"),
                                   known_hosts_sha256=release.digest(b"hosts"),
                                   user_data_sha256=release.digest(b"user-data"),
                                   metadata_sha256=release.digest(b"meta"),
                                   seed_sha256=release.digest(b"seed"))
    entries["launch_intent"].update(runtime_dir=str(runtime_parent / vm_id),
                                    control_dir=str(registry / (vm_id + ".control")),
                                    runtime_dir_device=runtime_stat.st_dev,
                                    runtime_dir_inode=runtime_stat.st_ino,
                                    control_dir_device=control_stat.st_dev,
                                    control_dir_inode=control_stat.st_ino,
                                    memory_mib=2048)
    entries["launch_receipt"].update(runtime_dir=str(runtime_parent / vm_id),
                                     control_dir=str(registry / (vm_id + ".control")),
                                     runtime_dir_device=runtime_stat.st_dev,
                                     runtime_dir_inode=runtime_stat.st_ino,
                                     control_dir_device=control_stat.st_dev,
                                     control_dir_inode=control_stat.st_ino,
                                     memory_mib=2048)
    with mock.patch.object(launch, "_safe_runtime_path"):
        args = launch._arguments(runtime_parent / vm_id, vm_id, 22022, 2048)
    entries["launch_intent"]["args"] = entries["launch_receipt"]["args"] = args
    refresh_links(entries)
    intent = {"schema": fixture.SCHEMA, "phase": "intent", "vm_id": vm_id,
              **{"source_" + key: provenance[key] for key in provenance
                 if key != "image_path"},
              "vm_parent": str(vm_parent), "vm_parent_device": vm_parent.stat().st_dev,
              "vm_parent_inode": vm_parent.stat().st_ino,
              "runtime_parent": str(runtime_parent),
              "runtime_parent_device": runtime_parent.stat().st_dev,
              "runtime_parent_inode": runtime_parent.stat().st_ino,
              "runtime_uid": 997, "runtime_gid": 989, "ssh_port": 22022,
              "virtual_gib": 20, "guest_profile": seed.ROOTLESS_FIXTURE_PROFILE,
              "started_at": 1000, "qualified": False,
              "launch_authorized": False, "product_dispatch_authorized": False}
    result = {"schema": fixture.SCHEMA, "phase": "prepared", "vm_id": vm_id,
              "intent_sha256": release.digest(release.encode(intent)),
              "creation_sha256": release.digest(release.encode(entries["creation_receipt"])),
              "transfer_sha256": release.digest(release.encode(entries["runtime_receipt"])),
              "seed_sha256": release.digest(release.encode(entries["seed_receipt"])),
              "guest_profile": seed.ROOTLESS_FIXTURE_PROFILE,
              "runtime_uid": 997, "runtime_gid": 989, "prepared_at": 1001,
              "qualified": False, "launch_authorized": False,
              "product_dispatch_authorized": False, "rootless_daemon_ready": False}
    records = {vm_id + "." + name.replace("_", "-") + ".json": value
               for name, value in entries.items()}
    records[vm_id + fixture.RECORD_SUFFIX] = intent
    records[vm_id + fixture.RESULT_SUFFIX] = result
    return records, provenance, source, registry, vm_parent, runtime_parent, vm_id, boot


def bound_with_mocks(records, provenance, source, registry, vm_parent,
                     runtime_parent, vm_id, boot):
    original_stat = os.stat
    control_names = {"controller_ed25519", "guest_host_ed25519",
                     "known_hosts", "user-data", "meta-data", "seed.iso"}
    def root_control_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if path in control_names and kwargs.get("dir_fd") is not None:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0,
                                   st_nlink=info.st_nlink)
        return info
    class Lease:
        def __enter__(self):
            self.parent = os.open(registry, os.O_RDONLY)
            return self
        def __exit__(self, *_):
            os.close(self.parent)
    def read(_fd, name):
        value = records[name]
        return release.encode(value), value
    def open_directory(path):
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    live = records[vm_id + ".launch-receipt.json"]
    with mock.patch.object(setup.os, "geteuid", return_value=0), \
         mock.patch.object(setup.os, "stat", side_effect=root_control_stat), \
         mock.patch.object(setup, "ControllerLease", return_value=Lease()), \
         mock.patch.object(setup.create, "_read_record", side_effect=read), \
         mock.patch.object(setup.create, "verify_source", return_value=provenance), \
         mock.patch.object(setup.launch, "_boot_id", return_value=boot), \
         mock.patch.object(setup.launch, "_safe_runtime_path"), \
         mock.patch.object(setup, "_directory", side_effect=open_directory), \
         mock.patch.object(setup.runtime, "_runtime_parent",
                           side_effect=open_directory), \
         mock.patch.object(setup.observer, "open_vm_dir",
                           side_effect=lambda p, _uid: open_directory(p)), \
         mock.patch.object(setup.launch, "_seed_media"), \
         mock.patch.object(setup.launch, "_live", return_value={
             "pid": live["pid"], "start_ticks": live["start_ticks"],
             "disk_fd": live["disk_fd"]}), \
         mock.patch.object(setup.launch, "_trusted_tool", return_value="a" * 64), \
         mock.patch.object(setup.seed, "_bytes", side_effect=lambda p, _max:
                           p.read_bytes()), \
         mock.patch.object(setup.create, "_rebind_directory"), \
         mock.patch.object(setup.runtime, "_same_path"):
        return setup.bound_fixture(source=source, registry=registry,
                                   vm_parent=vm_parent, runtime_parent=runtime_parent,
                                   vm_id=vm_id)


def test_exact_prepared_live_fixture_binds_without_product_authority():
    with tempfile.TemporaryDirectory() as tmp:
        args = fixture_records(Path(tmp))
        binding = bound_with_mocks(*args)
        assert binding["vm_id"] == args[-2]
        assert binding["qualified"] is False
        assert binding["product_dispatch_authorized"] is False


@pytest.mark.parametrize("change", ["source", "profile", "result", "launch"])
def test_mixed_factory_or_records_refuse(change):
    with tempfile.TemporaryDirectory() as tmp:
        records, provenance, source, registry, vm_parent, run, vm_id, boot = \
            fixture_records(Path(tmp))
        if change == "source":
            provenance = dict(provenance, image_sha256="b" * 64)
        elif change == "profile":
            records[vm_id + ".seed-receipt.json"]["fixture_profile"] = "legacy"
        elif change == "result":
            records[vm_id + fixture.RESULT_SUFFIX]["seed_sha256"] = "b" * 64
        else:
            records[vm_id + ".launch-intent.json"]["memory_mib"] = 4096
        with pytest.raises((ValueError, KeyError)):
            bound_with_mocks(records, provenance, source, registry,
                             vm_parent, run, vm_id, boot)
