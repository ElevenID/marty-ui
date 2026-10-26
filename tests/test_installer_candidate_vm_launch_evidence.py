"""Candidate evidence must reject the legacy engineering launch record."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_launch_evidence as evidence
import installer_release as release


def records():
    seed = b"seed receipt"
    boot = "01234567-89ab-4cde-8f01-23456789abcd"
    intent = dict(
        schema=evidence.LAUNCH_SCHEMA, phase="intent",
        vm_id="11111111-2222-4333-8444-555555555555",
        seed_receipt_sha256=release.digest(seed), runtime_dir="/runtime/vm",
        control_dir="/registry/vm.control", runtime_dir_device=1,
        runtime_dir_inode=2, control_dir_device=3, control_dir_inode=4,
        disk_device=1, disk_inode=5, seed_device=3, seed_inode=6,
        uid=997, gid=989, kvm_gid=108, ssh_port=22022, memory_mib=4096,
        cpus=2, args=["/usr/bin/qemu-system-x86_64"], qemu_sha256="a" * 64,
        controller_boot_id=boot, started_at=1000, qualified=False,
        dispatch_authorized=False)
    spawned = dict(schema=evidence.PID_SCHEMA, phase="spawned",
                   vm_id=intent["vm_id"], intent_sha256=release.digest(release.encode(intent)),
                   pid=1509, start_ticks="123456", controller_boot_id=boot,
                   spawned_at=1001)
    receipt = dict(intent, phase="launched", intent_sha256=spawned["intent_sha256"],
                   pid=spawned["pid"], start_ticks=spawned["start_ticks"],
                   disk_fd=9, observation_route="initial",
                   pid_authentication="exact_boot_and_start_ticks",
                   observed_at=1002)
    return intent, spawned, receipt, seed, boot


def bind(intent, spawned, receipt, seed, boot):
    return evidence.bind_exact_launch(release.encode(intent), release.encode(spawned),
                                      release.encode(receipt), seed, boot_id=boot)


def test_exact_chain_binds_bytes_without_granting_dispatch():
    intent, spawned, receipt, seed, boot = records()
    assert bind(intent, spawned, receipt, seed, boot) == tuple(
        release.digest(release.encode(item)) for item in (intent, spawned, receipt))
    assert receipt["dispatch_authorized"] is False
    receipt["observation_route"] = "existing"
    assert bind(intent, spawned, receipt, seed, boot)


@pytest.mark.parametrize("change", [
    lambda i, p, r: p.update(schema=evidence.LAUNCH_SCHEMA),
    lambda i, p, r: r.update(pid_authentication="bounded_seconds_engineering_only"),
    lambda i, p, r: r.update(start_ticks="123457"),
    lambda i, p, r: p.update(controller_boot_id="other"),
    lambda i, p, r: r.update(seed_receipt_sha256="b" * 64),
    lambda i, p, r: r.update(uid=1000),
    lambda i, p, r: r.update(qualified=True),
    lambda i, p, r: r.update(pid=1509.0),
    lambda i, p, r: p.update(start_ticks="١٢٣٤٥٦"),
    lambda i, p, r: i.update(vm_id="not-a-uuid"),
    lambda i, p, r: i.update(started_at="1000"),
    lambda i, p, r: p.update(spawned_at=999),
    lambda i, p, r: r.update(observed_at=1000),
])
def test_unsafe_or_mixed_launch_chain_refused(change):
    intent, spawned, receipt, seed, boot = records()
    change(intent, spawned, receipt)
    with pytest.raises(ValueError):
        bind(intent, spawned, receipt, seed, boot)


def test_changed_seed_and_noncanonical_records_refused():
    intent, spawned, receipt, seed, boot = records()
    with pytest.raises(ValueError):
        bind(intent, spawned, receipt, b"different seed", boot)
    raw = release.encode(intent).replace(b":", b": ", 1)
    with pytest.raises(ValueError, match="not canonical"):
        evidence.bind_exact_launch(raw, release.encode(spawned),
                                   release.encode(receipt), seed, boot_id=boot)


def chain():
    li, lp, lr, _, boot = records()
    vm_id = li["vm_id"]
    ci = dict(schema="elevenid.installer-vm-overlay-creation/v2",
              phase="intent", vm_id=vm_id, qualified=False,
              launch_authorized=False, image={"image_sha256": "a" * 64},
              vm_dir="/source/vm", disk_path="/source/vm/disk.qcow2",
              virtual_gib=32, started_at=1000)
    cr = dict((key, value) for key, value in ci.items() if key != "started_at")
    cr.update(phase="created", intent_sha256=release.digest(release.encode(ci)),
              disk_device=1, disk_inode=5, disk_bytes=1024,
              disk_sha256="b" * 64, created_at=1001)
    ri = dict(schema="elevenid.installer-vm-runtime-transfer/v1", phase="intent",
              vm_id=vm_id, creation_receipt_sha256=release.digest(release.encode(cr)),
              source_path=cr["disk_path"], target_path="/runtime/vm/disk.qcow2",
              disk_device=1, disk_inode=5, disk_bytes=1024,
              disk_sha256="b" * 64, runtime_uid=997, runtime_gid=989,
              runtime_account="mvq_test", started_at=1002,
              qualified=False, launch_authorized=False)
    rr = dict(ri, phase="transferred", intent_sha256=release.digest(release.encode(ri)),
              runtime_dir_device=1, runtime_dir_inode=2,
              transferred_at=1003)
    si = dict(schema="elevenid.installer-vm-seed/v1", phase="intent", vm_id=vm_id,
              runtime_receipt_sha256=release.digest(release.encode(rr)),
              control_dir="/registry/vm.control", runtime_dir="/runtime/vm",
              ssh_port=22022, guest_user="installer", packages={"docker.io": "1"},
              started_at=1004, qualified=False, launch_authorized=False)
    sr = dict(si, phase="seeded", intent_sha256=release.digest(release.encode(si)),
              control_dir_device=3, control_dir_inode=4, seed_device=3,
              seed_inode=6, seed_bytes=4096, seed_sha256="c" * 64,
              user_data_sha256="d" * 64, metadata_sha256="e" * 64,
              known_hosts_sha256="f" * 64,
              controller_public_sha256="1" * 64,
              guest_host_public_sha256="2" * 64,
              controller_private_sha256="3" * 64,
              guest_host_private_sha256="4" * 64, seeded_at=1005)
    li["started_at"] = 1006
    li["seed_receipt_sha256"] = release.digest(release.encode(sr))
    lp["intent_sha256"] = release.digest(release.encode(li))
    lp["spawned_at"] = 1007
    lr.update(seed_receipt_sha256=li["seed_receipt_sha256"],
              intent_sha256=lp["intent_sha256"], started_at=1006,
              observed_at=1008)
    return dict(creation_intent=ci, creation_receipt=cr, runtime_intent=ri,
                runtime_receipt=rr, seed_intent=si, seed_receipt=sr,
                launch_intent=li, launch_pid=lp, launch_receipt=lr), boot


def bind_chain(entries, boot):
    return evidence.bind_provisioned_launch(
        **{name: release.encode(record) for name, record in entries.items()},
        boot_id=boot)


def refresh_links(entries):
    """Rehash every downstream record after a contradictory source mutation."""
    e = entries
    e["runtime_intent"]["creation_receipt_sha256"] = release.digest(
        release.encode(e["creation_receipt"]))
    e["runtime_receipt"]["creation_receipt_sha256"] = e["runtime_intent"][
        "creation_receipt_sha256"]
    e["runtime_receipt"]["intent_sha256"] = release.digest(
        release.encode(e["runtime_intent"]))
    e["seed_intent"]["runtime_receipt_sha256"] = release.digest(
        release.encode(e["runtime_receipt"]))
    e["seed_receipt"]["runtime_receipt_sha256"] = e["seed_intent"][
        "runtime_receipt_sha256"]
    e["seed_receipt"]["intent_sha256"] = release.digest(
        release.encode(e["seed_intent"]))
    e["launch_intent"]["seed_receipt_sha256"] = release.digest(
        release.encode(e["seed_receipt"]))
    e["launch_pid"]["intent_sha256"] = release.digest(
        release.encode(e["launch_intent"]))
    e["launch_receipt"]["seed_receipt_sha256"] = e["launch_intent"][
        "seed_receipt_sha256"]
    e["launch_receipt"]["intent_sha256"] = e["launch_pid"]["intent_sha256"]


def test_provisioning_chain_binds_pristine_receipts_without_rehashing_booted_disk():
    entries, boot = chain()
    bound = bind_chain(entries, boot)
    assert bound["creation_receipt_sha256"] == release.digest(
        release.encode(entries["creation_receipt"]))
    assert len(bound) == 9


@pytest.mark.parametrize("name,field,value", [
    ("runtime_intent", "creation_receipt_sha256", "0" * 64),
    ("seed_intent", "runtime_receipt_sha256", "0" * 64),
    ("launch_intent", "disk_inode", 99),
    ("seed_receipt", "control_dir_inode", 99),
    ("runtime_receipt", "runtime_uid", 0),
])
def test_provisioning_chain_substitution_refused(name, field, value):
    entries, boot = chain()
    entries[name][field] = value
    with pytest.raises(ValueError):
        bind_chain(entries, boot)


@pytest.mark.parametrize("name,field,value", [
    ("creation_receipt", "image", {"image_sha256": "0" * 64}),
    ("creation_receipt", "launch_authorized", True),
    ("runtime_receipt", "runtime_account", "other-account"),
    ("seed_receipt", "packages", {"wrong": "1"}),
    ("creation_receipt", "disk_inode", True),
    ("creation_intent", "unexpected", "field"),
    ("seed_receipt", "launch_authorized", True),
    ("runtime_intent", "launch_authorized", True),
    ("seed_receipt", "seed_sha256", "G" * 64),
    ("creation_receipt", "disk_bytes", 0),
    ("seed_receipt", "seed_bytes", 0),
])
def test_rehashed_contradictory_provisioning_records_refused(name, field, value):
    entries, boot = chain()
    entries[name][field] = value
    refresh_links(entries)
    with pytest.raises(ValueError):
        bind_chain(entries, boot)
