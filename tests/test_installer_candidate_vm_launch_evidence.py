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
