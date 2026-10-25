"""Pure exact-process launch-chain check for candidate VM controllers.

This checks record consistency only. The caller must authenticate the root
registry, hold its lease, reobserve the live process and disk, and perform
guest readiness checks before any candidate approval or dispatch.
"""
from __future__ import annotations

import installer_release as release
import uuid

LAUNCH_SCHEMA = "elevenid.installer-vm-launch/v1"
PID_SCHEMA = "elevenid.installer-vm-pid/v2"


def bind_exact_launch(intent_raw: bytes, pid_raw: bytes, receipt_raw: bytes,
                      seed_raw: bytes, *, boot_id: str) -> tuple[str, str, str]:
    """Reject legacy recovery and bind the exact launch record bytes.

    Returned hashes are evidence references, never dispatch authorization.
    """
    intent, spawned, receipt = (release.decode(raw) for raw in
                                (intent_raw, pid_raw, receipt_raw))
    for raw, record in zip((intent_raw, pid_raw, receipt_raw),
                           (intent, spawned, receipt), strict=True):
        release.require(release.encode(record) == raw,
                        "VM launch record encoding is not canonical")
    release.require(
        type(intent.get("vm_id")) is str
        and str(uuid.UUID(intent["vm_id"])) == intent["vm_id"]
        and uuid.UUID(intent["vm_id"]).version == 4
        and type(boot_id) is str
        and str(uuid.UUID(boot_id)) == boot_id,
        "VM launch identity invalid",
    )
    release.exact(intent, {
        "schema", "phase", "vm_id", "seed_receipt_sha256", "runtime_dir",
        "control_dir", "runtime_dir_device", "runtime_dir_inode",
        "control_dir_device", "control_dir_inode", "disk_device",
        "disk_inode", "seed_device", "seed_inode", "uid", "gid",
        "kvm_gid", "ssh_port", "memory_mib", "cpus", "args",
        "qemu_sha256", "controller_boot_id", "started_at", "qualified",
        "dispatch_authorized",
    }, "VM launch intent")
    release.exact(spawned, {
        "schema", "phase", "vm_id", "intent_sha256", "pid",
        "start_ticks", "controller_boot_id", "spawned_at",
    }, "VM launch PID record")
    release.exact(receipt, set(intent) | {
        "intent_sha256", "pid", "start_ticks", "disk_fd",
        "observation_route", "pid_authentication", "observed_at",
    }, "VM launch receipt")
    release.require(
        intent["schema"] == receipt["schema"] == LAUNCH_SCHEMA
        and spawned["schema"] == PID_SCHEMA
        and intent["phase"] == "intent"
        and spawned["phase"] == "spawned"
        and receipt["phase"] == "launched"
        and intent["vm_id"] == spawned["vm_id"] == receipt["vm_id"]
        and type(boot_id) is str
        and intent["controller_boot_id"]
        == spawned["controller_boot_id"]
        == receipt["controller_boot_id"] == boot_id
        and spawned["intent_sha256"] == receipt["intent_sha256"]
        == release.digest(intent_raw)
        and intent["seed_receipt_sha256"] == release.digest(seed_raw)
        and type(spawned["pid"]) is int and spawned["pid"] > 4
        and type(spawned["start_ticks"]) is str
        and spawned["start_ticks"].isascii()
        and spawned["start_ticks"].isdecimal()
        and type(receipt["pid"]) is int
        and receipt["pid"] == spawned["pid"]
        and receipt["start_ticks"] == spawned["start_ticks"]
        and receipt["pid_authentication"] == "exact_boot_and_start_ticks"
        and receipt["observation_route"] in ("initial", "existing")
        and all(type(value) is int and value > 0 for value in
                (intent["started_at"], spawned["spawned_at"],
                 receipt["observed_at"]))
        and intent["started_at"] <= spawned["spawned_at"]
        <= receipt["observed_at"]
        and receipt["qualified"] is False
        and receipt["dispatch_authorized"] is False
        and type(receipt["disk_fd"]) is int and receipt["disk_fd"] >= 0
        and all(type(receipt[key]) is type(value) and receipt[key] == value
                for key, value in intent.items() if key != "phase"),
        "VM exact launch chain invalid",
    )
    return (release.digest(intent_raw), release.digest(pid_raw),
            release.digest(receipt_raw))
