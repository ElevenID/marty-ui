"""Pure exact-process launch-chain check for candidate VM controllers.

This checks record consistency only. The caller must authenticate the root
registry, hold its lease, reobserve the live process and disk, and perform
guest readiness checks before any candidate approval or dispatch.
"""
from __future__ import annotations

import installer_release as release
from installer_candidate_vm_seed import (ROOTLESS_FIXTURE_PACKAGES,
                                         ROOTLESS_FIXTURE_PROFILE)
import re
import uuid

LAUNCH_SCHEMA = "elevenid.installer-vm-launch/v1"
PID_SCHEMA = "elevenid.installer-vm-pid/v2"
CREATION_INTENT_FIELDS = {
    "schema", "phase", "vm_id", "image", "vm_dir", "disk_path",
    "virtual_gib", "started_at", "qualified", "launch_authorized",
}
CREATION_RECEIPT_FIELDS = (CREATION_INTENT_FIELDS - {"started_at"}) | {
    "intent_sha256", "disk_device", "disk_inode", "disk_bytes",
    "disk_sha256", "created_at",
}
RUNTIME_FIELDS = {
    "schema", "phase", "vm_id", "creation_receipt_sha256",
    "source_path", "target_path", "disk_device", "disk_inode",
    "disk_bytes", "disk_sha256", "runtime_uid", "runtime_gid",
    "runtime_account", "started_at", "qualified", "launch_authorized",
}
SEED_FIELDS = {
    "schema", "phase", "vm_id", "runtime_receipt_sha256", "control_dir",
    "runtime_dir", "ssh_port", "guest_user", "packages", "started_at",
    "qualified", "launch_authorized",
}
SEED_RECEIPT_EXTRA = {
    "intent_sha256", "control_dir_device", "control_dir_inode",
    "seed_device", "seed_inode", "seed_bytes", "seed_sha256",
    "user_data_sha256", "metadata_sha256", "known_hosts_sha256",
    "controller_public_sha256", "guest_host_public_sha256",
    "controller_private_sha256", "guest_host_private_sha256", "seeded_at",
}


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


def bind_provisioned_launch(*, creation_intent: bytes, creation_receipt: bytes,
                            runtime_intent: bytes, runtime_receipt: bytes,
                            seed_intent: bytes, seed_receipt: bytes,
                            launch_intent: bytes, launch_pid: bytes,
                            launch_receipt: bytes, boot_id: str) -> dict[str, str]:
    """Bind immutable provisioning records through an exact v2 launch.

    Booted overlay bytes are intentionally not compared with pristine creation
    bytes. Producer custody, live disk/process identity and guest state remain
    mandatory independent checks by the controller.
    """
    named = {
        "creation_intent": creation_intent,
        "creation_receipt": creation_receipt,
        "runtime_intent": runtime_intent,
        "runtime_receipt": runtime_receipt,
        "seed_intent": seed_intent,
        "seed_receipt": seed_receipt,
        "launch_intent": launch_intent,
        "launch_pid": launch_pid,
        "launch_receipt": launch_receipt,
    }
    records = {name: release.decode(raw) for name, raw in named.items()}
    for name, raw in named.items():
        release.require(release.encode(records[name]) == raw,
                        "VM provisioning record is not canonical")
    ci, cr = records["creation_intent"], records["creation_receipt"]
    ri, rr = records["runtime_intent"], records["runtime_receipt"]
    si, sr = records["seed_intent"], records["seed_receipt"]
    li = records["launch_intent"]
    vm_id = li["vm_id"]
    profile = si.get("fixture_profile")
    release.require(profile in (None, ROOTLESS_FIXTURE_PROFILE),
                    "VM seed profile unsupported")
    seed_fields = SEED_FIELDS | ({"fixture_profile"} if profile is not None else set())
    for record, fields, label in (
        (ci, CREATION_INTENT_FIELDS, "creation intent"),
        (cr, CREATION_RECEIPT_FIELDS, "creation receipt"),
        (ri, RUNTIME_FIELDS, "runtime intent"),
        (rr, RUNTIME_FIELDS | {"intent_sha256", "runtime_dir_device",
                               "runtime_dir_inode", "transferred_at"},
         "runtime receipt"),
        (si, seed_fields, "seed intent"),
        (sr, seed_fields | SEED_RECEIPT_EXTRA, "seed receipt"),
    ):
        release.exact(record, fields, "VM " + label)
    def inherited(intent: dict, receipt: dict) -> bool:
        return all(type(receipt[key]) is type(value) and receipt[key] == value
                   for key, value in intent.items() if key != "phase")

    chronological = (
        ci["started_at"], cr["created_at"], ri["started_at"],
        rr["transferred_at"], si["started_at"], sr["seeded_at"],
        li["started_at"], records["launch_pid"]["spawned_at"],
        records["launch_receipt"]["observed_at"],
    )
    release.require(
        all(record["vm_id"] == vm_id for record in (ci, cr, ri, rr, si, sr))
        and ci["schema"] == cr["schema"] == "elevenid.installer-vm-overlay-creation/v2"
        and ri["schema"] == rr["schema"] == "elevenid.installer-vm-runtime-transfer/v1"
        and si["schema"] == sr["schema"] == "elevenid.installer-vm-seed/v1"
        and (ci["phase"], cr["phase"], ri["phase"], rr["phase"],
             si["phase"], sr["phase"])
        == ("intent", "created", "intent", "transferred", "intent", "seeded")
        and cr["intent_sha256"] == release.digest(creation_intent)
        and all(type(cr[key]) is type(ci[key]) and cr[key] == ci[key]
                for key in ("schema", "vm_id", "image", "vm_dir", "disk_path",
                            "virtual_gib", "qualified", "launch_authorized"))
        and inherited(ri, rr) and inherited(si, sr)
        and ri["creation_receipt_sha256"] == release.digest(creation_receipt)
        and rr["intent_sha256"] == release.digest(runtime_intent)
        and si["runtime_receipt_sha256"] == release.digest(runtime_receipt)
        and sr["intent_sha256"] == release.digest(seed_intent)
        and (profile is None or (sr["fixture_profile"] == profile
                                 and si["packages"] == ROOTLESS_FIXTURE_PACKAGES
                                 and li["memory_mib"] == 2048))
        and li["seed_receipt_sha256"] == release.digest(seed_receipt)
        and (cr["disk_device"], cr["disk_inode"])
        == (ri["disk_device"], ri["disk_inode"])
        == (rr["disk_device"], rr["disk_inode"])
        == (li["disk_device"], li["disk_inode"])
        and (cr["disk_bytes"], cr["disk_sha256"])
        == (ri["disk_bytes"], ri["disk_sha256"])
        and ri["source_path"] == cr["disk_path"]
        and cr["disk_path"] == cr["vm_dir"] + "/disk.qcow2"
        and rr["runtime_dir_device"] == li["runtime_dir_device"]
        and rr["runtime_dir_inode"] == li["runtime_dir_inode"]
        and sr["control_dir_device"] == li["control_dir_device"]
        and sr["control_dir_inode"] == li["control_dir_inode"]
        and sr["seed_device"] == li["seed_device"]
        and sr["seed_inode"] == li["seed_inode"]
        and rr["target_path"] == li["runtime_dir"] + "/disk.qcow2"
        and sr["runtime_dir"] == li["runtime_dir"]
        and sr["control_dir"] == li["control_dir"]
        and rr["runtime_uid"] == li["uid"]
        and rr["runtime_gid"] == li["gid"]
        and sr["ssh_port"] == li["ssh_port"]
        and all(type(record[key]) is int and record[key] >= 0
                for record, keys in (
                    (cr, ("disk_device", "disk_inode", "disk_bytes")),
                    (ri, ("disk_device", "disk_inode", "disk_bytes",
                          "runtime_uid", "runtime_gid")),
                    (rr, ("runtime_dir_device", "runtime_dir_inode")),
                    (sr, ("control_dir_device", "control_dir_inode",
                          "seed_device", "seed_inode", "seed_bytes", "ssh_port")),
                    (li, ("disk_device", "disk_inode", "runtime_dir_device",
                          "runtime_dir_inode", "control_dir_device",
                          "control_dir_inode", "seed_device", "seed_inode",
                          "uid", "gid", "ssh_port")),
                ) for key in keys)
        and type(ci["virtual_gib"]) is int and 20 <= ci["virtual_gib"] <= 512
        and type(cr["virtual_gib"]) is int
        and type(cr["disk_sha256"]) is str
        and type(ri["disk_sha256"]) is str
        and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (cr["disk_sha256"], ri["disk_sha256"],
                              sr["seed_sha256"], sr["user_data_sha256"],
                              sr["metadata_sha256"], sr["known_hosts_sha256"],
                              sr["controller_public_sha256"],
                              sr["guest_host_public_sha256"],
                              sr["controller_private_sha256"],
                              sr["guest_host_private_sha256"]))
        and 0 < cr["disk_bytes"] <= 64 * 1024 * 1024
        and 0 < sr["seed_bytes"] <= 16 * 1024 * 1024
        and type(si["packages"]) is dict
        and all(type(value) is int and value > 0 for value in chronological)
        and list(chronological) == sorted(chronological)
        and all(record["qualified"] is False for record in
                (ci, cr, ri, rr, si, sr, li))
        and all(record["launch_authorized"] is False for record in
                (ci, cr, ri, rr, si, sr)),
        "VM provisioning chain invalid",
    )
    bind_exact_launch(launch_intent, launch_pid, launch_receipt,
                      seed_receipt, boot_id=boot_id)
    return {name + "_sha256": release.digest(raw) for name, raw in named.items()}
