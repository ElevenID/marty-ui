"""Bind a controller-approved VM record to an observed installer target.

Only an independent trusted provisioner may create this record in the
outside-guest controller registry. Parsing it, or finding a root-owned file,
does not prove its producer or authorize dispatch. The controller must verify
fresh image/overlay creation, hold the registry lease, and reobserve the live
VM before consuming a nonce.
"""
from __future__ import annotations

from pathlib import Path
import uuid

import installer_candidate_qemu_observe as observer
import installer_release as release

SCHEMA = "elevenid.installer-vm-approval/v1"
FIELDS = {
    "schema", "purpose", "approval_id", "installation_id", "approved_at",
    "expires_at", "controller_boot_id", "vm_id", "vm_uid", "vm_gid",
    "vm_dir_path", "vm_dir_device", "vm_dir_inode", "vm_config_sha256",
    "vm_executable_sha256", "vm_pid", "vm_start_ticks", "disk_path",
    "disk_device", "disk_inode", "disk_id", "base_image_sha256",
    "base_manifest_sha256", "overlay_creation_receipt_sha256", "ssh_port",
    "guest_user", "guest_uid", "known_hosts_sha256", "controller_key_sha256",
    "engine_id", "candidate_context_sha256", "authorization_sha256", "nonce",
}
HASHES = {
    "vm_config_sha256", "vm_executable_sha256", "disk_id",
    "base_image_sha256", "base_manifest_sha256", "overlay_creation_receipt_sha256",
    "known_hosts_sha256", "controller_key_sha256", "candidate_context_sha256",
    "authorization_sha256", "nonce",
}
INTEGERS = {
    "approved_at", "expires_at", "vm_uid", "vm_gid", "vm_dir_device",
    "vm_dir_inode", "vm_pid", "disk_device", "disk_inode", "ssh_port",
    "guest_uid",
}


def canonical_uuid(value: object) -> None:
    release.require(type(value) is str and str(uuid.UUID(value)) == value
                    and uuid.UUID(value).version == 4, "approval UUID invalid")


def validate(record: dict) -> None:
    """Validate shape only; approval provenance is a separate mandatory gate."""
    release.exact(record, FIELDS, "VM approval")
    release.require(record["schema"] == SCHEMA
                    and record["purpose"] in ("engineering-trial", "candidate-acceptance"),
                    "VM approval scope invalid")
    for field in ("approval_id", "installation_id", "vm_id"):
        canonical_uuid(record[field])
    release.require(type(record["controller_boot_id"]) is str
                    and str(uuid.UUID(record["controller_boot_id"]))
                    == record["controller_boot_id"],
                    "controller boot identity invalid")
    for field in HASHES:
        release.sha(record[field], 64)
    for field in INTEGERS:
        release.require(type(record[field]) is int and record[field] >= 0,
                        "VM approval integer invalid")
    release.require(0 < record["approved_at"] < record["expires_at"]
                    <= record["approved_at"] + 3600
                    and record["vm_pid"] > 4 and record["guest_uid"] > 0
                    and 1 <= record["ssh_port"] <= 65535,
                    "VM approval lifetime or account invalid")
    for field in ("vm_dir_path", "disk_path"):
        value = record[field]
        release.require(type(value) is str and Path(value).is_absolute()
                        and ".." not in Path(value).parts
                        and Path(value).as_posix() == value,
                        "VM approval path invalid")
    release.require(record["disk_path"] == record["vm_dir_path"] + "/disk.qcow2"
                    and type(record["vm_start_ticks"]) is str
                    and record["vm_start_ticks"].isdecimal()
                    and type(record["guest_user"]) is str
                    and record["guest_user"].isidentifier()
                    and type(record["engine_id"]) is str and record["engine_id"]
                    and type(record["purpose"]) is str,
                    "VM approval identity invalid")


def _record(approval: bytes, *, now: int) -> dict:
    record = release.decode(approval)
    release.require(release.encode(record) == approval,
                    "VM approval encoding is not canonical")
    validate(record)
    release.require(record["purpose"] == "candidate-acceptance"
                    and type(now) is int and record["approved_at"] <= now
                    and now < record["expires_at"], "VM approval unavailable")
    return record


def _fresh(record: dict, observation: dict, now: int) -> None:
    observed_at = observation["observed_at"]
    release.require(type(observed_at) is int and observed_at > 0
                    and record["approved_at"] - 60 <= observed_at <= now
                    and now - observed_at <= 60,
                    "VM observation is not fresh")


def _candidate(record: dict, context: dict, authorization: bytes,
               creation_receipt: bytes) -> None:
    release.require(record["candidate_context_sha256"]
                    == release.candidate_context_sha256(context)
                    and record["authorization_sha256"] == release.digest(authorization)
                    and record["nonce"] == context["nonce"]
                    and record["overlay_creation_receipt_sha256"]
                    == release.digest(creation_receipt),
                    "VM approval candidate or creation differs")


def _identity(record: dict, observation: dict) -> None:
    target = observation["target"]
    fields = {
        "controller_boot_id": "vm_boot_id", "vm_id": ("target", "guest_id"),
        "vm_uid": "vm_uid", "vm_gid": "vm_gid", "vm_dir_path": "vm_dir_path",
        "vm_dir_device": "vm_dir_device", "vm_dir_inode": "vm_dir_inode",
        "vm_config_sha256": "vm_config_sha256",
        "vm_executable_sha256": "vm_executable_sha256", "vm_pid": "vm_pid",
        "vm_start_ticks": "vm_start_ticks", "disk_path": "vm_disk_path",
        "disk_device": "vm_disk_device", "disk_inode": "vm_disk_inode",
        "disk_id": ("target", "disk_id"), "ssh_port": "ssh_port",
        "guest_user": "guest_user", "guest_uid": "guest_uid",
        "known_hosts_sha256": "known_hosts_sha256",
        "controller_key_sha256": "controller_key_sha256",
        "engine_id": ("target", "engine_id"),
        "installation_id": ("target", "installation_id"),
    }
    for approved, observed in fields.items():
        actual = target[observed[1]] if isinstance(observed, tuple) else observation[observed]
        release.require(type(record[approved]) is type(actual)
                        and record[approved] == actual,
                        "approved VM differs from observation")


def bind_observation(approval: bytes, observation: dict, *, context: dict,
                     authorization: bytes, creation_receipt: bytes,
                     now: int) -> str:
    """Compare independently produced approval and fresh initial evidence.

    This returns the exact approval-byte hash for a durable controller companion.
    The caller must authenticate the approval producer, creation receipt and
    candidate inputs; this comparison alone grants no dispatch.
    """
    record = _record(approval, now=now)
    observer.validate_initial(observation, record["installation_id"])
    _fresh(record, observation, now)
    _candidate(record, context, authorization, creation_receipt)
    _identity(record, observation)
    return release.digest(approval)


def bind_pre_dispatch(approval: bytes, initial: bytes, current: dict, *,
                      approved_initial_sha256: str, context: dict,
                      authorization: bytes, creation_receipt: bytes,
                      now: int) -> str:
    """Bind fresh pre-dispatch evidence to the exact earlier initial observation.

    The caller must supply the authenticated initial hash from its durable
    companion, hold the controller lease, and reobserve the live VM immediately
    before nonce consumption. This pure comparison does none of those actions.
    """
    record = _record(approval, now=now)
    release.sha(approved_initial_sha256, 64)
    release.require(release.digest(initial) == approved_initial_sha256,
                    "approved initial observation differs")
    first = release.decode(initial)
    release.require(release.encode(first) == initial,
                    "initial observation encoding is not canonical")
    observer.validate_initial(first, record["installation_id"])
    initial_at = first["observed_at"]
    release.require(type(initial_at) is int and initial_at > 0
                    and record["approved_at"] - 60 <= initial_at
                    and initial_at < record["expires_at"],
                    "initial observation time invalid")
    expected = (set(first) - {"initial_docker_clean"}
                | {"initial_observation_sha256", "docker_clean_at_observation"})
    release.require(type(current) is dict and set(current) == expected
                    and current["schema"] == first["schema"]
                    and current["observation_phase"] == "pre-dispatch"
                    and current["initial_observation_sha256"] == approved_initial_sha256
                    and current["docker_clean_at_observation"] is True
                    and current["dispatch_authorized"] is False
                    and current["clean_host_qualified"] is False
                    and current["capacity_qualified"] is False,
                    "pre-dispatch observation invalid")
    release.require(type(current["observed_at"]) is int
                    and initial_at <= current["observed_at"],
                    "pre-dispatch observation order invalid")
    _fresh(record, current, now)
    observer.require_same_vm(first, current)
    _candidate(record, context, authorization, creation_receipt)
    _identity(record, current)
    return release.digest(approval)
