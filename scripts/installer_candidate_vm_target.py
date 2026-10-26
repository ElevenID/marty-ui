"""Bind an exact v2 VM target from root-held provisioning and live evidence.

This pure comparison is not an approval. Its caller must hold the controller
lease, authenticate record custody and live observation, then separately verify
signed candidate assets, host admission and nonce consumption before dispatch.
"""
from __future__ import annotations

import re
import uuid

from installer_candidate_vm_launch_evidence import bind_provisioned_launch
from installer_candidate_vm_live_observe import bind_pre_dispatch
import installer_release as release

RECORDS = {
    "creation_intent", "creation_receipt", "runtime_intent",
    "runtime_receipt", "seed_intent", "seed_receipt",
    "launch_intent", "launch_pid", "launch_receipt",
}
GUEST_FIELDS = {
    "guest_uid", "guest_user", "packages", "cloud_init_status",
    "docker_engine_id", "docker_initially_empty", "guest_architecture",
}


def bind_target(records: dict[str, bytes], initial_raw: bytes, current: dict,
                *, observation_id: str, installation_id: str, now: int) -> dict:
    """Return only coordinates proved consistent with an exact v2 launch chain."""
    release.exact(records, RECORDS, "VM provisioning records")
    release.require(type(now) is int and now > 0,
                    "VM target observation time invalid")
    for value in (observation_id, installation_id):
        release.require(type(value) is str and str(uuid.UUID(value)) == value
                        and uuid.UUID(value).version == 4,
                        "VM target UUID invalid")
    initial = release.decode(initial_raw)
    release.require(release.encode(initial) == initial_raw,
                    "VM initial evidence is not canonical")
    bound = bind_provisioned_launch(**records,
                                    boot_id=initial["controller_boot_id"])
    bind_pre_dispatch(initial_raw, current, observation_id=observation_id,
                      now=now)
    release.require(initial["record_sha256"] == current["record_sha256"]
                    == bound, "VM evidence does not bind provisioning bytes")
    creation = release.decode(records["creation_receipt"])
    runtime = release.decode(records["runtime_receipt"])
    seed = release.decode(records["seed_receipt"])
    launch = release.decode(records["launch_receipt"])
    guest = current["guest"]
    release.exact(guest, GUEST_FIELDS, "VM guest readiness")
    engine = guest["docker_engine_id"]
    identities = {
        "vm_id": launch["vm_id"],
        "controller_boot_id": launch["controller_boot_id"],
        "process_pid": launch["pid"],
        "process_start_ticks": launch["start_ticks"],
        "process_disk_fd": launch["disk_fd"],
        "disk_device": runtime["disk_device"],
        "disk_inode": runtime["disk_inode"],
        "runtime_dir_device": runtime["runtime_dir_device"],
        "runtime_dir_inode": runtime["runtime_dir_inode"],
        "control_dir_device": seed["control_dir_device"],
        "control_dir_inode": seed["control_dir_inode"],
    }
    release.require(
        all(type(initial[key]) is type(value) and initial[key] == value
            for key, value in identities.items())
        and creation["vm_id"] == launch["vm_id"]
        and type(guest["guest_uid"]) is int and guest["guest_uid"] > 0
        and type(guest["guest_user"]) is str
        and guest["guest_user"] == seed["guest_user"]
        and type(guest["packages"]) is dict
        and guest["packages"] == seed["packages"]
        and type(guest["cloud_init_status"]) is str
        and guest["cloud_init_status"] == "done"
        and type(guest["guest_architecture"]) is str
        and guest["guest_architecture"] == "x86_64"
        and guest["docker_initially_empty"] is True
        and type(engine) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:-]{7,127}", engine),
        "VM live target differs from provisioning or guest policy",
    )
    disk_path = launch["runtime_dir"] + "/disk.qcow2"
    disk_id = release.digest(release.encode(dict(
        vm_id=launch["vm_id"], path=disk_path,
        device=runtime["disk_device"], inode=runtime["disk_inode"])))
    return dict(
        target=dict(guest_id=launch["vm_id"], disk_id=disk_id,
                    engine_id=engine, installation_id=installation_id),
        ssh=dict(host="127.0.0.1", port=seed["ssh_port"],
                 user=seed["guest_user"], control_dir=seed["control_dir"],
                 controller_key_sha256=seed["controller_private_sha256"],
                 known_hosts_sha256=seed["known_hosts_sha256"]),
        provisioning_sha256=bound,
        initial_guest_readiness_sha256=release.digest(initial_raw),
        pre_dispatch_sha256=release.digest(release.encode(current)),
        qualified=False, dispatch_authorized=False,
    )
