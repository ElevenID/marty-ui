"""Bind signed candidate inputs to a held-lease v2 VM host admission.

This produces controller-owned evidence before nonce consumption. A passing
preflight is neither dispatch permission nor installed release acceptance.
The caller must retain the lease, recheck freshness and consume the nonce once.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import time

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _read_record, _write
from installer_candidate_vm_live_observe import RECORDS, observe
from installer_candidate_vm_runtime import _same_path
from installer_candidate_vm_target import bind_target
import installer_candidate_dispatch as dispatch
import installer_candidate_receipt_upload as uploader
import installer_candidate_vm_host_probe as host_probe
from installer_acceptance_runner import host_admission
import installer_release as release
import verify_installer_provenance as provenance

SCHEMA = "elevenid.installer-vm-host-preflight/v1"
CONSUMPTION_INTENT_SCHEMA = "elevenid.installer-vm-consumption-intent/v1"
CONSUMPTION_INTENT_FIELDS = {
    "schema", "nonce", "vm_id", "installation_id", "preflight_observation_id",
    "consumption_observation_id", "preflight_sha256",
    "consumption_observation_sha256", "host_observation_sha256",
    "authorization_sha256", "inventory_sha256", "context_sha256", "target",
    "consumed_at", "nonce_consumed", "dispatch_authorized",
}


def _raw_at(parent: int, name: str, raw: bytes) -> None:
    release.require(name.endswith(".host-observation.json") and "/" not in name
                    and type(raw) is bytes and 0 < len(raw) <= 65536,
                    "VM raw host evidence invalid")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        os.fsync(parent)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent)
    finally:
        os.close(fd)


def _unchanged_raw(parent: int, name: str, raw: bytes) -> None:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                 | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        held = os.fstat(fd)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        release.require(stat.S_ISREG(held.st_mode) and held.st_uid == 0
                        and held.st_nlink == 1
                        and stat.S_IMODE(held.st_mode) == 0o600
                        and held.st_size == len(raw)
                        and identity(before) == identity(held),
                        "VM raw host evidence changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            release.require(stream.read(len(raw) + 1) == raw,
                            "VM raw host evidence changed")
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        release.require(identity(after) == identity(held)
                        and identity(os.fstat(fd)) == identity(held),
                        "VM raw host evidence changed")
    finally:
        os.close(fd)


def _raw_bytes_at(parent: int, name: str) -> bytes:
    release.require((name == "host-observation.json"
                     or name.endswith(".host-observation.json"))
                    and "/" not in name,
                    "VM raw host evidence name invalid")
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    release.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                    and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o600
                    and 0 < before.st_size <= 65536,
                    "VM raw host evidence custody invalid")
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                 | os.O_CLOEXEC, dir_fd=parent)
    try:
        held = os.fstat(fd)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        release.require(stat.S_ISREG(held.st_mode)
                        and identity(held) == identity(before),
                        "VM raw host evidence changed")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, before.st_size - len(raw))
            release.require(bool(chunk), "VM raw host evidence truncated")
            raw.extend(chunk)
        release.require(identity(os.fstat(fd)) == identity(before)
                        and identity(os.stat(name, dir_fd=parent,
                                             follow_symlinks=False)) == identity(before),
                        "VM raw host evidence changed")
        return bytes(raw)
    finally:
        os.close(fd)


def preflight(lease: ControllerLease, registry: Path, runtime_parent: Path, *,
              vm_id: str, installation_id: str, observation_id: str,
              final_observation_id: str, authorization: Path, assets: Path,
              expected: dict, gh: Path, cosign: Path, clock=time.time,
              verifier=provenance.command, guest_probe=host_probe.probe) -> dict:
    """Authenticate, probe and admit the exact same live VM without consuming."""
    release.require(os.geteuid() == 0 and lease.registry == registry
                    and lease.parent is not None and lease.owner_pid == os.getpid(),
                    "root controller lease required for host preflight")
    _same_path(registry, lease.parent, dispatch._directory)
    inventory = assets / "installer-inventory.json"
    first_auth, first_inventory = uploader.authenticate(
        authorization, inventory, assets, gh, cosign, runner=verifier)
    release.bind_candidate_authorization(
        first_auth, first_inventory, expected=expected, now=int(clock()))
    source = dispatch.verified_harness_script(
        expected["harness_source_sha"], "installer_host_probe.py")
    source_sha256 = release.digest(source.encode("utf-8"))
    initial_raw, _ = _read_record(
        lease.parent, vm_id + ".guest-readiness.json")
    records = {name.replace("-", "_"): _read_record(
        lease.parent, vm_id + "." + name + ".json")[0]
        for name in RECORDS}
    started_at = int(clock())
    first = observe(registry, runtime_parent, vm_id=vm_id,
                    pre_dispatch_id=observation_id, lease=lease)
    first_bound = bind_target(records, initial_raw, first,
                              observation_id=observation_id,
                              installation_id=installation_id, now=int(clock()))
    probe_started_at = int(clock())
    raw = guest_probe(first_bound, expected["harness_source_sha"])
    probe_finished_at = int(clock())
    release.require(0 < probe_started_at <= probe_finished_at,
                    "VM host probe time invalid")
    raw_name = vm_id + "." + observation_id + ".host-observation.json"
    _same_path(registry, lease.parent, dispatch._directory)
    _raw_at(lease.parent, raw_name, raw)
    second_auth, second_inventory = uploader.authenticate(
        authorization, inventory, assets, gh, cosign, runner=verifier)
    release.require((second_auth, second_inventory)
                    == (first_auth, first_inventory),
                    "signed candidate inputs changed during host probe")
    release.bind_candidate_authorization(
        second_auth, second_inventory, expected=expected, now=int(clock()))
    release.require(release.digest(dispatch.verified_harness_script(
        expected["harness_source_sha"], "installer_host_probe.py").encode("utf-8"))
                    == source_sha256, "signed host probe source changed")
    final = observe(registry, runtime_parent, vm_id=vm_id,
                    pre_dispatch_id=final_observation_id, lease=lease)
    final_bound = bind_target(records, initial_raw, final,
                              observation_id=final_observation_id,
                              installation_id=installation_id, now=int(clock()))
    release.require(first_bound["target"] == final_bound["target"]
                    and first_bound["ssh"] == final_bound["ssh"]
                    and first_bound["provisioning_sha256"]
                    == final_bound["provisioning_sha256"]
                    and first_bound["initial_guest_readiness_sha256"]
                    == final_bound["initial_guest_readiness_sha256"],
                    "VM target changed during host probe")
    host_admission(raw, final_bound["target"]["engine_id"])
    release.require(0 <= int(clock()) - probe_finished_at <= 60,
                    "VM host measurement is stale")
    release.bind_candidate_authorization(
        second_auth, second_inventory, expected=expected, now=int(clock()))
    _same_path(registry, lease.parent, dispatch._directory)
    _unchanged_raw(lease.parent, raw_name, raw)
    release.require(all(_read_record(
        lease.parent, vm_id + "." + name + ".json")[0]
        == records[name.replace("-", "_")] for name in RECORDS)
        and _read_record(lease.parent, vm_id + ".guest-readiness.json")[0]
        == initial_raw, "VM preflight inputs changed")
    published_at = int(clock())
    release.require(0 <= published_at - probe_finished_at <= 60,
                    "VM host measurement is stale")
    record = dict(schema=SCHEMA, vm_id=vm_id,
                  installation_id=installation_id, target=final_bound["target"],
                  ssh=final_bound["ssh"],
                  provisioning_sha256=final_bound["provisioning_sha256"],
                  initial_guest_readiness_sha256=release.digest(initial_raw),
                  first_observation_sha256=first_bound["pre_dispatch_sha256"],
                  final_observation_sha256=final_bound["pre_dispatch_sha256"],
                  host_observation_sha256=release.digest(raw),
                  host_probe_source_sha256=source_sha256,
                  authorization_sha256=release.digest(first_auth),
                  inventory_sha256=release.digest(first_inventory),
                  context_sha256=release.candidate_context_sha256(expected),
                  started_at=started_at, probe_started_at=probe_started_at,
                  probe_finished_at=probe_finished_at,
                  observed_at=published_at,
                  host_admission_passed=True, nonce_consumed=False,
                  qualified=False, dispatch_authorized=False)
    _write(lease.parent, vm_id + "." + observation_id + ".host-preflight.json",
           record)
    _same_path(registry, lease.parent, dispatch._directory)
    return record


def consume_preflight(lease: ControllerLease, registry: Path, runtime_parent: Path, *,
                      vm_id: str, installation_id: str, observation_id: str,
                      consumption_observation_id: str, preflight_record: dict,
                      authorization: Path, assets: Path, expected: dict,
                      gh: Path, cosign: Path, clock=time.time,
                      verifier=provenance.command) -> bytes:
    """Rebind a fresh live VM and durably consume its one candidate nonce."""
    release.require(os.geteuid() == 0 and lease.registry == registry
                    and lease.parent is not None and lease.owner_pid == os.getpid(),
                    "root controller lease required for consumption")
    _same_path(registry, lease.parent, dispatch._directory)
    name = vm_id + "." + observation_id + ".host-preflight.json"
    preflight_raw, persisted = _read_record(lease.parent, name)
    release.require(persisted == preflight_record and persisted["schema"] == SCHEMA
                    and persisted["vm_id"] == vm_id
                    and persisted["installation_id"] == installation_id
                    and persisted["host_admission_passed"] is True
                    and persisted["nonce_consumed"] is False
                    and persisted["qualified"] is False
                    and persisted["dispatch_authorized"] is False,
                    "VM preflight record differs")
    now = int(clock())
    release.require(type(persisted["probe_finished_at"]) is int
                    and 0 <= now - persisted["probe_finished_at"] <= 60,
                    "VM host measurement is stale")
    raw_name = vm_id + "." + observation_id + ".host-observation.json"
    raw = _raw_bytes_at(lease.parent, raw_name)
    release.require(release.digest(raw) == persisted["host_observation_sha256"],
                    "VM host evidence differs")
    _unchanged_raw(lease.parent, raw_name, raw)
    host_admission(raw, persisted["target"]["engine_id"])
    a, i = uploader.authenticate(authorization, assets / "installer-inventory.json",
                                 assets, gh, cosign, runner=verifier)
    release.bind_candidate_authorization(a, i, expected=expected, now=int(clock()))
    release.require(release.digest(a) == persisted["authorization_sha256"]
                    and release.digest(i) == persisted["inventory_sha256"]
                    and release.candidate_context_sha256(expected)
                    == persisted["context_sha256"],
                    "VM candidate differs from preflight")
    source = dispatch.verified_harness_script(
        expected["harness_source_sha"], "installer_host_probe.py")
    release.require(release.digest(source.encode("utf-8"))
                    == persisted["host_probe_source_sha256"],
                    "signed host probe source changed")
    initial_raw, _ = _read_record(lease.parent, vm_id + ".guest-readiness.json")
    records = {part.replace("-", "_"): _read_record(
        lease.parent, vm_id + "." + part + ".json")[0] for part in RECORDS}
    current = observe(registry, runtime_parent, vm_id=vm_id,
                      pre_dispatch_id=consumption_observation_id, lease=lease)
    observation_name = vm_id + ".pre-dispatch-" + consumption_observation_id + ".json"
    observation_raw, observation_record = _read_record(lease.parent, observation_name)
    release.require(observation_record == current
                    and observation_raw == release.encode(current),
                    "VM consumption observation differs")
    bound = bind_target(records, initial_raw, current,
                        observation_id=consumption_observation_id,
                        installation_id=installation_id, now=int(clock()))
    release.require(bound["target"] == persisted["target"]
                    and bound["ssh"] == persisted["ssh"]
                    and bound["provisioning_sha256"]
                    == persisted["provisioning_sha256"]
                    and bound["initial_guest_readiness_sha256"]
                    == persisted["initial_guest_readiness_sha256"],
                    "VM target changed before nonce consumption")
    release.require(0 <= int(clock()) - persisted["probe_finished_at"] <= 60,
                    "VM host measurement is stale")
    _same_path(registry, lease.parent, dispatch._directory)
    _unchanged_raw(lease.parent, raw_name, raw)
    release.require(all(_read_record(
        lease.parent, vm_id + "." + part + ".json")[0]
        == records[part.replace("-", "_")] for part in RECORDS)
        and _read_record(lease.parent, vm_id + ".guest-readiness.json")[0]
        == initial_raw and _read_record(lease.parent, name)[1] == persisted,
        "VM preflight inputs changed")
    target = bound["target"]
    consumed_at = int(clock())
    release.require(0 <= consumed_at - persisted["probe_finished_at"] <= 60,
                    "VM host measurement is stale")
    intent_name = expected["nonce"] + ".vm-consumption-intent.json"
    intent = dict(schema=CONSUMPTION_INTENT_SCHEMA, nonce=expected["nonce"],
                  vm_id=vm_id, installation_id=installation_id,
                  preflight_observation_id=observation_id,
                  consumption_observation_id=consumption_observation_id,
                  preflight_sha256=release.digest(preflight_raw),
                  consumption_observation_sha256=release.digest(observation_raw),
                  host_observation_sha256=release.digest(raw),
                  authorization_sha256=release.digest(a),
                  inventory_sha256=release.digest(i),
                  context_sha256=release.candidate_context_sha256(expected),
                  target=target, consumed_at=consumed_at,
                  nonce_consumed=False, dispatch_authorized=False)
    _write(lease.parent, intent_name, intent)
    _same_path(registry, lease.parent, dispatch._directory)
    release.require(_read_record(lease.parent, intent_name)[1] == intent
                    and _read_record(lease.parent, observation_name)[0]
                    == observation_raw and _read_record(lease.parent, name)[0]
                    == preflight_raw,
                    "VM consumption intent inputs changed")
    _unchanged_raw(lease.parent, raw_name, raw)
    fresh_now = int(clock())
    release.require(type(current["observed_at"]) is int
                    and 0 <= fresh_now - current["observed_at"] <= 60
                    and 0 <= fresh_now - persisted["probe_finished_at"] <= 60,
                    "VM consumption evidence is stale")
    return lease.consume(a, i, expected=expected, guest_id=target["guest_id"],
                         disk_id=target["disk_id"], engine_id=target["engine_id"],
                         installation_id=target["installation_id"],
                         consumed_at=consumed_at, now=fresh_now)


def verify_consumed_intent(lease: ControllerLease, registry: Path, *,
                           authorization: Path, assets: Path, expected: dict,
                           gh: Path, cosign: Path, clock=time.time,
                           verifier=provenance.command) -> dict:
    """Prove a durable nonce ledger matches its exact controller VM evidence."""
    release.require(os.geteuid() == 0 and lease.registry == registry
                    and lease.parent is not None and lease.owner_pid == os.getpid(),
                    "root controller lease required for consumed VM verification")
    _same_path(registry, lease.parent, dispatch._directory)
    a, i = uploader.authenticate(authorization, assets / "installer-inventory.json",
                                 assets, gh, cosign, runner=verifier)
    now = int(clock())
    release.bind_candidate_authorization(a, i, expected=expected, now=now)
    nonce = expected["nonce"]
    intent_raw, intent = _read_record(
        lease.parent, nonce + ".vm-consumption-intent.json")
    release.exact(intent, CONSUMPTION_INTENT_FIELDS, "VM consumption intent")
    release.require(intent["schema"] == CONSUMPTION_INTENT_SCHEMA
                    and intent["nonce"] == nonce
                    and intent["nonce_consumed"] is False
                    and intent["dispatch_authorized"] is False
                    and intent["authorization_sha256"] == release.digest(a)
                    and intent["inventory_sha256"] == release.digest(i)
                    and intent["context_sha256"]
                    == release.candidate_context_sha256(expected),
                    "VM consumption intent candidate differs")
    release.exact(intent["target"], dispatch.TARGET_FIELDS,
                  "VM consumption intent target")
    vm_id = intent["vm_id"]
    preflight_id = intent["preflight_observation_id"]
    consumption_id = intent["consumption_observation_id"]
    preflight_raw, preflight_record = _read_record(
        lease.parent, vm_id + "." + preflight_id + ".host-preflight.json")
    observation_raw, observation_record = _read_record(
        lease.parent, vm_id + ".pre-dispatch-" + consumption_id + ".json")
    host_raw = _raw_bytes_at(
        lease.parent, vm_id + "." + preflight_id + ".host-observation.json")
    release.require(release.digest(preflight_raw) == intent["preflight_sha256"]
                    and release.digest(observation_raw)
                    == intent["consumption_observation_sha256"]
                    and release.digest(host_raw) == intent["host_observation_sha256"]
                    and preflight_record["schema"] == SCHEMA
                    and preflight_record["vm_id"] == vm_id
                    and preflight_record["installation_id"]
                    == intent["installation_id"]
                    and preflight_record["target"] == intent["target"]
                    and preflight_record["host_admission_passed"] is True
                    and preflight_record["nonce_consumed"] is False
                    and preflight_record["qualified"] is False
                    and preflight_record["dispatch_authorized"] is False
                    and preflight_record["authorization_sha256"] == release.digest(a)
                    and preflight_record["inventory_sha256"] == release.digest(i)
                    and preflight_record["context_sha256"]
                    == release.candidate_context_sha256(expected)
                    and preflight_record["host_observation_sha256"]
                    == intent["host_observation_sha256"]
                    and observation_record["vm_id"] == vm_id
                    and observation_record["observation_id"] == consumption_id,
                    "VM consumption evidence differs")
    host_admission(host_raw, intent["target"]["engine_id"])
    _unchanged_raw(lease.parent,
                   vm_id + "." + preflight_id + ".host-observation.json", host_raw)
    ledger_raw, ledger = _read_record(lease.parent, nonce + ".json")
    bound = release.bind_controller_consumption(
        ledger_raw, a, i, expected=expected,
        expected_engine=intent["target"]["engine_id"], now=int(clock()))
    release.require(ledger == bound and ledger["consumed_at"] == intent["consumed_at"]
                    and all(bound[key] == value for key, value in intent["target"].items()),
                    "VM consumed nonce differs from intent")
    _same_path(registry, lease.parent, dispatch._directory)
    release.require(_read_record(
        lease.parent, nonce + ".vm-consumption-intent.json")[0] == intent_raw
        and _read_record(lease.parent, nonce + ".json")[0] == ledger_raw
        and _read_record(
            lease.parent, vm_id + "." + preflight_id + ".host-preflight.json")[0]
        == preflight_raw
        and _read_record(
            lease.parent, vm_id + ".pre-dispatch-" + consumption_id + ".json")[0]
        == observation_raw
        and _raw_bytes_at(
            lease.parent, vm_id + "." + preflight_id + ".host-observation.json")
        == host_raw,
        "VM consumed nonce evidence changed")
    return dict(intent_sha256=release.digest(intent_raw),
                receipt_sha256=release.digest(ledger_raw), target=intent["target"],
                ssh=preflight_record["ssh"],
                nonce=nonce, verified_at=int(clock()),
                guest_dispatched=False, acceptance=False)
