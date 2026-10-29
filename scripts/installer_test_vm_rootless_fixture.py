#!/usr/bin/env python3
"""Fresh disposable installer-only rootless VM preparation.

This root-controller primitive prepares a distinct signed-image overlay and a
guest seed without sudo, Docker group membership, or a rootful daemon start.
It deliberately stops before launch, guest package installation, account
qualification, daemon start, or product dispatch. An interrupted intent is
never adopted or retried automatically. Root-private source admission and a
reviewed caller are required before privileged use.
"""
from __future__ import annotations

import os
from pathlib import Path
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_runtime as runtime
import installer_candidate_vm_seed as seed
import installer_release as release

SCHEMA = "elevenid.installer-only-rootless-disposable-fixture/v1"
VIRTUAL_GIB = 20
RECORD_SUFFIX = ".rootless-fixture-preparation-intent.json"
RESULT_SUFFIX = ".rootless-fixture-prepared.json"


def _uuid4(value: str) -> None:
    release.require(type(value) is str and str(uuid.UUID(value)) == value
                    and uuid.UUID(value).version == 4, "fixture UUID invalid")


def prepare_fixture(*, source: Path, registry: Path, vm_parent: Path,
                    runtime_parent: Path, vm_id: str, runtime_uid: int,
                    runtime_gid: int, ssh_port: int) -> dict:
    """Prepare one new overlay and closed seed; never launch or provision.

    A root-private controller must separately authenticate its exact import
    closure and the dedicated QEMU UID/GID before calling this operation.
    The source, paths and numbers are constrained again by the existing VM
    create, transfer and seed primitives. Every stage is one-shot.
    """
    _uuid4(vm_id)
    release.require(os.geteuid() == 0 and all(p.is_absolute() for p in
                    (source, registry, vm_parent, runtime_parent))
                    and type(runtime_uid) is int and type(runtime_gid) is int
                    and runtime_uid > 0 and runtime_gid > 0
                    and type(ssh_port) is int and 1024 <= ssh_port <= 65535,
                    "fixture preparation request invalid")
    provenance = create.verify_source(source)
    with ControllerLease(registry) as lease:
        parent = _directory(vm_parent)
        try:
            runtime_fd = runtime._runtime_parent(runtime_parent)
            try:
                create._rebind_directory(registry, lease.parent)
                create._rebind_directory(vm_parent, parent)
                runtime._same_path(runtime_parent, runtime_fd,
                                   runtime._runtime_parent)
                intent = {"schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
                          "source_image_sha256": provenance["image_sha256"],
                          "source_manifest_sha256": provenance["manifest_sha256"],
                          "source_signature_sha256": provenance["signature_sha256"],
                          "source_keyring_sha256": provenance["keyring_sha256"],
                          "vm_parent": str(vm_parent),
                          "vm_parent_device": os.fstat(parent).st_dev,
                          "vm_parent_inode": os.fstat(parent).st_ino,
                          "runtime_parent": str(runtime_parent),
                          "runtime_parent_device": os.fstat(runtime_fd).st_dev,
                          "runtime_parent_inode": os.fstat(runtime_fd).st_ino,
                          "runtime_uid": runtime_uid,
                          "runtime_gid": runtime_gid, "ssh_port": ssh_port,
                          "virtual_gib": VIRTUAL_GIB,
                          "guest_profile": seed.ROOTLESS_FIXTURE_PROFILE,
                          "started_at": int(time.time()),
                          "qualified": False, "launch_authorized": False,
                          "product_dispatch_authorized": False}
                intent_raw = create._write(lease.parent, vm_id + RECORD_SUFFIX,
                                           intent)
            finally:
                os.close(runtime_fd)
        finally:
            os.close(parent)
    # Any failure after intent leaves a private, attributable partial fixture.
    # No retry/adoption/cleanup is implied by this primitive.
    created = create.create_overlay(source, registry, vm_parent, vm_id=vm_id,
                                    virtual_gib=VIRTUAL_GIB)
    transferred = runtime.transfer(source, registry, vm_parent, runtime_parent,
                                  vm_id=vm_id, uid=runtime_uid, gid=runtime_gid)
    seeded = seed.prepare(source, registry, vm_parent, runtime_parent, vm_id=vm_id,
                          ssh_port=ssh_port,
                          profile=seed.ROOTLESS_FIXTURE_PROFILE)
    release.require(seeded["guest_user"] == "installer"
                    and seeded["packages"] == seed.ROOTLESS_FIXTURE_PACKAGES
                    and seeded["fixture_profile"] == seed.ROOTLESS_FIXTURE_PROFILE,
                    "fixture seed policy changed")
    with ControllerLease(registry) as lease:
        current_intent_raw, current_intent = create._read_record(
            lease.parent, vm_id + RECORD_SUFFIX)
        creation_raw, current_created = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        transfer_raw, current_transfer = create._read_record(
            lease.parent, vm_id + ".runtime-receipt.json")
        seed_raw, current_seed = create._read_record(
            lease.parent, vm_id + ".seed-receipt.json")
        release.require(current_intent_raw == intent_raw and current_intent == intent
                        and current_created == created
                        and current_transfer == transferred
                        and current_seed == seeded
                        and all(created["image"][k] == provenance[k] for k in
                                ("image_sha256", "manifest_sha256",
                                 "signature_sha256", "keyring_sha256")),
                        "fixture preparation receipts changed")
        create._rebind_directory(registry, lease.parent)
        result = {"schema": SCHEMA, "phase": "prepared", "vm_id": vm_id,
                  "intent_sha256": release.digest(intent_raw),
                  "creation_sha256": release.digest(creation_raw),
                  "transfer_sha256": release.digest(transfer_raw),
                  "seed_sha256": release.digest(seed_raw),
                  "guest_profile": seed.ROOTLESS_FIXTURE_PROFILE,
                  "runtime_uid": runtime_uid, "runtime_gid": runtime_gid,
                  "prepared_at": int(time.time()), "qualified": False,
                  "launch_authorized": False,
                  "product_dispatch_authorized": False,
                  "rootless_daemon_ready": False}
        create._write(lease.parent, vm_id + RESULT_SUFFIX, result)
        return result


def launch_fixture(*, source: Path, registry: Path, vm_parent: Path,
                   runtime_parent: Path, vm_id: str) -> dict:
    """Launch only an exact prepared fixture under the dedicated QEMU UID.

    The launch primitive holds its own one-shot intent and refuses re-entry.
    This does not admit package installation, a daemon, or product dispatch.
    """
    _uuid4(vm_id)
    release.require(os.geteuid() == 0 and all(p.is_absolute() for p in
                    (source, registry, vm_parent, runtime_parent)),
                    "fixture launch request invalid")
    with ControllerLease(registry) as lease:
        intent_raw, intent = create._read_record(lease.parent, vm_id + RECORD_SUFFIX)
        _, result = create._read_record(lease.parent, vm_id + RESULT_SUFFIX)
        seed_raw, seeded = create._read_record(lease.parent,
                                               vm_id + ".seed-receipt.json")
        creation_raw, creation = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        transfer_raw, transfer = create._read_record(
            lease.parent, vm_id + ".runtime-receipt.json")
        release.exact(intent, {"schema", "phase", "vm_id", "source_image_sha256",
                               "source_manifest_sha256", "source_signature_sha256",
                               "source_keyring_sha256", "vm_parent",
                               "vm_parent_device", "vm_parent_inode", "runtime_parent",
                               "runtime_parent_device", "runtime_parent_inode",
                               "runtime_uid", "runtime_gid", "ssh_port", "virtual_gib",
                               "guest_profile", "started_at", "qualified",
                               "launch_authorized", "product_dispatch_authorized"},
                      "fixture preparation intent")
        release.exact(result, {"schema", "phase", "vm_id", "intent_sha256",
                               "creation_sha256", "transfer_sha256", "seed_sha256",
                               "guest_profile", "runtime_uid", "runtime_gid",
                               "prepared_at", "qualified", "launch_authorized",
                               "product_dispatch_authorized", "rootless_daemon_ready"},
                      "fixture preparation result")
        release.require(intent["schema"] == result["schema"] == SCHEMA
                        and intent["phase"] == "intent"
                        and result["phase"] == "prepared"
                        and intent["vm_id"] == result["vm_id"] == vm_id
                        and result["intent_sha256"] == release.digest(intent_raw)
                        and result["creation_sha256"] == release.digest(creation_raw)
                        and result["transfer_sha256"] == release.digest(transfer_raw)
                        and result["seed_sha256"] == release.digest(seed_raw)
                        and intent["guest_profile"] == result["guest_profile"]
                        == seeded.get("fixture_profile") == seed.ROOTLESS_FIXTURE_PROFILE
                        and intent["vm_parent"] == str(vm_parent)
                        and intent["runtime_parent"] == str(runtime_parent)
                        and intent["runtime_uid"] == result["runtime_uid"]
                        and intent["runtime_gid"] == result["runtime_gid"]
                        and intent["virtual_gib"] == VIRTUAL_GIB
                        and all(creation["image"][k] == intent["source_" + k]
                                for k in ("image_sha256", "manifest_sha256",
                                          "signature_sha256", "keyring_sha256"))
                        and creation["virtual_gib"] == VIRTUAL_GIB
                        and transfer["runtime_uid"] == intent["runtime_uid"]
                        and transfer["runtime_gid"] == intent["runtime_gid"]
                        and all(value is False for value in
                                (intent["qualified"], intent["launch_authorized"],
                                 intent["product_dispatch_authorized"],
                                 result["qualified"], result["launch_authorized"],
                                 result["product_dispatch_authorized"],
                                 result["rootless_daemon_ready"])),
                        "fixture preparation chain invalid")
    verified_seed = seed.verify_seed(source, registry, vm_parent, runtime_parent,
                                    vm_id=vm_id)
    release.require(verified_seed == seeded,
                    "fixture seed changed before launch")
    return launch.launch(source, registry, vm_parent, runtime_parent, vm_id=vm_id)
