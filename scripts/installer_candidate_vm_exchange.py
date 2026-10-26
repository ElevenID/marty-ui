"""Exchange one consumed VM nonce for its signed execution grant.

The nonce is already durable before this function starts. An uncertain upload
or grant retrieval is terminal for this attempt; callers preserve every file
and reconcile the GitHub draft manually rather than retrying or dispatching.
"""
from __future__ import annotations

import os
from pathlib import Path
import time

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _read_record, _write
from installer_candidate_vm_host_preflight import verify_consumed_intent
import installer_candidate_receipt_upload as uploader
import installer_candidate_grant_receive as receiver
import installer_candidate_dispatch as dispatch
import installer_release as release
import verify_installer_provenance as provenance


def exchange(*, client, registry: Path, authorization: Path, assets: Path,
             expected: dict, gh: Path, cosign: Path, descriptor: Path,
             upload_output: Path, grant_output: Path, controller_user_id: int,
             clock=time.time, verifier=provenance.command,
             upload=uploader.upload, receive=receiver.receive) -> dict:
    """Verify, upload once, retrieve once, then reverify durable VM binding."""
    release.require(os.geteuid() == 0 and registry.is_absolute(),
                    "root controller registry required for signed exchange")
    nonce = expected["nonce"]
    ledger = registry / (nonce + ".json")
    context_file = registry / (nonce + ".context.json")
    target_file = registry / (nonce + ".target.json")
    with ControllerLease(registry) as lease:
        before = verify_consumed_intent(
            lease, registry, authorization=authorization, assets=assets,
            expected=expected, gh=gh, cosign=cosign, clock=clock,
            verifier=verifier)
        _write(lease.parent, context_file.name, expected)
        _write(lease.parent, target_file.name, before["target"])
        dispatch.registry_unchanged(lease.parent, registry)
        release.require(_read_record(lease.parent, context_file.name)[1] == expected
                        and _read_record(lease.parent, target_file.name)[1]
                        == before["target"],
                        "independent exchange inputs changed")
    run = dict(harness_source_sha=expected["harness_source_sha"],
               run_id=expected["run_id"], run_attempt=expected["run_attempt"],
               controller_user_id=controller_user_id)
    uploaded = upload(
        client=client, authorization=authorization,
        inventory=assets / "installer-inventory.json", assets=assets,
        gh=gh, cosign=cosign, descriptor=descriptor, ledger=ledger,
        output=upload_output, clock=clock, verifier=verifier, **run)
    release.require(uploaded["receipt_sha256"] == before["receipt_sha256"]
                    and uploaded["context_sha256"]
                    == release.candidate_context_sha256(expected),
                    "uploaded VM receipt differs")
    retrieved = receive(
        client=client, authorization=authorization,
        inventory=assets / "installer-inventory.json", assets=assets,
        descriptor=descriptor, ledger=ledger,
        context_file=context_file, target_file=target_file,
        gh=gh, cosign=cosign, output=grant_output, clock=clock,
        verifier=verifier, **run)
    release.require(retrieved["receipt_sha256"] == before["receipt_sha256"]
                    and retrieved["context_sha256"]
                    == release.candidate_context_sha256(expected)
                    and retrieved["target_sha256"]
                    == release.digest(release.encode(before["target"])),
                    "signed execution grant differs from consumed VM")
    with ControllerLease(registry) as lease:
        after = verify_consumed_intent(
            lease, registry, authorization=authorization, assets=assets,
            expected=expected, gh=gh, cosign=cosign, clock=clock,
            verifier=verifier)
        release.require(after["receipt_sha256"] == before["receipt_sha256"]
                        and after["intent_sha256"] == before["intent_sha256"]
                        and after["target"] == before["target"]
                        and _read_record(lease.parent, context_file.name)[1]
                        == expected and _read_record(lease.parent, target_file.name)[1]
                        == before["target"],
                        "consumed VM changed during signed exchange")
    return dict(schema="elevenid.installer-vm-signed-exchange/v1",
                nonce=nonce, intent_sha256=before["intent_sha256"],
                receipt_sha256=before["receipt_sha256"],
                target=before["target"],
                upload_sha256=release.digest(release.encode(uploaded)),
                grant_sha256=release.digest(release.encode(retrieved)),
                verified_at=int(clock()), guest_dispatched=False,
                acceptance=False)
