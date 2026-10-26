"""Exchange one consumed VM nonce for its signed execution grant.

The nonce is already durable before this function starts. An uncertain upload
or grant retrieval is terminal for this attempt; callers preserve every file
and reconcile the GitHub draft manually rather than retrying or dispatching.
"""
from __future__ import annotations

import os
from pathlib import Path
import time
import uuid

from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _read_record, _write
from installer_candidate_vm_host_preflight import preflight, verify_consumed_intent
import installer_candidate_vm_host_probe as host_probe
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
                        and after["ssh"] == before["ssh"]
                        and _read_record(lease.parent, context_file.name)[1]
                        == expected and _read_record(lease.parent, target_file.name)[1]
                        == before["target"],
                        "consumed VM changed during signed exchange")
    return dict(schema="elevenid.installer-vm-signed-exchange/v1",
                nonce=nonce, intent_sha256=before["intent_sha256"],
                receipt_sha256=before["receipt_sha256"],
                target=before["target"], ssh=before["ssh"],
                upload_sha256=release.digest(release.encode(uploaded)),
                grant_sha256=release.digest(release.encode(retrieved)),
                verified_at=int(clock()), guest_dispatched=False,
                acceptance=False)


def dispatch_once(*, registry: Path, runtime_parent: Path, vm_id: str,
                  installation_id: str, observation_id: str,
                  final_observation_id: str, exchange_result: dict,
                  authorization: Path, assets: Path, expected: dict,
                  gh: Path, cosign: Path, grants: Path, ssh: Path, scp: Path,
                  clock=time.time, verifier=provenance.command,
                  guest_probe=host_probe.probe,
                  invoke=dispatch.dispatch) -> dict:
    """Re-admit the same live VM and invoke the signed installer once."""
    release.require(os.geteuid() == 0 and registry.is_absolute(),
                    "root controller required for VM dispatch")
    nonce = expected["nonce"]
    ledger = registry / (nonce + ".json")
    context_file = registry / (nonce + ".context.json")
    target_file = registry / (nonce + ".target.json")
    with ControllerLease(registry) as lease:
        bound = verify_consumed_intent(
            lease, registry, authorization=authorization, assets=assets,
            expected=expected, gh=gh, cosign=cosign, clock=clock,
            verifier=verifier)
        release.require(exchange_result["schema"]
                        == "elevenid.installer-vm-signed-exchange/v1"
                        and exchange_result["nonce"] == nonce
                        and exchange_result["intent_sha256"] == bound["intent_sha256"]
                        and exchange_result["receipt_sha256"] == bound["receipt_sha256"]
                        and exchange_result["target"] == bound["target"]
                        and exchange_result["ssh"] == bound["ssh"]
                        and exchange_result["guest_dispatched"] is False
                        and exchange_result["acceptance"] is False,
                        "signed exchange differs from consumed VM")
        fresh = preflight(
            lease, registry, runtime_parent, vm_id=vm_id,
            installation_id=installation_id, observation_id=observation_id,
            final_observation_id=final_observation_id,
            authorization=authorization, assets=assets, expected=expected,
            gh=gh, cosign=cosign, clock=clock, verifier=verifier,
            guest_probe=guest_probe)
        release.require(fresh["target"] == bound["target"]
                        and fresh["ssh"] == bound["ssh"],
                        "post-grant VM differs from consumed target")
        release.require(_read_record(lease.parent, context_file.name)[1] == expected
                        and _read_record(lease.parent, target_file.name)[1]
                        == bound["target"],
                        "independent dispatch inputs changed")
        a, receipt, i, _ = dispatch.verify(
            assets=assets, grants=grants, context=expected,
            target=bound["target"], ledger=ledger, gh=gh, cosign=cosign,
            now=int(clock()), runner=verifier)
        release.require(release.digest(receipt) == bound["receipt_sha256"]
                        and release.digest(a) == fresh["authorization_sha256"]
                        and release.digest(i) == fresh["inventory_sha256"],
                        "signed grant differs from fresh VM admission")
        control_dir = Path(fresh["ssh"]["control_dir"])
        key = control_dir / "controller_ed25519"
        known_hosts = control_dir / "known_hosts"
        release.require(dispatch.private_file(key, 8192)[0]
                        == fresh["ssh"]["controller_key_sha256"]
                        and dispatch.private_file(known_hosts, 4096)[0]
                        == fresh["ssh"]["known_hosts_sha256"],
                        "VM dispatch SSH material differs")
        rebound = verify_consumed_intent(
            lease, registry, authorization=authorization, assets=assets,
            expected=expected, gh=gh, cosign=cosign, clock=clock,
            verifier=verifier)
        release.require(rebound["intent_sha256"] == bound["intent_sha256"]
                        and rebound["receipt_sha256"] == bound["receipt_sha256"]
                        and rebound["target"] == bound["target"]
                        and rebound["ssh"] == bound["ssh"],
                        "consumed VM changed before dispatch")
        preflight_raw, preflight_record = _read_record(
            lease.parent, vm_id + "." + observation_id + ".host-preflight.json")
        release.require(preflight_record == fresh,
                        "fresh VM preflight changed before dispatch")
        approval_name = nonce + ".vm-dispatch-approval.json"
        approval = dict(schema="elevenid.installer-vm-dispatch-approval/v1",
                        nonce=nonce, vm_id=vm_id,
                        installation_id=installation_id,
                        exchange_sha256=release.digest(release.encode(exchange_result)),
                        intent_sha256=bound["intent_sha256"],
                        receipt_sha256=bound["receipt_sha256"],
                        fresh_preflight_sha256=release.digest(preflight_raw),
                        target=bound["target"], ssh=bound["ssh"],
                        approved_at=int(clock()),
                        installation_ready=False, acceptance=False)
        approval_raw = _write(lease.parent, approval_name, approval)
        dispatch.registry_unchanged(lease.parent, registry)
        release.require(_read_record(lease.parent, approval_name)[1] == approval
                        and _read_record(
                            lease.parent,
                            vm_id + "." + observation_id + ".host-preflight.json")[0]
                        == preflight_raw
                        and 0 <= int(clock()) - fresh["probe_finished_at"] <= 60,
                        "VM dispatch approval changed or expired")
        def admission_gate(stage):
            release.require(stage in ("setup", "transfer", "invoke"),
                            "VM dispatch stage invalid")
            check_id, final_id = str(uuid.uuid4()), str(uuid.uuid4())
            current = preflight(
                lease, registry, runtime_parent, vm_id=vm_id,
                installation_id=installation_id, observation_id=check_id,
                final_observation_id=final_id,
                authorization=authorization, assets=assets, expected=expected,
                gh=gh, cosign=cosign, clock=clock, verifier=verifier,
                guest_probe=guest_probe)
            release.require(current["target"] == bound["target"]
                            and current["ssh"] == bound["ssh"],
                            "VM changed before remote dispatch stage")
            stage_raw, stage_record = _read_record(
                lease.parent, vm_id + "." + check_id + ".host-preflight.json")
            release.require(stage_record == current
                            and 0 <= int(clock()) - current["probe_finished_at"] <= 60,
                            "VM remote dispatch admission is stale")
            stage_name = nonce + ".vm-dispatch-" + check_id + ".json"
            _write(lease.parent, stage_name, dict(
                schema="elevenid.installer-vm-dispatch-stage/v1",
                nonce=nonce, stage=stage, vm_id=vm_id,
                approval_sha256=release.digest(approval_raw),
                preflight_sha256=release.digest(stage_raw),
                target=bound["target"], ssh=bound["ssh"],
                observed_at=int(clock()), installation_ready=False,
                acceptance=False))
            dispatch.registry_unchanged(lease.parent, registry)
            release.require(_read_record(lease.parent, stage_name)[1]["stage"] == stage
                            and _read_record(
                                lease.parent,
                                vm_id + "." + check_id + ".host-preflight.json")[0]
                            == stage_raw
                            and 0 <= int(clock()) - current["probe_finished_at"] <= 60,
                            "VM remote dispatch stage changed or expired")
        result = invoke(
            assets=assets, grants=grants, context_file=context_file,
            target_file=target_file, ledger=ledger, gh=gh, cosign=cosign,
            ssh=ssh, scp=scp, key=key, known_hosts=known_hosts,
            host=fresh["ssh"]["host"], port=fresh["ssh"]["port"],
            user=fresh["ssh"]["user"], home="/home/" + fresh["ssh"]["user"],
            clock=clock, verifier=verifier, lease=lease,
            approved_ssh=dict(key_sha256=fresh["ssh"]["controller_key_sha256"],
                              known_hosts_sha256=fresh["ssh"]["known_hosts_sha256"]),
            admission_gate=admission_gate)
        release.require(result["installation_ready"] is False
                        and result["acceptance_report"] is False,
                        "dispatch falsely claims installed acceptance")
        return result
