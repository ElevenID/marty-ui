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
from installer_candidate_vm_host_preflight import preflight, verify_consumed_intent, _raw_bytes_at
import installer_candidate_vm_host_probe as host_probe
import installer_candidate_vm_live_observe as live_vm
import installer_acceptance_runner as acceptance
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
                  invoke=dispatch.dispatch,
                  process_observer=live_vm.observe,
                  observe_installed=acceptance.observe_after_dispatch,
                  execute=host_probe.command) -> dict:
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
        a, receipt, i, files = dispatch.verify(
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
        command_error = None
        result = None
        try:
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
        except (ValueError, OSError) as error:
            command_error = error
        if command_error is None:
            release.require(result["installation_ready"] is False
                            and result["acceptance_report"] is False,
                            "dispatch falsely claims installed acceptance")
        check_id = str(uuid.uuid4())
        process = process_observer(
            registry, runtime_parent, vm_id=vm_id,
            process_check_id=check_id, lease=lease)
        process_name = vm_id + ".process-check-" + check_id + ".json"
        process_raw, persisted_process = _read_record(lease.parent, process_name)
        release.require(persisted_process == process
                        and process["schema"] == live_vm.PROCESS_CHECK_SCHEMA
                        and process["vm_id"] == vm_id
                        and process["observation_id"] == check_id
                        and process["initial_guest_readiness_sha256"]
                        == fresh["initial_guest_readiness_sha256"],
                        "post-dispatch VM process differs")
        post = dict(schema="elevenid.installer-vm-post-dispatch/v1",
                    nonce=nonce, vm_id=vm_id,
                    installation_id=installation_id,
                    approval_sha256=release.digest(approval_raw),
                    intent_sha256=bound["intent_sha256"],
                    receipt_sha256=bound["receipt_sha256"],
                    process_check_sha256=release.digest(process_raw),
                    command_returned_zero=command_error is None,
                    installation_ready=False, acceptance=False,
                    observed_at=int(clock()))
        post_name = nonce + ".vm-post-dispatch.json"
        _write(lease.parent, post_name, post)
        dispatch.registry_unchanged(lease.parent, registry)
        release.require(_read_record(lease.parent, post_name)[1] == post
                        and _read_record(lease.parent, process_name)[0]
                        == process_raw,
                        "post-dispatch VM evidence changed")
        output_name = nonce + ".installed-observations"
        os.mkdir(output_name, mode=0o700, dir_fd=lease.parent)
        os.fsync(lease.parent)
        output = registry / output_name
        output_fd = dispatch._directory(output)
        try:
            def write_output(name, raw):
                release.require(type(name) is str and name
                                and "/" not in name and "\\" not in name
                                and name not in (".", "..")
                                and type(raw) is bytes and len(raw) <= 65536,
                                "installed observation output invalid")
                dispatch.registry_unchanged(output_fd, output)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                             dir_fd=output_fd)
                try:
                    os.fsync(output_fd)
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(fd)
                    os.fsync(output_fd)
                finally:
                    os.close(fd)
                dispatch.registry_unchanged(output_fd, output)
            host_name = vm_id + "." + observation_id + ".host-observation.json"
            host_raw = _raw_bytes_at(lease.parent, host_name)
            release.require(release.digest(host_raw)
                            == fresh["host_observation_sha256"],
                            "post-dispatch host admission differs")
            write_output("host-observation.json", host_raw)
            binding = dict(schema="elevenid.installer-vm-installed-observation-binding/v1",
                           nonce=nonce, vm_id=vm_id,
                           context_sha256=release.candidate_context_sha256(expected),
                           post_dispatch_sha256=release.digest(release.encode(post)),
                           host_observation_sha256=release.digest(host_raw),
                           receipt_sha256=bound["receipt_sha256"],
                           installation_ready=False, acceptance=False)
            binding_raw = release.encode(binding)
            write_output("vm-binding.json", binding_raw)
            def unchanged():
                dispatch.registry_unchanged(lease.parent, registry)
                dispatch.registry_unchanged(output_fd, output)
                current = verify_consumed_intent(
                    lease, registry, authorization=authorization, assets=assets,
                    expected=expected, gh=gh, cosign=cosign, clock=clock,
                    verifier=verifier)
                release.require(current["intent_sha256"] == bound["intent_sha256"]
                                and current["receipt_sha256"] == bound["receipt_sha256"]
                                and current["target"] == bound["target"]
                                and current["ssh"] == bound["ssh"]
                                and _read_record(lease.parent, post_name)[1] == post
                                and _read_record(lease.parent, process_name)[0]
                                == process_raw
                                and _raw_bytes_at(lease.parent, host_name) == host_raw
                                and _raw_bytes_at(output_fd, "host-observation.json")
                                == host_raw
                                and _read_record(output_fd, "vm-binding.json")[0]
                                == binding_raw,
                                "installed observation binding changed")
                release.require(dispatch.private_file(key, 8192)[0]
                                == fresh["ssh"]["controller_key_sha256"]
                                and dispatch.private_file(known_hosts, 4096)[0]
                                == fresh["ssh"]["known_hosts_sha256"],
                                "installed observation SSH custody changed")
                for path, expected_file in files.items():
                    release.require(dispatch.private_file(
                        path, expected_file[1], executable=path in (gh, cosign))
                        == expected_file, "installed candidate custody changed")
                check = str(uuid.uuid4())
                checked = process_observer(
                    registry, runtime_parent, vm_id=vm_id,
                    process_check_id=check, lease=lease)
                checked_raw, persisted = _read_record(
                    lease.parent, vm_id + ".process-check-" + check + ".json")
                release.require(persisted == checked
                                and checked["schema"] == live_vm.PROCESS_CHECK_SCHEMA
                                and checked["vm_id"] == vm_id
                                and checked["observation_id"] == check
                                and checked["initial_guest_readiness_sha256"]
                                == process["initial_guest_readiness_sha256"]
                                and checked_raw == release.encode(checked),
                                "installed observation VM process changed")
                dispatch.registry_unchanged(lease.parent, registry)
                dispatch.registry_unchanged(output_fd, output)
            def guarded_execute(argv, **kwargs):
                unchanged()
                raw = execute(argv, **kwargs)
                unchanged()
                return raw
            checkpoint = acceptance.incomplete_checkpoint(
                context=expected, target=bound["target"], authorization=a,
                receipt=receipt, inventory=i,
                host_observation_sha256=release.digest(host_raw),
                host_preflight="passed",
                dispatch_status=("returned_zero_unqualified"
                                 if command_error is None else "failed_or_incomplete"),
                observed_at=int(clock()))
            tls_source = dispatch.verified_harness_script(
                expected["harness_source_sha"], "installer_live_tls_probe.py")
            bootstrap_source = (dispatch.verified_bootstrap(
                expected["harness_source_sha"])
                if expected["phase"] == "published" else None)
            observed = observe_installed(
                checkpoint=checkpoint, output=output, context=expected,
                target=bound["target"], authorization=a, receipt=receipt,
                inventory=i, ssh=ssh, key=key, known_hosts=known_hosts,
                port=fresh["ssh"]["port"], host=fresh["ssh"]["host"],
                user=fresh["ssh"]["user"], home="/home/" + fresh["ssh"]["user"],
                bootstrap_source=bootstrap_source, tls_source=tls_source,
                unchanged=unchanged, guarded_execute=guarded_execute,
                clock=clock, writer=write_output)
            acceptance.validate(observed, context=expected,
                                target=bound["target"], authorization=a,
                                receipt=receipt, inventory=i)
            unchanged()
            if command_error is not None:
                raise command_error
            return result
        finally:
            os.close(output_fd)
