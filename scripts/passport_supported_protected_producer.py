#!/usr/bin/env python3
"""Exercise a protected, disposable Rust passport stack and destroy it.

The producer proves Flow execution and durable Rust restart/resume before
writing a receipt.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

if __package__:
    from .check_passport_supported_rust_model import PROJECT
    from .check_passport_supported_compose_ownership import (
        _inspect as inspect_owned, verify as verify_ownership,
    )
    from .collect_passport_supported_acceptance import COMPOSE_SERVICES, observe_compose
    from .passport_supported_certificate_rehearsal import validate_certificate_setup
    from .passport_supported_disposable_ceremony import (
        bootstrap_certificate_chain, recheck_current_managed_signer,
    )
    from .passport_supported_disposable_route_probe import exercise_owned_disposable
    from .passport_supported_flow_gateway import exercise_owned_flow
    from .probe_passport_beta_native_batch import clear_private_state
    from .passport_supported_native_batch_preflight import preflight_owned_native
    from .passport_supported_flow_restart import restart_owned_rust
    from .passport_supported_infra_rehearsal import (
        INFRA, MIN_TEARDOWN_LEASE, ROOT, _accept_bootstrap_files,
        _bootstrap_args, _compose_args, _inspect_local, _local_docker_environment,
        _prepare_bootstrap_output, _remove_bootstrap_output,
        _require_empty_project, _run, _staged_environment,
        protected_job_deadline, recover_infrastructure,
    )
    from .passport_supported_provisioning_producer import (
        WORKFLOW_REF, ProducerError, _remove_staged_inputs, _write_private,
        collect_record, destroy_disposable_project,
        destroy_partial_disposable_project, issue_disposable_api_key,
        issue_disposable_operator_key, issue_disposable_tenant_probe_key,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )
else:
    from check_passport_supported_rust_model import PROJECT
    from check_passport_supported_compose_ownership import (
        _inspect as inspect_owned, verify as verify_ownership,
    )
    from collect_passport_supported_acceptance import COMPOSE_SERVICES, observe_compose
    from passport_supported_certificate_rehearsal import validate_certificate_setup
    from passport_supported_disposable_ceremony import (
        bootstrap_certificate_chain, recheck_current_managed_signer,
    )
    from passport_supported_disposable_route_probe import exercise_owned_disposable
    from passport_supported_flow_gateway import exercise_owned_flow
    from probe_passport_beta_native_batch import clear_private_state
    from passport_supported_native_batch_preflight import preflight_owned_native
    from passport_supported_flow_restart import restart_owned_rust
    from passport_supported_infra_rehearsal import (
        INFRA, MIN_TEARDOWN_LEASE, ROOT, _accept_bootstrap_files,
        _bootstrap_args, _compose_args, _inspect_local, _local_docker_environment,
        _prepare_bootstrap_output, _remove_bootstrap_output,
        _require_empty_project, _run, _staged_environment,
        protected_job_deadline, recover_infrastructure,
    )
    from passport_supported_provisioning_producer import (
        WORKFLOW_REF, ProducerError, _remove_staged_inputs, _write_private,
        collect_record, destroy_disposable_project,
        destroy_partial_disposable_project, issue_disposable_api_key,
        issue_disposable_operator_key, issue_disposable_tenant_probe_key,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )

from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did


WORKFLOW_NAME = "Passport Supported Disposable Provisioning Producer"
RESERVED_TEARDOWN = timedelta(minutes=10)
MIN_JOB_BUDGET = timedelta(minutes=45)


def _remove_batch_state(project: str) -> None:
    """Clear only this project's private pending marker after verified teardown."""
    if not isinstance(project, str) or PROJECT.fullmatch(project) is None:
        raise ProducerError("Disposable native batch state project is invalid")
    state_dir = Path(tempfile.gettempdir()) / f"{project}-native-batch-state"
    if not state_dir.exists() and not state_dir.is_symlink():
        return
    if state_dir.is_symlink() or not state_dir.is_dir():
        raise ProducerError("Disposable native batch state changed identity")
    state_path = state_dir / "pending.json"
    if state_path.exists() or state_path.is_symlink():
        if state_path.is_symlink() or not state_path.is_file():
            raise ProducerError("Disposable native batch state changed identity")
        clear_private_state(state_path)
    state_dir.rmdir()


def _producer_deadline(environment: dict[str, str]) -> datetime:
    return protected_job_deadline(
        environment, job_name="producer", workflow_name=WORKFLOW_NAME,
    )


def _execute_local(args: list[str], output: object, environment: dict[str, str]) -> bool:
    """Keep Docker output private; the key extractor alone receives a file."""
    try:
        result = subprocess.run(
            ["docker", *args], env=environment,
            stdout=output if output is not None else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _application(gateway_port: int) -> dict:
    """Use only synthetic data; the route probe hashes this input in its receipt."""
    return {
        "organization_id": ORGANIZATION_ID,
        "issuer_did": issuer_did(gateway_port),
        "flow_execution_id": "disposable-producer-synthetic-flow",
        "application_template_id": "disposable-passport-template",
        "credential_template_id": "disposable-passport-credential",
        "delivery_destination_profile_id": "passport-beta-bureau",
        "country_code": "USA", "applicant": {}, "mrz": {},
        "data_groups": {"DG1": "YQ==", "DG2": "Yg=="},
    }


def _observe_bound_runtime(
    record: dict, surface: str, gateway_port: int, now: datetime,
    inspector: Callable[[list[str]], str], *,
    observe: Callable[..., dict] = observe_compose,
    ownership: Callable[..., dict] = verify_ownership,
) -> dict:
    """Bind the released Rust image inventory to the owned, post-restart stack."""
    if ownership(record, surface, now, inspector).get("live_ownership_verified") is not True:
        raise ProducerError("Disposable Rust runtime ownership is unverified")

    def docker_inspector(args: list[str]) -> str:
        if not args or args[0] != "docker":
            raise ProducerError("Runtime inspection escaped Docker")
        return inspector(args[1:])

    runtime = observe(
        surface, record["project"], record["services_reference"],
        runner=docker_inspector,
    )
    if (not isinstance(runtime, dict)
        or set(runtime) != set(COMPOSE_SERVICES) | {"edge"}
        or not isinstance(record.get("containers"), dict)):
        raise ProducerError("Disposable Rust runtime inventory is incomplete")
    for service in (*COMPOSE_SERVICES, "edge"):
        if (not isinstance(runtime[service], dict)
            or runtime[service].get("container_id") != record["containers"].get(service)):
            raise ProducerError(f"Disposable {service} runtime identity changed")
    if runtime["edge"].get("loopback_port") != gateway_port:
        raise ProducerError("Disposable HTTPS edge port changed")
    return runtime


def produce_disposable_receipt(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], gateway_port: int, *,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    deadline_lookup: Callable[[dict[str, str]], datetime] = _producer_deadline,
    verify: Callable[..., dict] = verify_plan_release,
    preflight: Callable[..., dict] = verify_pre_mutation,
    inspect: Callable[[list[str]], str] | None = None,
    run: Callable[[list[str], dict[str, str], int], bool] = _run,
    setup: Callable[..., dict] = bootstrap_certificate_chain,
    recheck_signer: Callable[..., dict] = recheck_current_managed_signer,
    preflight_native: Callable[..., dict] = preflight_owned_native,
    record_live: Callable[..., dict] = collect_record,
    issue_key: Callable[..., Path] = issue_disposable_api_key,
    issue_tenant_probe_key: Callable[..., Path] = issue_disposable_tenant_probe_key,
    issue_operator_key: Callable[..., Path] = issue_disposable_operator_key,
    execute: Callable[[list[str], object, dict[str, str]], bool] = _execute_local,
    probe: Callable[..., dict] = exercise_owned_disposable,
    flow_proof: Callable[..., dict] = exercise_owned_flow,
    restart_rust: Callable[..., bool] = restart_owned_rust,
    observe_runtime: Callable[..., dict] = _observe_bound_runtime,
    teardown_complete: Callable[..., bool] = destroy_disposable_project,
    teardown_partial: Callable[..., bool] = destroy_partial_disposable_project,
) -> dict:
    """Reuse the attested plan, then require live ownership before each probe."""
    read_clock = clock or (lambda: datetime.now(timezone.utc))
    current = now or read_clock()
    plan = verify(plan_path, manifest_path, plan_run_id, environment,
                  now=current, workflow_ref=WORKFLOW_REF)
    deadline = deadline_lookup(environment)
    if deadline.tzinfo is None:
        raise ProducerError("Protected producer job deadline is invalid")
    expires = datetime.fromisoformat(plan["expires_at"])
    if expires - current < MIN_TEARDOWN_LEASE:
        raise ProducerError("Disposable plan has insufficient teardown lease")
    root, env_file = stage_disposable_inputs(plan, gateway_port, now=current)
    output_dir = root / "bootstrap-output"
    batch_state_dir = root.parent / f"{plan['project']}-native-batch-state"
    batch_state_path = batch_state_dir / "pending.json"
    batch_state_created = False
    mutation_started = False
    record = None
    cleaned = False
    try:
        checked = preflight(plan_path, manifest_path, plan_run_id, environment,
                            env_file, root, now=current, workflow_ref=WORKFLOW_REF)
        if checked != plan:
            raise ProducerError("Disposable pre-mutation plan differs")
        staged_env = _local_docker_environment(_staged_environment(env_file))
        inspector = inspect or (lambda args: _inspect_local(args, staged_env))
        _require_empty_project(plan["project"], inspector)
        compose = _compose_args(plan, env_file)
        admission = read_clock() if clock is not None or now is None else now
        if (admission.tzinfo is None
            or expires - admission < MIN_TEARDOWN_LEASE
            or deadline - admission < MIN_JOB_BUDGET):
            raise ProducerError("Protected producer has insufficient teardown budget")
        _prepare_bootstrap_output(output_dir)
        mutation_started = True
        if not run([*compose, "up", "-d", "--no-deps", "--wait",
                    "--wait-timeout", "120", *INFRA], staged_env, 300):
            raise ProducerError("Disposable infrastructure startup failed")
        if not run(_bootstrap_args(plan, root, output_dir, gateway_port), staged_env, 180):
            raise ProducerError("Disposable OpenBao bootstrap failed")
        _accept_bootstrap_files(root, output_dir)
        if plan["surface"] == "selfhost":
            overlay = ROOT / "docker-compose.passport-supported-disposable-selfhost-ceremony.yml"
            if not overlay.is_file():
                raise ProducerError("Disposable certificate ceremony overlay is missing")
            ceremony_compose = [*compose, "-f", str(overlay)]
        else:
            ceremony_compose = compose
        if not run([*ceremony_compose, "up", "-d", "--wait",
                    "--wait-timeout", "360", "signing-keys"], staged_env, 600):
            raise ProducerError("Disposable managed signer startup failed")
        before_setup = read_clock() if clock is not None or now is None else now
        if (before_setup.tzinfo is None
            or min(expires, deadline) - before_setup < RESERVED_TEARDOWN):
            raise ProducerError("Disposable certificate teardown budget is exhausted")
        csca_material: list[str] = []
        dsc_material: list[tuple[str, str]] = []
        certificate = setup(plan, root, gateway_port, now=before_setup,
                            on_csca_material=csca_material.append,
                            on_dsc_material=lambda der, wire: dsc_material.append((der, wire)))
        validate_certificate_setup(certificate, plan, gateway_port)
        if (len(csca_material) != 1
            or "BEGIN CERTIFICATE" not in csca_material[0]):
            raise ProducerError("Disposable CSCA ceremony material is unavailable")
        if (len(dsc_material) != 1
            or dsc_material[0][0] != certificate["evidence"]["dsc_certificate_sha256"]
            or not isinstance(dsc_material[0][1], str)
            or re.fullmatch(r"[0-9a-f]{64}", dsc_material[0][1]) is None):
            raise ProducerError("Disposable DSC ceremony material is unavailable")
        if not run([*compose, "up", "-d", "--wait", "--wait-timeout", "360"],
                   staged_env, 600):
            raise ProducerError("Disposable Rust stack startup failed")
        if plan["surface"] == "selfhost":
            # The certificate phase temporarily puts Gateway and Signing Keys
            # in beta. Replace both before recording normal selfhost ownership.
            if not run([*compose, "up", "-d", "--no-deps", "--force-recreate",
                        "--wait", "--wait-timeout", "360", "gateway", "signing-keys"],
                       staged_env, 600):
                raise ProducerError("Disposable selfhost ceremony exit failed")
        before_probe = read_clock() if clock is not None or now is None else now
        if (before_probe.tzinfo is None
            or min(expires, deadline) - before_probe < RESERVED_TEARDOWN):
            raise ProducerError("Disposable route teardown budget is exhausted")
        record = record_live(plan_path, plan, environment["GITHUB_RUN_ID"],
                             root, before_probe, inspector)
        containers = record.get("containers") if isinstance(record, dict) else None
        signer_id = containers.get("signing-keys") if isinstance(containers, dict) else None
        if not isinstance(signer_id, str):
            raise ProducerError("Current disposable Signing Keys container is unavailable")
        current_signer = recheck_signer(
            signer_id, root, gateway_port, certificate, csca_material.pop())
        if (not isinstance(current_signer, dict)
            or set(current_signer) != {
                "signing_keys_container_id", "managed_kms_custody_verified",
                "chain_verified", "csca_issuer_profile_commitment",
                "dsc_issuer_profile_commitment", "mode", "issuer_profile_type",
                "organization_id", "private_key_exported", "csca", "dsc"}
            or current_signer.get("signing_keys_container_id") != signer_id
            or current_signer.get("mode") != "managed_kms"
            or current_signer.get("issuer_profile_type") != "ICAO_EMRTD"
            or current_signer.get("organization_id") != ORGANIZATION_ID
            or current_signer.get("private_key_exported") is not False
            or current_signer.get("managed_kms_custody_verified") is not True
            or current_signer.get("chain_verified") is not True
            or any(current_signer.get(field) != certificate["evidence"][field]
                   for field in ("csca_issuer_profile_commitment",
                                 "dsc_issuer_profile_commitment"))
            or any(not isinstance(current_signer.get(role), dict)
                   or current_signer[role] != {
                       "status": "active", "organization_id": ORGANIZATION_ID,
                       "issuer_profile_commitment": current_signer[
                           f"{role}_issuer_profile_commitment"],
                       "certificate_sha256": certificate["evidence"][
                           f"{role}_certificate_sha256"],
                   }
                   for role in ("csca", "dsc"))):
            raise ProducerError("Current disposable managed signer differs from ceremony")
        native_preflight = preflight_native(
            record, plan["surface"], inspector=inspector)
        if (not isinstance(native_preflight, dict)
            or native_preflight != {
                "native_container_id": containers.get("issuance-native"),
                "native_batch_preflight_verified": True,
            }):
            raise ProducerError("Disposable native batch preflight is invalid")
        key_path = issue_key(record, plan["surface"], before_probe,
                             inspector=inspector,
                             executor=lambda args, output: execute(args, output, staged_env))
        if key_path != root / "secrets" / "passport_acceptance_api_key":
            raise ProducerError("Disposable API key escaped the project root")
        tenant_probe_path = issue_tenant_probe_key(
            record, plan["surface"], before_probe, inspector=inspector,
            executor=lambda args, output: execute(args, output, staged_env))
        if tenant_probe_path != root / "secrets" / "passport_acceptance_tenant_probe_api_key":
            raise ProducerError("Disposable second tenant key escaped the project root")
        route = probe(record, plan["surface"], _application(gateway_port),
                      now=before_probe, inspector=inspector)
        if (not isinstance(route, dict) or route.get("verified") is not True
            or route.get("flow_execution_verified") is not False
            or not isinstance(route.get("evidence"), dict)
            or route["evidence"].get("signed_gateway_callback_verified") is not True
            or route["evidence"].get("organization_id") != ORGANIZATION_ID
            or route["evidence"].get("unauthenticated_status") not in (401, 403)
            or route["evidence"].get("cross_tenant_status") != 404
            or route["evidence"].get("tenant_capability_unauthenticated_status")
                not in (401, 403)
            or route["evidence"].get("tenant_capability_status") != 200):
            raise ProducerError("Disposable Rust route receipt is invalid")
        before_flow = read_clock() if clock is not None or now is None else now
        if (before_flow.tzinfo is None
            or min(expires, deadline) - before_flow < RESERVED_TEARDOWN):
            raise ProducerError("Disposable Flow teardown budget is exhausted")
        operator_path = issue_operator_key(
            record, plan["surface"], before_flow, inspector=inspector,
            executor=lambda args, output: execute(args, output, staged_env),
        )
        if operator_path != root / "secrets" / "passport_acceptance_operator_api_key":
            raise ProducerError("Disposable Flow operator key escaped the project root")
        pre_restart_native_runtime = None

        def restart_with_inspected_baseline() -> bool:
            nonlocal pre_restart_native_runtime
            if pre_restart_native_runtime is not None:
                raise ProducerError("Disposable Rust restart was repeated")
            before_restart = read_clock() if clock is not None or now is None else now
            baseline = observe_runtime(record, plan["surface"], gateway_port,
                                       before_restart, inspector)
            native = baseline.get("issuance-native") if isinstance(baseline, dict) else None
            native_id = record.get("containers", {}).get("issuance-native")
            if (not isinstance(native, dict)
                or native.get("container_id") != native_id
                or not isinstance(native_id, str)):
                raise ProducerError("Disposable native restart baseline is unowned")
            inspection = inspect_owned("container", native_id, inspector)
            if (inspection.get("Id") != native_id
                or inspection.get("Image") != native.get("image_id")):
                raise ProducerError("Disposable native restart inspection drifted")
            inspection_digest = hashlib.sha256(json.dumps(
                inspection, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            if restart_rust(record, plan["surface"], compose, staged_env,
                            inspector=inspector, run=run) is not True:
                raise ProducerError("Disposable Rust restart was not verified")
            pre_restart_native_runtime = {
                **native, "inspection_receipt_sha256": inspection_digest,
            }
            return True

        if batch_state_dir.exists():
            raise ProducerError("Disposable native batch pending state requires reconciliation")
        batch_state_dir.mkdir(mode=0o700)
        batch_state_created = True
        flow = flow_proof(
            record, plan["surface"], gateway_port, plan_run_id,
            dsc_der_sha256=dsc_material[0][0],
            dsc_pem_wire_sha256=dsc_material[0][1],
            batch_state_path=batch_state_path,
            batch_deadline=min(expires, deadline),
            inspector=inspector, restart=restart_with_inspected_baseline)
        batch = flow.get("batch") if isinstance(flow, dict) else None
        batch_evidence = batch.get("batch", {}).get("evidence") if isinstance(batch, dict) else None
        if (not isinstance(flow, dict)
            or set(flow) != {"references", "flow", "execution", "batch"}
            or not isinstance(flow["references"], dict)
            or not isinstance(flow["flow"], dict)
            or not isinstance(flow["execution"], dict)
            or flow["execution"].get("durable_history_verified") is not True
            or flow["execution"].get("restart_resume_verified") is not True
            or not isinstance(batch, dict)
            or batch.get("final_native_preflight") != {
                "native_container_id": record["containers"]["issuance-native"],
                "native_batch_preflight_verified": True}
            or not isinstance(batch_evidence, dict)
            or batch.get("batch", {}).get("verified") is not True
            or batch_evidence.get("selected_flow_in_two_job_batch") is not True
            or batch_evidence.get("first_accepted_material_verified") is not True
            or batch.get("selected_source_job_sha256")
            != flow["flow"].get("native_job_id_sha256")
            or batch.get("selected_bureau_job_sha256")
            != flow["execution"].get("bureau_job_id_sha256")
            or batch.get("dsc_der_sha256")
            != certificate["evidence"]["dsc_certificate_sha256"]
            or pre_restart_native_runtime is None):
            raise ProducerError("Disposable Rust Flow execution proof is invalid")
        before_inventory = read_clock() if clock is not None or now is None else now
        if (before_inventory.tzinfo is None
            or min(expires, deadline) - before_inventory < RESERVED_TEARDOWN):
            raise ProducerError("Disposable runtime teardown budget is exhausted")
        runtime = observe_runtime(record, plan["surface"], gateway_port,
                                  before_inventory, inspector)
        if (pre_restart_native_runtime["container_id"]
            == runtime["issuance-native"]["container_id"]
            or pre_restart_native_runtime["image_id"]
            != runtime["issuance-native"]["image_id"]
            or current_signer["signing_keys_container_id"]
            != runtime["signing-keys"]["container_id"]):
            raise ProducerError("Disposable Rust runtime image or container drifted")
        current_signer["services_oci_reference"] = runtime["signing-keys"]["oci_reference"]
        return {
            "schema": "marty.passport-supported-rust-producer/v1",
            "status": "blocked", "project": plan["project"],
            "surface": plan["surface"], "source_commit": plan["source_commit"],
            "gateway_port": gateway_port, "physical_claim": "not_claimed",
            "plan_run_id": plan_run_id,
            "producer_run_id": environment["GITHUB_RUN_ID"],
            "certificate_setup_passed": True,
            "live_ownership_verified": True,
            "rust_routes_verified": True,
            "signed_gateway_callback_verified": True,
            "flow_start_verified": True,
            "flow_execution_verified": True,
            "rust_restart_resume_verified": True,
            "certificate": certificate,
            "current_managed_signer": current_signer,
            "native_batch_preflight": native_preflight,
            "route": route,
            "flow_execution": flow,
            "runtime_images": {service: runtime[service]
                               for service in COMPOSE_SERVICES},
            "pre_restart_native_runtime": pre_restart_native_runtime,
            "runtime_edge": runtime["edge"],
            "blocker": "Live protected beta acceptance remains unproven",
        }
    finally:
        try:
            if mutation_started:
                if record is not None:
                    cleaned = teardown_complete(
                        record, inspector,
                        lambda args, output: execute(args, output, staged_env))
                    if not cleaned:
                        # A failed recreate may leave new owned IDs that the
                        # pre-recreate record cannot authorize for teardown.
                        cleaned = teardown_partial(
                            plan_path, manifest_path, plan_run_id, environment,
                            inspector=inspector,
                            executor=lambda args, output: execute(args, output, staged_env),
                            now=now, workflow_ref=WORKFLOW_REF)
                else:
                    cleaned = teardown_partial(
                        plan_path, manifest_path, plan_run_id, environment,
                        inspector=inspector,
                        executor=lambda args, output: execute(args, output, staged_env),
                        now=now, workflow_ref=WORKFLOW_REF)
                if not cleaned:
                    raise ProducerError("Disposable producer teardown is unverified")
        finally:
            try:
                _remove_bootstrap_output(output_dir)
            finally:
                try:
                    _remove_staged_inputs(root)
                finally:
                    if batch_state_created and cleaned:
                        _remove_batch_state(plan["project"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan-run-id", required=True)
    parser.add_argument("--gateway-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recover-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.recover_only:
            recover_infrastructure(args.plan, args.manifest, args.plan_run_id,
                                   os.environ, workflow_ref=WORKFLOW_REF)
            recovered_plan = json.loads(args.plan.read_text(encoding="utf-8"))
            _remove_batch_state(recovered_plan["project"])
            return 0
        if args.output.resolve().is_relative_to(ROOT.resolve()) or not args.output.parent.is_dir():
            raise ProducerError("Protected producer output path is invalid")
        report = produce_disposable_receipt(
            args.plan, args.manifest, args.plan_run_id, os.environ, args.gateway_port)
        _write_private(args.output, (json.dumps(report, sort_keys=True) + "\n").encode())
    except (ProducerError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected disposable producer blocked: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
