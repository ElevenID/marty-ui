#!/usr/bin/env python3
"""Exercise a protected, disposable Rust passport stack and destroy it.

The producer proves Flow execution before writing a receipt; durable Rust
restart/resume remains a separate gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Callable

if __package__:
    from .passport_supported_certificate_rehearsal import validate_certificate_setup
    from .passport_supported_disposable_ceremony import bootstrap_certificate_chain
    from .passport_supported_disposable_route_probe import exercise_owned_disposable
    from .passport_supported_flow_gateway import exercise_owned_flow
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
        issue_disposable_operator_key,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )
else:
    from passport_supported_certificate_rehearsal import validate_certificate_setup
    from passport_supported_disposable_ceremony import bootstrap_certificate_chain
    from passport_supported_disposable_route_probe import exercise_owned_disposable
    from passport_supported_flow_gateway import exercise_owned_flow
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
        issue_disposable_operator_key,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )

from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did


WORKFLOW_NAME = "Passport Supported Disposable Provisioning Producer"
RESERVED_TEARDOWN = timedelta(minutes=10)
MIN_JOB_BUDGET = timedelta(minutes=45)


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
    record_live: Callable[..., dict] = collect_record,
    issue_key: Callable[..., Path] = issue_disposable_api_key,
    issue_operator_key: Callable[..., Path] = issue_disposable_operator_key,
    execute: Callable[[list[str], object, dict[str, str]], bool] = _execute_local,
    probe: Callable[..., dict] = exercise_owned_disposable,
    flow_proof: Callable[..., dict] = exercise_owned_flow,
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
    mutation_started = False
    record = None
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
        certificate = setup(plan, root, gateway_port, now=before_setup)
        validate_certificate_setup(certificate, plan, gateway_port)
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
        key_path = issue_key(record, plan["surface"], before_probe,
                             inspector=inspector,
                             executor=lambda args, output: execute(args, output, staged_env))
        if key_path != root / "secrets" / "passport_acceptance_api_key":
            raise ProducerError("Disposable API key escaped the project root")
        route = probe(record, plan["surface"], _application(gateway_port),
                      now=before_probe, inspector=inspector)
        if (not isinstance(route, dict) or route.get("verified") is not True
            or route.get("flow_execution_verified") is not False
            or not isinstance(route.get("evidence"), dict)
            or route["evidence"].get("signed_gateway_callback_verified") is not True):
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
        flow = flow_proof(record, plan["surface"], gateway_port, plan_run_id,
                          inspector=inspector)
        if (not isinstance(flow, dict)
            or set(flow) != {"references", "flow", "execution"}
            or not isinstance(flow["references"], dict)
            or not isinstance(flow["flow"], dict)
            or not isinstance(flow["execution"], dict)
            or flow["execution"].get("durable_history_verified") is not True):
            raise ProducerError("Disposable Rust Flow execution proof is invalid")
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
            "rust_restart_resume_verified": False,
            "certificate": certificate,
            "route": route,
            "flow_execution": flow,
            "blocker": "Rust restart/resume remains unproven",
        }
    finally:
        try:
            if mutation_started:
                if record is not None:
                    cleaned = teardown_complete(
                        record, inspector,
                        lambda args, output: execute(args, output, staged_env))
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
                _remove_staged_inputs(root)


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
