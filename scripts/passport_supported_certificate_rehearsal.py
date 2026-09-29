#!/usr/bin/env python3
"""Run and destroy an isolated selfhost certificate fixture under a protected plan.

This rehearsal verifies the managed CSCA/DSC setup. It does not qualify public
Gateway authorization, the nine passport routes, rollback, or beta acceptance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Callable

if __package__:
    from .passport_supported_disposable_ceremony import bootstrap_certificate_chain
    from .passport_supported_infra_rehearsal import (
        INFRA, MIN_JOB_BUDGET, MIN_TEARDOWN_LEASE, ROOT,
        _accept_bootstrap_files, _bootstrap_args, _compose_args,
        _inspect_local, _local_docker_environment, _prepare_bootstrap_output,
        _remove_bootstrap_output, _require_empty_project, _run,
        _staged_environment, protected_job_deadline, recover_infrastructure,
    )
    from .passport_supported_provisioning_producer import (
        CERTIFICATE_WORKFLOW_REF, ProducerError, _remove_staged_inputs,
        _write_private, destroy_partial_disposable_project,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )
else:
    from passport_supported_disposable_ceremony import bootstrap_certificate_chain
    from passport_supported_infra_rehearsal import (
        INFRA, MIN_JOB_BUDGET, MIN_TEARDOWN_LEASE, ROOT,
        _accept_bootstrap_files, _bootstrap_args, _compose_args,
        _inspect_local, _local_docker_environment, _prepare_bootstrap_output,
        _remove_bootstrap_output, _require_empty_project, _run,
        _staged_environment, protected_job_deadline, recover_infrastructure,
    )
    from passport_supported_provisioning_producer import (
        CERTIFICATE_WORKFLOW_REF, ProducerError, _remove_staged_inputs,
        _write_private, destroy_partial_disposable_project,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )


WORKFLOW_NAME = "Passport Supported Disposable Certificate Rehearsal"
RESERVED_TEARDOWN = timedelta(minutes=10)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CERTIFICATE_HASHES = (
    "csca_certificate_sha256", "dsc_certificate_sha256",
    "csca_issuer_did_sha256", "dsc_issuer_did_sha256",
)


def _certificate_deadline(environment: dict[str, str]) -> datetime:
    return protected_job_deadline(
        environment, job_name="certificates", workflow_name=WORKFLOW_NAME,
    )


def rehearse_certificates(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], gateway_port: int, *,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    deadline_lookup: Callable[[dict[str, str]], datetime] = _certificate_deadline,
    verify: Callable[..., dict] = verify_plan_release,
    preflight: Callable[..., dict] = verify_pre_mutation,
    inspect: Callable[[list[str]], str] | None = None,
    run: Callable[[list[str], dict[str, str], int], bool] = _run,
    setup: Callable[..., dict] = bootstrap_certificate_chain,
    teardown: Callable[..., bool] = destroy_partial_disposable_project,
) -> dict:
    """Prove disposable managed certificate setup, then verify full teardown."""
    read_clock = clock or (lambda: datetime.now(timezone.utc))
    current = now or read_clock()
    plan = verify(plan_path, manifest_path, plan_run_id, environment, now=current,
                  workflow_ref=CERTIFICATE_WORKFLOW_REF)
    if plan.get("surface") != "selfhost":
        raise ProducerError("Disposable certificate rehearsal requires selfhost")
    job_deadline = deadline_lookup(environment)
    if job_deadline.tzinfo is None:
        raise ProducerError("Protected job deadline is invalid")
    expires = datetime.fromisoformat(plan["expires_at"])
    if expires - current < MIN_TEARDOWN_LEASE:
        raise ProducerError("Disposable plan has insufficient teardown lease")
    root, env_file = stage_disposable_inputs(plan, gateway_port, now=current)
    output_dir = root / "bootstrap-output"
    mutation_started = False
    try:
        checked = preflight(plan_path, manifest_path, plan_run_id, environment,
                            env_file, root, now=current,
                            workflow_ref=CERTIFICATE_WORKFLOW_REF)
        if checked != plan:
            raise ProducerError("Disposable pre-mutation plan differs")
        staged_env = _local_docker_environment(_staged_environment(env_file))
        inspector = inspect or (lambda args: _inspect_local(args, staged_env))
        _require_empty_project(plan["project"], inspector)
        compose = _compose_args(plan, env_file)
        overlay = ROOT / "docker-compose.passport-supported-disposable-selfhost-ceremony.yml"
        if not overlay.is_file():
            raise ProducerError("Disposable certificate ceremony overlay is missing")
        ceremony_compose = [*compose, "-f", str(overlay)]
        admission = read_clock() if clock is not None or now is None else now
        if admission.tzinfo is None or expires - admission < MIN_TEARDOWN_LEASE:
            raise ProducerError("Disposable plan has insufficient teardown lease")
        if job_deadline - admission < MIN_JOB_BUDGET:
            raise ProducerError("Protected job has insufficient teardown budget")
        _prepare_bootstrap_output(output_dir)
        mutation_started = True
        if not run([*compose, "up", "-d", "--no-deps", "--wait",
                    "--wait-timeout", "120", *INFRA], staged_env, 300):
            raise ProducerError("Disposable infrastructure startup failed")
        if not run(_bootstrap_args(plan, root, output_dir, gateway_port), staged_env, 180):
            raise ProducerError("Disposable OpenBao bootstrap failed")
        _accept_bootstrap_files(root, output_dir)
        if not run([*ceremony_compose, "up", "-d", "--wait",
                    "--wait-timeout", "360", "signing-keys"], staged_env, 600):
            raise ProducerError("Disposable managed signer startup failed")
        before_setup = read_clock() if clock is not None or now is None else now
        if (before_setup.tzinfo is None
            or min(expires, job_deadline) - before_setup < RESERVED_TEARDOWN):
            raise ProducerError("Disposable certificate teardown budget is exhausted")
        certificate = setup(plan, root, gateway_port, now=before_setup)
        if (not isinstance(certificate, dict)
            or certificate.get("schema") !=
            "marty.passport-supported-disposable-certificate-setup/v1"
            or certificate.get("status") != "setup_only"
            or certificate.get("gateway_operator_authorization_verified") is not False
            or certificate.get("project") != plan["project"]
            or certificate.get("source_commit") != plan["source_commit"]
            or not isinstance(certificate.get("evidence"), dict)):
            raise ProducerError("Disposable certificate setup evidence is invalid")
        evidence = certificate["evidence"]
        if (any(type(evidence.get(field)) is not str
                or SHA256.fullmatch(evidence[field]) is None
                for field in CERTIFICATE_HASHES)
            or evidence.get("chain_verified_by") != "openssl-x509-strict"
            or type(evidence.get("csca_http_status")) is not int
            or evidence["csca_http_status"] != 200
            or type(evidence.get("dsc_http_status")) is not int
            or evidence["dsc_http_status"] != 200):
            raise ProducerError("Disposable certificate setup evidence is invalid")
        return {
            "schema": "marty.passport-supported-certificate-rehearsal/v1",
            "status": "setup_only", "certificate_setup_passed": True,
            "gateway_operator_authorization_verified": False,
            "rollback_accepted": False, "project": plan["project"],
            "source_commit": plan["source_commit"],
            "plan_run_id": plan_run_id, "certificate": certificate,
        }
    finally:
        try:
            if mutation_started and not teardown(
                plan_path, manifest_path, plan_run_id, environment,
                inspector=inspector,
                executor=lambda args, output: run(["docker", *args], staged_env, 30),
                now=now, workflow_ref=CERTIFICATE_WORKFLOW_REF,
            ):
                raise ProducerError("Disposable certificate project teardown is unverified")
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
                                   os.environ, workflow_ref=CERTIFICATE_WORKFLOW_REF)
            return 0
        if (args.output.resolve().is_relative_to(ROOT.resolve())
            or not args.output.parent.is_dir()):
            raise ProducerError("Protected rehearsal output path is invalid")
        report = rehearse_certificates(
            args.plan, args.manifest, args.plan_run_id, os.environ,
            args.gateway_port,
        )
        _write_private(args.output, (json.dumps(report, sort_keys=True) + "\n").encode(
            "utf-8"))
    except (ProducerError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected certificate rehearsal blocked: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
