#!/usr/bin/env python3
"""Bounded disposable infrastructure rehearsal for protected passport plans.

This module does not qualify supported-consumer rollback or Python retirement.
The separate protected infra workflow invokes it; the full producer remains blocked.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Callable

if __package__:
    from .passport_supported_provisioning_producer import (
        INFRA_WORKFLOW_REF, PROJECT, ProducerError, _remove_staged_inputs, _write_private,
        destroy_partial_disposable_project, stage_disposable_inputs,
        verify_plan_release, verify_pre_mutation,
    )
else:
    from passport_supported_provisioning_producer import (
        INFRA_WORKFLOW_REF, PROJECT, ProducerError, _remove_staged_inputs, _write_private,
        destroy_partial_disposable_project, stage_disposable_inputs,
        verify_plan_release, verify_pre_mutation,
    )


ROOT = Path(__file__).resolve().parents[1]
INFRA = ("postgres", "redis", "openbao")
TOKEN = re.compile(r"[!-~]{8,512}\Z")
MIN_TEARDOWN_LEASE = timedelta(minutes=90)
MIN_JOB_BUDGET = timedelta(minutes=45)
JOB_TIMEOUT = timedelta(minutes=60)


def _run(args: list[str], environment: dict[str, str], timeout: int) -> bool:
    """Run a fixed Docker command without capturing sensitive output."""
    try:
        result = subprocess.run(args, env=environment, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _local_docker_environment(environment: dict[str, str]) -> dict[str, str]:
    local = environment.copy()
    local["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        local.pop(name, None)
    return local


def _inspect_local(args: list[str], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(["docker", *args], env=environment,
                                capture_output=True, text=True, encoding="utf-8",
                                check=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProducerError("Disposable local Docker inspection failed") from exc
    if len(result.stdout) > 1024 * 1024:
        raise ProducerError("Disposable local Docker inspection is oversized")
    return result.stdout


def _run_attempt_jobs(run_id: str, attempt: str) -> dict:
    try:
        result = subprocess.run([
            "gh", "api", "repos/ElevenID/marty-ui/actions/runs/"
            f"{run_id}/attempts/{attempt}/jobs",
        ], capture_output=True, text=True, encoding="utf-8", check=True, timeout=30)
        if len(result.stdout) > 1024 * 1024:
            raise ProducerError("Protected job response is oversized")
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ProducerError("Protected job identity cannot be verified") from exc
    if not isinstance(payload, dict):
        raise ProducerError("Protected job response is invalid")
    return payload


def protected_job_deadline(
    environment: dict[str, str],
    lookup: Callable[[str, str], dict] = _run_attempt_jobs,
) -> datetime:
    """Bind remaining budget to this exact GitHub job attempt's start time."""
    run_id = environment.get("GITHUB_RUN_ID")
    attempt = environment.get("GITHUB_RUN_ATTEMPT")
    if (environment.get("GITHUB_JOB") != "infra"
        or not isinstance(run_id, str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is None
        or not isinstance(attempt, str)
        or re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is None):
        raise ProducerError("Protected job context is invalid")
    payload = lookup(run_id, attempt)
    jobs = payload.get("jobs") if isinstance(payload, dict) else None
    if not isinstance(jobs, list) or payload.get("total_count") != 1 or len(jobs) != 1:
        raise ProducerError("Protected job attempt is ambiguous")
    job = jobs[0]
    if (not isinstance(job, dict) or job.get("name") != "infra"
        or job.get("workflow_name") != "Passport Supported Disposable Infra Rehearsal"
        or job.get("run_id") != int(run_id)
        or job.get("run_attempt") != int(attempt)
        or job.get("head_sha") != environment.get("GITHUB_SHA")
        or job.get("status") != "in_progress"):
        raise ProducerError("Protected job identity differs from the current run")
    try:
        started = datetime.fromisoformat(job["started_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProducerError("Protected job start time is invalid") from exc
    if started.tzinfo is None:
        raise ProducerError("Protected job start time is not timezone aware")
    return started + JOB_TIMEOUT


def _staged_environment(env_file: Path) -> dict[str, str]:
    values = {}
    for line in env_file.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise ProducerError("Disposable staged environment is invalid")
        values[key] = value
    environment = os.environ.copy()
    environment.update(values)
    environment["COMPOSE_PROFILES"] = ""
    return environment


def _compose_args(plan: dict, env_file: Path) -> list[str]:
    surface = plan["surface"]
    files = [ROOT / "docker-compose.passport-supported-disposable.yml",
             ROOT / f"docker-compose.passport-supported-disposable-{surface}.yml"]
    if not all(path.is_file() for path in files):
        raise ProducerError("Disposable Compose source is missing")
    return ["docker", "compose", "--project-name", plan["project"],
            "--env-file", str(env_file),
            *(argument for path in files for argument in ("-f", str(path)))]


def _require_empty_project(project: str, inspector: Callable[[list[str]], str]) -> None:
    for args in (
        ["ps", "-aq", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={project}"],
        ["network", "ls", "-q", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={project}"],
        ["volume", "ls", "-q", "--filter",
         f"label=com.docker.compose.project={project}"],
    ):
        if inspector(args).split():
            raise ProducerError("Disposable project already has live resources")
    for suffix in ("private", "callback_signing"):
        if inspector(["network", "ls", "-q", "--filter",
                      f"name=^{project}_{suffix}$"]).split():
            raise ProducerError("Disposable network name is already occupied")
    if inspector(["volume", "ls", "-q", "--filter",
                  f"name=^{project}_"]).split():
        raise ProducerError("Disposable volume namespace is already occupied")


def _bootstrap_args(plan: dict, root: Path, output_dir: Path) -> list[str]:
    project = plan["project"]
    labels = {"com.docker.compose.project": project,
              "com.docker.compose.service": "passport-openbao-bootstrap",
              **plan["owner_labels"]}
    script = ROOT / "scripts/passport_supported_openbao_bootstrap.sh"
    initializer = ROOT / "docker/openbao-init.sh"
    if not script.is_file() or not initializer.is_file():
        raise ProducerError("Disposable OpenBao bootstrap source is missing")
    return [
        "docker", "run", "--rm", "--name",
        f"{project}-passport-openbao-bootstrap-1",
        "--network", f"{project}_private",
        *(argument for key, value in sorted(labels.items())
          for argument in ("--label", f"{key}={value}")),
        "--mount", ("type=bind,src=" + str(root / "secrets" / "bao_root_token")
                    + ",dst=/run/secrets/bao_root_token,readonly"),
        "--mount", ("type=bind,src=" + str(output_dir)
                    + ",dst=/work/secrets"),
        "--mount", ("type=bind,src=" + str(script)
                    + ",dst=/scripts/passport_supported_openbao_bootstrap.sh,readonly"),
        "--mount", ("type=bind,src=" + str(initializer)
                    + ",dst=/scripts/openbao-init.sh,readonly"),
        "--env", "BAO_ADDR=http://openbao:8200", "--entrypoint", "/bin/sh",
        plan["infra_images"]["openbao"],
        "/scripts/passport_supported_openbao_bootstrap.sh",
    ]


def _accept_bootstrap_files(root: Path, output_dir: Path) -> None:
    secret_dir = root / "secrets"
    root_token = (secret_dir / "bao_root_token").read_text(encoding="ascii")
    issued = []
    for name in ("bao_token", "callback_signer_bao_token"):
        path = output_dir / name
        if path.is_symlink() or not path.is_file():
            raise ProducerError("Disposable OpenBao token file is missing")
        value = path.read_text(encoding="ascii")
        if TOKEN.fullmatch(value) is None or value == root_token:
            raise ProducerError("Disposable OpenBao token file is invalid")
        issued.append(value)
    if issued[0] == issued[1]:
        raise ProducerError("Disposable OpenBao tokens are not distinct")
    if {path.name for path in output_dir.iterdir()} != {
        "bao_token", "callback_signer_bao_token",
    }:
        raise ProducerError("Disposable OpenBao output directory is invalid")
    for name in ("bao_token", "callback_signer_bao_token"):
        destination = secret_dir / name
        if destination.exists() or destination.is_symlink():
            raise ProducerError("Disposable OpenBao token destination exists")
        (output_dir / name).rename(destination)


def _remove_bootstrap_output(output_dir: Path) -> None:
    if not output_dir.exists():
        return
    if output_dir.is_symlink() or output_dir.resolve() != output_dir:
        raise ProducerError("Disposable OpenBao output directory changed identity")
    for path in output_dir.iterdir():
        if re.fullmatch(
            r"(?:bao_token|callback_signer_bao_token|"
            r"\.(?:bao_token|callback_signer_bao_token)\.[A-Za-z0-9]{6})",
            path.name,
        ) is None:
            raise ProducerError("Disposable OpenBao output has an unexpected file")
        path.unlink()
    output_dir.rmdir()


def rehearse_infrastructure(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], gateway_port: int, *,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    deadline_lookup: Callable[[dict[str, str]], datetime] = protected_job_deadline,
    verify: Callable[..., dict] = verify_plan_release,
    preflight: Callable[..., dict] = verify_pre_mutation,
    inspect: Callable[[list[str]], str] | None = None,
    run: Callable[[list[str], dict[str, str], int], bool] = _run,
    teardown: Callable[..., bool] = destroy_partial_disposable_project,
) -> dict:
    """Start only isolated infra, bootstrap Transit, then always destroy it."""
    read_clock = clock or (lambda: datetime.now(timezone.utc))
    current = now or read_clock()
    plan = verify(plan_path, manifest_path, plan_run_id, environment, now=current,
                  workflow_ref=INFRA_WORKFLOW_REF)
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
                            workflow_ref=INFRA_WORKFLOW_REF)
        if checked != plan:
            raise ProducerError("Disposable pre-mutation plan differs")
        staged_env = _local_docker_environment(_staged_environment(env_file))
        inspector = inspect or (lambda args: _inspect_local(args, staged_env))
        _require_empty_project(plan["project"], inspector)
        compose = _compose_args(plan, env_file)
        admission = read_clock() if clock is not None or now is None else now
        if admission.tzinfo is None or expires - admission < MIN_TEARDOWN_LEASE:
            raise ProducerError("Disposable plan has insufficient teardown lease")
        if job_deadline - admission < MIN_JOB_BUDGET:
            raise ProducerError("Protected job has insufficient teardown budget")
        output_dir.mkdir(mode=0o700)
        if output_dir.is_symlink() or output_dir.resolve() != output_dir:
            raise ProducerError("Disposable OpenBao output directory is invalid")
        if os.name == "posix" and (
            output_dir.stat().st_uid != os.getuid()
            or stat.S_IMODE(output_dir.stat().st_mode) != 0o700
        ):
            raise ProducerError("Disposable OpenBao output directory is not private")
        mutation_started = True
        if not run([*compose, "up", "-d", "--no-deps", "--wait",
                    "--wait-timeout", "120", *INFRA], staged_env, 300):
            raise ProducerError("Disposable infrastructure startup failed")
        if not run(_bootstrap_args(plan, root, output_dir), staged_env, 180):
            raise ProducerError("Disposable OpenBao bootstrap failed")
        _accept_bootstrap_files(root, output_dir)
        return {"schema": "marty.passport-supported-infra-rehearsal/v1",
                "status": "blocked", "infra_rehearsal_passed": True,
                "project": plan["project"], "source_commit": plan["source_commit"],
                "plan_run_id": plan_run_id}
    finally:
        try:
            if mutation_started and not teardown(
                plan_path, manifest_path, plan_run_id, environment,
                inspector=inspector,
                executor=lambda args, output: run(["docker", *args], staged_env, 30),
                now=now,
                workflow_ref=INFRA_WORKFLOW_REF,
            ):
                raise ProducerError("Disposable infrastructure teardown is unverified")
        finally:
            try:
                _remove_bootstrap_output(output_dir)
            finally:
                _remove_staged_inputs(root)


def recover_infrastructure(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], *,
    teardown: Callable[..., bool] = destroy_partial_disposable_project,
) -> None:
    """Independently prove teardown after the bounded rehearsal step exits."""
    plan_bytes = plan_path.read_bytes()
    plan = json.loads(plan_bytes)
    project = plan.get("project") if isinstance(plan, dict) else None
    if not isinstance(project, str) or PROJECT.fullmatch(project) is None:
        raise ProducerError("Disposable infrastructure recovery plan is invalid")
    staged_env = _local_docker_environment(environment)

    def inspector(args: list[str]) -> str:
        return _inspect_local(args, staged_env)

    if not teardown(plan_path, manifest_path, plan_run_id, environment,
                    inspector=inspector,
                    executor=lambda args, output: _run(["docker", *args], staged_env, 30),
                    workflow_ref=INFRA_WORKFLOW_REF):
        raise ProducerError("Disposable infrastructure recovery is unverified")
    if plan_path.read_bytes() != plan_bytes:
        raise ProducerError("Disposable infrastructure recovery plan changed")
    root = Path(tempfile.gettempdir()) / project
    if root.exists() or root.is_symlink():
        _remove_bootstrap_output(root / "bootstrap-output")
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
                                   os.environ)
            return 0
        if args.output.resolve().is_relative_to(ROOT.resolve()) or not args.output.parent.is_dir():
            raise ProducerError("Protected rehearsal output path is invalid")
        report = rehearse_infrastructure(
            args.plan, args.manifest, args.plan_run_id, os.environ,
            args.gateway_port,
        )
        _write_private(args.output, (json.dumps(report, sort_keys=True) + "\n").encode(
            "utf-8"))
    except (ProducerError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected disposable infrastructure rehearsal blocked: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
