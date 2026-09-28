#!/usr/bin/env python3
"""Bounded disposable infrastructure rehearsal for protected passport plans.

This module does not qualify supported-consumer rollback or Python retirement.
The protected producer workflow does not invoke it yet.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

if __package__:
    from .passport_supported_provisioning_producer import (
        ProducerError, _remove_staged_inputs, destroy_partial_disposable_project,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )
else:
    from passport_supported_provisioning_producer import (
        ProducerError, _remove_staged_inputs, destroy_partial_disposable_project,
        stage_disposable_inputs, verify_plan_release, verify_pre_mutation,
    )


ROOT = Path(__file__).resolve().parents[1]
INFRA = ("postgres", "redis", "openbao")
TOKEN = re.compile(r"[!-~]{8,512}\Z")


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
        "docker", "run", "--rm", "--network", f"{project}_private",
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
    verify: Callable[..., dict] = verify_plan_release,
    preflight: Callable[..., dict] = verify_pre_mutation,
    inspect: Callable[[list[str]], str] | None = None,
    run: Callable[[list[str], dict[str, str], int], bool] = _run,
    teardown: Callable[..., bool] = destroy_partial_disposable_project,
) -> dict:
    """Start only isolated infra, bootstrap Transit, then always destroy it."""
    read_clock = clock or (lambda: datetime.now(timezone.utc))
    current = now or read_clock()
    plan = verify(plan_path, manifest_path, plan_run_id, environment, now=current)
    expires = datetime.fromisoformat(plan["expires_at"])
    if expires - current < timedelta(minutes=30):
        raise ProducerError("Disposable plan has insufficient teardown lease")
    root, env_file = stage_disposable_inputs(plan, gateway_port, now=current)
    output_dir = root / "bootstrap-output"
    mutation_started = False
    try:
        checked = preflight(plan_path, manifest_path, plan_run_id, environment,
                            env_file, root, now=current)
        if checked != plan:
            raise ProducerError("Disposable pre-mutation plan differs")
        staged_env = _local_docker_environment(_staged_environment(env_file))
        inspector = inspect or (lambda args: _inspect_local(args, staged_env))
        _require_empty_project(plan["project"], inspector)
        compose = _compose_args(plan, env_file)
        admission = read_clock() if clock is not None or now is None else now
        if admission.tzinfo is None or expires - admission < timedelta(minutes=30):
            raise ProducerError("Disposable plan has insufficient teardown lease")
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
            ):
                raise ProducerError("Disposable infrastructure teardown is unverified")
        finally:
            try:
                _remove_bootstrap_output(output_dir)
            finally:
                _remove_staged_inputs(root)
