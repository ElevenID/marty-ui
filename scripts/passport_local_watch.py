#!/usr/bin/env python3
"""Run the released disposable passport model locally with a Rust source watcher.

This is a debugging aid. It never emits protected acceptance evidence.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from passport_supported_certificate_rehearsal import validate_certificate_setup
from passport_supported_disposable_ceremony import bootstrap_certificate_chain
from passport_supported_infra_rehearsal import (
    INFRA, ROOT, _accept_bootstrap_files, _bootstrap_args, _compose_args,
    _local_docker_environment, _prepare_bootstrap_output, _remove_bootstrap_output,
    _require_empty_project, _staged_environment,
)
from passport_supported_provisioning_producer import (
    _remove_staged_inputs, stage_disposable_inputs,
)


def run(args: list[str], env: dict[str, str], log: Path, timeout: int) -> bool:
    with log.open("ab") as output:
        output.write(("\nCOMMAND: " + " ".join(args[:3]) + " ...\n").encode())
        output.flush()
        try:
            result = subprocess.run(args, env=env, stdout=output, stderr=output,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            output.write(f"\nERROR: {type(exc).__name__}\n".encode())
            return False
        output.write(f"\nEXIT: {result.returncode}\n".encode())
        return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--port", type=int, default=29878)
    parser.add_argument("--resume", action="store_true",
                        help="reuse this project's already staged local resources")
    parser.add_argument("--watch-only", action="store_true",
                        help="refresh only the watcher on an existing local stack")
    parser.add_argument("--stop", action="store_true",
                        help="remove this disposable project and its staged secrets")
    args = parser.parse_args()
    if (args.watch_only or args.stop) and not args.resume:
        parser.error("--watch-only and --stop require --resume")
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    ui = next((item for item in manifest.get("components", [])
               if item.get("name") == "marty-ui"), {})
    now = datetime.now(timezone.utc)
    if (plan.get("surface") != "base"
        or plan.get("source_commit") != ui.get("commit")
        or plan.get("stack_manifest_sha256") != hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        or (not args.stop and not datetime.fromisoformat(plan["created_at"]) <= now
            < datetime.fromisoformat(plan["expires_at"]))):
        raise SystemExit("The local source, release manifest, or plan lease differs")
    project = plan["project"]
    docker_env = _local_docker_environment(os.environ.copy())

    def inspect(command: list[str]) -> str:
        return subprocess.check_output(["docker", *command], env=docker_env,
                                       text=True, timeout=30)

    if args.resume:
        root = Path("/tmp") / project
        env_file = root / "acceptance.env"
        if not env_file.is_file():
            raise SystemExit("Staged local environment is missing")
    else:
        _require_empty_project(project, inspect)
        root, env_file = stage_disposable_inputs(plan, args.port, now=now)
    env = _local_docker_environment(_staged_environment(env_file))
    if args.resume:
        args.port = int(env["PASSPORT_ACCEPTANCE_GATEWAY_PORT"])
    compose = _compose_args(plan, env_file)
    log = root / "local-watch.log"
    output_dir = root / "bootstrap-output"
    watch = ROOT / "docker-compose.passport-supported-disposable-watch.yml"
    if args.stop:
        owned = inspect(["ps", "-aq", "--filter",
                         f"label=com.docker.compose.project={project}"]).split()
        for container in owned:
            details = json.loads(inspect(["inspect", container]))
            labels = details[0]["Config"]["Labels"] if len(details) == 1 else {}
            if labels.get("com.marty.passport.acceptance.owner") != "supported-consumer":
                raise SystemExit("Disposable project contains an unowned container")
        print(f"Stopping disposable project {project}...", flush=True)
        if not run([*compose, "-f", str(watch), "down", "--volumes",
                    "--remove-orphans"], env, log, 300):
            raise SystemExit(f"Disposable teardown failed; inspect {log}")
        _remove_bootstrap_output(output_dir)
        log.unlink(missing_ok=True)
        _remove_staged_inputs(root)
        print("Disposable project and staged secrets removed.", flush=True)
        return 0
    log.touch(mode=0o600, exist_ok=True)
    print(f"Disposable project: {project}", flush=True)
    print(f"Private startup log: {log}", flush=True)
    phases = (
        ("infrastructure", [*compose, "up", "-d", "--no-deps", "--wait",
                            "--wait-timeout", "120", *INFRA], 300),
        ("OpenBao bootstrap", _bootstrap_args(plan, root, output_dir, args.port), 180),
    )
    if not args.resume:
        _prepare_bootstrap_output(output_dir)
        for name, command, timeout in phases:
            print(f"Starting {name}...", flush=True)
            if not run(command, env, log, timeout):
                print(f"{name} failed. Inspect {log} and project containers.", flush=True)
                return 1
        _accept_bootstrap_files(root, output_dir)
        print("Starting managed signer...", flush=True)
        if not run([*compose, "up", "-d", "--wait", "--wait-timeout", "360",
                    "signing-keys"], env, log, 600):
            print(f"Managed signer failed. Inspect {log}.", flush=True)
            return 1
        certificate = bootstrap_certificate_chain(plan, root, args.port,
                                                  now=datetime.now(timezone.utc))
        validate_certificate_setup(certificate, plan, args.port)
    if not args.watch_only:
        print("Starting complete local stack...", flush=True)
        if not run([*compose, "-f", str(watch), "up", "-d", "--build",
                    "--wait", "--wait-timeout", "1200"],
                   env, log, 1500):
            print(f"Local stack startup failed. Project retained for diagnosis: {project}",
                  flush=True)
            return 1
    print("Replacing issuance-native with source watcher...", flush=True)
    if not run([*compose, "-f", str(watch), "up", "-d", "--no-deps",
                "--build", "--force-recreate", "--wait", "--wait-timeout", "1200",
                "issuance-native"], env, log, 1500):
        print(f"Watcher startup failed. Project retained for diagnosis: {project}",
              flush=True)
        return 1
    print(f"Local live-refresh stack is running at https://localhost:{args.port}", flush=True)
    print(f"Rust edits under {ROOT / 'rust'} trigger issuance-native rebuilds.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
