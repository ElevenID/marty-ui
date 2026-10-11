#!/usr/bin/env python3
"""Disposable cold backup/restore rehearsal for the three self-host state mounts.

The caller supplies complete, rendered source and target Compose models. This
checks state mechanics; it does not restore OpenBao, secrets, or app business data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from check_selfhost_recovery_scope import recovery_scope


PROBE = "marty-recovery-probe"


def run(*args: str, timeout: int = 120) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()


def read_model(path: Path, state_root: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    model = json.loads(raw)
    recovery_scope(model, state_root, digest)
    for service in ("postgres", "redis"):
        image = model["services"][service].get("image")
        if (not isinstance(image, str) or not image or
                (":" not in image.rsplit("/", 1)[-1] and "@sha256:" not in image) or
                image.endswith(":latest")):
            raise ValueError(f"{service} requires a versioned image in the model")
    return model, digest


def start(name: str, image: str, state: Path, kind: str, password: str) -> None:
    mount = f"type=bind,src={state},dst={'/var/lib/postgresql/data' if kind == 'postgres' else '/data'}"
    args = ["docker", "run", "-d", "--name", name, "--label", "marty.recovery-rehearsal=true", "--mount", mount]
    if kind == "postgres":
        args += ["-e", f"POSTGRES_PASSWORD={password}", image]
    else:
        args += [image, "redis-server", "--appendonly", "yes"]
    run(*args)
    check = ("pg_isready", "-U", "postgres") if kind == "postgres" else ("redis-cli", "ping")
    for _ in range(40):
        try:
            run("docker", "exec", name, *check, timeout=5)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            time.sleep(1)
    raise RuntimeError(f"{kind} did not become ready")


def stop_owned(name: str) -> None:
    try:
        label = run("docker", "inspect", "--format", "{{index .Config.Labels \"marty.recovery-rehearsal\"}}", name)
    except subprocess.CalledProcessError:
        return
    if label != "true":
        raise RuntimeError(f"refusing to remove unowned container {name}")
    run("docker", "rm", "-f", name)


def probe_write(pg: str, redis: str, applicant: Path, marker: str) -> None:
    run("docker", "exec", pg, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c",
        f"CREATE TABLE recovery_probe (marker text NOT NULL); INSERT INTO recovery_probe VALUES ('{marker}');")
    run("docker", "exec", redis, "redis-cli", "SET", PROBE, marker)
    applicant.mkdir(parents=True, exist_ok=True)
    (applicant / "applicant_store.json").write_text(json.dumps({"recovery_probe": marker}), encoding="utf-8")


def probe_check(pg: str, redis: str, applicant: Path, marker: str) -> None:
    pg_value = run("docker", "exec", pg, "psql", "-U", "postgres", "-At", "-c",
                   "SELECT marker FROM recovery_probe")
    redis_value = run("docker", "exec", redis, "redis-cli", "GET", PROBE)
    applicant_value = json.loads((applicant / "applicant_store.json").read_text(encoding="utf-8"))["recovery_probe"]
    if (pg_value, redis_value, applicant_value) != (marker, marker, marker):
        raise RuntimeError("restored state probe mismatch")


def rehearse(source_model: dict, target_model: dict, source_digest: str, target_digest: str,
             source_version: str, target_version: str, work_root: Path) -> dict:
    """Run only in a fresh, disposable directory; never point at operator state."""
    if work_root.exists() and any(work_root.iterdir()):
        raise ValueError("rehearsal work directory must be empty")
    work_root.mkdir(exist_ok=True)
    marker = secrets.token_hex(16)
    names = {kind: f"marty-recovery-{uuid.uuid4().hex[:16]}-{kind}" for kind in ("postgres", "redis")}
    source = work_root / "source"
    backup = work_root / "backup"
    restored = work_root / "restored"
    for root in (source, backup, restored):
        root.mkdir()
    try:
        for kind in names:
            (source / kind).mkdir()
            start(names[kind], source_model["services"][kind]["image"], source / kind, kind, marker)
        probe_write(names["postgres"], names["redis"], source / "applicant", marker)
        for name in names.values():
            stop_owned(name)
        for kind in ("postgres", "redis", "applicant"):
            shutil.copytree(source / kind, backup / kind)
            shutil.copytree(backup / kind, restored / kind)
        for kind in names:
            start(names[kind], target_model["services"][kind]["image"], restored / kind, kind, marker)
        probe_check(names["postgres"], names["redis"], restored / "applicant", marker)
        return {
            "schema": "marty.selfhost-state-rehearsal/v1",
            "result": "pass",
            "qualification": "state-mechanics-only",
            "source_version": source_version,
            "target_version": target_version,
            "source_compose_sha256": source_digest,
            "target_compose_sha256": target_digest,
            "source_images": {kind: source_model["services"][kind]["image"] for kind in names},
            "target_images": {kind: target_model["services"][kind]["image"] for kind in names},
            "verified_state": ["postgres-row", "redis-aof-key", "applicant-json-file"],
            "excluded": ["OpenBao state/export", "operator secrets and environment", "application business journey"],
        }
    finally:
        for name in names.values():
            stop_owned(name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-model", type=Path, required=True)
    parser.add_argument("--target-model", type=Path, required=True)
    parser.add_argument("--source-state-root", type=Path, required=True)
    parser.add_argument("--target-state-root", type=Path, required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.source_version == args.target_version:
        raise ValueError("source and target versions must differ for an upgrade rehearsal")
    source, source_digest = read_model(args.source_model, args.source_state_root)
    target, target_digest = read_model(args.target_model, args.target_state_root)
    with tempfile.TemporaryDirectory(prefix="marty-recovery-") as temp:
        report = rehearse(source, target, source_digest, target_digest,
                          args.source_version, args.target_version, Path(temp))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
