#!/usr/bin/env python3
"""Fail-closed pre-mutation gates and read-only record collection for a future producer.

No function in this module creates or removes Docker resources. The protected
workflow deliberately stops before provisioning until disposable KMS and
provider credentials are governed and available.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable

if __package__:
    from .check_passport_supported_compose_ownership import (
        _inspect, docker, verify as verify_ownership,
    )
    from .check_passport_supported_rollback_model import (
        DISPOSABLE_SERVICES, ModelPreflightError, preflight_attested_plan,
        source_identity,
    )
    from .passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, PlanError, _attest, release_inputs,
    )
else:
    from check_passport_supported_compose_ownership import (
        _inspect, docker, verify as verify_ownership,
    )
    from check_passport_supported_rollback_model import (
        DISPOSABLE_SERVICES, ModelPreflightError, preflight_attested_plan,
        source_identity,
    )
    from passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, PlanError, _attest, release_inputs,
    )


WORKFLOW_REF = (
    "ElevenID/marty-ui/.github/workflows/"
    "passport-supported-provisioning-producer.yml@refs/heads/main"
)
RESOURCE_ID = re.compile(r"[0-9a-f]{64}\Z")


class ProducerError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ProducerError(message)


def protected_context(environment: dict[str, str]) -> tuple[str, str]:
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
            and environment.get("GITHUB_REF") == "refs/heads/main"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_WORKFLOW_REF") == WORKFLOW_REF,
            "Protected producer workflow identity is invalid")
    source, run_id = environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID")
    require(isinstance(source, str) and COMMIT.fullmatch(source) is not None
            and isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None,
            "Protected producer source/run is invalid")
    return source, run_id


def verify_plan_release(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], *,
    attest: Callable[[str, str, str, str, str], bool] = _attest,
    release: Callable[..., dict] = release_inputs,
    now: datetime | None = None,
    checkout: Callable[[], tuple[str, bool]] = source_identity,
) -> dict:
    """Verify source, exact plan run, lease and release before any model read."""
    source, _ = protected_context(environment)
    require(RUN_ID.fullmatch(plan_run_id) is not None,
            "Protected plan run ID is invalid")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProducerError("Protected plan artifact is invalid") from exc
    require(isinstance(plan, dict)
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and plan.get("status") == "blocked"
            and plan.get("source_commit") == source
            and plan.get("run_id") == plan_run_id
            and plan.get("surface") in {"base", "selfhost"},
            "Protected plan source/run/surface mismatch")
    try:
        verified = attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                          source, "refs/heads/main")
    except (OSError, ValueError) as exc:
        raise ProducerError("Protected plan attestation failed") from exc
    require(verified is True, "Protected plan attestation failed")
    head, dirty = checkout()
    require(head == source and not dirty,
            "Protected producer checkout differs from attested plan")
    try:
        created = datetime.fromisoformat(plan["created_at"])
        expires = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProducerError("Protected plan lease is invalid") from exc
    current = now or datetime.now(timezone.utc)
    require(current.tzinfo is not None and created.tzinfo is not None
            and expires.tzinfo is not None
            and created <= current < expires <= created + timedelta(hours=2),
            "Protected plan lease is expired or too broad")
    require(plan.get("stack_manifest_sha256") == hashlib.sha256(
        manifest_path.read_bytes()).hexdigest(),
        "Official release manifest differs from protected plan")
    try:
        official = release(manifest_path, source)
    except (PlanError, OSError, ValueError) as exc:
        raise ProducerError("Official release verification failed") from exc
    require(all(plan.get(key) == value for key, value in official.items()),
            "Official release differs from protected plan")
    return plan


def verify_pre_mutation(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], env_file: Path, disposable_root: Path,
    *, now: datetime | None = None,
) -> dict:
    """Complete release and model gates for a future explicitly enabled producer."""
    plan = verify_plan_release(plan_path, manifest_path, plan_run_id,
                               environment, now=now)
    report = preflight_attested_plan(
        plan["surface"], plan["project"], env_file, disposable_root,
        plan["services_reference"], plan_path, now=now)
    require(report.get("status") == "blocked"
            and report.get("model", {}).get("model_safe") is True,
            "Disposable model preflight failed")
    return plan


def collect_record(
    plan_path: Path, plan: dict, producer_run_id: str,
    now: datetime, runner: Callable[[list[str]], str] = docker,
    *, ownership: Callable[..., dict] = verify_ownership,
) -> dict:
    """Read exact live IDs and require the ownership proof before returning a record."""
    require(isinstance(producer_run_id, str)
            and RUN_ID.fullmatch(producer_run_id) is not None,
            "Protected producer run ID is invalid")
    project = plan.get("project")
    require(isinstance(project, str), "Protected project is invalid")
    labels = plan.get("owner_labels")
    require(isinstance(labels, dict), "Protected resource labels are invalid")
    ids = runner(["ps", "-aq", "--no-trunc", "--filter",
                  f"label=com.docker.compose.project={project}"]).split()
    containers: dict[str, str] = {}
    for identifier in ids:
        require(RESOURCE_ID.fullmatch(identifier) is not None,
                "Disposable container ID is invalid")
        item = _inspect("container", identifier, runner)
        config = item.get("Config")
        actual_labels = config.get("Labels") if isinstance(config, dict) else None
        require(isinstance(actual_labels, dict),
                "Disposable container labels are missing")
        service = actual_labels.get("com.docker.compose.service")
        require(service in DISPOSABLE_SERVICES and service not in containers,
                "Disposable service set is invalid")
        containers[service] = identifier
    require(set(containers) == DISPOSABLE_SERVICES,
            "Disposable service set is incomplete")
    network_ids = runner(["network", "ls", "-q", "--no-trunc", "--filter",
                          f"label=com.docker.compose.project={project}"]).split()
    networks: dict[str, str] = {}
    for identifier in network_ids:
        require(RESOURCE_ID.fullmatch(identifier) is not None,
                "Disposable network ID is invalid")
        item = _inspect("network", identifier, runner)
        name = item.get("Name")
        require(isinstance(name, str) and name not in networks,
                "Disposable network set is invalid")
        networks[name] = identifier
    volumes = runner(["volume", "ls", "-q", "--filter",
                      f"label=com.docker.compose.project={project}"]).split()
    require(len(volumes) == len(set(volumes)), "Disposable volume set is invalid")
    record = {
        "schema": "marty.passport-supported-compose-ownership/v1",
        "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "producer_run_id": producer_run_id,
        "containers": containers, "networks": networks, "volumes": volumes,
        **{key: plan[key] for key in (
            "run_id", "project", "source_commit", "services_reference",
            "migrations_reference", "legacy_reference", "infra_images",
            "created_at", "expires_at", "owner_labels",
        )},
    }
    proof = ownership(record, plan["surface"], now, runner)
    require(proof.get("live_ownership_verified") is True
            and proof.get("rollback_accepted") is False,
            "Disposable live ownership proof failed")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan-run-id", required=True)
    args = parser.parse_args()
    try:
        verify_plan_release(args.plan, args.manifest, args.plan_run_id, os.environ)
    except (ProducerError, ModelPreflightError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected disposable provisioning blocked: {exc}\n")
    parser.exit(1, "Protected disposable provisioning blocked: governed KMS/bootstrap and provider inputs are absent\n")


if __name__ == "__main__":
    raise SystemExit(main())
