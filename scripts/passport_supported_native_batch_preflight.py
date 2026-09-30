#!/usr/bin/env python3
"""Preflight native beta reconciliation inside the owned disposable project."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.passport_disposable_identity import ORGANIZATION_ID

if __package__:
    from .check_passport_supported_compose_ownership import (
        docker, verify as verify_ownership,
    )
    from .passport_supported_disposable_ceremony import _local_docker_env, _operator_key
    from .probe_passport_beta_native_batch import (
        CONTAINER_ID, request_private_preflight,
    )
else:
    from check_passport_supported_compose_ownership import docker, verify as verify_ownership
    from passport_supported_disposable_ceremony import _local_docker_env, _operator_key
    from probe_passport_beta_native_batch import CONTAINER_ID, request_private_preflight


class DisposableBatchPreflightError(ValueError):
    pass


def preflight_owned_native(
    record: dict[str, Any], surface: str, *,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    request: Callable[..., None] = request_private_preflight,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Require the exact project's current native process and distinct tokens."""
    project = record.get("project") if isinstance(record, dict) else None
    containers = record.get("containers") if isinstance(record, dict) else None
    native_id = containers.get("issuance-native") if isinstance(containers, dict) else None
    if (not isinstance(project, str)
        or not project.startswith(f"marty-passport-acceptance-{surface}-")
        or not isinstance(native_id, str) or CONTAINER_ID.fullmatch(native_id) is None):
        raise DisposableBatchPreflightError("Owned native batch identity is invalid")
    root = Path(tempfile.gettempdir()) / project
    if record.get("disposable_root") != str(root) or root.resolve() != root:
        raise DisposableBatchPreflightError("Owned native batch root is invalid")

    def require_ownership() -> None:
        proof = ownership(record, surface, clock(), inspector)
        if not isinstance(proof, dict) or proof.get("live_ownership_verified") is not True:
            raise DisposableBatchPreflightError("Disposable native batch ownership changed")

    require_ownership()
    service_token = _operator_key(root / "secrets", "grpc_service_token")
    operator_token = _operator_key(
        root / "secrets", "passport_beta_reconciliation_operator_token")
    if service_token == operator_token:
        raise DisposableBatchPreflightError("Native batch operator token is not distinct")

    def runner(command: list[str], body: bytes) -> bytes:
        if command != ["docker", "exec", "-i", native_id, "curl", "--config", "-"]:
            raise DisposableBatchPreflightError("Native batch request escaped its owner")
        require_ownership()
        try:
            result = run(command, input=body, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, check=False, timeout=70,
                         env=_local_docker_env())
        except (OSError, subprocess.SubprocessError) as exc:
            raise DisposableBatchPreflightError("Owned native batch request failed") from exc
        if result.returncode != 0:
            raise DisposableBatchPreflightError("Owned native batch request failed")
        return result.stdout

    request(native_id, ORGANIZATION_ID, service_token, operator_token,
            runner=runner)
    require_ownership()
    return {"native_container_id": native_id,
            "native_batch_preflight_verified": True}
