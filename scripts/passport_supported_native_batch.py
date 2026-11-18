#!/usr/bin/env python3
"""Bind first accepted bureau material to the owned disposable PostgreSQL."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable

if __package__:
    from .check_passport_supported_compose_ownership import (
        IDENTIFIER, docker, verify as verify_ownership,
    )
    from .probe_passport_beta_host import material_receipt
    from .passport_supported_disposable_ceremony import _local_docker_env, _operator_key
    from .passport_supported_flow_gateway import _private_key, owned_gateway_request
    from .passport_supported_native_batch_preflight import preflight_owned_native
    from .passport_supported_private_bureau_poll import poll_owned_bureau
    from .probe_passport_beta_native_batch import (
        exercise as exercise_native_batch,
        request_private_batch,
    )
else:
    from check_passport_supported_compose_ownership import (
        IDENTIFIER, docker, verify as verify_ownership,
    )
    from probe_passport_beta_host import material_receipt
    from passport_supported_disposable_ceremony import _local_docker_env, _operator_key
    from passport_supported_flow_gateway import _private_key, owned_gateway_request
    from passport_supported_native_batch_preflight import preflight_owned_native
    from passport_supported_private_bureau_poll import poll_owned_bureau
    from probe_passport_beta_native_batch import (
        exercise as exercise_native_batch,
        request_private_batch,
    )


class DisposableMaterialError(ValueError):
    pass


def exercise_owned_native_batch(
    record: dict[str, Any], surface: str, gateway_port: int,
    application: dict[str, Any], physical_document: dict[str, Any],
    selected_flow_instance_id: str, selected_application_id: str,
    selected_source_job_id: str, selected_sod_sha256: str,
    dsc_der_sha256: str, dsc_pem_wire_sha256: str,
    private_state_path: Path, deadline: datetime, *,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    preflight: Callable[..., dict] = preflight_owned_native,
    batch: Callable[..., tuple[str, dict[str, Any]]] = exercise_native_batch,
    gateway_factory: Callable[..., Any] = owned_gateway_request,
    private_request: Callable[..., tuple[int, dict[str, Any]]] = request_private_batch,
    poll: Callable[..., tuple[int, dict[str, Any]]] = poll_owned_bureau,
    material: Callable[..., dict[str, Any]] | None = None,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, dict[str, Any]]:
    """Submit the selected Flow job through exact owned native and bureau peers."""
    if not isinstance(deadline, datetime) or deadline.tzinfo is None:
        raise DisposableMaterialError("Disposable batch deadline is invalid")
    containers = record.get("containers") if isinstance(record, dict) else None
    native_id = containers.get("issuance-native") if isinstance(containers, dict) else None
    bureau_id = containers.get("passport-beta-bureau") if isinstance(containers, dict) else None
    if (not isinstance(native_id, str) or IDENTIFIER.fullmatch(native_id) is None
        or not isinstance(bureau_id, str) or IDENTIFIER.fullmatch(bureau_id) is None):
        raise DisposableMaterialError("Disposable batch peers are unowned")
    root = Path(record["disposable_root"])
    _, api_key = _private_key(record, False)
    service_token = _operator_key(root / "secrets", "grpc_service_token")
    operator_token = _operator_key(
        root / "secrets", "passport_beta_reconciliation_operator_token")
    if service_token == operator_token:
        raise DisposableMaterialError("Disposable batch operator token is not distinct")

    def require_budget(seconds: float = 0) -> None:
        current = clock()
        if (current.tzinfo is None or current.timestamp() + seconds + 600
            >= deadline.timestamp()):
            raise DisposableMaterialError("Disposable batch teardown budget is exhausted")

    def require_ownership() -> None:
        require_budget()
        proof = ownership(record, surface, clock(), inspector)
        if not isinstance(proof, dict) or proof.get("live_ownership_verified") is not True:
            raise DisposableMaterialError("Disposable batch ownership changed")

    require_ownership()
    ready = preflight(record, surface, inspector=inspector, ownership=ownership)
    if ready != {"native_container_id": native_id,
                 "native_batch_preflight_verified": True}:
        raise DisposableMaterialError("Recreated native batch preflight is invalid")
    gateway = gateway_factory(
        record, surface, operator=False, passport_write=True,
        expected_port=gateway_port, inspector=inspector, ownership=ownership)

    def public_request(method: str, path: str, body: dict | None,
                       supplied_key: str) -> tuple[int, dict]:
        if supplied_key != api_key:
            raise DisposableMaterialError("Disposable batch API authority changed")
        require_ownership()
        return gateway(method, path, body, {})

    def docker_runner(command: list[str], body: bytes) -> bytes:
        if command != ["docker", "exec", "-i", native_id, "curl", "--config", "-"]:
            raise DisposableMaterialError("Disposable batch Docker request escaped its owner")
        require_ownership()
        try:
            result = run(command, input=body, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, check=False, timeout=70,
                         env=_local_docker_env())
        except (OSError, subprocess.SubprocessError) as exc:
            raise DisposableMaterialError("Disposable batch private request failed") from exc
        if result.returncode != 0:
            raise DisposableMaterialError("Disposable batch private request failed")
        return result.stdout

    def private_call(*args):
        return private_request(*args, runner=docker_runner)

    def simulator_call(container_id: str, method: str, path: str) -> tuple[int, bytes, dict]:
        prefix = "/v1/personalization/jobs/"
        if (container_id != bureau_id or method != "GET"
            or not path.startswith(prefix)
            or re.fullmatch(r"[0-9a-f-]{36}", path[len(prefix):]) is None):
            raise DisposableMaterialError("Disposable simulator poll escaped its owner")
        require_ownership()
        status, projection = poll(
            record, surface, path[len(prefix):], now=clock(),
            inspector=inspector, ownership=ownership)
        return status, b"", projection

    def material_call(*args):
        require_ownership()
        return (material or read_owned_material_receipt)(
            record, surface, *args, inspector=inspector,
            ownership=ownership, clock=clock)

    def bounded_sleep(seconds: float) -> None:
        require_budget(seconds)
        sleep(seconds)
        require_budget()

    selected_bureau_id, proof = batch(
        application, physical_document, api_key, service_token, operator_token,
        native_id, bureau_id, selected_flow_instance_id, selected_application_id,
        selected_source_job_id, selected_sod_sha256, dsc_der_sha256,
        dsc_pem_wire_sha256, material_call, private_state_path,
        gateway_request=public_request, private_request=private_call,
        simulator_get=simulator_call, sleep=bounded_sleep)
    require_ownership()
    return selected_bureau_id, {"final_native_preflight": ready, "batch": proof}


def read_owned_material_receipt(
    record: dict[str, Any], surface: str,
    organization_id: str, source_job_id: str, bureau_job_id: str,
    sod_der_sha256: str, dsc_der_sha256: str, dsc_pem_wire_sha256: str,
    commitment_key: bytes, *,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Read exactly one accepted row from this project, never ambient beta."""
    containers = record.get("containers") if isinstance(record, dict) else None
    postgres = containers.get("postgres") if isinstance(containers, dict) else None
    if (not isinstance(postgres, str) or IDENTIFIER.fullmatch(postgres) is None
        or record.get("project") is None):
        raise DisposableMaterialError("Disposable material database is unowned")

    def query(sql: str) -> str:
        proof = ownership(record, surface, clock(), inspector)
        if not isinstance(proof, dict) or proof.get("live_ownership_verified") is not True:
            raise DisposableMaterialError("Disposable material database ownership changed")
        output = inspector([
            "exec", "--user", "postgres", postgres,
            "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "marty", "-d", "marty", "-c", sql,
        ])
        if not isinstance(output, str) or len(output) > 64 or len(output.strip().splitlines()) != 1:
            raise DisposableMaterialError("Disposable material row output is invalid")
        return output.strip()

    return material_receipt(
        organization_id, source_job_id, bureau_job_id,
        sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
        commitment_key, query=query, source="private disposable PostgreSQL",
    )
