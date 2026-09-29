#!/usr/bin/env python3
"""Read the owned disposable Flow's durable step history without publishing it."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Callable
from uuid import UUID

if __package__:
    from .check_passport_supported_compose_ownership import (
        IDENTIFIER, docker, verify as verify_ownership,
    )
else:
    from check_passport_supported_compose_ownership import (
        IDENTIFIER, docker, verify as verify_ownership,
    )

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.passport_disposable_identity import ORGANIZATION_ID


class FlowHistoryError(ValueError):
    pass


def _uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise FlowHistoryError("Disposable Flow history ID is invalid") from error
    if str(parsed) != value:
        raise FlowHistoryError("Disposable Flow history ID is not canonical")
    return value


def read_owned_flow_history(
    record: dict[str, Any], surface: str, instance_id: str,
    definition_id: str, *,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
) -> dict[str, Any]:
    """Read only the instance history and definition steps from owned Postgres."""
    instance_id = _uuid(instance_id)
    definition_id = _uuid(definition_id)
    proof = ownership(record, surface, datetime.now(timezone.utc), inspector)
    if proof.get("live_ownership_verified") is not True:
        raise FlowHistoryError("Disposable Flow storage ownership is unverified")
    containers = record.get("containers")
    postgres = containers.get("postgres") if isinstance(containers, dict) else None
    if not isinstance(postgres, str) or IDENTIFIER.fullmatch(postgres) is None:
        raise FlowHistoryError("Disposable Flow Postgres owner is invalid")
    query = (
        "SELECT json_build_object("
        "'organization_id',i.organization_id,"
        "'flow_definition_id',i.flow_definition_id,"
        "'status',i.status,"
        "'step_history',i.step_history,"
        "'steps',d.steps) "
        "FROM flow_service.flow_instances i "
        "JOIN flow_service.flow_definitions d ON d.id=i.flow_definition_id "
        f"WHERE i.id='{instance_id}' AND d.id='{definition_id}' "
        f"AND i.organization_id='{ORGANIZATION_ID}' "
        f"AND d.organization_id='{ORGANIZATION_ID}'"
    )
    output = inspector([
        "exec", "--user", "postgres", postgres,
        "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1",
        "-U", "marty", "-d", "marty", "-c", query,
    ])
    if not isinstance(output, str) or len(output) > 131072:
        raise FlowHistoryError("Disposable Flow history output is invalid")
    lines = output.strip().splitlines()
    if len(lines) != 1:
        raise FlowHistoryError("Disposable Flow history row is missing")
    try:
        value = json.loads(lines[0])
    except ValueError as error:
        raise FlowHistoryError("Disposable Flow history row is invalid") from error
    if not isinstance(value, dict) or set(value) != {
        "organization_id", "flow_definition_id", "status", "step_history", "steps",
    }:
        raise FlowHistoryError("Disposable Flow history shape is invalid")
    return value
