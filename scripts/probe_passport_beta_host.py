#!/usr/bin/env python3
"""Read-only Docker/PostgreSQL probes for beta passport drain and prod continuity."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from typing import Any, Callable


PRODUCTION_PROJECTS = ("marty-selfhost-prod", "marty-selfhost-openbao")
REQUIRED_PRODUCTION_SERVICES = {
    "marty-selfhost-prod": {"gateway", "postgres", "ui"},
    "marty-selfhost-openbao": {"openbao"},
}
BETA_PROJECT = "elevenid-beta"
COUNT = re.compile(r"[0-9]+\Z")
LEGACY_ARTIFACT_SQL = """
WITH artifacts AS (
    SELECT CASE WHEN left(secure_artifact_ciphertext, 1) = '{'
        THEN secure_artifact_ciphertext::jsonb ELSE NULL END AS manifest,
        CASE WHEN left(secure_artifact_ciphertext, 1) = '{'
        THEN secure_artifact_ciphertext::json ELSE NULL END AS raw_manifest
    FROM issuance_service.physical_document_jobs
)
SELECT count(*) FROM artifacts WHERE CASE
    WHEN manifest IS NULL THEN true
    WHEN jsonb_typeof(manifest) IS DISTINCT FROM 'object' THEN true
    WHEN (SELECT count(*) FROM json_each(raw_manifest)) <> 2 THEN true
    WHEN manifest->>'schema' IS DISTINCT FROM 'marty.passport-artifact-manifest/v1'
        OR jsonb_typeof(manifest->'chunks') IS DISTINCT FROM 'array'
        OR manifest - 'schema' - 'chunks' <> '{}'::jsonb THEN true
    WHEN jsonb_array_length(manifest->'chunks') NOT BETWEEN 1 AND 4096 THEN true
    WHEN EXISTS (
        SELECT 1 FROM jsonb_array_elements(manifest->'chunks') AS chunk(value)
        WHERE jsonb_typeof(chunk.value) <> 'string'
            OR left(chunk.value #>> '{}', 7) <> 'vault:v'
            OR length(chunk.value #>> '{}') > 2000000
    ) THEN true
    ELSE false
END
"""
ACTIVE_PHYSICAL_FLOWS_SQL = """
SELECT count(*) FROM flow_service.flow_instances AS instance
LEFT JOIN flow_service.flow_definitions AS definition ON definition.id = instance.flow_definition_id
WHERE ((definition.id IS NULL AND NOT COALESCE((
        instance.status = 'awaiting_wallet'
        AND instance.expires_at < clock_timestamp()
        AND instance.current_step_id IS NULL
        AND instance.application_flow_key_hash IS NULL
        AND instance.step_history::jsonb = '[]'::jsonb
        AND instance.context::jsonb->>'flow_definition_reference' = '__verification__'
        AND instance.context::jsonb->>'flow_type' = 'verification'
        AND instance.context::jsonb->>'protocol_flow_type' = 'oid4vp_presentation'
        AND jsonb_typeof(instance.context::jsonb->'auth_request') = 'string'
        AND nullif(btrim(instance.context::jsonb->>'auth_request'), '') IS NOT NULL
        AND jsonb_typeof(instance.context::jsonb->'oid4vp_profile') = 'string'
        AND nullif(btrim(instance.context::jsonb->>'oid4vp_profile'), '') IS NOT NULL
        AND jsonb_typeof(instance.context::jsonb->'request_uri') = 'string'
        AND nullif(btrim(instance.context::jsonb->>'request_uri'), '') IS NOT NULL
        AND instance.context::jsonb::text NOT ILIKE '%physical_document%'
        AND instance.context::jsonb::text NOT ILIKE '%passport%'
        AND ((instance.subject_type = 'holder'
                AND instance.state_history::jsonb->0->>'event' = 'verification_started'
                AND instance.state_history::jsonb->0->>'actor' = 'verification_api')
            OR (instance.subject_type = 'applicant'
                AND instance.state_history::jsonb = '[]'::jsonb))
    ), false))
    OR lower(definition.flow_type) = 'physical_document_issuance'
    OR (lower(definition.flow_type) = 'custom'
        AND definition.extension::jsonb->>'extends_flow_type' = 'physical_document_issuance')
    OR instance.context::jsonb ? 'physical_document_job')
    AND lower(instance.status) NOT IN ('completed', 'failed', 'cancelled', 'expired')
"""


class HostProbeError(ValueError):
    pass


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        # Docker inspect output and psql stderr may contain unrelated secrets.
        raise HostProbeError("Beta host inspection failed") from exc
    return result.stdout.strip()


def ids(project: str, runner: Callable[[list[str]], str] = run) -> list[str]:
    output = runner(["docker", "ps", "--all", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}}"])
    result = [line.strip() for line in output.splitlines() if line.strip()]
    if len(result) != len(set(result)):
        raise HostProbeError("Compose project has duplicate container IDs")
    return result


def inspect(container_id: str, runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    try:
        value = json.loads(runner(["docker", "inspect", container_id]))
    except ValueError as exc:
        raise HostProbeError("Docker inspection response is invalid") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise HostProbeError("Docker inspection response is ambiguous")
    return value[0]


def production_snapshot(runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    projected = []
    counts = {}
    for project in PRODUCTION_PROJECTS:
        project_ids = ids(project, runner)
        if not project_ids:
            raise HostProbeError(f"Production Compose project {project} is missing")
        counts[project] = len(project_ids)
        running_services = set()
        for container_id in project_ids:
            record = inspect(container_id, runner)
            config = record.get("Config")
            state = record.get("State")
            if not isinstance(config, dict) or not isinstance(state, dict):
                raise HostProbeError("Production container state is incomplete")
            labels = config.get("Labels")
            if not isinstance(labels, dict) or labels.get("com.docker.compose.project") != project:
                raise HostProbeError("Production Compose project identity changed")
            service = labels.get("com.docker.compose.service")
            if state.get("Running") is True and state.get("Status") == "running":
                running_services.add(service)
                health = state.get("Health")
                if isinstance(health, dict) and health.get("Status") != "healthy":
                    raise HostProbeError("A running production service is unhealthy")
            mounts = record.get("Mounts")
            if not isinstance(mounts, list):
                raise HostProbeError("Production mounts are unavailable")
            projected_mounts = [
                {"type": mount.get("Type"), "name": mount.get("Name"),
                 "destination": mount.get("Destination"), "read_write": mount.get("RW")}
                for mount in mounts if isinstance(mount, dict)
            ]
            projected_mounts.sort(key=lambda item: json.dumps(item, sort_keys=True))
            projected.append({
                "id": record.get("Id"), "image": record.get("Image"),
                "name": record.get("Name"), "project": project,
                "service": labels.get("com.docker.compose.service"),
                "running": state.get("Running"), "status": state.get("Status"),
                "started_at": state.get("StartedAt"),
                "health": state.get("Health", {}).get("Status") if isinstance(state.get("Health"), dict) else None,
                "mounts": projected_mounts,
            })
        if not REQUIRED_PRODUCTION_SERVICES[project].issubset(running_services):
            raise HostProbeError(f"Required production runtime is unavailable in {project}")
    projected.sort(key=lambda item: (item["project"], str(item["service"]), str(item["name"])))
    encoded = json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "container_counts": counts}


def assert_production_unchanged(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before != after:
        raise HostProbeError("Production container identity or state changed during beta probes")
    return {"verified": True, "evidence": {"before_sha256": before["sha256"],
                                           "after_sha256": after["sha256"],
                                           "container_counts": after["container_counts"],
                                           "scope": "acceptance-run-window-only"}}


def beta_legacy_drain(runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    postgres_ids = []
    for container_id in ids(BETA_PROJECT, runner):
        record = inspect(container_id, runner)
        config = record.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if isinstance(labels, dict) and labels.get("com.docker.compose.service") == "postgres":
            postgres_ids.append(container_id)
    if len(postgres_ids) != 1:
        raise HostProbeError("Beta PostgreSQL service is missing or ambiguous")
    container_id = postgres_ids[0]

    def query(sql: str) -> str:
        return runner(["docker", "exec", container_id, "psql", "-U", "postgres", "-d", "marty",
                       "-At", "-v", "ON_ERROR_STOP=1", "-c", sql])

    if query("SELECT to_regclass('issuance_service.physical_document_jobs') IS NOT NULL") != "t":
        raise HostProbeError("Beta physical document job table is missing")
    pending = query("SELECT count(*) FROM issuance_service.physical_document_jobs WHERE status NOT IN ('ACTIVE', 'FAILED', 'CANCELLED')")
    legacy = query(LEGACY_ARTIFACT_SQL)
    if query("SELECT to_regclass('flow_service.flow_instances') IS NOT NULL AND to_regclass('flow_service.flow_definitions') IS NOT NULL") != "t":
        raise HostProbeError("Beta physical document Flow tables are missing")
    active_flows = query(ACTIVE_PHYSICAL_FLOWS_SQL)
    if not COUNT.fullmatch(pending) or not COUNT.fullmatch(legacy) or not COUNT.fullmatch(active_flows):
        raise HostProbeError("Beta passport drain counts are invalid")
    if int(pending) != 0 or int(legacy) != 0 or int(active_flows) != 0:
        raise HostProbeError("In-flight passport jobs or Flows, or legacy artifacts remain in beta")
    return {"verified": True, "evidence": {"in_flight_jobs": 0, "legacy_or_unknown_artifacts": 0,
                                           "active_physical_document_flows": 0,
                                           "database": "beta", "source": "live PostgreSQL"}}
