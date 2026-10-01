#!/usr/bin/env python3
"""Read-only Docker/PostgreSQL probes for beta passport drain and prod continuity."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import subprocess
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable


PRODUCTION_PROJECTS = ("marty-selfhost-prod", "marty-selfhost-openbao")
PRODUCTION_PUBLIC_ORIGIN = "https://elevenidllc.com/"
REQUIRED_PRODUCTION_SERVICES = {
    "marty-selfhost-prod": {"gateway", "postgres", "ui"},
    "marty-selfhost-openbao": {"openbao"},
}
BETA_PROJECT = "elevenid-beta"
NATIVE_ROUTE_FLAGS = {
    "gateway": "PASSPORT_NATIVE_GATEWAY_ENABLED",
    "flow": "PASSPORT_NATIVE_FLOW_ENABLED",
    "issuance-native": "PASSPORT_NATIVE_HTTP_ENABLED",
}
COUNT = re.compile(r"[0-9]+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
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


def production_public_route(
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    """Check the public production route without reading private response data."""
    request = urllib.request.Request(
        PRODUCTION_PUBLIC_ORIGIN,
        headers={"User-Agent": "Mozilla/5.0 (Marty production continuity)"},
    )
    try:
        with opener(request, timeout=10) as response:
            status = response.status
            final_url = response.url
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise HostProbeError("Production public route is unavailable") from exc
    if status != 200 or final_url != PRODUCTION_PUBLIC_ORIGIN:
        raise HostProbeError("Production public route changed or is unavailable")
    return {"origin": PRODUCTION_PUBLIC_ORIGIN, "status": status}


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


def production_attachment_sha256(
    runner: Callable[[list[str]], str] = run,
) -> str:
    """Bind production networks and host ports without exposing their details."""
    projected = []
    for project in PRODUCTION_PROJECTS:
        for short_id in ids(project, runner):
            record = inspect(short_id, runner)
            config = record.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            network_settings = record.get("NetworkSettings")
            networks = network_settings.get("Networks") if isinstance(
                network_settings, dict) else None
            host = record.get("HostConfig")
            bindings = host.get("PortBindings") if isinstance(host, dict) else None
            if not (isinstance(record.get("Id"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", record["Id"]) is not None
                    and isinstance(labels, dict)
                    and labels.get("com.docker.compose.project") == project
                    and isinstance(networks, dict) and networks
                    and isinstance(bindings, (dict, type(None)))):
                raise HostProbeError("Production network or port baseline is incomplete")
            attachments = []
            for name, value in sorted(networks.items()):
                if not (isinstance(name, str) and isinstance(value, dict)
                        and isinstance(value.get("NetworkID"), str)):
                    raise HostProbeError("Production network attachment is invalid")
                attachments.append({"name": name, "network_id": value["NetworkID"],
                                    "aliases": value.get("Aliases"),
                                    "ip_address": value.get("IPAddress")})
            projected.append({"id": record["Id"], "project": project,
                              "networks": attachments, "port_bindings": bindings})
    if not projected:
        raise HostProbeError("Production network baseline is empty")
    projected.sort(key=lambda item: (item["project"], item["id"]))
    return hashlib.sha256(json.dumps(projected, sort_keys=True,
                                   separators=(",", ":")).encode()).hexdigest()


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


def beta_native_route_ownership(
    runtime_images: dict[str, dict[str, Any]],
    provider_ingress_image: dict[str, Any] | None = None,
    inspector: Callable[[str], dict[str, Any]] = inspect,
) -> dict[str, Any]:
    """Project only the exact routing selectors from signed beta containers."""
    webhook_owner = None
    for service, selector in NATIVE_ROUTE_FLAGS.items():
        image = runtime_images.get(service)
        if not isinstance(image, dict) or not isinstance(image.get("container_id"), str):
            raise HostProbeError("Beta native route container is missing")
        record = inspector(image["container_id"])
        config = record.get("Config")
        state = record.get("State")
        if not isinstance(config, dict) or not isinstance(state, dict):
            raise HostProbeError("Beta native route state is incomplete")
        labels = config.get("Labels")
        if not isinstance(labels, dict) or labels.get("com.docker.compose.project") != BETA_PROJECT or labels.get("com.docker.compose.service") != service:
            raise HostProbeError("Beta native route container identity changed")
        if record.get("Image") != image.get("image_id") or config.get("Image") != image.get("oci_reference"):
            raise HostProbeError("Beta native route image changed")
        if state.get("Running") is not True or state.get("Status") != "running":
            raise HostProbeError("Beta native route service is not running")
        env = config.get("Env")
        if not isinstance(env, list) or not all(isinstance(item, str) and "=" in item for item in env):
            raise HostProbeError("Beta native route configuration is incomplete")
        relevant = {}
        required = {selector, "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"}
        if service == "flow":
            required.add("ISSUANCE_NATIVE_SERVICE_URL")
        if service == "gateway":
            required.update(("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", "PASSPORT_PROVIDER_INGRESS_SERVICE_URL"))
        for item in env:
            name, value = item.split("=", 1)
            if name in required:
                if name in relevant:
                    raise HostProbeError("Beta native route selector is ambiguous")
                relevant[name] = value
        if relevant.get(selector) != "true" or relevant.get("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED") != "true":
            raise HostProbeError("Beta native route selector is disabled")
        if service == "flow" and relevant.get("ISSUANCE_NATIVE_SERVICE_URL") != "http://issuance-native:8005":
            raise HostProbeError("Beta Flow does not target the native passport owner")
        if service == "gateway":
            provider_enabled = relevant.get("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED")
            if provider_enabled not in ("true", "false"):
                raise HostProbeError("Beta provider ingress selector is invalid")
            if provider_enabled == "true":
                if relevant.get("PASSPORT_PROVIDER_INGRESS_SERVICE_URL") != "http://passport-provider-ingress:8021":
                    raise HostProbeError("Beta provider ingress target is invalid")
                webhook_owner = "passport-provider-ingress"
            else:
                webhook_owner = "issuance-native"
    if webhook_owner == "passport-provider-ingress":
        image = provider_ingress_image
        if not isinstance(image, dict) or not isinstance(image.get("container_id"), str):
            raise HostProbeError("Selected beta provider ingress is absent from signed deployment")
        record = inspector(image["container_id"])
        config = record.get("Config")
        state = record.get("State")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (not isinstance(labels, dict) or labels.get("com.docker.compose.project") != BETA_PROJECT
                or labels.get("com.docker.compose.service") != webhook_owner
                or not isinstance(state, dict) or state.get("Running") is not True
                or state.get("Status") != "running" or record.get("Image") != image.get("image_id")
                or config.get("Image") != image.get("oci_reference")):
            raise HostProbeError("Selected beta provider ingress identity changed")
    bureau_image = runtime_images.get("passport-beta-bureau")
    if not isinstance(bureau_image, dict) or not isinstance(bureau_image.get("container_id"), str):
        raise HostProbeError("Beta simulator container is missing")
    bureau_record = inspector(bureau_image["container_id"])
    bureau_config = bureau_record.get("Config")
    bureau_state = bureau_record.get("State")
    bureau_labels = bureau_config.get("Labels") if isinstance(bureau_config, dict) else None
    if (not isinstance(bureau_labels, dict)
            or bureau_labels.get("com.docker.compose.project") != BETA_PROJECT
            or bureau_labels.get("com.docker.compose.service") != "passport-beta-bureau"
            or not isinstance(bureau_state, dict) or bureau_state.get("Running") is not True
            or bureau_state.get("Status") != "running"
            or bureau_record.get("Image") != bureau_image.get("image_id")
            or bureau_config.get("Image") != bureau_image.get("oci_reference")):
        raise HostProbeError("Beta simulator identity changed")
    bureau_env = bureau_config.get("Env")
    if not isinstance(bureau_env, list) or not all(isinstance(item, str) and "=" in item for item in bureau_env):
        raise HostProbeError("Beta simulator route configuration is incomplete")
    callback = {}
    for item in bureau_env:
        name, value = item.split("=", 1)
        if name in ("PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED", "PASSPORT_BUREAU_CALLBACK_URL"):
            if name in callback:
                raise HostProbeError("Beta simulator callback route is ambiguous")
            callback[name] = value
    if (callback.get("PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED") != "true"
            or callback.get("PASSPORT_BUREAU_CALLBACK_URL")
            != "http://gateway:8000/v1/passport/webhooks/personalization"):
        raise HostProbeError("Beta simulator signed callback bypasses Gateway")
    return {"verified": True, "evidence": {
        "compose_project": BETA_PROJECT,
        "services": sorted(NATIVE_ROUTE_FLAGS),
        "native_selectors": True,
        "internal_service_auth": True,
        "flow_native_target": True,
        "webhook_owner": webhook_owner,
        "simulator_callback_gateway_target": True,
    }}


def beta_postgres_container(runner: Callable[[list[str]], str]) -> str:
    postgres_ids = []
    for container_id in ids(BETA_PROJECT, runner):
        record = inspect(container_id, runner)
        config = record.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (isinstance(labels, dict) and labels.get("com.docker.compose.project") == BETA_PROJECT
                and labels.get("com.docker.compose.service") == "postgres"):
            state = record.get("State")
            if not isinstance(state, dict) or state.get("Running") is not True or state.get("Status") != "running":
                raise HostProbeError("Beta PostgreSQL service is not running")
            postgres_ids.append(container_id)
    if len(postgres_ids) != 1:
        raise HostProbeError("Beta PostgreSQL service is missing or ambiguous")
    return postgres_ids[0]


def beta_psql(sql: str, runner: Callable[[list[str]], str], container_id: str) -> str:
    return runner(["docker", "exec", container_id, "psql", "-U", "postgres", "-d", "marty",
                   "-At", "-v", "ON_ERROR_STOP=1", "-c", sql])


def material_receipt(
    organization_id: str,
    source_job_id: str,
    bureau_job_id: str,
    sod_der_sha256: str,
    dsc_der_sha256: str,
    dsc_pem_wire_sha256: str,
    commitment_key: bytes,
    *, query: Callable[[str], str], source: str,
) -> dict[str, Any]:
    """Compare first accepted material in an explicitly selected private database."""
    if (not all(isinstance(value, str) and 0 < len(value) <= 256 for value in (organization_id, source_job_id))
            or not all(isinstance(value, str) and SHA256.fullmatch(value) for value in
                       (sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256))
            or not isinstance(commitment_key, bytes) or len(commitment_key) < 32
            or source not in {"private beta PostgreSQL", "private disposable PostgreSQL"}):
        raise HostProbeError("Beta material receipt inputs are invalid")
    try:
        bureau_uuid = uuid.UUID(bureau_job_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise HostProbeError("Beta bureau job identity is invalid") from exc
    # Hex encoding keeps tenant and source identifiers out of SQL string syntax.
    org_hex = organization_id.encode("utf-8").hex()
    source_hex = source_job_id.encode("utf-8").hex()
    sql = (
        "SELECT count(*), "
        f"COALESCE(bool_and(sod_der_sha256 = decode('{sod_der_sha256}', 'hex')), false), "
        f"COALESCE(bool_and(dsc_der_sha256 = decode('{dsc_der_sha256}', 'hex')), false), "
        f"COALESCE(bool_and(dsc_pem_wire_sha256 = decode('{dsc_pem_wire_sha256}', 'hex')), false) "
        "FROM issuance_service.passport_beta_bureau_jobs "
        f"WHERE organization_id = convert_from(decode('{org_hex}', 'hex'), 'UTF8') "
        f"AND source_job_id = convert_from(decode('{source_hex}', 'hex'), 'UTF8') "
        f"AND bureau_job_id = '{bureau_uuid}'::uuid"
    )
    parts = query(sql).split("|")
    if parts != ["1", "t", "t", "t"]:
        raise HostProbeError("Beta first accepted SOD and DSC material did not match the selected job and chain")
    def commitment(label: str, value: str) -> str:
        return hmac.new(commitment_key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()
    return {"verified": True, "evidence": {
        "source_job_id_commitment": commitment("source-job", source_job_id),
        "bureau_job_id_commitment": commitment("bureau-job", str(bureau_uuid)),
        "tenant_and_job_binding": True,
        "first_accepted_sod_der_matches_native": True,
        "first_accepted_dsc_der_matches_selected_chain": True,
        "first_accepted_dsc_pem_wire_matches_selected_chain": True,
        "source": source,
    }}


def beta_material_receipt(
    organization_id: str,
    source_job_id: str,
    bureau_job_id: str,
    sod_der_sha256: str,
    dsc_der_sha256: str,
    dsc_pem_wire_sha256: str,
    commitment_key: bytes,
    runner: Callable[[list[str]], str] = run,
) -> dict[str, Any]:
    """Select the live beta database, then use the shared material comparison."""
    return material_receipt(
        organization_id, source_job_id, bureau_job_id,
        sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
        commitment_key,
        query=lambda sql: beta_psql(sql, runner, beta_postgres_container(runner)),
        source="private beta PostgreSQL",
    )


def beta_legacy_drain(runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    container_id = beta_postgres_container(runner)

    def query(sql: str) -> str:
        return beta_psql(sql, runner, container_id)

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
