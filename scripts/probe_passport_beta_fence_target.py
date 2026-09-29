#!/usr/bin/env python3
"""Read-only, source-independent identity inventory for the beta fence operator."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from .probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, assert_production_unchanged, beta_legacy_drain,
        beta_postgres_container, beta_psql, ids, inspect, production_snapshot, run,
    )
except ImportError:
    from probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, assert_production_unchanged, beta_legacy_drain,
        beta_postgres_container, beta_psql, ids, inspect, production_snapshot, run,
    )


REQUIRED_SERVICES = (
    "postgres", "issuance", "gateway", "flow", "issuance-native", "signing-keys"
)
BETA_NETWORK = "elevenid-beta-network"
DATABASE_SERVICES = {"issuance", "flow", "issuance-native"}
ROUTE_SELECTORS = {
    "gateway": "PASSPORT_NATIVE_GATEWAY_ENABLED",
    "flow": "PASSPORT_NATIVE_FLOW_ENABLED",
    "issuance-native": "PASSPORT_NATIVE_HTTP_ENABLED",
}
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
SYSTEM_ID = re.compile(r"[0-9]+\Z")
DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
ROLE_SQL = """
SELECT coalesce(jsonb_agg(jsonb_build_object(
    'role', rolname, 'login', rolcanlogin, 'superuser', rolsuper,
    'create_role', rolcreaterole, 'bypass_rls', rolbypassrls,
    'issuance_create', has_schema_privilege(rolname,'issuance_service','CREATE'),
    'flow_create', has_schema_privilege(rolname,'flow_service','CREATE'),
    'job_write', has_table_privilege(rolname,'issuance_service.physical_document_jobs',
        'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER'),
    'definition_write', has_table_privilege(rolname,'flow_service.flow_definitions',
        'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER'),
    'instance_write', has_table_privilege(rolname,'flow_service.flow_instances',
        'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')) ORDER BY rolname), '[]'::jsonb)
FROM pg_roles WHERE rolcanlogin
"""
GUARDED_OWNER_SQL = """
SELECT coalesce(jsonb_agg(jsonb_build_object('kind',kind,'name',name,
    'owner',owner,'acl',acl) ORDER BY kind,name), '[]'::jsonb)
FROM (
    SELECT 'schema' AS kind, nspname AS name,
        pg_get_userbyid(nspowner) AS owner, nspacl::text AS acl
    FROM pg_namespace WHERE nspname IN ('issuance_service','flow_service')
    UNION ALL
    SELECT 'table', n.nspname || '.' || c.relname,
        pg_get_userbyid(c.relowner), c.relacl::text
    FROM pg_class AS c JOIN pg_namespace AS n ON n.oid=c.relnamespace
    WHERE (n.nspname,c.relname) IN (
        ('issuance_service','physical_document_jobs'),
        ('flow_service','flow_definitions'),('flow_service','flow_instances'))
) AS guarded
"""


def service_inventory(
    runner: Callable[[list[str]], str] = run,
) -> dict[str, dict[str, str]]:
    selected: dict[str, dict[str, str]] = {}
    for container_id in ids(BETA_PROJECT, runner):
        record = inspect(container_id, runner)
        config = record.get("Config")
        state = record.get("State")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(labels, dict) or not isinstance(state, dict):
            raise HostProbeError("Beta container identity is incomplete")
        if labels.get("com.docker.compose.project") != BETA_PROJECT:
            raise HostProbeError("Beta container has foreign Compose identity")
        service = labels.get("com.docker.compose.service")
        if service not in REQUIRED_SERVICES:
            continue
        if service in selected:
            raise HostProbeError(f"Beta {service} has ambiguous container generations")
        if state.get("Running") is not True or state.get("Status") != "running":
            raise HostProbeError(f"Beta {service} is not running")
        full_id = record.get("Id")
        image_id = record.get("Image")
        image_ref = config.get("Image")
        started_at = state.get("StartedAt")
        if (not isinstance(full_id, str) or not DOCKER_ID.fullmatch(full_id)
                or not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)
                or not isinstance(image_ref, str) or not image_ref
                or not isinstance(started_at, str) or not started_at):
            raise HostProbeError(f"Beta {service} image or runtime identity is invalid")
        selected[service] = {
            "container_id": full_id, "image_id": image_id,
            "configured_image": image_ref, "started_at": started_at,
        }
        environment = config.get("Env")
        if not isinstance(environment, list) or any(
            not isinstance(item, str) or "=" not in item for item in environment
        ):
            raise HostProbeError(f"Beta {service} environment is invalid")
        names = [item.split("=", 1)[0] for item in environment]
        if len(names) != len(set(names)):
            raise HostProbeError(f"Beta {service} environment has duplicate names")
        selected_env = dict(item.split("=", 1) for item in environment)
        if service in DATABASE_SERVICES:
            raw_url = selected_env.get("DATABASE_URL")
            if not isinstance(raw_url, str):
                raise HostProbeError(f"Beta {service} database target is missing")
            try:
                target = urlsplit(raw_url)
                host, port = target.hostname, target.port
            except ValueError as exc:
                raise HostProbeError(f"Beta {service} database target is invalid") from exc
            if (target.scheme not in ("postgresql", "postgresql+asyncpg")
                    or target.query or target.fragment
                    or host != "postgres" or port != 5432
                    or target.path != "/marty" or target.username != "marty"):
                raise HostProbeError(f"Beta {service} database target differs from beta PostgreSQL")
            selected[service]["database_target"] = "postgres:5432/marty"
        selector = ROUTE_SELECTORS.get(service)
        if selector:
            value = selected_env.get(selector, "unset")
            if value not in ("unset", "true", "false", "1", "0"):
                raise HostProbeError(f"Beta {service} passport route selector is invalid")
            selected[service]["passport_route_selector"] = value
    if set(selected) != set(REQUIRED_SERVICES):
        raise HostProbeError("Required beta fence services are missing")
    return selected


def database_network_binding(
    selected: dict[str, dict[str, str]],
    runner: Callable[[list[str]], str] = run,
) -> dict[str, str]:
    """Bind the app's postgres DNS name to the exact inspected beta database."""
    raw = runner(["docker", "ps", "--all", "--filter", f"network={BETA_NETWORK}",
                  "--format", "{{.ID}}"])
    container_ids = [item.strip() for item in raw.splitlines() if item.strip()]
    if len(container_ids) != len(set(container_ids)) or not container_ids:
        raise HostProbeError("Beta database network inventory is ambiguous")
    network_id = None
    postgres_alias_owners = []
    observed = set()
    for container_id in container_ids:
        record = inspect(container_id, runner)
        full_id = record.get("Id")
        settings = record.get("NetworkSettings")
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(full_id, str) or not DOCKER_ID.fullmatch(full_id) or full_id in observed:
            raise HostProbeError("Beta database network container identity is invalid")
        observed.add(full_id)
        if not isinstance(networks, dict) or BETA_NETWORK not in networks:
            raise HostProbeError("Beta database network attachment changed")
        endpoint = networks[BETA_NETWORK]
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("NetworkID"), str):
            raise HostProbeError("Beta database network endpoint is invalid")
        if network_id is None:
            network_id = endpoint["NetworkID"]
        elif network_id != endpoint["NetworkID"]:
            raise HostProbeError("Beta database network identity changed")
        aliases = endpoint.get("Aliases")
        dns_names = endpoint.get("DNSNames")
        if not isinstance(aliases, list) or not isinstance(dns_names, list):
            raise HostProbeError("Beta database DNS aliases are unavailable")
        if "postgres" in aliases or "postgres" in dns_names:
            postgres_alias_owners.append(full_id)
        for service in ("postgres", *sorted(DATABASE_SERVICES)):
            if full_id == selected[service]["container_id"] and set(networks) != {BETA_NETWORK}:
                raise HostProbeError(f"Beta {service} has an ambiguous database network route")
            if full_id == selected[service]["container_id"] and service in DATABASE_SERVICES:
                config = record.get("Config")
                host = record.get("HostConfig")
                mounts = record.get("Mounts")
                if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(mounts, list):
                    raise HostProbeError(f"Beta {service} host routing metadata is unavailable")
                extra_hosts = host.get("ExtraHosts") or []
                links = host.get("Links") or []
                if (host.get("NetworkMode") != BETA_NETWORK
                        or not isinstance(extra_hosts, list)
                        or extra_hosts
                        or not isinstance(links, list) or links
                        or any(host.get(field) not in (None, [])
                               for field in ("Dns", "DnsSearch", "DnsOptions"))
                        or str(config.get("Hostname", "")).split(".", 1)[0].lower() == "postgres"
                        or any(not isinstance(mount, dict)
                               or mount.get("Destination") in ("/etc/hosts", "/etc/resolv.conf")
                               for mount in mounts)):
                    raise HostProbeError(f"Beta {service} overrides the bound postgres DNS route")
    if set(selected[service]["container_id"] for service in
           ("postgres", *DATABASE_SERVICES)) - observed:
        raise HostProbeError("A beta database client is absent from the bound network")
    if postgres_alias_owners != [selected["postgres"]["container_id"]]:
        raise HostProbeError("Beta postgres DNS alias does not uniquely select the fenced database")
    if not network_id or not DOCKER_ID.fullmatch(network_id):
        raise HostProbeError("Beta database network ID is invalid")
    return {"name": BETA_NETWORK, "id": network_id,
            "postgres_container_id": selected["postgres"]["container_id"]}


def observe(runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    """Require stable beta/production identities across all read-only probes."""
    context = runner(["docker", "context", "show"])
    daemon_id = runner(["docker", "info", "--format", "{{.ID}}"])
    if not context or not daemon_id:
        raise HostProbeError("Docker context or daemon identity is unavailable")
    production_before = production_snapshot(runner)
    before = service_inventory(runner)
    database_route = database_network_binding(before, runner)
    postgres_id = beta_postgres_container(runner)
    if before["postgres"]["container_id"] != inspect(postgres_id, runner).get("Id"):
        raise HostProbeError("Beta PostgreSQL identity changed during inventory")
    identity = beta_psql(
        "SELECT system_identifier::text || '|' || "
        "(SELECT oid::text FROM pg_database WHERE datname=current_database()) "
        "FROM pg_control_system()",
        runner, postgres_id,
    ).split("|")
    if len(identity) != 2 or not all(SYSTEM_ID.fullmatch(item) for item in identity):
        raise HostProbeError("Beta PostgreSQL cluster or database identity is invalid")
    try:
        roles = json.loads(beta_psql(ROLE_SQL, runner, postgres_id))
    except ValueError as exc:
        raise HostProbeError("Beta database role inventory is invalid") from exc
    if (not isinstance(roles, list)
            or {item.get("role") for item in roles if isinstance(item, dict)}
            != {"postgres", "marty", "keycloak"}):
        raise HostProbeError("Beta database login roles differ from reviewed inventory")
    by_role = {item["role"]: item for item in roles}
    if (by_role["marty"].get("superuser") is not False
            or by_role["marty"].get("create_role") is not False
            or by_role["marty"].get("bypass_rls") is not False
            or any(by_role["marty"].get(key) is not True for key in
                   ("issuance_create", "flow_create", "job_write",
                    "definition_write", "instance_write"))
            or any(by_role["keycloak"].get(key) is not False for key in
                   ("superuser", "create_role", "bypass_rls",
                    "issuance_create", "flow_create"))
            or any(by_role["keycloak"].get(key) is not False for key in
                   ("job_write", "definition_write", "instance_write"))
            or by_role["postgres"].get("superuser") is not True):
        raise HostProbeError("Beta application role privileges differ from reviewed inventory")
    try:
        owners = json.loads(beta_psql(GUARDED_OWNER_SQL, runner, postgres_id))
    except ValueError as exc:
        raise HostProbeError("Beta guarded owner inventory is invalid") from exc
    expected_owners = {
        ("schema", "issuance_service"), ("schema", "flow_service"),
        ("table", "issuance_service.physical_document_jobs"),
        ("table", "flow_service.flow_definitions"),
        ("table", "flow_service.flow_instances"),
    }
    if (not isinstance(owners, list) or len(owners) != len(expected_owners)
            or {(item.get("kind"), item.get("name")) for item in owners
                if isinstance(item, dict)} != expected_owners
            or any(item.get("owner") != "marty" or item.get("acl") is not None
                   for item in owners)):
        raise HostProbeError("Beta guarded ownership or ACL differs from reviewed inventory")
    memberships = beta_psql(
        "SELECT count(*) FROM pg_auth_members WHERE member IN "
        "(SELECT oid FROM pg_roles WHERE rolcanlogin)", runner, postgres_id,
    )
    if memberships != "0":
        raise HostProbeError("Beta login role memberships differ from reviewed inventory")
    drain = beta_legacy_drain(runner)
    after = service_inventory(runner)
    if before != after:
        raise HostProbeError("Beta service generation changed during fence inventory")
    if database_network_binding(after, runner) != database_route:
        raise HostProbeError("Beta database network route changed during fence inventory")
    production_after = production_snapshot(runner)
    assert_production_unchanged(production_before, production_after)
    if (runner(["docker", "context", "show"]) != context
            or runner(["docker", "info", "--format", "{{.ID}}"])
            != daemon_id):
        raise HostProbeError("Docker daemon changed during fence inventory")
    receipt = {
        "schema": "marty.passport-beta-fence-target/v1",
        "authority": "discovery_only_requires_protected_baseline",
        "docker": {"context": context, "daemon_id": daemon_id},
        "beta": {
            "compose_project": BETA_PROJECT, "services": before,
            "postgres_system_identifier": identity[0],
            "database": "marty", "database_oid": identity[1],
            "login_roles": roles, "guarded_owners": owners,
            "login_role_memberships": 0, "drain": drain,
            "database_route": database_route,
        },
        "production": production_after,
    }
    receipt["observation_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return receipt


if __name__ == "__main__":
    try:
        print(json.dumps(observe(), sort_keys=True, separators=(",", ":")))
    except HostProbeError as exc:
        raise SystemExit(str(exc)) from exc
