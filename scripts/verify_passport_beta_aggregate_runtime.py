#!/usr/bin/env python3
"""Read-only proof that the signed beta generation replaced stopped writers."""

from __future__ import annotations

import argparse
import hmac
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .prepare_passport_beta_aggregate_compose import (
        RUNTIME_ENV, SIGNED_APPLICATIONS, verify_render_plan,
    )
    from .prepare_passport_beta_aggregate_handoff import verify_fence
    from .probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_attachment_sha256, production_snapshot, run,
    )
except ImportError:
    from prepare_passport_beta_aggregate_compose import (
        RUNTIME_ENV, SIGNED_APPLICATIONS, verify_render_plan,
    )
    from prepare_passport_beta_aggregate_handoff import verify_fence
    from probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, beta_psql, ids, inspect,
        production_attachment_sha256, production_snapshot, run,
    )


CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def service_record(container_id: str, project: str,
                   runner: Callable[[list[str]], str]) -> dict[str, Any]:
    require(re.fullmatch(r"[0-9a-f]{12,64}", container_id) is not None,
            "Aggregate beta container identity is invalid")
    record = inspect(container_id, runner)
    config = record.get("Config")
    state = record.get("State")
    labels = config.get("Labels") if isinstance(config, dict) else None
    full_id = record.get("Id")
    require(isinstance(full_id, str) and CONTAINER.fullmatch(full_id) is not None
            and full_id.startswith(container_id)
            and isinstance(config, dict) and isinstance(state, dict)
            and isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == project
            and isinstance(labels.get("com.docker.compose.service"), str)
            and state.get("Running") is True and state.get("Status") == "running",
            "Aggregate beta service identity or running state changed")
    health = state.get("Health")
    require(health is None or (isinstance(health, dict)
                              and health.get("Status") == "healthy"),
            "Aggregate beta service is unhealthy")
    return record


def environment_values(config: dict[str, Any]) -> dict[str, str]:
    env = config.get("Env")
    require(isinstance(env, list) and all(isinstance(item, str) and "=" in item
                                          for item in env),
            "Aggregate beta runtime environment is invalid")
    values = {}
    for item in env:
        key, value = item.split("=", 1)
        require(key not in values, "Aggregate beta runtime environment is duplicated")
        values[key] = value
    return values


def selected_environment(config: dict[str, Any], name: str) -> None:
    values = environment_values(config)
    require(values.get("SERVICE_NAME") == name.replace("-", "_"),
            "Aggregate beta runtime service dispatch differs")
    for key, expected in RUNTIME_ENV.get(name, {}).items():
        require(values.get(key) == expected,
                "Aggregate beta runtime passport selector differs")


def verify(plan: dict[str, Any], intent: dict[str, Any],
           expected_production_attachments_sha256: str,
           runner: Callable[[list[str]], str] = run,
           render_verifier: Callable[[dict[str, Any]], dict[str, Any]] = verify_render_plan,
) -> dict[str, Any]:
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and plan.get("beta_origin") == "https://beta.elevenidllc.com"
            and intent.get("schema") == "marty.passport-beta-db-maintenance-plan/v1"
            and plan.get("source_commit") == intent.get("source_commit")
            and SHA.fullmatch(str(plan.get("source_commit"))) is not None,
            "Aggregate beta runtime plan or source is invalid")
    render = render_verifier(plan)
    require(render.get("verified") is True,
            "Aggregate beta Compose render changed")
    docker = intent.get("docker")
    require(isinstance(docker, dict)
            and runner(["docker", "context", "show"]) == docker.get("context")
            and runner(["docker", "info", "--format", "{{.ID}}"]) == docker.get("daemon_id"),
            "Aggregate beta Docker context changed")
    require(production_snapshot(runner).get("sha256")
            == plan.get("production_snapshot_sha256"),
            "Production changed during aggregate beta deployment")
    require(SHA256.fullmatch(expected_production_attachments_sha256) is not None
            and expected_production_attachments_sha256
                == plan.get("production_attachments_sha256")
            and production_attachment_sha256(runner)
                == expected_production_attachments_sha256,
            "Production network or host ports changed during aggregate beta deployment")
    old = plan.get("old_container_ids_by_service")
    targets = plan.get("target_services")
    require(isinstance(old, dict) and isinstance(targets, list)
            and old.get("postgres") == plan.get("postgres_container_id")
            and set(targets) == (set(old) - {"postgres"})
                | {"passport-callback-signer", "passport-beta-bureau"},
            "Aggregate beta service inventory is invalid")
    observed = {}
    for container_id in ids(BETA_PROJECT, runner):
        record = service_record(container_id, BETA_PROJECT, runner)
        name = record["Config"]["Labels"]["com.docker.compose.service"]
        require(name not in observed, "Aggregate beta service is duplicated")
        observed[name] = record
    require(set(observed) == set(targets) | {"postgres"}
            and observed["postgres"]["Id"] == old["postgres"],
            "Aggregate beta generation differs from signed plan")
    keycloak_env = environment_values(observed["keycloak"]["Config"])
    nginx_env = environment_values(observed["nginx-proxy"]["Config"])
    require(keycloak_env.get("KC_HOSTNAME") == plan["beta_origin"]
            and keycloak_env.get("UI_BASE_URL") == plan["beta_origin"]
            and keycloak_env.get("PUBLIC_DOMAIN") == "beta.elevenidllc.com"
            and nginx_env.get("PUBLIC_DOMAIN") == "beta.elevenidllc.com"
            and nginx_env.get("GATEWAY_UPSTREAM") == "gateway:8000",
            "Aggregate beta ingress points outside the beta origin")
    expected_networks = plan.get("expected_networks_by_service")
    require(isinstance(expected_networks, dict)
            and set(expected_networks) == set(observed),
            "Aggregate beta network plan is incomplete")
    for name, record in observed.items():
        networks = record.get("NetworkSettings", {}).get("Networks")
        expected = expected_networks[name]
        require(isinstance(networks, dict)
                and isinstance(expected, list)
                and set(networks) == set(expected)
                and len(expected) == len(set(expected)),
                f"Aggregate beta service network differs: {name}")
    preserved = [item for item in intent.get("beta_generation", [])
                 if isinstance(item, dict) and item.get("service") == "openbao"]
    require(len(preserved) == 1
            and preserved[0].get("container_id") == old.get("openbao")
            and observed["openbao"]["Id"] == preserved[0]["container_id"]
            and observed["openbao"].get("Image") == preserved[0].get("image_id")
            and observed["openbao"].get("State", {}).get("StartedAt")
                == preserved[0].get("started_at"),
            "Preserved OpenBao restarted or changed during aggregate beta deployment")
    restart = set(plan.get("preserved_infrastructure", [])) | set(
        plan.get("restart_infrastructure", [])) | set(
        plan.get("restart_ingress_last", []))
    recreate = set(plan.get("recreate_applications", [])) | set(
        plan.get("recreate_ingress_last", []))
    require(restart | recreate == set(targets) and not restart & recreate,
            "Aggregate beta startup groups are invalid")
    for name in targets:
        record = observed[name]
        config = record["Config"]
        if name in restart:
            require(record["Id"] == old.get(name),
                    "Aggregate beta infrastructure changed identity")
        else:
            require(record["Id"] != old.get(name),
                    "Stopped beta application was restarted instead of replaced")
            expected = (plan["issuance_image"] if name == "issuance"
                        else plan["services_image"])
            require(config.get("Image") == expected,
                    "Aggregate beta runtime image differs from signed release")
            expected_hashes = plan.get("service_config_hashes")
            require(isinstance(expected_hashes, dict)
                    and SHA256.fullmatch(str(expected_hashes.get(name))) is not None
                    and config["Labels"].get("com.docker.compose.config-hash")
                        == expected_hashes.get(name),
                    "Aggregate beta runtime Compose config differs")
            if name in SIGNED_APPLICATIONS:
                selected_environment(config, name)
    callback_networks = observed["passport-callback-signer"].get(
        "NetworkSettings", {}).get("Networks")
    require(isinstance(callback_networks, dict)
            and set(callback_networks) == {"elevenid-beta-passport-callback-signing"},
            "Aggregate callback signer escaped isolated network")
    network_raw = runner(["docker", "network", "inspect",
                          "elevenid-beta-passport-callback-signing"])
    try:
        network_items = json.loads(network_raw)
    except ValueError as exc:
        raise HostProbeError("Aggregate callback network inspection is invalid") from exc
    require(isinstance(network_items, list) and len(network_items) == 1
            and isinstance(network_items[0], dict)
            and network_items[0].get("Name")
                == "elevenid-beta-passport-callback-signing"
            and network_items[0].get("Internal") is True
            and isinstance(network_items[0].get("Id"), str)
            and CONTAINER.fullmatch(network_items[0]["Id"]) is not None
            and callback_networks["elevenid-beta-passport-callback-signing"].get(
                "NetworkID") == network_items[0]["Id"],
            "Aggregate callback signing network is not isolated")
    members = network_items[0].get("Containers")
    require(isinstance(members, dict)
            and set(members) == {
                observed["openbao"]["Id"],
                observed["passport-callback-signer"]["Id"],
                observed["passport-beta-bureau"]["Id"],
            },
            "Aggregate callback signing network has unexpected members")
    bao_network = observed["openbao"].get("NetworkSettings", {}).get("Networks", {})
    bao_attachment = bao_network.get("elevenid-beta-passport-callback-signing")
    require(isinstance(bao_attachment, dict)
            and bao_attachment.get("NetworkID") == network_items[0]["Id"]
            and "openbao" in (bao_attachment.get("Aliases") or []),
            "Preserved OpenBao lacks private callback signer alias")
    bao_env = observed["openbao"]["Config"].get("Env")
    signer_env = observed["passport-callback-signer"]["Config"].get("Env")
    require(isinstance(bao_env, list) and isinstance(signer_env, list),
            "Aggregate callback KMS environment is invalid")
    bao_tokens = [value.split("=", 1)[1] for value in bao_env
                  if isinstance(value, str) and value.startswith("BAO_DEV_ROOT_TOKEN_ID=")]
    signer_tokens = [value.split("=", 1)[1] for value in signer_env
                     if isinstance(value, str) and value.startswith("BAO_TOKEN=")]
    require(len(bao_tokens) == 1 and len(signer_tokens) == 1
            and bool(bao_tokens[0])
            and hmac.compare_digest(bao_tokens[0], signer_tokens[0]),
            "Aggregate callback signer token differs from preserved OpenBao")
    require(not observed["passport-callback-signer"].get(
        "HostConfig", {}).get("PortBindings"),
        "Aggregate callback signer publishes a host port")
    ui_ids = ids("elevenid-beta-ui", runner)
    require(len(ui_ids) == 1, "Aggregate beta UI generation is ambiguous")
    ui = service_record(ui_ids[0], "elevenid-beta-ui", runner)
    require(ui["Config"]["Labels"]["com.docker.compose.service"] == "ui-prod"
            and ui["Config"].get("Image") == plan.get("ui_image")
            and SHA256.fullmatch(str(plan.get("ui_config_hash"))) is not None
            and ui["Config"]["Labels"].get("com.docker.compose.config-hash")
                == plan.get("ui_config_hash"),
            "Aggregate beta UI image differs from signed release")
    ui_networks = ui.get("NetworkSettings", {}).get("Networks")
    require(isinstance(ui_networks, dict)
            and set(ui_networks) == {"elevenid-beta-network"},
            "Aggregate beta UI joined an unexpected network")
    container = plan["postgres_container_id"]
    epoch = str(plan.get("fence_epoch"))
    source = plan["source_commit"]
    digest = str(plan.get("migration_set_sha256"))
    require(CONTAINER.fullmatch(container) is not None
            and re.fullmatch(r"[0-9]+", epoch) is not None
            and SHA256.fullmatch(digest) is not None,
            "Aggregate beta native receipt identity is invalid")
    sql = (
        "SELECT (SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles "
        "WHERE rolname='marty_beta_migrator')"
    )
    require(beta_psql(sql, runner, container) == f"{epoch}|{source}|{digest}|true|false",
            "Aggregate beta native SQL marker or app login differs")
    verify_fence(intent, runner)
    require(production_snapshot(runner).get("sha256")
            == plan.get("production_snapshot_sha256"),
            "Production changed during aggregate beta verification")
    require(production_attachment_sha256(runner)
            == expected_production_attachments_sha256,
            "Production network or host ports changed during aggregate beta verification")
    return {"schema": "marty.passport-beta-aggregate-runtime/v1",
            "verified": True, "source_commit": source,
            "beta_origin": plan["beta_origin"],
            "postgres_container_id": container,
            "production_snapshot_sha256": plan["production_snapshot_sha256"],
            "beta_services": sorted(observed), "ui_container_id": ui["Id"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--maintenance-intent", required=True, type=Path)
    parser.add_argument("--production-attachments-sha256")
    parser.add_argument("--capture-production-attachments", action="store_true")
    args = parser.parse_args()
    try:
        if args.capture_production_attachments:
            print(production_attachment_sha256())
            return
        require(isinstance(args.production_attachments_sha256, str),
                "Production attachment baseline is required")
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        intent = json.loads(args.maintenance_intent.read_text(encoding="utf-8"))
        require(isinstance(plan, dict) and isinstance(intent, dict),
                "Aggregate beta runtime input is invalid")
        result = verify(plan, intent, args.production_attachments_sha256)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Protected aggregate beta runtime is unavailable: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
