#!/usr/bin/env python3
"""Read-only proof that the signed beta generation replaced stopped writers."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .prepare_passport_beta_aggregate_compose import (
        RUNTIME_ENV, SIGNED_APPLICATIONS, verify_render_plan,
    )
    from .verify_passport_beta_rust_owner import verify as verify_rust_owner
    from .check_passport_beta_fence_authority import manifest_source, protected_source
    from .probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, ids, inspect,
        production_attachment_sha256, production_public_route,
        production_snapshot, run,
    )
except ImportError:
    from prepare_passport_beta_aggregate_compose import (
        RUNTIME_ENV, SIGNED_APPLICATIONS, verify_render_plan,
    )
    from verify_passport_beta_rust_owner import verify as verify_rust_owner
    from check_passport_beta_fence_authority import manifest_source, protected_source
    from probe_passport_beta_host import (
        BETA_PROJECT, HostProbeError, ids, inspect,
        production_attachment_sha256, production_public_route,
        production_snapshot, run,
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


def runtime_identity(record: dict[str, Any]) -> dict[str, Any]:
    """Project a checked container without copying its private environment."""
    config = record["Config"]
    labels = config["Labels"]
    state = record["State"]
    networks = record["NetworkSettings"]["Networks"]
    image_id = record.get("Image")
    image = config.get("Image")
    started_at = state.get("StartedAt")
    require(isinstance(image_id, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            and isinstance(image, str) and bool(image)
            and isinstance(started_at, str) and bool(started_at)
            and isinstance(networks, dict),
            "Aggregate beta runtime identity is incomplete")
    return {"container_id": record["Id"], "image_id": image_id,
            "configured_image": image, "started_at": started_at,
            "config_hash": labels.get("com.docker.compose.config-hash"),
            "networks": sorted(networks)}


def verify_production_baseline(source: str, snapshot_sha256: str,
                               attachments_sha256: str,
                               runner: Callable[[list[str]], str],
                               docker: dict[str, Any] | None = None) -> dict[str, Any]:
    require(isinstance(source, str) and SHA.fullmatch(source) is not None
            and isinstance(snapshot_sha256, str)
            and SHA256.fullmatch(snapshot_sha256) is not None
            and isinstance(attachments_sha256, str)
            and SHA256.fullmatch(attachments_sha256) is not None,
            "Production continuity baseline is invalid")
    if docker is not None:
        require(runner(["docker", "context", "show"]) == docker.get("context")
                and runner(["docker", "info", "--format", "{{.ID}}"])
                    == docker.get("daemon_id"),
                "Aggregate beta Docker context changed")
    snapshot = production_snapshot(runner)
    require(snapshot.get("sha256") == snapshot_sha256,
            "Production changed during aggregate beta deployment")
    require(production_attachment_sha256(runner) == attachments_sha256,
            "Production network or host ports changed during aggregate beta deployment")
    route = production_public_route()
    return {"schema": "marty.passport-beta-production-continuity/v1",
            "verified": True, "source_commit": source,
            "production_snapshot_sha256": snapshot["sha256"],
            "production_attachments_sha256": attachments_sha256,
            "public_route": route}


def verify_production(plan: dict[str, Any], intent: dict[str, Any],
                      expected_attachments_sha256: str,
                      runner: Callable[[list[str]], str] = run) -> dict[str, Any]:
    """Verify the preserved production generation against the aggregate plan."""
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and intent.get("schema") == "marty.passport-beta-db-maintenance-plan/v1"
            and plan.get("source_commit") == intent.get("source_commit")
            and plan.get("production_snapshot_sha256")
                == intent.get("production_snapshot_sha256")
            and plan.get("production_attachments_sha256")
                == intent.get("production_attachments_sha256")
                == expected_attachments_sha256
            and isinstance(intent.get("docker"), dict),
            "Aggregate production continuity inputs are invalid")
    return verify_production_baseline(
        plan["source_commit"], plan["production_snapshot_sha256"],
        expected_attachments_sha256, runner, intent["docker"])


def verify_production_maintenance(
    manifest_path: Path, intent_path: Path, maintenance_path: Path,
    fence_path: Path, native_path: Path,
    runner: Callable[[list[str]], str] = run,
    source_verifier: Callable[[], str] = protected_source,
    manifest_verifier: Callable[[Path, str], dict[str, Any]] = manifest_source,
) -> dict[str, Any]:
    """Use the signed fenced-maintenance chain when a plan is unavailable."""
    def read(path: Path) -> tuple[dict[str, Any], str]:
        payload = path.read_bytes()
        value = json.loads(payload)
        require(isinstance(value, dict), "Fenced maintenance receipt is invalid")
        return value, hashlib.sha256(payload).hexdigest()

    head = source_verifier()
    signed = manifest_verifier(manifest_path, head)
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    intent, intent_sha256 = read(intent_path)
    maintenance, maintenance_sha256 = read(maintenance_path)
    fence, fence_sha256 = read(fence_path)
    native, _ = read(native_path)
    require(maintenance.get("schema") == "marty.passport-beta-db-maintenance-start/v1"
            and fence.get("schema") == "marty.passport-beta-fence-installation/v1"
            and intent.get("schema") == "marty.passport-beta-db-maintenance-plan/v1"
            and native.get("schema") == "marty.passport-beta-native-db-gates/v1"
            and signed.get("signed_manifest_verified") is True
            and signed.get("source_commit") == head
            and signed.get("manifest_sha256") == manifest_sha256
            and maintenance.get("source_commit") == fence.get("source_commit")
                == intent.get("source_commit") == native.get("source_commit") == head
            and intent.get("stack_manifest_sha256") == manifest_sha256
            and isinstance(intent.get("docker"), dict)
            and intent.get("fence_receipt_sha256") == fence_sha256
            and maintenance.get("intent_sha256") == intent_sha256
            and native.get("maintenance_receipt_sha256") == maintenance_sha256
            and maintenance.get("production_snapshot_sha256")
                == fence.get("production_snapshot_sha256")
                == intent.get("production_snapshot_sha256")
                == native.get("production_snapshot_sha256")
            and maintenance.get("production_attachments_sha256")
                == fence.get("production_attachments_sha256")
                == intent.get("production_attachments_sha256"),
            "Fenced maintenance production baseline is invalid")
    return verify_production_baseline(
        head,
        maintenance["production_snapshot_sha256"],
        maintenance["production_attachments_sha256"], runner,
        intent.get("docker"))


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
    verify_production(plan, intent, expected_production_attachments_sha256, runner)
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
            expected = plan["services_image"]
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
    rust_owner = verify_rust_owner(plan, runner=runner,
                                   render_verifier=lambda _: render)
    require(rust_owner.get("verified") is True
            and rust_owner.get("source_commit") == source
            and rust_owner.get("postgres_container_id") == container
            and str(rust_owner.get("fence_epoch")) == epoch
            and re.fullmatch(r"[0-9]+", str(rust_owner.get("transition_txid")))
                is not None,
            "Aggregate beta Rust owner proof differs from signed plan")
    production = verify_production(
        plan, intent, expected_production_attachments_sha256, runner)
    return {"schema": "marty.passport-beta-aggregate-runtime/v1",
            "verified": True, "source_commit": source,
            "beta_origin": plan["beta_origin"],
            "postgres_container_id": container,
            "production_snapshot_sha256": plan["production_snapshot_sha256"],
            "production_public_route": production["public_route"],
            "rust_owner": rust_owner,
            "beta_services": sorted(observed), "ui_container_id": ui["Id"],
            "beta_runtime": {name: runtime_identity(observed[name])
                             for name in sorted(observed)},
            "ui_runtime": runtime_identity(ui)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--maintenance-intent", type=Path)
    parser.add_argument("--maintenance-receipt", type=Path)
    parser.add_argument("--fence-receipt", type=Path)
    parser.add_argument("--native-receipt", type=Path)
    parser.add_argument("--stack-manifest", type=Path)
    parser.add_argument("--production-attachments-sha256")
    parser.add_argument("--capture-production-attachments", action="store_true")
    parser.add_argument("--production-only", action="store_true")
    parser.add_argument("--production-maintenance-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.capture_production_attachments:
            print(production_attachment_sha256())
            return
        if args.production_maintenance_only:
            require(args.maintenance_receipt is not None
                    and args.fence_receipt is not None
                    and args.native_receipt is not None
                    and args.stack_manifest is not None
                    and args.maintenance_intent is not None,
                    "Signed fenced maintenance chain is required")
            result = verify_production_maintenance(
                args.stack_manifest, args.maintenance_intent,
                args.maintenance_receipt, args.fence_receipt,
                args.native_receipt)
        else:
            require(args.plan is not None and args.maintenance_intent is not None
                    and isinstance(args.production_attachments_sha256, str),
                    "Aggregate production baseline is required")
            plan = json.loads(args.plan.read_text(encoding="utf-8"))
            intent = json.loads(args.maintenance_intent.read_text(encoding="utf-8"))
            require(isinstance(plan, dict) and isinstance(intent, dict),
                    "Aggregate beta runtime input is invalid")
            if args.production_only:
                result = verify_production(
                    plan, intent, args.production_attachments_sha256)
            else:
                result = verify(plan, intent, args.production_attachments_sha256)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Protected aggregate beta runtime is unavailable: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
