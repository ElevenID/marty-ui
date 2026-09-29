#!/usr/bin/env python3
"""Validate a rendered signed Rust beta Compose generation before startup."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

try:
    from .prepare_passport_beta_aggregate_handoff import (
        prepare as handoff_prepare, verify_fence,
    )
    from .check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file, protected_source,
        run,
    )
    from .probe_passport_beta_host import (
        BETA_PROJECT, beta_psql, ids, inspect, production_attachment_sha256,
        production_snapshot,
    )
except ImportError:
    from prepare_passport_beta_aggregate_handoff import (
        prepare as handoff_prepare, verify_fence,
    )
    from check_passport_beta_fence_authority import (
        PROTECTED_FILES, file_sha256, manifest_source, protected_file, protected_source,
        run,
    )
    from probe_passport_beta_host import (
        BETA_PROJECT, beta_psql, ids, inspect, production_attachment_sha256,
        production_snapshot,
    )


SERVICES_IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:"
ISSUANCE_IMAGE = "ghcr.io/elevenid/marty-credentials-issuance@sha256:"
UI_IMAGE = "ghcr.io/elevenid/marty-ui-oss/ui@sha256:"
SIGNED_APPLICATIONS = frozenset({
    "auth", "organization", "credential-template", "trust-profile", "applicant",
    "notification", "compliance-profile", "presentation-policy", "deployment-profile",
    "signing-keys", "flow", "verification", "revocation-profile",
    "device-registration", "event-stream", "issuance-native", "canvas-sync-worker",
    "gateway", "passport-callback-signer", "passport-beta-bureau",
})
INGRESS = frozenset({"cloudflared", "nginx-proxy", "envoy", "gateway", "waltid-nginx"})
NEW_SERVICES = frozenset({"passport-callback-signer", "passport-beta-bureau"})
RUNTIME_ENV = {
    "gateway": {"PASSPORT_NATIVE_GATEWAY_ENABLED": "true",
                "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
                "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
                "PASSPORT_TENANT_API_KEYS": "",
                "PASSPORT_TENANT_API_KEYS_FILE": ""},
    "flow": {"PASSPORT_NATIVE_FLOW_ENABLED": "true",
             "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
             "MARTY_SCHEMA_STARTUP_MODE": "validate",
             "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
             "PASSPORT_TENANT_API_KEYS": "",
             "PASSPORT_TENANT_API_KEYS_FILE": ""},
    "issuance-native": {"PASSPORT_NATIVE_HTTP_ENABLED": "true",
                        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
                        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
                        "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
                        "PASSPORT_KMS_CALLBACKS_ENABLED": "true",
                        "MARTY_SCHEMA_STARTUP_MODE": "validate",
                        "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED": "false",
                        "PHYSICAL_DOCUMENT_ARTIFACT_KEY": "",
                        "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE": "",
                        "ICAO_DOCUMENT_SIGNER_URL": "",
                        "ICAO_DOCUMENT_SIGNER_API_KEY": "",
                        "ICAO_DOCUMENT_SIGNER_API_KEY_FILE": "",
                        "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
                        "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
                        "PERSONALIZATION_BUREAU_API_KEY_FILE": "",
                        "PERSONALIZATION_BUREAU_WEBHOOK_SECRET": "",
                        "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE": "",
                        "PASSPORT_TENANT_API_KEYS": "",
                        "PASSPORT_TENANT_API_KEYS_FILE": ""},
    "passport-callback-signer": {"PASSPORT_CALLBACK_SIGNER_ENABLED": "true"},
    "passport-beta-bureau": {"PASSPORT_BETA_BUREAU_ENABLED": "true"},
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.base.yml", "docker-compose.beta.yml",
    "docker-compose.profile.dev.yml", "docker-compose.profile.tunnel.yml",
    "docker-compose.profile.waltid.yml", "docker-compose.profile.canvas-real.yml",
    "docker-compose.profile.canvas-sandbox.yml",
    "docker-compose.profile.passport-native-beta.yml",
    "docker-compose.profile.passport-premigrated-beta.yml",
)
UI_COMPOSE_FILE = "docker-compose.ui-release.yml"
ENV_FILES = (".env.tunnel.beta.local", ".env.beta.generated.local")
BETA_ORIGIN = "https://beta.elevenidllc.com"
BETA_DOMAIN = "beta.elevenidllc.com"
PUBLIC_URL_KEYS = frozenset({"PUBLIC_API_URL", "ISSUER_BASE_URL",
                             "PUBLIC_BASE_URL", "UI_BASE_URL"})


class ComposePlanError(ValueError):
    """Rendered beta Compose does not match the signed Rust handoff."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ComposePlanError(message)


def environment(service: dict[str, Any]) -> dict[str, str]:
    value = service.get("environment", {})
    require(isinstance(value, dict)
            and all(isinstance(k, str) and isinstance(v, str)
                    for k, v in value.items()),
            "Rendered beta service environment is invalid")
    return value


def assert_beta_origin(services: dict[str, Any]) -> None:
    """Reject a rendered beta release that advertises another public origin."""
    for name, service in services.items():
        require(isinstance(service, dict),
                f"Rendered beta service is invalid: {name}")
        env = environment(service)
        for key in PUBLIC_URL_KEYS:
            if key in env:
                require(env[key] == BETA_ORIGIN,
                        f"Rendered beta public origin differs: {name}.{key}")
        if "PUBLIC_DOMAIN" in env:
            require(env["PUBLIC_DOMAIN"] == BETA_DOMAIN,
                    f"Rendered beta public domain differs: {name}")
    required = {
        "auth": {"UI_BASE_URL": BETA_ORIGIN,
                 "UI_ADDITIONAL_BASE_URLS": "",
                 "OIDC_REDIRECT_URI": BETA_ORIGIN + "/v1/auth/callback",
                 "OIDC_POST_LOGOUT_REDIRECT_URI": BETA_ORIGIN + "/"},
        "gateway": {"ISSUER_BASE_URL": BETA_ORIGIN},
        "flow": {"PUBLIC_BASE_URL": BETA_ORIGIN},
        "keycloak": {"KC_HOSTNAME": BETA_ORIGIN,
                     "PUBLIC_DOMAIN": BETA_DOMAIN,
                     "UI_BASE_URL": BETA_ORIGIN},
        "nginx-proxy": {"PUBLIC_DOMAIN": BETA_DOMAIN,
                        "GATEWAY_UPSTREAM": "gateway:8000"},
        "signing-keys": {"PUBLIC_DOMAIN": BETA_DOMAIN},
        "issuance": {"ISSUER_BASE_URL": BETA_ORIGIN},
    }
    for name, expected in required.items():
        require(name in services, f"Rendered beta origin service is absent: {name}")
        env = environment(services[name])
        for key, value in expected.items():
            require(env.get(key) == value,
                    f"Rendered beta public origin differs: {name}.{key}")
    issuer = environment(services["auth"]).get("OIDC_EXTERNAL_ISSUER_URL", "")
    require(re.fullmatch(re.escape(BETA_ORIGIN) + r"/realms/[A-Za-z0-9_-]+", issuer)
            is not None,
            "Rendered beta OIDC issuer origin differs")
    cors = environment(services["gateway"]).get("CORS_ORIGINS", "")
    origins = cors.split(",")
    allowed = {BETA_ORIGIN, "http://localhost:9080", "http://localhost:3000",
               "http://localhost:5173"}
    require(BETA_ORIGIN in origins and len(origins) == len(set(origins))
            and set(origins).issubset(allowed),
            "Rendered beta Gateway CORS origins differ")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_override(handoff: dict[str, Any]) -> str:
    rows = ["services:"]
    for name in sorted(SIGNED_APPLICATIONS):
        rows.extend((f"  {name}:", "    image: ${MARTY_SERVICES_IMAGE}",
                     "    environment:",
                     f"      SERVICE_NAME: {name.replace('-', '_')}"))
    rows.extend(("  issuance:", "    image: ${MARTY_ISSUANCE_IMAGE}"))
    require(handoff.get("services_image") and handoff.get("issuance_image"),
            "Signed aggregate image references are absent")
    return "\n".join(rows) + "\n"


def render_candidate(handoff: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Render both projects from one protected file list and pinned image env."""
    paths = [ROOT / relative for relative in (*COMPOSE_FILES, UI_COMPOSE_FILE, *ENV_FILES)]
    require(all(path.is_file() and not path.is_symlink() for path in paths),
            "Protected aggregate Compose inputs are absent or redirected")
    before = {path.name: sha256(path) for path in paths}
    override = image_override(handoff)
    environment_values = {**os.environ,
                          "MARTY_SERVICES_IMAGE": handoff["services_image"],
                          "MARTY_ISSUANCE_IMAGE": handoff["issuance_image"],
                          "MARTY_UI_RELEASE_IMAGE": handoff["ui_image"],
                          "MARTY_NETWORK_NAME": "elevenid-beta-network"}
    env_args = [part for relative in ENV_FILES
                for part in ("--env-file", str(ROOT / relative))]
    common = ["docker", "compose", "--project-name", "elevenid-beta",
              *env_args, *(part for relative in COMPOSE_FILES
                           for part in ("-f", str(ROOT / relative))), "-f", "-"]
    ui_common = ["docker", "compose", "--project-name", "elevenid-beta-ui",
                 *env_args, "-f", str(ROOT / UI_COMPOSE_FILE)]
    ui_command = ui_common + ["config", "--format", "json"]
    try:
        beta = subprocess.run(common + ["config", "--format", "json"],
                              input=override, capture_output=True, text=True,
                              env=environment_values, cwd=ROOT, timeout=120, check=False)
        ui = subprocess.run(ui_command, capture_output=True, text=True,
                            env=environment_values, cwd=ROOT, timeout=120, check=False)
        service_hashes = {}
        for name in sorted(SIGNED_APPLICATIONS | {"issuance"}):
            result = subprocess.run(common + ["config", "--hash", name],
                                    input=override, capture_output=True, text=True,
                                    env=environment_values, cwd=ROOT, timeout=120,
                                    check=False)
            require(result.returncode == 0 and re.fullmatch(
                rf"{re.escape(name)} [0-9a-f]{{64}}\s*", result.stdout) is not None,
                "Protected aggregate Compose service hash is unavailable")
            service_hashes[name] = result.stdout.split()[1]
        ui_hash = subprocess.run(ui_common + ["config", "--hash", "ui-prod"],
                                 capture_output=True, text=True,
                                 env=environment_values, cwd=ROOT, timeout=120,
                                 check=False)
        require(ui_hash.returncode == 0 and re.fullmatch(
            r"ui-prod [0-9a-f]{64}\s*", ui_hash.stdout) is not None,
            "Protected aggregate UI Compose hash is unavailable")
    except (OSError, subprocess.SubprocessError) as exc:
        raise ComposePlanError("Protected aggregate Compose rendering failed") from exc
    require(beta.returncode == 0 and ui.returncode == 0,
            "Protected aggregate Compose rendering failed")
    require(before == {path.name: sha256(path) for path in paths},
            "Aggregate Compose input changed during rendering")
    try:
        beta_config = json.loads(beta.stdout)
        ui_config = json.loads(ui.stdout)
    except ValueError as exc:
        raise ComposePlanError("Aggregate Compose render is invalid") from exc
    require(isinstance(beta_config, dict) and isinstance(ui_config, dict),
            "Aggregate Compose render is invalid")
    evidence = {"compose_files_sha256": {name: before[name] for name in COMPOSE_FILES},
                "ui_compose_file_sha256": before[UI_COMPOSE_FILE],
                "env_files_sha256": {name: before[name] for name in ENV_FILES},
                "image_override_sha256": hashlib.sha256(override.encode()).hexdigest(),
                "image_override": override,
                "beta_render_sha256": hashlib.sha256(beta.stdout.encode()).hexdigest(),
                "ui_render_sha256": hashlib.sha256(ui.stdout.encode()).hexdigest(),
                "service_config_hashes": service_hashes,
                "ui_config_hash": ui_hash.stdout.split()[1]}
    return beta_config, ui_config, evidence


def prepare(handoff: dict[str, Any], maintenance_intent: dict[str, Any],
            rendered: dict[str, Any], ui_rendered: dict[str, Any]) -> dict[str, Any]:
    require(handoff.get("schema") == "marty.passport-beta-aggregate-handoff/v1"
            and SHA.fullmatch(str(handoff.get("source_commit"))) is not None
            and DIGEST.fullmatch(str(handoff.get("services_image", "")).split("@")[-1])
                is not None
            and str(handoff.get("services_image", "")).startswith(SERVICES_IMAGE)
            and str(handoff.get("issuance_image", "")).startswith(ISSUANCE_IMAGE)
            and DIGEST.fullmatch(str(handoff.get("issuance_image", "")).split("@")[-1])
                is not None
            and str(handoff.get("ui_image", "")).startswith(UI_IMAGE)
            and DIGEST.fullmatch(str(handoff.get("ui_image", "")).split("@")[-1])
                is not None,
            "Signed beta handoff image identities are invalid")
    require(maintenance_intent.get("schema") == "marty.passport-beta-db-maintenance-plan/v1"
            and maintenance_intent.get("source_commit") == handoff["source_commit"]
            and maintenance_intent.get("stop_container_ids")
                == handoff.get("stopped_container_ids"),
            "Beta maintenance intent differs from signed handoff")
    generation = maintenance_intent.get("beta_generation")
    require(isinstance(generation, list) and generation,
            "Beta maintenance generation is invalid")
    previous = {}
    for item in generation:
        require(isinstance(item, dict)
                and isinstance(item.get("service"), str)
                and CONTAINER.fullmatch(str(item.get("container_id"))) is not None
                and item["service"] not in previous,
                "Beta maintenance generation has ambiguous services")
        previous[item["service"]] = item["container_id"]
    require("postgres" in previous
            and (SIGNED_APPLICATIONS - NEW_SERVICES | {"issuance"}).issubset(previous)
            and not (NEW_SERVICES & previous.keys()),
            "Beta generation or simulator service state is unexpected")
    services = rendered.get("services")
    require(isinstance(services, dict)
            and set(previous).issubset(services)
            and SIGNED_APPLICATIONS.issubset(services),
            "Rendered beta Compose omits required services")
    assert_beta_origin(services)
    for name in SIGNED_APPLICATIONS:
        service = services[name]
        require(isinstance(service, dict), f"Rendered beta service is invalid: {name}")
        require(service.get("image") == handoff["services_image"],
                f"Rendered beta service image differs from signed release: {name}")
        env = environment(service)
        require(env.get("SERVICE_NAME") == name.replace("-", "_"),
                f"Rendered beta service dispatch differs: {name}")
        for key, expected in RUNTIME_ENV.get(name, {}).items():
            require(env.get(key) == expected,
                    f"Rendered beta Rust selector differs: {name}.{key}")
        if name in NEW_SERVICES:
            require(not service.get("ports"),
                    f"Synthetic passport service publishes a port: {name}")
    callback = services["passport-callback-signer"]
    require(set(callback.get("networks", {})) == {"passport-callback-signing"}
            and not callback.get("volumes") and not callback.get("secrets"),
            "Passport callback signer isolation differs")
    bureau = services["passport-beta-bureau"]
    require(set(bureau.get("networks", {}))
            == {"marty-network", "passport-callback-signing"},
            "Passport synthetic bureau networks differ")
    signing_network = rendered.get("networks", {}).get("passport-callback-signing")
    require(isinstance(signing_network, dict)
            and signing_network.get("name") == "elevenid-beta-passport-callback-signing"
            and signing_network.get("internal") is True,
            "Passport callback signing network is not isolated")
    for name in SIGNED_APPLICATIONS - {"issuance-native", "canvas-sync-worker"}:
        require(not services[name].get("entrypoint") and not services[name].get("command"),
                f"Rendered beta service overrides signed dispatch: {name}")
    require(services["issuance-native"].get("entrypoint")
            == ["/app/services/entrypoint.sh"]
            and services["issuance-native"].get("command") == [],
            "Native issuance entrypoint differs")
    require(services["canvas-sync-worker"].get("command")
            == ["/usr/local/bin/marty-canvas-sync-worker"]
            and not services["canvas-sync-worker"].get("entrypoint"),
            "Canvas worker command differs")
    issuance = services.get("issuance")
    require(isinstance(issuance, dict)
            and issuance.get("image") == handoff["issuance_image"],
            "Rendered beta issuance image differs from signed release")
    for name in ("passport-provider-ingress", "passport-callback-signer-supported"):
        require(name not in services,
                "External physical provider profile entered synthetic beta Compose")
    require(rendered.get("name") == "elevenid-beta",
            "Rendered Compose project is not the beta project")
    ui_services = ui_rendered.get("services")
    require(ui_rendered.get("name") == "elevenid-beta-ui"
            and isinstance(ui_services, dict)
            and set(ui_services) == {"ui-prod"}
            and isinstance(ui_services["ui-prod"], dict)
            and ui_services["ui-prod"].get("image") == handoff["ui_image"],
            "Rendered beta UI differs from signed release")
    ui_networks = ui_rendered.get("networks")
    require(isinstance(ui_networks, dict)
            and isinstance(ui_networks.get("default"), dict)
            and ui_networks["default"].get("external") is True
            and ui_networks["default"].get("name") == "elevenid-beta-network",
            "Rendered beta UI network differs")
    old_services = set(previous) - {"postgres"}
    require("openbao" in old_services
            and previous["openbao"] not in maintenance_intent["stop_container_ids"],
            "Beta OpenBao was not preserved through maintenance")
    replacement = (old_services & (SIGNED_APPLICATIONS | {"issuance"})) | NEW_SERVICES
    restart = old_services - replacement - {"openbao"}
    network_definitions = rendered.get("networks")
    require(isinstance(network_definitions, dict),
            "Rendered beta networks are invalid")
    expected_networks = {}
    for name in sorted(set(previous) | NEW_SERVICES):
        service = services[name]
        configured = service.get("networks", {"marty-network": None})
        keys = list(configured) if isinstance(configured, dict) else configured
        require(isinstance(keys, list)
                and all(isinstance(key, str) for key in keys),
                "Rendered beta service network configuration is invalid")
        names = []
        for key in keys:
            definition = network_definitions.get(key)
            require(isinstance(definition, dict)
                    and isinstance(definition.get("name"), str),
                    "Rendered beta network name is invalid")
            names.append(definition["name"])
        require(bool(names) and len(names) == len(set(names)),
                "Rendered beta service networks are ambiguous")
        expected_networks[name] = sorted(names)
    return {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "beta_origin": BETA_ORIGIN,
        "source_commit": handoff["source_commit"],
        "stack_manifest_sha256": handoff["stack_manifest_sha256"],
        "fence_receipt_sha256": handoff["fence_receipt_sha256"],
        "maintenance_receipt_sha256": handoff["maintenance_receipt_sha256"],
        "native_receipt_sha256": handoff["native_receipt_sha256"],
        "postgres_container_id": previous["postgres"],
        "postgres_system_identifier": maintenance_intent["postgres_system_identifier"],
        "database_oid": maintenance_intent["database_oid"],
        "fence_epoch": handoff["fence_epoch"],
        "migration_set_sha256": handoff["migration_set_sha256"],
        "enable_login_sql_sha256": handoff["enable_login_sql_sha256"],
        "production_snapshot_sha256": handoff["production_snapshot_sha256"],
        "production_attachments_sha256": handoff["production_attachments_sha256"],
        "services_image": handoff["services_image"],
        "issuance_image": handoff["issuance_image"],
        "restart_infrastructure": sorted(restart - INGRESS),
        "preserved_infrastructure": ["openbao"],
        "recreate_applications": sorted(replacement - INGRESS),
        "restart_ingress_last": sorted(restart & INGRESS),
        "recreate_ingress_last": sorted(replacement & INGRESS),
        "target_services": sorted(old_services | NEW_SERVICES),
        "old_container_ids_by_service": previous,
        "expected_networks_by_service": expected_networks,
        "schema_startup_mode": "validate",
        "ui_project": "elevenid-beta-ui",
        "ui_image": handoff["ui_image"],
    }


RENDER_EVIDENCE = (
    "compose_files_sha256", "ui_compose_file_sha256", "env_files_sha256",
    "image_override_sha256", "image_override", "beta_render_sha256",
    "ui_render_sha256", "service_config_hashes", "ui_config_hash",
)


def verify_render_plan(recorded: dict[str, Any]) -> dict[str, Any]:
    """Re-render pinned inputs under the operator's host lock before each up."""
    require(recorded.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and protected_source(run) == recorded.get("source_commit"),
            "Aggregate Compose source changed")
    for relative in PROTECTED_FILES:
        protected_file(relative, run)
    beta, ui, fresh = render_candidate(recorded)
    require(all(recorded.get(key) == fresh[key] for key in RENDER_EVIDENCE),
            "Aggregate Compose render or input changed")
    require(beta.get("name") == "elevenid-beta"
            and ui.get("name") == "elevenid-beta-ui",
            "Aggregate Compose projects changed")
    return {"schema": "marty.passport-beta-aggregate-render-check/v1",
            "verified": True, "source_commit": recorded["source_commit"],
            "beta_render_sha256": fresh["beta_render_sha256"],
            "ui_render_sha256": fresh["ui_render_sha256"]}


def verify_preserved_openbao_token(recorded: dict[str, Any]) -> dict[str, Any]:
    """Match the new signer token to the still-running beta OpenBao without logging it."""
    verify_render_plan(recorded)
    rendered, _, _ = render_candidate(recorded)
    old = recorded.get("old_container_ids_by_service")
    require(isinstance(old, dict)
            and CONTAINER.fullmatch(str(old.get("openbao"))) is not None,
            "Preserved OpenBao identity is invalid")
    bao = inspect(old["openbao"], run)
    config = bao.get("Config")
    raw_env = config.get("Env") if isinstance(config, dict) else None
    require(bao.get("Id") == old["openbao"]
            and isinstance(raw_env, list)
            and all(isinstance(value, str) and "=" in value for value in raw_env),
            "Preserved OpenBao environment is invalid")
    token_rows = [value.split("=", 1)[1] for value in raw_env
                  if value.startswith("BAO_DEV_ROOT_TOKEN_ID=")]
    services = rendered.get("services")
    signer = services.get("passport-callback-signer") if isinstance(services, dict) else None
    signer_token = environment(signer).get("BAO_TOKEN") if isinstance(signer, dict) else None
    require(len(token_rows) == 1 and bool(token_rows[0])
            and isinstance(signer_token, str) and bool(signer_token)
            and hmac.compare_digest(token_rows[0], signer_token),
            "New callback signer token differs from preserved OpenBao")
    return {"schema": "marty.passport-beta-openbao-token-check/v1", "verified": True,
            "source_commit": recorded["source_commit"]}


def verify_resume_plan(
    recorded: dict[str, Any], intent: dict[str, Any], stack_manifest: Path,
    fence_receipt: Path, maintenance_receipt: Path, native_receipt: Path,
) -> dict[str, Any]:
    """Recheck pinned inputs and a partial Rust generation after app login opens."""
    verify_render_plan(recorded)
    source = recorded["source_commit"]
    signed = manifest_source(stack_manifest, source)
    require(signed["manifest_sha256"] == recorded.get("stack_manifest_sha256")
            and signed["services_image"] == recorded.get("services_image")
            and signed["issuance_image"] == recorded.get("issuance_image")
            and (UI_IMAGE + signed["oci_digests"]["ghcr.io/elevenid/marty-ui-oss/ui"].split(":", 1)[1])
                == recorded.get("ui_image")
            and file_sha256(fence_receipt) == recorded.get("fence_receipt_sha256")
            and file_sha256(maintenance_receipt) == recorded.get("maintenance_receipt_sha256")
            and file_sha256(native_receipt) == recorded.get("native_receipt_sha256"),
            "Aggregate resume source or receipt changed")
    try:
        maintenance = json.loads(maintenance_receipt.read_text(encoding="utf-8"))
        native = json.loads(native_receipt.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ComposePlanError("Aggregate resume receipt is unreadable") from exc
    intent_path = Path(str(maintenance_receipt) + ".intent.json")
    require(isinstance(maintenance, dict) and isinstance(native, dict)
            and maintenance.get("schema") == "marty.passport-beta-db-maintenance-start/v1"
            and native.get("schema") == "marty.passport-beta-native-db-gates/v1"
            and maintenance.get("source_commit") == source
            and native.get("source_commit") == source
            and maintenance.get("intent_sha256") == file_sha256(intent_path)
            and native.get("maintenance_receipt_sha256")
                == file_sha256(maintenance_receipt)
            and maintenance.get("production_snapshot_sha256")
                == recorded.get("production_snapshot_sha256")
            and maintenance.get("production_attachments_sha256")
                == recorded.get("production_attachments_sha256")
            and native.get("production_snapshot_sha256")
                == recorded.get("production_snapshot_sha256")
            and native.get("migration_set_sha256")
                == recorded.get("migration_set_sha256")
            and maintenance.get("postgres_container_id")
                == recorded.get("postgres_container_id")
            and native.get("postgres_container_id")
                == recorded.get("postgres_container_id")
            and str(maintenance.get("fence_epoch"))
                == str(recorded.get("fence_epoch"))
            and str(native.get("fence_epoch"))
                == str(recorded.get("fence_epoch"))
            and native.get("stopped_container_ids")
                == maintenance.get("stopped_container_ids")
            and native.get("app_login_enabled") is False
            and file_sha256(ROOT / "scripts/sql/passport-beta-db-enable-app-login.sql")
                == recorded.get("enable_login_sql_sha256"),
            "Aggregate resume receipt lineage changed")
    old = recorded.get("old_container_ids_by_service")
    generation = intent.get("beta_generation")
    require(isinstance(old, dict) and isinstance(generation, list)
            and intent.get("source_commit") == source
            and {item.get("service"): item.get("container_id") for item in generation
                 if isinstance(item, dict)} == old
            and intent.get("stop_container_ids")
                == [item["container_id"] for item in generation
                    if item["service"] not in {"postgres", "openbao"}]
            and intent.get("stop_container_ids")
                == maintenance.get("stopped_container_ids")
            and intent.get("postgres_container_id")
                == recorded.get("postgres_container_id")
            and str(intent.get("fence_epoch"))
                == str(recorded.get("fence_epoch")),
            "Aggregate resume maintenance intent changed")
    handoff = {**recorded, "schema": "marty.passport-beta-aggregate-handoff/v1",
               "stopped_container_ids": intent["stop_container_ids"]}
    beta_rendered, ui_rendered, _ = render_candidate(recorded)
    recomputed = prepare(handoff, intent, beta_rendered, ui_rendered)
    require(all(recorded.get(key) == value for key, value in recomputed.items()),
            "Aggregate resume startup groups differ from signed generation")
    docker = intent.get("docker")
    require(isinstance(docker, dict)
            and run(["docker", "context", "show"]) == docker.get("context")
            and run(["docker", "info", "--format", "{{.ID}}"]) == docker.get("daemon_id")
            and production_snapshot(run).get("sha256")
                == recorded.get("production_snapshot_sha256")
            and production_attachment_sha256(run)
                == recorded.get("production_attachments_sha256"),
            "Aggregate resume target or production changed")
    for service in ("postgres", "openbao"):
        item = next((entry for entry in generation if entry["service"] == service), None)
        require(isinstance(item, dict), "Aggregate resume preserved service is absent")
        container = inspect(item["container_id"], run)
        state = container.get("State")
        require(container.get("Id") == item["container_id"]
                and container.get("Image") == item.get("image_id")
                and isinstance(state, dict)
                and state.get("StartedAt") == item.get("started_at")
                and state.get("Running") is True
                and state.get("Status") == "running",
                f"Aggregate resume preserved {service} changed")
    observed: dict[str, list[dict[str, Any]]] = {}
    for container_id in ids(BETA_PROJECT, run):
        container = inspect(container_id, run)
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        require(isinstance(service, str)
                and labels.get("com.docker.compose.project") == BETA_PROJECT
                and service in set(old) | NEW_SERVICES,
                "Aggregate resume beta service inventory changed")
        observed.setdefault(service, []).append(container)
    require(all(len(items) <= 2 for items in observed.values()),
            "Aggregate resume beta service is duplicated")
    recreated = set(recorded.get("recreate_applications", [])) | set(
        recorded.get("recreate_ingress_last", []))
    rendered_services = beta_rendered.get("services")
    require(isinstance(rendered_services, dict),
            "Aggregate resume rendered services are invalid")
    for service, containers in observed.items():
        replacements = [item for item in containers
                        if item.get("Id") != old.get(service)]
        require(len(replacements) <= 1,
                "Aggregate resume beta service has duplicate replacements")
        for container in containers:
            state = container.get("State")
            require(isinstance(state, dict), "Aggregate resume beta state is invalid")
            networks = container.get("NetworkSettings", {}).get("Networks")
            expected_networks = recorded.get("expected_networks_by_service")
            require(isinstance(networks, dict)
                    and isinstance(expected_networks, dict)
                    and isinstance(expected_networks.get(service), list)
                    and set(networks).issubset(set(expected_networks[service])),
                    "Aggregate resume beta service joined an unexpected network")
            if service in recreated:
                if container.get("Id") == old.get(service):
                    require(state.get("Running") is False,
                            "Stopped old beta application restarted during resume")
                else:
                    expected = (recorded["issuance_image"] if service == "issuance"
                                else recorded["services_image"])
                    config = container.get("Config")
                    require(isinstance(config, dict)
                            and config.get("Image") == expected,
                            "Aggregate resume application image differs")
                    labels = config.get("Labels")
                    expected_hashes = recorded.get("service_config_hashes")
                    require(isinstance(labels, dict)
                            and isinstance(expected_hashes, dict)
                            and re.fullmatch(r"[0-9a-f]{64}",
                                             str(expected_hashes.get(service))) is not None
                            and labels.get("com.docker.compose.config-hash")
                                == expected_hashes.get(service),
                            "Aggregate resume Compose service config differs")
                    if service in SIGNED_APPLICATIONS:
                        raw_env = config.get("Env")
                        require(isinstance(raw_env, list)
                                and all(isinstance(value, str) and "=" in value
                                        for value in raw_env),
                                "Aggregate resume application environment is invalid")
                        selected = dict(value.split("=", 1) for value in raw_env)
                        require(len(selected) == len(raw_env)
                                and selected.get("SERVICE_NAME")
                                    == service.replace("-", "_")
                                and all(selected.get(key) == value
                                        for key, value in RUNTIME_ENV.get(service, {}).items()),
                                "Aggregate resume Rust runtime selector differs")
                    expected_service = rendered_services.get(service)
                    require(isinstance(expected_service, dict),
                            "Aggregate resume rendered application is absent")
                    for field, docker_field in (("entrypoint", "Entrypoint"),
                                                ("command", "Cmd")):
                        if field in expected_service:
                            require(config.get(docker_field) == expected_service[field],
                                    "Aggregate resume application process differs")
                    if service == "passport-callback-signer":
                        networks = container.get("NetworkSettings", {}).get("Networks")
                        require(isinstance(networks, dict)
                                and set(networks)
                                    == {"elevenid-beta-passport-callback-signing"},
                                "Aggregate resume callback signer network differs")
            else:
                require(container.get("Id") == old.get(service),
                        "Aggregate resume infrastructure identity changed")
    ready_services = []
    for service in sorted(recreated):
        containers = observed.get(service, [])
        if len(containers) != 1 or containers[0].get("Id") == old.get(service):
            continue
        state = containers[0]["State"]
        health = state.get("Health")
        networks = containers[0].get("NetworkSettings", {}).get("Networks")
        if (state.get("Running") is True and state.get("Status") == "running"
                and isinstance(networks, dict)
                and set(networks)
                    == set(recorded["expected_networks_by_service"][service])
                and (health is None or (isinstance(health, dict)
                                         and health.get("Status") == "healthy"))):
            ready_services.append(service)
    ui_ids = ids("elevenid-beta-ui", run)
    require(len(ui_ids) <= 1, "Aggregate resume UI generation is ambiguous")
    ready_ui = False
    if ui_ids:
        ui_container = inspect(ui_ids[0], run)
        ui_config = ui_container.get("Config")
        ui_labels = ui_config.get("Labels") if isinstance(ui_config, dict) else None
        ui_state = ui_container.get("State")
        require(isinstance(ui_labels, dict)
                and ui_labels.get("com.docker.compose.project") == "elevenid-beta-ui"
                and ui_labels.get("com.docker.compose.service") == "ui-prod"
                and isinstance(ui_state, dict),
                "Aggregate resume UI identity is invalid")
        ui_health = ui_state.get("Health")
        ready_ui = (ui_config.get("Image") == recorded.get("ui_image")
                    and ui_labels.get("com.docker.compose.config-hash")
                        == recorded.get("ui_config_hash")
                    and set(ui_container.get("NetworkSettings", {}).get("Networks", {}))
                        == {"elevenid-beta-network"}
                    and ui_state.get("Running") is True
                    and ui_state.get("Status") == "running"
                    and (ui_health is None or (isinstance(ui_health, dict)
                                               and ui_health.get("Status") == "healthy")))
    marker = beta_psql(
        "SELECT (SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles "
        "WHERE rolname='marty_beta_migrator')",
        run, recorded["postgres_container_id"],
    )
    prefix = (f"{recorded['fence_epoch']}|{source}|"
              f"{recorded['migration_set_sha256']}|")
    require(marker in {prefix + "true|false", prefix + "false|false"},
            "Aggregate resume native migration marker or role state changed")
    verify_fence(intent, run)
    return {"schema": "marty.passport-beta-aggregate-resume-check/v1",
            "verified": True, "source_commit": source,
            "app_login_enabled": marker.endswith("true|false"),
            "ready_services": ready_services, "ready_ui": ready_ui}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", required=True, type=Path)
    parser.add_argument("--fence-receipt", required=True, type=Path)
    parser.add_argument("--maintenance-receipt", required=True, type=Path)
    parser.add_argument("--native-receipt", required=True, type=Path)
    parser.add_argument("--verify-plan", type=Path)
    parser.add_argument("--verify-render-plan", type=Path)
    parser.add_argument("--verify-openbao-token", type=Path)
    parser.add_argument("--verify-resume-plan", type=Path)
    args = parser.parse_args()
    try:
        require(sum(bool(item) for item in (args.verify_plan,
                                            args.verify_render_plan,
                                            args.verify_openbao_token,
                                            args.verify_resume_plan)) <= 1,
                "Choose one aggregate Compose verification mode")
        if args.verify_resume_plan:
            recorded = json.loads(args.verify_resume_plan.read_text(encoding="utf-8"))
            intent_path = Path(str(args.maintenance_receipt) + ".intent.json")
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            require(isinstance(recorded, dict) and isinstance(intent, dict),
                    "Recorded aggregate resume input is invalid")
            result = verify_resume_plan(recorded, intent, args.stack_manifest,
                                        args.fence_receipt, args.maintenance_receipt,
                                        args.native_receipt)
        elif args.verify_openbao_token:
            recorded = json.loads(args.verify_openbao_token.read_text(encoding="utf-8"))
            require(isinstance(recorded, dict), "Recorded Compose plan is invalid")
            result = verify_preserved_openbao_token(recorded)
        elif args.verify_render_plan:
            recorded = json.loads(args.verify_render_plan.read_text(encoding="utf-8"))
            require(isinstance(recorded, dict), "Recorded Compose plan is invalid")
            result = verify_render_plan(recorded)
        else:
            handoff = handoff_prepare(args.stack_manifest, args.fence_receipt,
                                      args.maintenance_receipt, args.native_receipt)
            intent_path = Path(str(args.maintenance_receipt) + ".intent.json")
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            require(isinstance(intent, dict), "Aggregate Compose input is invalid")
            rendered, ui_rendered, evidence = render_candidate(handoff)
            result = prepare(handoff, intent, rendered, ui_rendered)
            result.update(evidence)
            if args.verify_plan:
                recorded = json.loads(args.verify_plan.read_text(encoding="utf-8"))
                require(recorded == result, "Recorded aggregate Compose plan changed")
                result = {"schema": "marty.passport-beta-aggregate-plan-check/v1",
                          "verified": True, "source_commit": result["source_commit"]}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected beta aggregate Compose plan is unavailable: {exc}") from exc


if __name__ == "__main__":
    main()
