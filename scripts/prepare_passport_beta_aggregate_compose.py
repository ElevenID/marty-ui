#!/usr/bin/env python3
"""Validate a rendered signed Rust beta Compose generation before startup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

try:
    from .prepare_passport_beta_aggregate_handoff import prepare as handoff_prepare
except ImportError:
    from prepare_passport_beta_aggregate_handoff import prepare as handoff_prepare


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
    ui_command = ["docker", "compose", "--project-name", "elevenid-beta-ui",
                  *env_args, "-f", str(ROOT / UI_COMPOSE_FILE),
                  "config", "--format", "json"]
    try:
        beta = subprocess.run(common + ["config", "--format", "json"],
                              input=override, capture_output=True, text=True,
                              env=environment_values, cwd=ROOT, timeout=120, check=False)
        ui = subprocess.run(ui_command, capture_output=True, text=True,
                            env=environment_values, cwd=ROOT, timeout=120, check=False)
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
                "ui_render_sha256": hashlib.sha256(ui.stdout.encode()).hexdigest()}
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
    replacement = (old_services & (SIGNED_APPLICATIONS | {"issuance"})) | NEW_SERVICES
    restart = old_services - replacement
    return {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "source_commit": handoff["source_commit"],
        "postgres_container_id": previous["postgres"],
        "restart_infrastructure": sorted(restart - INGRESS),
        "recreate_applications": sorted(replacement - INGRESS),
        "restart_ingress_last": sorted(restart & INGRESS),
        "recreate_ingress_last": sorted(replacement & INGRESS),
        "target_services": sorted(old_services | NEW_SERVICES),
        "schema_startup_mode": "validate",
        "ui_project": "elevenid-beta-ui",
        "ui_image": handoff["ui_image"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", required=True, type=Path)
    parser.add_argument("--fence-receipt", required=True, type=Path)
    parser.add_argument("--maintenance-receipt", required=True, type=Path)
    parser.add_argument("--native-receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        handoff = handoff_prepare(args.stack_manifest, args.fence_receipt,
                                  args.maintenance_receipt, args.native_receipt)
        intent_path = Path(str(args.maintenance_receipt) + ".intent.json")
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        require(isinstance(intent, dict),
                "Aggregate Compose input is invalid")
        rendered, ui_rendered, evidence = render_candidate(handoff)
        plan = prepare(handoff, intent, rendered, ui_rendered)
        plan.update(evidence)
        print(json.dumps(plan,
                         sort_keys=True, separators=(",", ":")))
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        raise SystemExit(f"Protected beta aggregate Compose plan is unavailable: {exc}") from exc


if __name__ == "__main__":
    main()
