"""Rendered beta Compose must start the signed Rust generation in validate mode."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import prepare_passport_beta_aggregate_compose as compose
from scripts.prepare_passport_beta_aggregate_compose import (
    ComposePlanError, ISSUANCE_IMAGE, RUNTIME_ENV, SERVICES_IMAGE, UI_IMAGE,
    SIGNED_APPLICATIONS, NEW_SERVICES, prepare,
)


def candidate():
    head = "a" * 40
    services_image = SERVICES_IMAGE + "b" * 64
    issuance_image = ISSUANCE_IMAGE + "c" * 64
    old_names = sorted((SIGNED_APPLICATIONS - NEW_SERVICES) | {
        "issuance", "postgres", "redis", "cloudflared", "nginx-proxy", "envoy",
    })
    generation = [{"service": name, "container_id": f"{index + 1:064x}"}
                  for index, name in enumerate(old_names)]
    stops = [item["container_id"] for item in generation
             if item["service"] != "postgres"]
    handoff = {
        "schema": "marty.passport-beta-aggregate-handoff/v1",
        "source_commit": head, "services_image": services_image,
        "issuance_image": issuance_image, "stopped_container_ids": stops,
        "ui_image": UI_IMAGE + "d" * 64,
    }
    intent = {
        "schema": "marty.passport-beta-db-maintenance-plan/v1",
        "source_commit": head, "stop_container_ids": stops,
        "beta_generation": generation,
    }
    services = {name: {} for name in old_names}
    services.update({name: {} for name in NEW_SERVICES})
    for name in SIGNED_APPLICATIONS:
        services[name] = {"image": services_image,
                          "environment": {"SERVICE_NAME": name.replace("-", "_"),
                                          **deepcopy(RUNTIME_ENV.get(name, {}))}}
    services["issuance-native"]["entrypoint"] = ["/app/services/entrypoint.sh"]
    services["issuance-native"]["command"] = []
    services["canvas-sync-worker"]["command"] = [
        "/usr/local/bin/marty-canvas-sync-worker"]
    services["passport-callback-signer"]["networks"] = {
        "passport-callback-signing": None}
    services["passport-beta-bureau"]["networks"] = {
        "marty-network": None, "passport-callback-signing": None}
    services["issuance"] = {"image": issuance_image}
    rendered = {"name": "elevenid-beta", "services": services,
                "networks": {"passport-callback-signing": {
                    "name": "elevenid-beta-passport-callback-signing", "internal": True}}}
    ui = {"name": "elevenid-beta-ui", "services": {
        "ui-prod": {"image": handoff["ui_image"]}},
        "networks": {"default": {"external": True,
                                 "name": "elevenid-beta-network"}}}
    return handoff, intent, rendered, ui


def test_rendered_compose_assigns_signed_rust_start_groups():
    plan = prepare(*candidate())
    assert plan["schema"] == "marty.passport-beta-aggregate-compose-plan/v1"
    assert plan["schema_startup_mode"] == "validate"
    assert "gateway" in plan["recreate_ingress_last"]
    assert "cloudflared" in plan["restart_ingress_last"]
    assert "flow" in plan["recreate_applications"]
    assert "postgres" not in plan["target_services"]
    assert plan["ui_project"] == "elevenid-beta-ui"


@pytest.mark.parametrize("service,key,value", [
    ("flow", "MARTY_SCHEMA_STARTUP_MODE", "migrate"),
    ("issuance-native", "MARTY_SCHEMA_STARTUP_MODE", "migrate"),
    ("issuance-native", "PASSPORT_KMS_CALLBACKS_ENABLED", "false"),
])
def test_rendered_compose_rejects_unsafe_rust_selector(service, key, value):
    handoff, intent, rendered, ui = candidate()
    rendered["services"][service]["environment"][key] = value
    with pytest.raises(ComposePlanError, match="Rust selector differs"):
        prepare(handoff, intent, rendered, ui)


def test_rendered_compose_rejects_wrong_image_and_public_simulator_port():
    handoff, intent, rendered, ui = candidate()
    rendered["services"]["signing-keys"]["image"] = "python:latest"
    with pytest.raises(ComposePlanError, match="image differs"):
        prepare(handoff, intent, rendered, ui)
    rendered["services"]["signing-keys"]["image"] = handoff["services_image"]
    rendered["services"]["passport-beta-bureau"]["ports"] = [{"published": "8020"}]
    with pytest.raises(ComposePlanError, match="publishes a port"):
        prepare(handoff, intent, rendered, ui)


def test_rendered_compose_rejects_external_provider_profile():
    handoff, intent, rendered, ui = candidate()
    rendered["services"]["passport-provider-ingress"] = {}
    with pytest.raises(ComposePlanError, match="External physical provider"):
        prepare(handoff, intent, rendered, ui)


@pytest.mark.parametrize("service,key,value", [
    ("gateway", "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", "true"),
    ("issuance-native", "PERSONALIZATION_BUREAU_URL", "https://external.example"),
    ("issuance-native", "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID", "external"),
    ("issuance-native", "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE", "/run/old-key"),
])
def test_rendered_compose_rejects_external_or_legacy_passport_binding(service, key, value):
    handoff, intent, rendered, ui = candidate()
    rendered["services"][service]["environment"][key] = value
    with pytest.raises(ComposePlanError, match="Rust selector differs"):
        prepare(handoff, intent, rendered, ui)


def test_rendered_compose_rejects_wrong_dispatch_and_signer_network():
    handoff, intent, rendered, ui = candidate()
    rendered["services"]["flow"]["environment"]["SERVICE_NAME"] = "auth"
    with pytest.raises(ComposePlanError, match="dispatch differs"):
        prepare(handoff, intent, rendered, ui)
    rendered["services"]["flow"]["environment"]["SERVICE_NAME"] = "flow"
    rendered["services"]["passport-callback-signer"]["networks"]["marty-network"] = None
    with pytest.raises(ComposePlanError, match="signer isolation differs"):
        prepare(handoff, intent, rendered, ui)


def test_rendered_compose_rejects_wrong_ui_image():
    handoff, intent, rendered, ui = candidate()
    ui["services"]["ui-prod"]["image"] = "nginx:latest"
    with pytest.raises(ComposePlanError, match="UI differs"):
        prepare(handoff, intent, rendered, ui)


def test_candidate_render_uses_protected_file_list_and_signed_images(tmp_path: Path,
                                                                      monkeypatch):
    handoff, _, beta, ui = candidate()
    monkeypatch.setattr(compose, "ROOT", tmp_path)
    monkeypatch.setattr(compose, "COMPOSE_FILES", ("base.yml", "passport.yml"))
    monkeypatch.setattr(compose, "UI_COMPOSE_FILE", "ui.yml")
    monkeypatch.setattr(compose, "ENV_FILES", ("tunnel.env", "generated.env"))
    for name in (*compose.COMPOSE_FILES, compose.UI_COMPOSE_FILE, *compose.ENV_FILES):
        (tmp_path / name).write_text("test\n", encoding="utf-8")
    commands = []
    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        payload = ui if "elevenid-beta-ui" in command else beta
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(compose.subprocess, "run", fake_run)
    rendered, ui_rendered, evidence = compose.render_candidate(handoff)
    assert rendered == beta and ui_rendered == ui
    assert commands[0][0][-5:] == ["-f", "-", "config", "--format", "json"]
    assert commands[0][1]["input"] == evidence["image_override"]
    assert commands[0][1]["env"]["MARTY_SERVICES_IMAGE"] == handoff["services_image"]
    assert commands[1][1]["env"]["MARTY_UI_RELEASE_IMAGE"] == handoff["ui_image"]
    assert set(evidence["compose_files_sha256"]) == {"base.yml", "passport.yml"}
