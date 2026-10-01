"""A completed beta must contain only the signed replacement generation."""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from scripts import verify_passport_beta_aggregate_runtime as runtime


P = "1" * 64
OLD_FLOW = "2" * 64
NEW_FLOW = "3" * 64
REDIS = "4" * 64
KEYCLOAK = "8" * 64
NGINX = "a" * 64
CALLBACK = "5" * 64
BUREAU = "6" * 64
UI = "7" * 64
OPENBAO = "9" * 64
HEAD = "a" * 40
DIGEST = "b" * 64
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "c" * 64
UI_IMAGE = "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "d" * 64


def record(container_id, project, service, image, env=None, networks=None):
    return {"Id": container_id, "Image": "sha256:" + "a" * 64,
            "Config": {"Image": image,
                       "Labels": {"com.docker.compose.project": project,
                                  "com.docker.compose.service": service,
                                  "com.docker.compose.config-hash": "0" * 64},
                       "Env": [f"{key}={value}" for key, value in (env or {}).items()]},
            "State": {"Running": True, "Status": "running",
                      "StartedAt": "2026-09-29T00:00:00Z",
                      "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Networks": networks if networks is not None else {
                "elevenid-beta-network": {"NetworkID": "e" * 64}}}}


def fixture(monkeypatch):
    old = {"postgres": P, "flow": OLD_FLOW, "redis": REDIS,
           "openbao": OPENBAO, "keycloak": KEYCLOAK, "nginx-proxy": NGINX}
    plan = {
        "schema": "marty.passport-beta-aggregate-compose-plan/v1",
        "beta_origin": "https://beta.elevenidllc.com",
        "source_commit": HEAD, "postgres_container_id": P,
        "production_snapshot_sha256": "e" * 64,
        "production_attachments_sha256": "f" * 64,
        "service_config_hashes": {name: "0" * 64 for name in
                                  ("flow", "passport-callback-signer",
                                   "passport-beta-bureau")},
        "ui_config_hash": "0" * 64,
        "old_container_ids_by_service": old,
        "target_services": ["flow", "redis", "openbao", "keycloak",
                            "nginx-proxy", "passport-callback-signer",
                            "passport-beta-bureau"],
        "expected_networks_by_service": {
            name: (["elevenid-beta-passport-callback-signing"]
                   if name == "passport-callback-signer" else
                   ["elevenid-beta-network", "elevenid-beta-passport-callback-signing"]
                   if name in {"openbao", "passport-beta-bureau"} else
                   ["elevenid-beta-network"])
            for name in ("postgres", "flow", "redis", "openbao", "keycloak",
                         "nginx-proxy",
                         "passport-callback-signer", "passport-beta-bureau")},
        "restart_infrastructure": ["redis", "keycloak"],
        "preserved_infrastructure": ["openbao"],
        "recreate_applications": ["flow", "passport-callback-signer",
                                  "passport-beta-bureau"],
        "restart_ingress_last": ["nginx-proxy"], "recreate_ingress_last": [],
        "services_image": SERVICES, "issuance_image": "unused",
        "ui_image": UI_IMAGE, "fence_epoch": "7",
        "migration_set_sha256": DIGEST,
    }
    intent = {"schema": "marty.passport-beta-db-maintenance-plan/v1",
              "source_commit": HEAD,
              "beta_generation": [{"service": "openbao", "container_id": OPENBAO,
                                   "image_id": "sha256:" + "a" * 64,
                                   "started_at": "2026-09-29T00:00:00Z"}],
              "docker": {"context": "desktop-linux", "daemon_id": "daemon"}}
    records = {
        P: record(P, "elevenid-beta", "postgres", "postgres:15"),
        NEW_FLOW: record(NEW_FLOW, "elevenid-beta", "flow", SERVICES,
                         {"SERVICE_NAME": "flow", **runtime.RUNTIME_ENV["flow"]}),
        REDIS: record(REDIS, "elevenid-beta", "redis", "redis:7"),
        KEYCLOAK: record(KEYCLOAK, "elevenid-beta", "keycloak", "keycloak:25",
                         {"KC_HOSTNAME": "https://beta.elevenidllc.com",
                          "UI_BASE_URL": "https://beta.elevenidllc.com",
                          "PUBLIC_DOMAIN": "beta.elevenidllc.com"}),
        NGINX: record(NGINX, "elevenid-beta", "nginx-proxy", "nginx:alpine",
                      {"PUBLIC_DOMAIN": "beta.elevenidllc.com",
                       "GATEWAY_UPSTREAM": "gateway:8000"}),
        OPENBAO: record(OPENBAO, "elevenid-beta", "openbao", "openbao:2",
                        {"BAO_DEV_ROOT_TOKEN_ID": "test-token"},
                        networks={"elevenid-beta-network": {"NetworkID": "e" * 64},
                                  "elevenid-beta-passport-callback-signing": {
                                      "NetworkID": "8" * 64, "Aliases": ["openbao"]}}),
        CALLBACK: record(CALLBACK, "elevenid-beta", "passport-callback-signer",
                         SERVICES, {"SERVICE_NAME": "passport_callback_signer",
                                    "BAO_TOKEN": "test-token",
                                    **runtime.RUNTIME_ENV["passport-callback-signer"]},
                         {"elevenid-beta-passport-callback-signing": {
                             "NetworkID": "8" * 64}}),
        BUREAU: record(BUREAU, "elevenid-beta", "passport-beta-bureau", SERVICES,
                       {"SERVICE_NAME": "passport_beta_bureau",
                        **runtime.RUNTIME_ENV["passport-beta-bureau"]},
                       networks={"elevenid-beta-network": {"NetworkID": "e" * 64},
                                 "elevenid-beta-passport-callback-signing": {
                                     "NetworkID": "8" * 64}}),
        UI: record(UI, "elevenid-beta-ui", "ui-prod", UI_IMAGE,
                   networks={"elevenid-beta-network": {}}),
    }
    monkeypatch.setattr(runtime, "ids", lambda project, _runner: [
        key[:12] for key, value in records.items()
        if value["Config"]["Labels"]["com.docker.compose.project"] == project])
    monkeypatch.setattr(runtime, "inspect", lambda short, _runner: next(
        value for key, value in records.items() if key.startswith(short)))
    monkeypatch.setattr(runtime, "production_snapshot", lambda _runner: {
        "sha256": "e" * 64})
    monkeypatch.setattr(runtime, "production_attachment_sha256", lambda _runner: "f" * 64)
    monkeypatch.setattr(runtime, "verify_rust_owner", lambda *_args, **_kwargs: {
        "verified": True, "source_commit": HEAD,
        "postgres_container_id": plan["postgres_container_id"],
        "fence_epoch": "7", "transition_txid": "9",
    })
    def runner(command):
        if command[:3] == ["docker", "context", "show"]:
            return "desktop-linux"
        if command[:2] == ["docker", "info"]:
            return "daemon"
        if command[:3] == ["docker", "network", "inspect"]:
            return json.dumps([{"Name": "elevenid-beta-passport-callback-signing",
                                "Internal": True, "Id": "8" * 64,
                                "Containers": {key: {} for key in
                                               (OPENBAO, CALLBACK, BUREAU)}}])
        raise AssertionError(command)
    return plan, intent, records, runner


def test_runtime_requires_replaced_signed_generation(monkeypatch):
    plan, intent, _, runner = fixture(monkeypatch)
    evidence = runtime.verify(plan, intent, "f" * 64, runner,
                              lambda _: {"verified": True})
    assert evidence["verified"] is True
    assert evidence["beta_origin"] == "https://beta.elevenidllc.com"
    assert evidence["ui_container_id"] == UI
    assert evidence["beta_runtime"]["flow"] == {
        "container_id": NEW_FLOW, "image_id": "sha256:" + "a" * 64,
        "configured_image": SERVICES, "started_at": "2026-09-29T00:00:00Z",
        "config_hash": "0" * 64, "networks": ["elevenid-beta-network"],
    }
    assert set(evidence["beta_runtime"]) == set(evidence["beta_services"])
    assert evidence["ui_runtime"]["container_id"] == UI
    assert evidence["ui_runtime"]["configured_image"] == UI_IMAGE
    assert "test-token" not in json.dumps(evidence)


def test_runtime_rejects_preserved_ingress_pointing_elsewhere(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[NGINX]["Config"]["Env"] = [
        "GATEWAY_UPSTREAM=prod-gateway:8000" if item.startswith("GATEWAY_UPSTREAM=")
        else item for item in records[NGINX]["Config"]["Env"]]
    with pytest.raises(runtime.HostProbeError, match="outside the beta origin"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_old_flow_restart(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[OLD_FLOW] = records.pop(NEW_FLOW)
    records[OLD_FLOW]["Id"] = OLD_FLOW
    with pytest.raises(runtime.HostProbeError, match="restarted instead of replaced"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_wrong_signed_image(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[NEW_FLOW]["Config"]["Image"] = "python:latest"
    with pytest.raises(runtime.HostProbeError, match="image differs"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_refuses_receipt_without_exact_image_identity(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[NEW_FLOW]["Image"] = None
    with pytest.raises(runtime.HostProbeError, match="runtime identity is incomplete"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_changed_production(monkeypatch):
    plan, intent, _, runner = fixture(monkeypatch)
    changed = deepcopy(plan)
    changed["production_snapshot_sha256"] = "f" * 64
    with pytest.raises(runtime.HostProbeError, match="Production changed"):
        runtime.verify(changed, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_duplicate_selector(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[NEW_FLOW]["Config"]["Env"].insert(0, "MARTY_SCHEMA_STARTUP_MODE=migrate")
    with pytest.raises(runtime.HostProbeError, match="environment is duplicated"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_ui_extra_network(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[UI]["NetworkSettings"]["Networks"]["production"] = {}
    with pytest.raises(runtime.HostProbeError, match="unexpected network"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_beta_service_attached_to_production_network(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[NEW_FLOW]["NetworkSettings"]["Networks"]["production-network"] = {
        "NetworkID": "9" * 64}
    with pytest.raises(runtime.HostProbeError, match="service network differs: flow"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_public_callback_network(monkeypatch):
    plan, intent, _, base_runner = fixture(monkeypatch)
    def runner(command):
        if command[:3] == ["docker", "network", "inspect"]:
            return json.dumps([{"Name": "elevenid-beta-passport-callback-signing",
                                "Internal": False, "Id": "8" * 64,
                                "Containers": {key: {} for key in
                                               (OPENBAO, CALLBACK, BUREAU)}}])
        return base_runner(command)
    with pytest.raises(runtime.HostProbeError, match="network is not isolated"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})


def test_runtime_rejects_restarted_openbao_or_signer_token_drift(monkeypatch):
    plan, intent, records, runner = fixture(monkeypatch)
    records[OPENBAO]["State"]["StartedAt"] = "2026-09-29T01:00:00Z"
    with pytest.raises(runtime.HostProbeError, match="OpenBao restarted"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})
    records[OPENBAO]["State"]["StartedAt"] = "2026-09-29T00:00:00Z"
    records[CALLBACK]["Config"]["Env"] = [
        "BAO_TOKEN=wrong" if item.startswith("BAO_TOKEN=") else item
        for item in records[CALLBACK]["Config"]["Env"]]
    with pytest.raises(runtime.HostProbeError, match="signer token differs"):
        runtime.verify(plan, intent, "f" * 64, runner, lambda _: {"verified": True})
