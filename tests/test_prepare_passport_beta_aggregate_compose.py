"""Rendered beta Compose must start the signed Rust generation in validate mode."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import prepare_passport_beta_aggregate_compose as compose
from scripts import verify_passport_beta_rust_owner as rust_owner
from scripts.prepare_passport_beta_aggregate_compose import (
    BETA_ORIGIN, ComposePlanError, RUNTIME_ENV, SERVICES_IMAGE, UI_IMAGE,
    SIGNED_APPLICATIONS, NEW_SERVICES, prepare,
)


def test_signed_rust_override_scopes_plaintext_grpc_to_beta():
    handoff, *_ = candidate()
    override = compose.image_override(handoff)
    document = yaml.compose(override)
    services_node = next(value for key, value in document.value
                         if key.value == "services")
    names = [key.value for key, _ in services_node.value]
    assert len(names) == len(set(names))
    services = yaml.safe_load(override.replace("!reset null", "null"))["services"]
    for name in ("issuance", "issuance-native"):
        environment = services[name]["environment"]
        assert environment["ENVIRONMENT"] == "beta"
        assert environment["GRPC_INSECURE_ALLOWED"] == "true"


def test_live_operator_binds_all_signed_image_interpolation_inputs():
    source = (Path(__file__).resolve().parents[1]
              / "scripts/run-passport-beta-aggregate-deploy.ps1").read_text(
                  encoding="utf-8")
    for variable, field in (
        ("MARTY_SERVICES_IMAGE", "services_image"),
        ("MARTY_UI_RELEASE_IMAGE", "ui_image"),
    ):
        binding = f"$env:{variable} = [string]$script:plan.{field}"
        assert source.count(binding) == 1
        assert source.index(binding) < source.index("Invoke-SignedIssuanceMigration\n")



def test_maintenance_preflight_reuses_full_credential_validator(monkeypatch):
    head = "a" * 40
    docs_id = "b" * 64
    image_id = "sha256:" + "c" * 64
    signed = {
        "services_image": SERVICES_IMAGE + "d" * 64,
        "issuance_image": SERVICES_IMAGE + "d" * 64,
        "oci_digests": {"ghcr.io/elevenid/marty-ui-oss/ui": "sha256:" + "f" * 64},
        "build_only_artifacts": {},
    }
    docs = {"Id": docs_id, "Image": image_id,
            "Config": {"Image": image_id,
                       "Labels": {"com.docker.compose.project": "elevenid-beta",
                                  "com.docker.compose.service": "docs"}}}
    observed = []
    monkeypatch.setattr(compose, "manifest_source", lambda *_, **__: signed)
    monkeypatch.setattr(compose, "inspect", lambda *_: docs)
    monkeypatch.setattr(compose, "render_candidate",
                        lambda handoff: ({"services": {"auth": {}, "gateway": {
                            "ports": [{"host_ip": "127.0.0.1", "target": 8000}]}}},
                                         {}, {}))
    monkeypatch.setattr(compose, "assert_beta_origin",
                        lambda services: observed.append("origin"))
    monkeypatch.setattr(compose, "validate_model",
                        lambda model, **kwargs: observed.append(kwargs))
    result = compose.preflight_maintenance_compose(Path("stack-manifest.json"),
                                                   head, docs_id, image_id)
    assert result["verified"] is True
    assert observed == ["origin", {"passport_enabled": True,
                                    "files": compose.COMPOSE_FILES}]


def candidate():
    head = "a" * 40
    services_image = SERVICES_IMAGE + "b" * 64
    issuance_image = services_image
    old_names = sorted((SIGNED_APPLICATIONS - NEW_SERVICES) | {
        "issuance", "postgres", "openbao", "redis", "keycloak",
        "cloudflared", "nginx-proxy", "envoy",
    })
    generation = [{"service": name, "container_id": f"{index + 1:064x}"}
                  for index, name in enumerate(old_names)]
    stops = [item["container_id"] for item in generation
             if item["service"] not in {"postgres", "openbao"}]
    handoff = {
        "schema": "marty.passport-beta-aggregate-handoff/v1",
        "source_commit": head, "services_image": services_image,
        "issuance_image": issuance_image, "stopped_container_ids": stops,
        "ui_image": UI_IMAGE + "d" * 64,
        "stack_manifest_sha256": "1" * 64,
        "fence_receipt_sha256": "2" * 64,
        "cutover_snapshot_file_sha256": "a" * 64,
        "cutover_snapshot_sha256": "b" * 64,
        "cutover_report_file_sha256": "d" * 64,
        "cutover_report_run_id": 42,
        "legacy_writer_container_id": next(item["container_id"] for item in generation
                                           if item["service"] == "issuance"),
        "legacy_writer_image_digest": "sha256:" + "c" * 64,
        "legacy_writer_started_at": "start",
        "legacy_writer_generation": 0,
        "maintenance_receipt_sha256": "3" * 64,
        "native_receipt_sha256": "4" * 64,
        "fence_epoch": "7", "migration_set_sha256": "5" * 64,
        "enable_login_sql_sha256": "6" * 64,
        **{field: compose.file_sha256(compose.ROOT / "scripts/sql" / filename)
           for field, filename in compose.TRANSITION_SQL_FILES.items()},
        "production_snapshot_sha256": "7" * 64,
        "production_attachments_sha256": "8" * 64,
        "build_only_artifacts": {
            f"MARTY_{name}_{field}": (
                f"https://example.test/{name.lower()}.whl" if field == "URI"
                else "sha256:" + "9" * 64)
            for name in ("COMMON", "RS", "VERIFICATION", "ISO18013")
            for field in ("URI", "DIGEST")},
        "docs_image": "sha256:" + "a" * 64,
    }
    intent = {
        "schema": "marty.passport-beta-db-maintenance-plan/v1",
        "source_commit": head, "stop_container_ids": stops,
        "postgres_system_identifier": "100", "database_oid": "200",
        "beta_generation": generation,
        "cutover_snapshot_file_sha256": handoff["cutover_snapshot_file_sha256"],
        "cutover_snapshot_sha256": handoff["cutover_snapshot_sha256"],
        "cutover_report_file_sha256": handoff["cutover_report_file_sha256"],
        "cutover_report_run_id": handoff["cutover_report_run_id"],
        "legacy_writer_container_id": handoff["legacy_writer_container_id"],
        "legacy_writer_image_digest": handoff["legacy_writer_image_digest"],
        "legacy_writer_started_at": handoff["legacy_writer_started_at"],
        "legacy_writer_generation": handoff["legacy_writer_generation"],
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
    services["openbao"]["networks"] = {
        "marty-network": None, "passport-callback-signing": None}
    services["passport-beta-bureau"]["networks"] = {
        "marty-network": None, "passport-callback-signing": None}
    services["issuance"] = {
        "image": services_image,
        "entrypoint": ["/usr/local/bin/marty-issuance-service"],
        "command": [],
    }
    services["issuance-migrations"] = {
        "image": services_image,
        "entrypoint": ["/usr/local/bin/marty-issuance-service"],
        "command": ["verify-owned-schema"],
        "environment": {
            "SERVICE_NAME": "issuance_native",
            "DATABASE_URL": "postgresql://marty:synthetic@postgres:5432/marty",
        },
        "depends_on": {
            "organization": {"condition": "service_healthy"},
            "credential-template": {"condition": "service_healthy"},
        },
    }
    services["auth"]["environment"].update({
        "UI_BASE_URL": BETA_ORIGIN,
        "UI_ADDITIONAL_BASE_URLS": "",
        "OIDC_EXTERNAL_ISSUER_URL": BETA_ORIGIN + "/realms/11id",
        "OIDC_REDIRECT_URI": BETA_ORIGIN + "/v1/auth/callback",
        "OIDC_POST_LOGOUT_REDIRECT_URI": BETA_ORIGIN + "/",
    })
    services["gateway"]["environment"]["ISSUER_BASE_URL"] = BETA_ORIGIN
    services["gateway"]["ports"] = [{"host_ip": "127.0.0.1", "target": 8000,
                                      "published": "8000", "protocol": "tcp"}]
    services["gateway"]["environment"]["CORS_ORIGINS"] = (
        BETA_ORIGIN + ",http://localhost:9080,http://localhost:3000,http://localhost:5173")
    services["flow"]["environment"]["PUBLIC_BASE_URL"] = BETA_ORIGIN
    services["signing-keys"]["environment"]["PUBLIC_DOMAIN"] = "beta.elevenidllc.com"
    services["issuance"]["environment"] = {
        "ISSUER_BASE_URL": BETA_ORIGIN,
        "SERVICE_NAME": "issuance_native",
        "MARTY_SCHEMA_STARTUP_MODE": "validate",
        "CANVAS_MIRROR_WORKER_ENABLED": "false",
    }
    services["keycloak"]["environment"] = {
        "KC_HOSTNAME": BETA_ORIGIN, "PUBLIC_DOMAIN": "beta.elevenidllc.com",
        "UI_BASE_URL": BETA_ORIGIN,
    }
    services["nginx-proxy"]["environment"] = {
        "PUBLIC_DOMAIN": "beta.elevenidllc.com", "GATEWAY_UPSTREAM": "gateway:8000",
    }
    rendered = {"name": "elevenid-beta", "services": services,
                "networks": {
                    "marty-network": {"name": "elevenid-beta-network"},
                    "passport-callback-signing": {
                        "name": "elevenid-beta-passport-callback-signing",
                        "internal": True}}}
    ui = {"name": "elevenid-beta-ui", "services": {
        "ui-prod": {"image": handoff["ui_image"]}},
        "networks": {"default": {"external": True,
                                 "name": "elevenid-beta-network"}}}
    return handoff, intent, rendered, ui


def test_rendered_compose_assigns_signed_rust_start_groups():
    plan = prepare(*candidate())
    assert plan["schema"] == "marty.passport-beta-aggregate-compose-plan/v1"
    assert plan["beta_origin"] == BETA_ORIGIN
    assert plan["schema_startup_mode"] == "validate"
    assert "gateway" in plan["recreate_applications"]
    assert "cloudflared" in plan["restart_ingress_last"]
    assert "flow" in plan["recreate_applications"]
    assert "postgres" not in plan["target_services"]
    assert plan["preserved_infrastructure"] == ["openbao"]
    assert "openbao" not in plan["restart_infrastructure"]
    assert plan["ui_project"] == "elevenid-beta-ui"


def test_aggregate_rejects_a_separate_python_issuance_image():
    handoff, intent, rendered, ui = candidate()
    handoff["issuance_image"] = (
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "e" * 64
    )
    with pytest.raises(ComposePlanError, match="image identities"):
        prepare(handoff, intent, rendered, ui)


@pytest.mark.parametrize("field", compose.TRANSITION_SQL_FILES)
def test_rust_owner_plan_rejects_changed_protected_sql(field):
    handoff, intent, rendered, ui = candidate()
    handoff[field] = "0" * 64
    with pytest.raises(ComposePlanError, match="Rust owner SQL changed"):
        prepare(handoff, intent, rendered, ui)


@pytest.mark.parametrize("service,key,value", [
    ("gateway", "ISSUER_BASE_URL", "https://prod.elevenidllc.com"),
    ("flow", "PUBLIC_BASE_URL", "https://prod.elevenidllc.com"),
    ("auth", "OIDC_REDIRECT_URI", "https://prod.elevenidllc.com/v1/auth/callback"),
    ("auth", "UI_ADDITIONAL_BASE_URLS", "https://prod.elevenidllc.com"),
    ("gateway", "CORS_ORIGINS", "https://beta.elevenidllc.com,https://prod.elevenidllc.com"),
    ("keycloak", "KC_HOSTNAME", "https://prod.elevenidllc.com"),
    ("nginx-proxy", "GATEWAY_UPSTREAM", "prod-gateway:8000"),
    ("signing-keys", "PUBLIC_DOMAIN", "prod.elevenidllc.com"),
    ("issuance", "ISSUER_BASE_URL", "https://prod.elevenidllc.com"),
    ("credential-template", "PUBLIC_API_URL", "https://prod.elevenidllc.com"),
])
def test_rendered_beta_origin_rejects_other_destination(service, key, value):
    handoff, intent, rendered, ui = candidate()
    rendered["services"][service].setdefault("environment", {})[key] = value
    with pytest.raises(ComposePlanError, match="origin|domain"):
        prepare(handoff, intent, rendered, ui)


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


def test_private_gateway_cannot_start_with_public_host_port():
    handoff, intent, rendered, ui = candidate()
    rendered["services"]["gateway"]["ports"][0]["host_ip"] = "0.0.0.0"
    with pytest.raises(ComposePlanError, match="Gateway must bind only"):
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
    monkeypatch.setenv("MARTY_COMMON_DIGEST", "sha256:" + "f" * 64)
    monkeypatch.setenv("MARTY_DOCS_IMAGE", "sha256:" + "f" * 64)
    monkeypatch.setattr(compose, "ROOT", tmp_path)
    monkeypatch.setattr(compose, "COMPOSE_FILES", ("base.yml", "passport.yml"))
    monkeypatch.setattr(compose, "UI_COMPOSE_FILE", "ui.yml")
    monkeypatch.setattr(compose, "ENV_FILES", ("tunnel.env", "generated.env"))
    for name in (*compose.COMPOSE_FILES, compose.UI_COMPOSE_FILE, *compose.ENV_FILES):
        (tmp_path / name).write_text("test\n", encoding="utf-8")
    commands = []
    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        if "--hash" in command:
            return SimpleNamespace(returncode=0,
                                   stdout=f"{command[-1]} {'0' * 64}\n", stderr="")
        payload = ui if "elevenid-beta-ui" in command else beta
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(compose.subprocess, "run", fake_run)
    rendered, ui_rendered, evidence = compose.render_candidate(handoff)
    assert rendered == beta and ui_rendered == ui
    assert commands[0][0][-5:] == ["-f", "-", "config", "--format", "json"]
    assert commands[0][1]["input"] == evidence["image_override"]
    assert commands[0][1]["env"]["MARTY_SERVICES_IMAGE"] == handoff["services_image"]
    assert commands[1][1]["env"]["MARTY_UI_RELEASE_IMAGE"] == handoff["ui_image"]
    assert commands[0][1]["env"]["MARTY_COMMON_DIGEST"] == (
        handoff["build_only_artifacts"]["MARTY_COMMON_DIGEST"])
    assert commands[0][1]["env"]["MARTY_DOCS_IMAGE"] == handoff["docs_image"]
    assert set(evidence["compose_files_sha256"]) == {"base.yml", "passport.yml"}
    assert evidence["service_config_hashes"]["flow"] == "0" * 64


def test_render_recheck_rejects_environment_drift(monkeypatch):
    handoff, intent, beta, ui = candidate()
    plan = prepare(handoff, intent, beta, ui)
    plan.update({key: "a" for key in compose.RENDER_EVIDENCE})
    monkeypatch.setattr(compose, "protected_source", lambda _runner: handoff["source_commit"])
    monkeypatch.setattr(compose, "PROTECTED_FILES", ())
    monkeypatch.setattr(compose, "render_candidate", lambda _: (
        beta, ui, {key: "b" for key in compose.RENDER_EVIDENCE}))
    monkeypatch.setattr(compose, "validate_model", lambda *_args, **_kwargs: None)
    with pytest.raises(ComposePlanError, match="render or input changed"):
        compose.verify_render_plan(plan)


def test_render_recheck_rejects_rotated_invalid_credentials(monkeypatch):
    handoff, intent, beta, ui = candidate()
    plan = prepare(handoff, intent, beta, ui)
    plan.update({key: "a" for key in compose.RENDER_EVIDENCE})
    monkeypatch.setattr(compose, "protected_source", lambda _runner: handoff["source_commit"])
    monkeypatch.setattr(compose, "PROTECTED_FILES", ())
    monkeypatch.setattr(compose, "render_candidate", lambda _: (
        beta, ui, {key: "a" for key in compose.RENDER_EVIDENCE}))
    def invalid_credentials(_model, **_kwargs):
        raise ValueError("Beta operator credential isolation is invalid")
    monkeypatch.setattr(compose, "validate_model", invalid_credentials)
    with pytest.raises(ValueError, match="credential isolation"):
        compose.verify_render_plan(plan)


def test_render_recheck_requires_protected_source(monkeypatch):
    handoff, intent, beta, ui = candidate()
    plan = prepare(handoff, intent, beta, ui)
    monkeypatch.setattr(compose, "protected_source", lambda _runner: "0" * 40)
    with pytest.raises(ComposePlanError, match="source changed"):
        compose.verify_render_plan(plan)


def test_preserved_openbao_token_matches_new_signer_without_exposing_it(monkeypatch):
    handoff, intent, beta, ui = candidate()
    plan = prepare(handoff, intent, beta, ui)
    beta["services"]["passport-callback-signer"]["environment"]["BAO_TOKEN"] = "secret"
    monkeypatch.setattr(compose, "verify_render_plan", lambda _: {"verified": True})
    monkeypatch.setattr(compose, "render_candidate", lambda _: (beta, ui, {}))
    monkeypatch.setattr(compose, "inspect", lambda _id, _runner: {
        "Id": plan["old_container_ids_by_service"]["openbao"],
        "Config": {"Env": ["BAO_DEV_ROOT_TOKEN_ID=secret"]},
    })
    assert compose.verify_preserved_openbao_token(plan)["verified"] is True
    beta["services"]["passport-callback-signer"]["environment"]["BAO_TOKEN"] = "wrong"
    with pytest.raises(ComposePlanError, match="differs from preserved OpenBao"):
        compose.verify_preserved_openbao_token(plan)


def test_resume_accepts_partial_signed_generation_after_login(monkeypatch, tmp_path):
    handoff, intent, rendered, ui = candidate()
    plan = prepare(handoff, intent, rendered, ui)
    plan["service_config_hashes"] = {name: "0" * 64 for name in
                                     compose.SIGNED_APPLICATIONS | {"issuance"}}
    for item in intent["beta_generation"]:
        item.update({"image_id": "sha256:" + "e" * 64, "started_at": "start"})
    records = {}
    for service in ("postgres", "openbao"):
        container_id = plan["old_container_ids_by_service"][service]
        records[container_id] = {
            "Id": container_id, "Image": "sha256:" + "e" * 64,
            "Config": {"Labels": {"com.docker.compose.project": "elevenid-beta",
                                  "com.docker.compose.service": service}},
            "State": {"StartedAt": "start", "Running": True, "Status": "running"},
            "NetworkSettings": {"Networks": (
                {"elevenid-beta-network": {},
                 "elevenid-beta-passport-callback-signing": {}}
                if service == "openbao" else {"elevenid-beta-network": {}})},
        }
    new_flow_id = "f" * 64
    records[new_flow_id] = {
        "Id": new_flow_id,
        "Config": {"Image": plan["services_image"],
                   "Env": ["SERVICE_NAME=flow"] + [
                       f"{key}={value}" for key, value in compose.RUNTIME_ENV["flow"].items()],
                   "Labels": {"com.docker.compose.project": "elevenid-beta",
                              "com.docker.compose.service": "flow",
                              "com.docker.compose.config-hash": "0" * 64}},
        "State": {"Running": True, "Status": "running"},
        "NetworkSettings": {"Networks": {"elevenid-beta-network": {}}},
    }
    monkeypatch.setattr(compose, "verify_render_plan", lambda _: {"verified": True})
    monkeypatch.setattr(compose, "render_candidate", lambda _: (rendered, ui, {}))
    monkeypatch.setattr(compose, "manifest_source", lambda *_, **__: {
        "manifest_sha256": plan["stack_manifest_sha256"],
        "services_image": plan["services_image"],
        "issuance_image": plan["services_image"],
        "oci_digests": {"ghcr.io/elevenid/marty-ui-oss/ui": "sha256:" + "d" * 64},
    })
    receipt_hashes = {"fence": plan["fence_receipt_sha256"],
                      "maintenance": plan["maintenance_receipt_sha256"],
                      "native": plan["native_receipt_sha256"],
                      "maintenance.intent.json": "0" * 64,
                      "passport-beta-db-enable-app-login.sql":
                          plan["enable_login_sql_sha256"]}
    receipt_hashes.update({filename: plan[field]
                           for field, filename in compose.TRANSITION_SQL_FILES.items()})
    snapshot_path = tmp_path / "cutover-snapshot.json"
    snapshot_path.write_text("{}", encoding="utf-8")
    report_path = tmp_path / "cutover-report.json"
    report_path.write_text("{}", encoding="utf-8")
    receipt_hashes[snapshot_path.name] = plan["cutover_snapshot_file_sha256"]
    receipt_hashes[report_path.name] = plan["cutover_report_file_sha256"]
    intent["cutover_snapshot_path"] = str(snapshot_path)
    intent["cutover_report_path"] = str(report_path)
    monkeypatch.setattr(compose, "file_sha256", lambda path: receipt_hashes[path.name])
    (tmp_path / "maintenance").write_text(json.dumps({
        "schema": "marty.passport-beta-db-maintenance-start/v1",
        "source_commit": plan["source_commit"], "intent_sha256": "0" * 64,
        "production_snapshot_sha256": plan["production_snapshot_sha256"],
        "production_attachments_sha256": plan["production_attachments_sha256"],
        "postgres_container_id": plan["postgres_container_id"],
        "fence_epoch": plan["fence_epoch"],
        "stopped_container_ids": intent["stop_container_ids"],
        **{field: plan[field] for field in (
            "cutover_snapshot_file_sha256", "cutover_snapshot_sha256",
            "cutover_report_file_sha256", "cutover_report_run_id",
            "legacy_writer_container_id", "legacy_writer_image_digest",
            "legacy_writer_started_at", "legacy_writer_generation")},
    }), encoding="utf-8")
    (tmp_path / "native").write_text(json.dumps({
        "schema": "marty.passport-beta-native-db-gates/v1",
        "source_commit": plan["source_commit"],
        "maintenance_receipt_sha256": plan["maintenance_receipt_sha256"],
        "production_snapshot_sha256": plan["production_snapshot_sha256"],
        "postgres_container_id": plan["postgres_container_id"],
        "fence_epoch": plan["fence_epoch"],
        "migration_set_sha256": plan["migration_set_sha256"],
        "stopped_container_ids": intent["stop_container_ids"],
        "app_login_enabled": False,
    }), encoding="utf-8")
    monkeypatch.setattr(compose, "run", lambda command: (
        "desktop-linux" if command[1] == "context" else "daemon"))
    intent["docker"] = {"context": "desktop-linux", "daemon_id": "daemon"}
    intent["postgres_container_id"] = plan["postgres_container_id"]
    intent["fence_epoch"] = plan["fence_epoch"]
    monkeypatch.setattr(compose, "production_snapshot", lambda _: {
        "sha256": plan["production_snapshot_sha256"]})
    monkeypatch.setattr(compose, "production_attachment_sha256", lambda _: (
        plan["production_attachments_sha256"]))
    monkeypatch.setattr(compose, "inspect", lambda container_id, _: records[container_id])
    monkeypatch.setattr(compose, "ids", lambda project, _: (
        list(records) if project == "elevenid-beta" else []))
    monkeypatch.setattr(compose, "beta_psql", lambda query, *_: (
        "fully_fenced" if query.startswith("SELECT phase") else
        f"{plan['fence_epoch']}|{plan['source_commit']}|"
        f"{plan['migration_set_sha256']}|true|false"))
    monkeypatch.setattr(compose, "verify_fence", lambda *_: None)
    evidence = compose.verify_resume_plan(plan, intent, tmp_path / "stack",
                                          tmp_path / "fence", tmp_path / "maintenance",
                                          tmp_path / "native")
    assert evidence["app_login_enabled"] is True
    assert evidence["ready_services"] == ["flow"]
    monkeypatch.setattr(compose, "beta_psql", lambda query, *_: (
        "rust_owner" if query.startswith("SELECT phase") else
        f"{plan['fence_epoch']}|{plan['source_commit']}|"
        f"{plan['migration_set_sha256']}|true|false"))
    monkeypatch.setattr(rust_owner, "verify", lambda *_args, **_kwargs: {
        "verified": True, "transition_txid": "9"})
    resumed_owner = compose.verify_resume_plan(plan, intent, tmp_path / "stack",
                                               tmp_path / "fence",
                                               tmp_path / "maintenance",
                                               tmp_path / "native")
    assert resumed_owner["passport_phase"] == "rust_owner"
    assert resumed_owner["rust_owner"]["transition_txid"] == "9"
    records[new_flow_id]["NetworkSettings"]["Networks"] = {}
    disconnected = compose.verify_resume_plan(plan, intent, tmp_path / "stack",
                                              tmp_path / "fence",
                                              tmp_path / "maintenance",
                                              tmp_path / "native")
    assert disconnected["ready_services"] == []
    records[new_flow_id]["NetworkSettings"]["Networks"] = {
        "elevenid-beta-network": {}}
    changed = {**plan, "production_attachments_sha256": "9" * 64}
    with pytest.raises(ComposePlanError, match="receipt lineage changed"):
        compose.verify_resume_plan(changed, intent, tmp_path / "stack",
                                   tmp_path / "fence", tmp_path / "maintenance",
                                   tmp_path / "native")
    changed = {**plan, "restart_infrastructure": sorted(
        set(plan["restart_infrastructure"]) | {"flow"}),
        "recreate_applications": [name for name in plan["recreate_applications"]
                                  if name != "flow"]}
    with pytest.raises(ComposePlanError, match="startup groups differ"):
        compose.verify_resume_plan(changed, intent, tmp_path / "stack",
                                   tmp_path / "fence", tmp_path / "maintenance",
                                   tmp_path / "native")
    records[new_flow_id]["Config"]["Labels"]["com.docker.compose.config-hash"] = "9" * 64
    with pytest.raises(ComposePlanError, match="Compose service config differs"):
        compose.verify_resume_plan(plan, intent, tmp_path / "stack",
                                   tmp_path / "fence", tmp_path / "maintenance",
                                   tmp_path / "native")
    records[new_flow_id]["Config"]["Labels"]["com.docker.compose.config-hash"] = "0" * 64
    records[plan["old_container_ids_by_service"]["flow"]] = {
        "Id": plan["old_container_ids_by_service"]["flow"],
        "Config": {"Image": "old", "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": "flow"}},
        "State": {"Running": True, "Status": "running"},
        "NetworkSettings": {"Networks": {"elevenid-beta-network": {}}},
    }
    with pytest.raises(ComposePlanError, match="old beta application restarted"):
        compose.verify_resume_plan(plan, intent, tmp_path / "stack",
                                   tmp_path / "fence", tmp_path / "maintenance",
                                   tmp_path / "native")
