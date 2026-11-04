"""Mutation tests against the approved KMS-only self-host model."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import runpy
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_selfhost_native_owner_compose.py"))


def test_selfhost_runtime_disallows_insecure_grpc_override():
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    assert model["x-runtime-env"]["GRPC_INSECURE_ALLOWED"] == "false"
    for name, service in model["services"].items():
        environment = service.get("environment", {})
        if isinstance(environment, dict) and "GRPC_INSECURE_ALLOWED" in environment:
            assert environment["GRPC_INSECURE_ALLOWED"] == "false", name


def test_auth_login_uses_bootstrapped_organization_issuer_did():
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    services = model["services"]
    expected = (
        "${MARTY_ISSUER_DID:-did:web:${PUBLIC_DOMAIN:?PUBLIC_DOMAIN must be set}:orgs:"
        "${MARTY_ORG_SLUG:-marty}}"
    )
    assert services["auth"]["environment"]["CREDENTIAL_LOGIN_ISSUER_DID"] == expected
    assert services["flow"]["environment"]["OID4VP_ISSUER_DID"] == expected


@pytest.mark.parametrize("owner,setting", [
    ("auth", "CREDENTIAL_LOGIN_ISSUER_DID"),
    ("flow", "OID4VP_ISSUER_DID"),
    ("issuance-native", "MARTY_ISSUER_DID"),
])
def test_preservation_gate_rejects_issuer_identity_drift(rendered_models, owner, setting):
    approved, current = deepcopy(rendered_models)
    current["services"][owner]["environment"][setting] = "did:web:unreviewed.example"
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


def test_flow_waits_for_both_issuance_peers_without_a_startup_cycle():
    # Flow's physical-document health check contacts Issuance at startup.
    # A restored Compose up can otherwise leave Issuance Created while Flow
    # restarts, blocking Auth, Gateway and Edge behind Flow health.
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    services = model["services"]
    flow_dependencies = services["flow"]["depends_on"]
    for peer in ("issuance", "issuance-native"):
        assert flow_dependencies[peer] == {"condition": "service_healthy"}
    for peer in ("issuance", "issuance-native"):
        pending = [peer]
        visited = set()
        while pending:
            service = pending.pop()
            if service in visited:
                continue
            visited.add(service)
            pending.extend(services[service].get("depends_on", {}))
        assert "flow" not in visited


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell is required")
def test_keycloak_preserves_scoped_openbao_token_file(tmp_path):
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    env = model["services"]["keycloak"]["environment"]
    assert env["BAO_TOKEN_FILE"] == "/run/secrets/keycloak_signing_kms_token"
    assert "BAO_TOKEN" not in env
    assert env["KC_HOSTNAME"] == "https://${PUBLIC_DOMAIN:-localhost}"
    assert "PRESERVE_BAO_TOKEN_FILE=1" in (
        ROOT / "scripts/keycloak-selfhost-start.sh"
    ).read_text()
    token_file = tmp_path / "token"
    token_file.write_text("synthetic-scoped-token", encoding="ascii")
    result = subprocess.run(
        ["sh", "-c", '. "$1"; test -n "$BAO_TOKEN_FILE" && test -z "${BAO_TOKEN:-}"',
         "sh", str(ROOT / "scripts/load-secrets-env.sh")],
        env={"PATH": "/usr/bin:/bin", "BAO_TOKEN_FILE": str(token_file),
             "PRESERVE_BAO_TOKEN_FILE": "1"},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_selfhost_openbao_requires_transactional_raft_storage():
    config = (ROOT / "docker/openbao-selfhost.hcl").read_text(encoding="utf-8")
    bootstrap = (ROOT / "docker/openbao-selfhost-init.sh").read_text(encoding="utf-8")
    assert 'storage "raft" {' in config
    assert 'storage "file" {' not in config
    assert "bao operator raft list-peers" in bootstrap


@pytest.mark.parametrize("changed", [None, "false", "${KEYCLOAK_SETUP_STRICT:-true}"])
def test_ordinary_keycloak_setup_cannot_suppress_configuration_failure(rendered_models, changed):
    approved, current = deepcopy(rendered_models)
    environment = current["services"]["keycloak-configurator"]["environment"]
    assert environment["KEYCLOAK_SETUP_STRICT"] == "true"
    if changed is None:
        del environment["KEYCLOAK_SETUP_STRICT"]
    else:
        environment["KEYCLOAK_SETUP_STRICT"] = changed
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


def test_selfhost_redis_is_socket_only_and_available_to_exact_consumers():
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    services = model["services"]
    assert all("container_name" not in service for service in services.values())
    redis = services["redis"]
    assert redis["command"].split()[0:3] == ["redis-server", "--port", "0"]
    assert "--unixsocket /data/run/redis.sock" in redis["command"]
    assert "--unixsocketperm 777" in redis["command"]
    assert model["volumes"] == {"redis-socket": None}
    consumers = {
        "db-migrate", "kms-initialize", "gateway", "auth", "organization", "signing-keys",
        "flow", "verification", "revocation-profile", "device-registration",
    }
    for name, service in services.items():
        mounts = [item for item in service.get("volumes", [])
                  if isinstance(item, dict) and item.get("source") == "redis-socket"]
        if name == "redis":
            assert len(mounts) == 1 and mounts[0]["target"] == "/data/run"
        elif name in consumers:
            assert len(mounts) == 1 and mounts[0]["target"] == "/run/marty-redis"
            assert mounts[0]["read_only"] is True
            key = "SIGNING_KEYS_REDIS_URL" if name == "signing-keys" else "REDIS_URL"
            assert service["environment"][key].startswith(
                "unix:///run/marty-redis/redis.sock"
            )
        else:
            assert not mounts, name


def test_reference_identity_and_descriptor_closure():
    GATE["assert_input_inventory"]()
    data = (ROOT / GATE["APPROVED"]).read_text(encoding="utf-8").encode()
    assert (
        hashlib.sha256(data).hexdigest()
        == GATE["APPROVED_SHA256"]
    )
    import json

    descriptor = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert "docker-compose.service.issuance-native-runtime.yml" in descriptor["assets"]


def test_required_inputs_preserve_historical_and_current_contracts():
    approved = (ROOT / GATE["APPROVED"]).read_text(encoding="utf-8")
    current = (ROOT / GATE["GATE"]["BASE"]).read_text(encoding="utf-8")
    historical, required = GATE["required_input_sets"](approved, current)
    assert len(historical) == 63
    assert len(required) == 10
    assert "BAO_ADDR" in historical - required
    assert "PUBLIC_DOMAIN" in required


@pytest.mark.parametrize("fault", ["dropped", "added"])
def test_required_inputs_reject_unrelated_changes(fault):
    approved = (ROOT / GATE["APPROVED"]).read_text(encoding="utf-8")
    current = (ROOT / GATE["GATE"]["BASE"]).read_text(encoding="utf-8")
    if fault == "dropped":
        changed, count = re.subn(
            r"\$\{PUBLIC_DOMAIN:\?[^}]*\}", "${PUBLIC_DOMAIN:-}", current
        )
    else:
        changed, count = re.subn(
            r"\$\{MARTY_ORG_SLUG:-[^}]*\}",
            "${MARTY_ORG_SLUG:?unreviewed required input}",
            current,
        )
    assert count > 0
    with pytest.raises(AssertionError, match="Unreviewed required self-host inputs"):
        GATE["required_input_sets"](approved, changed)


@pytest.fixture(scope="module")
def rendered_models():
    # Compare the independently approved KMS-only source to the current model.
    render = GATE["GATE"]["render"]
    before = render(GATE["APPROVED"])
    after = render(GATE["GATE"]["BASE"])
    GATE["assert_models"](before, after)
    return before, after


def test_core_hosting_separates_optional_connectors_from_the_frozen_model(rendered_models):
    approved, current = rendered_models
    for section, names in (
        ("services", {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"}),
        ("secrets", {"cloudflare_tunnel_token", "cloudflare_beta_tunnel_token"}),
    ):
        assert names <= set(approved[section])
        assert not names & set(current[section])
    assert current["services"]["gateway"]["environment"]["GATEWAY_OBSERVE_CLIENT_IP"] == (
        "${GATEWAY_OBSERVE_CLIENT_IP:-true}"
    )


def test_edge_startup_changes_only_reviewed_dependencies_and_health_target(rendered_models):
    approved, current = rendered_models
    original = approved["services"]["edge"]
    selected = current["services"]["edge"]
    assert original["depends_on"] == {
        owner: {"condition": "service_healthy", "required": True}
        for owner in ("ui", "gateway", "flow", "keycloak")
    }
    assert "depends_on" not in selected
    assert original["healthcheck"]["test"] == [
        "CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1/ready",
    ]
    assert selected["healthcheck"] == {
        **original["healthcheck"],
        "test": ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1/edge-healthz"],
    }


@pytest.mark.parametrize("fault", ["dependency", "readiness", "health-command", "health-timing", "port", "mount", "upstream"])
def test_edge_review_does_not_allow_product_gates_or_unrelated_ingress_drift(rendered_models, fault):
    approved, current = deepcopy(rendered_models)
    edge = current["services"]["edge"]
    if fault == "dependency":
        edge["depends_on"] = {"gateway": {"condition": "service_healthy", "required": True}}
    elif fault == "readiness":
        edge["healthcheck"]["test"][-1] = "http://127.0.0.1/ready"
    elif fault == "health-command":
        edge["healthcheck"]["test"] = ["CMD", "true"]
    elif fault == "health-timing":
        edge["healthcheck"]["interval"] = "1s"
    elif fault == "port":
        assert edge["ports"][0].startswith("127.0.0.1:")
        edge["ports"][0] = edge["ports"][0].replace("127.0.0.1:", "0.0.0.0:", 1)
    elif fault == "mount":
        edge["volumes"].pop()
    else:
        edge["environment"]["GATEWAY_UPSTREAM"] = "unreviewed:8000"
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


def test_web_selection_changes_only_the_reviewed_ui_inputs(rendered_models):
    approved, current = rendered_models
    original = approved["services"]["ui"]
    selected = current["services"]["ui"]
    assert "UI_ENABLED_SECTIONS" not in original["environment"]
    assert original["healthcheck"]["test"][-1] == "http://127.0.0.1:80/"
    assert selected["environment"] == {
        **original["environment"],
        "UI_ENABLED_SECTIONS": "${UI_ENABLED_SECTIONS-public,console}",
        "ORGANIZATION_CREATION_ENABLED": "${ORGANIZATION_CREATION_ENABLED:-false}",
    }
    assert selected["healthcheck"] == {
        **original["healthcheck"],
        "test": [*original["healthcheck"]["test"][:-1], "http://127.0.0.1:80/healthz"],
    }


@pytest.mark.parametrize("external_foundation", [False, True])
def test_optional_credentials_have_only_the_existing_consumers(rendered_models, external_foundation):
    _, current = rendered_models
    if external_foundation:
        current = GATE["GATE"]["render"](
            GATE["GATE"]["BASE"],
            "deploy-config/compose/selfhost-installer/compose.aws-foundation.yml",
        )
    for secret, owners in (
        ("passport_tenant_api_keys", {"gateway", "flow", "issuance-native"}),
        ("personalization_bureau_api_key", {"issuance-native"}),
        ("canvas_credentials_api_token", {"issuance", "issuance-native"}),
    ):
        mounted = {name for name, service in current["services"].items()
                   if any(item["source"] == secret for item in service.get("secrets", []))}
        assert mounted == owners
        assert current["secrets"][secret]["file"].endswith("/" + secret)
        setting = secret.upper() + "_FILE"
        for owner in owners:
            service = current["services"][owner]
            environment = GATE["GATE"]["environment_mapping"](service["environment"])
            assert environment[setting] == "${" + setting + ":-}"
            selected = [item for item in service["secrets"] if item["source"] == secret]
            assert len(selected) == 1
            assert selected[0]["target"] in {secret, f"/run/secrets/{secret}"}


def test_passport_credentials_cannot_gain_an_unrelated_consumer(rendered_models):
    approved, current = deepcopy(rendered_models)
    current["services"]["ui"].setdefault("secrets", []).append({
        "source": "passport_tenant_api_keys", "target": "/run/secrets/passport_tenant_api_keys"})
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


@pytest.mark.parametrize("path,replacement", [
    (("environment", "UI_ENABLED_SECTIONS"), None),
    (("environment", "UI_ENABLED_SECTIONS"), "${UI_ENABLED_SECTIONS-none}"),
    (("environment", "UI_ENABLED_SECTIONS"), "${UI_ENABLED_SECTIONS:-public,console}"),
    (("environment", "UI_ENABLED_SECTIONS"), "public,console"),
    (("environment", "ORGANIZATION_CREATION_ENABLED"), None),
    (("environment", "ORGANIZATION_CREATION_ENABLED"), "true"),
    (("environment", "UI_PRODUCTION_MARKETING"), "true"),
    (("healthcheck", "test", -1), "http://127.0.0.1:80/"),
    (("healthcheck", "test", -1), "http://127.0.0.1:80/console"),
    (("healthcheck", "test"), ["CMD-SHELL", "true"]),
    (("healthcheck", "disable"), True),
    (("healthcheck", "interval"), "1h"),
])
def test_web_selection_gate_rejects_defaults_bypass_and_healthcheck_drift(
    rendered_models, path, replacement,
):
    approved, current = deepcopy(rendered_models)
    target = current["services"]["ui"]
    for key in path[:-1]:
        target = target[key]
    if replacement is None:
        del target[path[-1]]
    else:
        target[path[-1]] = replacement
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


def test_web_selection_cannot_change_another_service_environment(rendered_models):
    approved, current = deepcopy(rendered_models)
    current["services"]["gateway"]["environment"]["UI_ENABLED_SECTIONS"] = "none"
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


@pytest.mark.parametrize("fault", ["connector", "token", "gateway-default", "gateway-missing"])
def test_core_hosting_gate_rejects_optional_owner_or_gateway_default_drift(rendered_models, fault):
    approved, current = deepcopy(rendered_models)
    if fault == "connector":
        current["services"]["cloudflared"] = deepcopy(approved["services"]["cloudflared"])
    elif fault == "token":
        current["secrets"]["cloudflare_tunnel_token"] = deepcopy(
            approved["secrets"]["cloudflare_tunnel_token"]
        )
    elif fault == "gateway-default":
        current["services"]["gateway"]["environment"]["GATEWAY_OBSERVE_CLIENT_IP"] = (
            "${GATEWAY_OBSERVE_CLIENT_IP:-false}"
        )
    else:
        del current["services"]["gateway"]["environment"]["GATEWAY_OBSERVE_CLIENT_IP"]
    with pytest.raises(AssertionError, match="Unreviewed self-host model change"):
        GATE["assert_models"](approved, current)


def test_ordinary_migration_cannot_provision_kms(rendered_models):
    _, current = rendered_models
    services = current["services"]
    migration = services["db-migrate"]
    initializer = services["kms-initialize"]
    assert migration["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] == "false"
    assert "BAO_TOKEN_FILE" not in migration["environment"]
    assert all(secret["source"] != "openbao_bootstrap_token"
               for secret in migration["secrets"])
    assert initializer["profiles"] == ["kms-init"]
    assert initializer["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] == "true"
    assert initializer["environment"]["BAO_TOKEN_FILE"] == "/run/secrets/openbao_bootstrap_token"
    assert initializer["depends_on"]["db-migrate"]["condition"] == "service_completed_successfully"


@pytest.mark.parametrize("missing", ["environment", "mount"])
def test_issuance_alias_requires_authenticated_kms_binding(rendered_models, missing):
    approved, current = deepcopy(rendered_models)
    issuance = current["services"]["issuance"]
    if missing == "environment":
        del issuance["environment"]["SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE"]
    else:
        issuance["secrets"] = [
            secret
            for secret in issuance["secrets"]
            if secret["source"] != "signing_keys_integration_secret_key"
        ]
    with pytest.raises(AssertionError):
        GATE["assert_models"](approved, current)


@pytest.fixture
def models(rendered_models):
    return deepcopy(rendered_models)


@pytest.mark.parametrize("fault", ["raw-environment", "raw-secret-mount"])
def test_approved_model_rejects_return_of_raw_master_key(models, fault):
    approved, current = models
    for model in (approved, current):
        if fault == "raw-environment":
            model["services"]["issuance"]["environment"][
                "INTEGRATION_SECRET_MASTER_KEY_FILE"
            ] = "/run/secrets/integration_secret_master_key"
        else:
            model["secrets"]["integration_secret_master_key"] = {
                "file": "/synthetic/integration_secret_master_key"
            }
            model["services"]["issuance"]["secrets"].append(
                {"source": "integration_secret_master_key"}
            )
    with pytest.raises(AssertionError):
        GATE["assert_models"](approved, current)


def test_approved_model_rejects_workload_tls_private_key_even_if_snapshotted(models):
    approved, current = models
    for model in (approved, current):
        model["services"]["flow"]["environment"]["GRPC_WORKLOAD_TLS_SERVER_KEY"] = (
            "/run/secrets/flow_workload_server_key"
        )
    with pytest.raises(AssertionError):
        GATE["assert_models"](approved, current)


@pytest.mark.parametrize(
    "field",
    [
        "build",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "depends_on",
        "healthcheck",
        "restart",
        "networks",
    ],
)
def test_every_native_field_is_closed(models, field):
    before, after = models
    after["services"]["issuance-native"][field] = "changed"
    with pytest.raises(AssertionError):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "owner,key",
    [
        (owner, key)
        for owner, additions in GATE["PASSPORT_CONSUMER_ADDITIVE"].items()
        for key in additions
    ],
)
def test_passport_consumer_additions_are_closed(models, owner, key):
    before, after = models
    after["services"][owner]["environment"][key] = "unreviewed"
    with pytest.raises(AssertionError):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "fault",
    [
        "token-path",
        "secret-source",
        "missing-secret",
        "bootstrap-token-path",
        "bootstrap-secret-source",
        "bootstrap-secret-missing",
    ],
)
def test_production_migration_kms_identities_are_closed(models, fault):
    before, after = models
    migration = after["services"]["db-migrate"]
    if fault == "token-path":
        migration["environment"]["NOTIFICATION_OPENBAO_TOKEN_FILE"] = "/other"
    elif fault == "secret-source":
        migration["secrets"][-1]["source"] = "openbao_service_token"
    elif fault == "missing-secret":
        migration["secrets"].pop()
    elif fault == "bootstrap-token-path":
        migration["environment"]["BAO_TOKEN_FILE"] = "/run/secrets/openbao_service_token"
    elif fault == "bootstrap-secret-source":
        migration["secrets"][-2]["source"] = "openbao_service_token"
    else:
        migration["secrets"].pop(-2)
    with pytest.raises((AssertionError, KeyError, IndexError)):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "fault",
    ["issuance-key", "signing-key", "mount", "unpaired", "physical", "token", "tls"],
)
def test_flow_selection_preserves_secret_identity_and_sibling_transports(models, fault):
    before, after = models
    flow = after["services"]["flow"]
    if fault in {"issuance-key", "signing-key"}:
        key = (
            "ISSUANCE_API_KEY_FILE"
            if fault == "issuance-key"
            else "SIGNING_KEYS_INTERNAL_API_KEY_FILE"
        )
        flow["environment"].pop(key)
    elif fault == "mount":
        flow["secrets"][0]["source"] = "unowned"
    elif fault == "unpaired":
        flow["environment"]["SIGNING_KEYS_INTERNAL_API_KEY_FILE"] = "/run/secrets/other"
    elif fault == "physical":
        flow["environment"]["ISSUANCE_SERVICE_URL"] = "http://issuance-native:8005"
    elif fault == "token":
        flow["environment"]["GRPC_SERVICE_TOKEN"] = "unpaired"
    else:
        flow["environment"]["GRPC_WORKLOAD_TLS_CA_CERT"] = "/unowned.pem"
    with pytest.raises((AssertionError, KeyError)):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "fault",
    ["flow", "legacy", "volume", "gateway", "readiness", "extra-secret", "shared"],
)
def test_siblings_resources_and_secret_boundary_are_closed(models, fault):
    before, after = models
    if fault == "flow":
        after["services"]["flow"]["environment"]["ISSUANCE_GRPC_TARGET"] = (
            "issuance:9005"
        )
    elif fault == "legacy":
        after["services"]["issuance"]["environment"].pop("BAO_ADDR")
    elif fault == "volume":
        after["volumes"] = {}
    elif fault == "gateway":
        after["services"]["gateway"]["environment"]["ISSUANCE_SERVICE_URL"] = (
            "http://issuance-native:8005"
        )
    elif fault == "readiness":
        after["services"]["gateway"]["environment"][
            "GATEWAY_REQUIRED_READY_SERVICES"
        ] = "issuance-native"
    elif fault == "extra-secret":
        after["services"]["issuance-native"]["secrets"].append(
            {"source": "openbao_service_token"}
        )
    else:
        after["x-issuance-application-env"]["BAO_ADDR"] = "legacy"
    with pytest.raises(AssertionError):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize("fault", ["file", "binding", "mount"])
def test_signing_keys_has_a_dedicated_openbao_token(models, fault):
    before, after = models
    if fault == "file":
        after["secrets"]["signing_keys_openbao_token"]["file"] = (
            "/synthetic/openbao_service_token"
        )
    elif fault == "binding":
        after["services"]["signing-keys"]["environment"]["BAO_TOKEN_FILE"] = (
            "/run/secrets/openbao_service_token"
        )
    else:
        after["services"]["signing-keys"]["secrets"][0]["source"] = (
            "openbao_service_token"
        )
    with pytest.raises(AssertionError):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "setting", ["ALLOWED_REDIRECT_URIS", "ISSUANCE_AUTH_SESSION_TTL_MINUTES"]
)
@pytest.mark.parametrize("fault", ["shared", "legacy", "native"])
def test_authorization_settings_are_shared_without_weakening_model_closure(
    models, setting, fault
):
    before, after = models
    if fault == "shared":
        after["x-issuance-application-env"].pop(setting)
    else:
        after["services"]["issuance" if fault == "legacy" else "issuance-native"][
            "environment"
        ][setting] = "changed"
    with pytest.raises((AssertionError, KeyError)):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize("setting", sorted(GATE["PUBLICATION_SETTINGS"]))
@pytest.mark.parametrize("fault", ["shared", "legacy", "native"])
def test_canvas_credentials_publication_controls_are_shared_and_closed(
    models, setting, fault
):
    before, after = models
    if fault == "shared":
        after["x-issuance-application-env"].pop(setting)
    else:
        after["services"]["issuance" if fault == "legacy" else "issuance-native"][
            "environment"
        ][setting] = "hostile-mismatch"
    with pytest.raises((AssertionError, KeyError)):
        GATE["assert_models"](before, after)


def test_ci_runs_preservation_gate_unconditionally():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["test-rust-service-images"]
    assert not job.get("continue-on-error", False)
    steps = [
        step
        for step in job["steps"]
        if step.get("name") == "Verify self-host native owner preservation"
    ]
    assert steps == [
        {
            "name": "Verify self-host native owner preservation",
            "run": "python3 scripts/test_selfhost_native_owner_compose.py",
        }
    ]


@pytest.mark.parametrize(
    "target", [None, "http://localhost:8017", "http://issuance-native:8017"]
)
def test_signing_binding_missing_loopback_and_wrong_owner_are_rejected(models, target):
    before, after = models
    gateway = after["services"]["gateway"]["environment"]
    if target is None:
        gateway.pop("SIGNING_KEYS_SERVICE_URL")
    else:
        gateway["SIGNING_KEYS_SERVICE_URL"] = target
    with pytest.raises((AssertionError, KeyError)):
        GATE["assert_models"](before, after)


@pytest.mark.parametrize(
    "target",
    [
        "http://signing-keys:8017",
        None,
        "http://localhost:8017",
        "http://issuance-native:8017",
    ],
)
def test_signing_dependency_is_derived_from_actual_source_owners(target):
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    gateway = model["services"]["gateway"]["environment"]
    assert gateway["SIGNING_KEYS_SERVICE_URL"] == "http://signing-keys:8017"
    if target is None:
        gateway.pop("SIGNING_KEYS_SERVICE_URL")
    else:
        gateway["SIGNING_KEYS_SERVICE_URL"] = target
    if target == "http://signing-keys:8017":
        GATE["assert_signing_binding"](model)
    else:
        with pytest.raises(AssertionError):
            GATE["assert_signing_binding"](model)
