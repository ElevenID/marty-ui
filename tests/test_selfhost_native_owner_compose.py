"""Mutation tests against the frozen and current rendered self-host models."""

from copy import deepcopy
import hashlib
from pathlib import Path
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_selfhost_native_owner_compose.py"))


def test_selfhost_openbao_requires_transactional_raft_storage():
    config = (ROOT / "docker/openbao-selfhost.hcl").read_text(encoding="utf-8")
    bootstrap = (ROOT / "docker/openbao-selfhost-init.sh").read_text(encoding="utf-8")
    assert 'storage "raft" {' in config
    assert 'storage "file" {' not in config
    assert "bao operator raft list-peers" in bootstrap


def test_reference_identity_and_descriptor_closure():
    GATE["assert_input_inventory"]()
    data = (ROOT / GATE["FROZEN"]).read_text(encoding="utf-8").encode()
    assert (
        hashlib.sha256(data).hexdigest()
        == "5c643478422ecb9f71bb9bd3133af55805e91b184bd8f3c84852fafd418905f8"
    )
    import json

    descriptor = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert "docker-compose.service.issuance-native-runtime.yml" in descriptor["assets"]


@pytest.fixture(scope="module")
def rendered_models():
    # Compare the reviewed frozen source to the current complete Rust model.
    render = GATE["GATE"]["render"]
    before = render(GATE["FROZEN"])
    after = render(GATE["GATE"]["BASE"])
    GATE["assert_models"](before, after)
    return before, after


@pytest.fixture
def models(rendered_models):
    return deepcopy(rendered_models)

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


@pytest.mark.parametrize("fault", ["token-path", "secret-source", "missing-secret"])
def test_production_migration_notification_identity_is_closed(models, fault):
    before, after = models
    migration = after["services"]["db-migrate"]
    if fault == "token-path":
        migration["environment"]["NOTIFICATION_OPENBAO_TOKEN_FILE"] = "/other"
    elif fault == "secret-source":
        migration["secrets"][-1]["source"] = "openbao_service_token"
    else:
        migration["secrets"].pop()
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
