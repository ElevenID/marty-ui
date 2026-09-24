"""Pure comparator mutation tests; actual Compose rendering is a separate gate."""

from copy import deepcopy
import hashlib
from pathlib import Path
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_selfhost_native_owner_compose.py"))


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


@pytest.fixture
def models():
    # Small independently spelled models test the comparator, not Compose.
    before = {
        "services": {
            "issuance": {
                "environment": {
                    "ISSUANCE_AUTH_SESSION_TTL_MINUTES": GATE["SHARED_SETTINGS"][
                        "ISSUANCE_AUTH_SESSION_TTL_MINUTES"
                    ],
                    "ENVIRONMENT": "production",
                    "BAO_ADDR": "legacy",
                    "TOKEN_HMAC_KEY_FILE": "/run/secrets/token",
                },
                "secrets": [{"source": "token"}, {"source": "openbao_service_token"}],
            },
            "gateway": {
                "environment": {"ISSUANCE_SERVICE_URL": "http://issuance:8005"},
                "depends_on": {},
            },
            "flow": {
                "environment": {"ISSUANCE_GRPC_TARGET": "issuance:9005"},
                "secrets": [],
            },
        },
        "volumes": {"preserved": {}},
    }
    after = deepcopy(before)
    after["services"]["flow"]["environment"].update(
        ISSUANCE_GRPC_TARGET="issuance-native:9005",
        ISSUANCE_API_KEY_FILE="/run/secrets/issuance_api_key",
        SIGNING_KEYS_INTERNAL_API_KEY_FILE="/run/secrets/issuance_api_key",
    )
    after["services"]["flow"]["secrets"].append(
        {"source": "issuance_api_key", "target": "/run/secrets/issuance_api_key"}
    )
    after["x-issuance-application-env"] = {
        "ENVIRONMENT": "production",
        "TOKEN_HMAC_KEY_FILE": "/run/secrets/token",
        **GATE["SHARED_SETTINGS"],
    }
    after["services"]["issuance"]["environment"].update(
        GATE["SHARED_ADDITIONS"]
    )
    after["services"]["gateway"]["environment"].update(
        ISSUANCE_NATIVE_SERVICE_URL="http://issuance-native:8005",
        GATEWAY_REQUIRED_READY_SERVICES=GATE["READY"],
        SIGNING_KEYS_SERVICE_URL="http://signing-keys:8017",
    )
    after["services"]["gateway"]["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    after["services"]["issuance-native"] = {
        "build": {
            "context": ".",
            "dockerfile": "services/Dockerfile",
            "args": {"SERVICE_NAME": "issuance-native"},
        },
        "entrypoint": ["/app/services/entrypoint.sh"],
        "command": [],
        "environment": {
            "ENVIRONMENT": "production",
            "TOKEN_HMAC_KEY_FILE": "/run/secrets/token",
            **GATE["SHARED_SETTINGS"],
            "SERVICE_NAME": "issuance_native",
            "ISSUANCE_GRPC_ENABLED": "true",
            "RP_GRPC_TARGET": "revocation-profile:9013",
            **GATE["NATIVE_ADDITIVE"],
        },
        "secrets": [{"source": "token"}],
        "depends_on": {
            name: {"condition": condition, "required": True}
            for name, condition in [
                ("db-migrate", "service_completed_successfully"),
                ("issuance-migrations", "service_completed_successfully"),
                ("postgres", "service_healthy"),
                ("signing-keys", "service_healthy"),
                ("revocation-profile", "service_healthy"),
            ]
        },
        "healthcheck": {
            "test": ["CMD", "curl", "--fail", "http://localhost:8005/health"],
            "interval": "10s",
            "timeout": "5s",
            "retries": 3,
        },
        "restart": "unless-stopped",
        "networks": {"default": None},
    }
    GATE["assert_models"](before, after)
    return before, after


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
        after["services"][
            "issuance" if fault == "legacy" else "issuance-native"
        ]["environment"][setting] = "changed"
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
