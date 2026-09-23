"""Parsed source-wiring guards, not native activation or deployed-state proof."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
TARGET = "ISSUANCE_GRPC_TARGET"
PRIVATE = "DIDCOMM_ALLOW_PRIVATE_IPS"
UNUSED_PRIVATE = "DIDCOMM_ALLOW_PRIVATE_ENDPOINTS"
NATIVE_URL = "http://issuance-native:8005"
LEGACY_URL = "http://issuance:8005"


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        assert key not in seen, f"Duplicate YAML mapping key: {key}"
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def load(path):
    return yaml.load((ROOT / path).read_text(), Loader=UniqueKeyLoader)


def load_all(path):
    return list(yaml.load_all((ROOT / path).read_text(), Loader=UniqueKeyLoader))


def source_models():
    documents = load_all("k8s/oracle/07-microservices.yaml")
    config = load("k8s/oracle/01-configmap.yaml")
    base = load("docker-compose.base.yml")
    selfhost = load("docker-compose.selfhost.prod.yml")
    return documents, config, base, selfhost


def resource(documents, kind, name):
    matches = [
        item
        for item in documents
        if item and item["kind"] == kind and item["metadata"]["name"] == name
    ]
    assert len(matches) == 1
    assert matches[0]["metadata"]["namespace"] == "marty-prod"
    return matches[0]


def container(documents, deployment, name):
    pod = resource(documents, "Deployment", deployment)["spec"]["template"]["spec"]
    matches = [item for item in pod["containers"] if item["name"] == name]
    assert len(matches) == 1
    return matches[0]


def environment(item):
    entries = item.get("env", [])
    result = {
        entry["name"]: {key: value for key, value in entry.items() if key != "name"}
        for entry in entries
    }
    assert len(result) == len(entries), "Duplicate explicit container environment"
    return result


def target_key(name):
    return name.endswith("_GRPC_TARGET") or name in {
        "DIDCOMM_DELIVERY_OWNER",
        "ISSUANCE_SERVICE_URL",
        "ISSUANCE_NATIVE_SERVICE_URL",
    }


def assert_kubernetes_bindings(documents, config):
    flow = container(documents, "flow", "flow")
    issuance = container(documents, "issuance", "issuance")
    gateway = container(documents, "gateway", "gateway")
    assert environment(gateway)["SIGNING_KEYS_INTERNAL_API_KEY"] == {
        "valueFrom": {
            "secretKeyRef": {
                "name": "marty-secrets",
                "key": "SIGNING_KEYS_INTERNAL_API_KEY",
            }
        }
    }
    service = resource(documents, "Service", "issuance")
    assert flow["envFrom"] == [{"configMapRef": {"name": "marty-config"}}]
    assert config["metadata"]["name"] == "marty-config"
    assert config["metadata"]["namespace"] == "marty-prod"
    assert {key: value for key, value in config["data"].items() if target_key(key)} == {
        "ISSUANCE_SERVICE_URL": LEGACY_URL,
        "ISSUANCE_NATIVE_SERVICE_URL": LEGACY_URL,
        "ES_GRPC_TARGET": "event-stream:9015",
    }
    assert environment(flow)[TARGET] == {"value": "issuance:9005"}
    assert service["spec"]["ports"] == [
        {"port": 8005, "targetPort": 8005, "name": "http"},
        {"port": 9005, "targetPort": 9005, "name": "grpc"},
    ]
    assert service["spec"]["selector"] == {"app": "issuance"}
    assert issuance["ports"] == [{"containerPort": 8005}, {"containerPort": 9005}]
    assert issuance["image"] == "${MARTY_ISSUANCE_IMAGE}"
    assert "command" not in issuance and "args" not in issuance
    assert not any(
        item and item["metadata"]["name"] == "issuance-native" for item in documents
    )

    # Check exact ownership, including init containers. A same-named value in an
    # unrelated container cannot satisfy the Flow binding. Preserve every other
    # explicit RPC/issuance target and the shared physical-document HTTP alias.
    actual = {}
    for document in documents:
        if not document:
            continue
        pod = document.get("spec", {}).get("template", {}).get("spec", {})
        for kind in ("containers", "initContainers"):
            for item in pod.get(kind, []):
                targets = {
                    key: value
                    for key, value in environment(item).items()
                    if target_key(key)
                }
                if targets:
                    key = (
                        document["kind"],
                        document["metadata"]["name"],
                        kind,
                        item["name"],
                    )
                    assert key not in actual
                    actual[key] = targets
    legacy_alias = {
        "valueFrom": {
            "configMapKeyRef": {"name": "marty-config", "key": "ISSUANCE_SERVICE_URL"}
        }
    }
    native_alias = {
        "valueFrom": {
            "configMapKeyRef": {
                "name": "marty-config",
                "key": "ISSUANCE_NATIVE_SERVICE_URL",
            }
        }
    }
    expected = {
        "gateway": {
            "ISSUANCE_SERVICE_URL": legacy_alias,
            "AUTH_GRPC_TARGET": {"value": "auth:9001"},
        },
        "organization": {"ES_GRPC_TARGET": {"value": "event-stream:9015"}},
        "issuance": {
            "ORG_GRPC_TARGET": {"value": "organization:9002"},
            "CT_GRPC_TARGET": {"value": "credential-template:9003"},
        },
        "verification": {
            "PP_GRPC_TARGET": {"value": "presentation-policy:9009"},
            "ORG_GRPC_TARGET": {"value": "organization:9002"},
            "CT_GRPC_TARGET": {"value": "credential-template:9003"},
        },
        "auth": {"ISSUANCE_NATIVE_SERVICE_URL": native_alias},
        "applicant": {"ISSUANCE_NATIVE_SERVICE_URL": native_alias},
        "presentation-policy": {"ISSUANCE_NATIVE_SERVICE_URL": native_alias},
        "revocation-profile": {"ORG_GRPC_TARGET": {"value": "organization:9002"}},
        "device-registration": {"ORG_GRPC_TARGET": {"value": "organization:9002"}},
        "flow": {
            TARGET: {"value": "issuance:9005"},
            "ISSUANCE_SERVICE_URL": legacy_alias,
            "ISSUANCE_NATIVE_SERVICE_URL": native_alias,
        },
    }
    assert actual == {
        ("Deployment", name, "containers", name): values
        for name, values in expected.items()
    }


def assert_selfhost_bindings(compose):
    services = compose["services"]
    flow = services["flow"]
    for key in ("ISSUANCE_API_KEY_FILE", "SIGNING_KEYS_INTERNAL_API_KEY_FILE"):
        assert flow["environment"][key] == "/run/secrets/issuance_api_key"
    assert flow["secrets"].count("issuance_api_key") == 1
    assert services["issuance-native"]["extends"] == {
        "file": "docker-compose.service.issuance-native-runtime.yml",
        "service": "issuance-native",
    }
    issuance = services["issuance"]
    assert (
        issuance["image"]
        == "${MARTY_ISSUANCE_IMAGE:?set MARTY_ISSUANCE_IMAGE to an immutable issuance image digest}"
    )
    assert issuance["entrypoint"] == ["/bin/sh", "/app/load-openbao-token-and-start.sh"]
    assert issuance["command"] == [
        "python",
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8005",
    ]
    flags = {
        name: {
            key: value
            for key, value in item.get("environment", {}).items()
            if key in {PRIVATE, UNUSED_PRIVATE}
        }
        for name, item in services.items()
    }
    assert {name: values for name, values in flags.items() if values} == {
        "issuance": {PRIVATE: "false"},
        "issuance-native": {PRIVATE: "false"},
    }

    common = "revocation-profile-migrate db-migrate issuance-migrations gateway auth organization credential-template trust-profile issuance applicant notification compliance-profile presentation-policy deployment-profile signing-keys flow verification revocation-profile device-registration event-stream".split()
    expected = {name: {"ES_GRPC_TARGET": "event-stream:9015"} for name in common}
    organization = {"ORG_GRPC_TARGET": "organization:9002"}
    for name in (
        "gateway",
        "auth",
        "credential-template",
        "trust-profile",
        "issuance",
        "applicant",
        "compliance-profile",
        "presentation-policy",
        "deployment-profile",
        "flow",
        "verification",
        "revocation-profile",
        "device-registration",
    ):
        expected[name].update(organization)
    for name in ("issuance", "flow", "verification"):
        expected[name]["CT_GRPC_TARGET"] = "credential-template:9003"
    for name in ("flow", "verification"):
        expected[name]["PP_GRPC_TARGET"] = "presentation-policy:9009"
    for name in ("auth", "applicant"):
        expected[name]["FLOW_GRPC_TARGET"] = "flow:9011"
    expected["gateway"]["ISSUANCE_SERVICE_URL"] = LEGACY_URL
    expected["gateway"]["ISSUANCE_NATIVE_SERVICE_URL"] = NATIVE_URL
    for name in ("auth", "applicant", "presentation-policy"):
        expected[name]["ISSUANCE_SERVICE_URL"] = LEGACY_URL
    expected["flow"]["ISSUANCE_SERVICE_URL"] = LEGACY_URL
    expected["gateway"]["AUTH_GRPC_TARGET"] = "auth:9001"
    expected["flow"][TARGET] = "issuance-native:9005"
    expected["issuance-native"] = {
        "ES_GRPC_TARGET": "event-stream:9015",
        "ORG_GRPC_TARGET": "organization:9002",
        "CT_GRPC_TARGET": "credential-template:9003",
        "RP_GRPC_TARGET": "revocation-profile:9013",
    }
    actual = {
        name: {
            key: value
            for key, value in item.get("environment", {}).items()
            if target_key(key)
        }
        for name, item in services.items()
    }
    assert {name: values for name, values in actual.items() if values} == expected


def assert_compose_owner_split(compose, *, production=False):
    services = compose["services"]
    expected = (
        {
            "gateway": {
                "ISSUANCE_SERVICE_URL": LEGACY_URL,
                "ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL,
            },
            "auth": {"ISSUANCE_SERVICE_URL": LEGACY_URL},
            "applicant": {"ISSUANCE_SERVICE_URL": LEGACY_URL},
            "presentation-policy": {"ISSUANCE_SERVICE_URL": LEGACY_URL},
            "flow": {"ISSUANCE_SERVICE_URL": LEGACY_URL},
        }
        if production
        else {
            "gateway": {
                "ISSUANCE_SERVICE_URL": LEGACY_URL,
                "ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL,
            },
            "auth": {"ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL},
            "applicant": {"ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL},
            "presentation-policy": {"ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL},
            "flow": {
                "ISSUANCE_SERVICE_URL": LEGACY_URL,
                "ISSUANCE_NATIVE_SERVICE_URL": NATIVE_URL,
            },
        }
    )
    actual = {
        name: {
            key: value
            for key, value in service.get("environment", {}).items()
            if key in {"ISSUANCE_SERVICE_URL", "ISSUANCE_NATIVE_SERVICE_URL"}
        }
        for name, service in services.items()
        if name in expected
    }
    assert {name: values for name, values in actual.items() if values} == expected
    if production:
        for name in ("auth", "applicant", "presentation-policy", "flow"):
            assert "issuance" not in services[name]["depends_on"]
            assert "issuance-native" not in services[name]["depends_on"]
        dependency_owners = ("gateway",)
    else:
        for name in ("auth", "applicant", "presentation-policy"):
            assert services[name]["depends_on"].get("issuance-native") == {
                "condition": "service_healthy"
            }
            assert "issuance" not in services[name]["depends_on"]
        dependency_owners = ("gateway", "flow")
    for name in dependency_owners:
        assert services[name]["depends_on"].get("issuance") == {
            "condition": "service_healthy"
        }
        assert services[name]["depends_on"].get("issuance-native") == {
            "condition": "service_healthy"
        }


def test_source_bindings_match_actual_service_and_restrictive_policy():
    documents, config, base, selfhost = source_models()
    assert_kubernetes_bindings(documents, config)
    assert_compose_owner_split(base)
    assert_compose_owner_split(selfhost, production=True)
    assert_selfhost_bindings(selfhost)


@pytest.mark.parametrize("mutation", ["duplicate", "other-reference"])
def test_gateway_retains_exactly_one_unchanged_signing_key_reference(mutation):
    documents, config, _, _ = source_models()
    gateway = container(documents, "gateway", "gateway")
    entry = next(
        entry
        for entry in gateway["env"]
        if entry["name"] == "SIGNING_KEYS_INTERNAL_API_KEY"
    )
    if mutation == "duplicate":
        gateway["env"].append(deepcopy(entry))
    else:
        entry["valueFrom"]["secretKeyRef"]["key"] = "OTHER_SYNTHETIC_KEY"
    with pytest.raises(AssertionError):
        assert_kubernetes_bindings(documents, config)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "wrong-port",
        "native",
        "duplicate",
        "wrong-container",
        "init-container",
        "service-port",
        "container-port",
        "physical-http",
        "other-target",
    ],
)
def test_kubernetes_guard_rejects_misplaced_or_unrelated_target_changes(mutation):
    documents, config, _, _ = source_models()
    flow = container(documents, "flow", "flow")
    target = next(entry for entry in flow["env"] if entry["name"] == TARGET)
    if mutation == "missing":
        flow["env"].remove(target)
    elif mutation == "wrong-port":
        target["value"] = "issuance:9006"
    elif mutation == "native":
        target["value"] = "issuance-native:9005"
    elif mutation == "duplicate":
        flow["env"].append(deepcopy(target))
    elif mutation == "wrong-container":
        flow["env"].remove(target)
        container(documents, "gateway", "gateway")["env"].append(target)
    elif mutation == "init-container":
        flow["env"].remove(target)
        resource(documents, "Deployment", "flow")["spec"]["template"]["spec"][
            "initContainers"
        ] = [{"name": "flow", "env": [target]}]
    elif mutation == "service-port":
        resource(documents, "Service", "issuance")["spec"]["ports"][1]["port"] = 9006
    elif mutation == "container-port":
        container(documents, "issuance", "issuance")["ports"][1]["containerPort"] = 9006
    elif mutation == "physical-http":
        config["data"]["ISSUANCE_SERVICE_URL"] = "http://issuance-native:8005"
    else:
        entry = next(
            entry
            for entry in container(documents, "issuance", "issuance")["env"]
            if entry["name"] == "CT_GRPC_TARGET"
        )
        entry["value"] = "other:9003"
    with pytest.raises((AssertionError, KeyError)):
        assert_kubernetes_bindings(documents, config)


@pytest.mark.parametrize(
    "mutation",
    [
        "typo",
        "true",
        "boolean",
        "interpolation",
        "wrong-service",
        "duplicate-owner",
        "native-target",
        "physical-http",
        "other-target",
        "native-command",
    ],
)
def test_selfhost_guard_rejects_policy_drift_and_unrelated_target_changes(mutation):
    _, _, _, compose = source_models()
    services = compose["services"]
    env = services["issuance"]["environment"]
    if mutation == "typo":
        env[UNUSED_PRIVATE] = env.pop(PRIVATE)
    elif mutation == "true":
        env[PRIVATE] = "true"
    elif mutation == "boolean":
        env[PRIVATE] = False
    elif mutation == "interpolation":
        env[PRIVATE] = "${DIDCOMM_ALLOW_PRIVATE_IPS:-true}"
    elif mutation == "wrong-service":
        services["flow"]["environment"][PRIVATE] = env.pop(PRIVATE)
    elif mutation == "duplicate-owner":
        services["flow"]["environment"][PRIVATE] = "false"
    elif mutation == "native-target":
        services["flow"]["environment"][TARGET] = "issuance:9005"
    elif mutation == "physical-http":
        services["flow"]["environment"]["ISSUANCE_SERVICE_URL"] = (
            "http://issuance-native:8005"
        )
    elif mutation == "other-target":
        services["flow"]["environment"]["CT_GRPC_TARGET"] = "other:9003"
    else:
        services["issuance"]["command"] = ["/usr/local/bin/marty-issuance-service"]
    with pytest.raises(AssertionError):
        assert_selfhost_bindings(compose)


@pytest.mark.parametrize(
    "mutation", ["issuance-key", "signing-key", "mount", "duplicate-mount"]
)
def test_selfhost_flow_requires_paired_existing_secret_identity(mutation):
    _, _, _, compose = source_models()
    flow = compose["services"]["flow"]
    if mutation == "issuance-key":
        flow["environment"]["ISSUANCE_API_KEY_FILE"] = "/run/secrets/unowned"
    elif mutation == "signing-key":
        flow["environment"]["SIGNING_KEYS_INTERNAL_API_KEY_FILE"] = (
            "/run/secrets/unowned"
        )
    elif mutation == "mount":
        flow["secrets"].remove("issuance_api_key")
    else:
        flow["secrets"].append("issuance_api_key")
    with pytest.raises(AssertionError):
        assert_selfhost_bindings(compose)


@pytest.mark.parametrize(
    ("family", "service", "setting"),
    [
        ("base", "auth", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("base", "applicant", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("base", "presentation-policy", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("base", "flow", "ISSUANCE_SERVICE_URL"),
        ("base", "flow", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("base", "gateway", "ISSUANCE_SERVICE_URL"),
        ("base", "gateway", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("selfhost", "auth", "ISSUANCE_SERVICE_URL"),
        ("selfhost", "applicant", "ISSUANCE_SERVICE_URL"),
        ("selfhost", "presentation-policy", "ISSUANCE_SERVICE_URL"),
        ("selfhost", "flow", "ISSUANCE_SERVICE_URL"),
        ("selfhost", "gateway", "ISSUANCE_SERVICE_URL"),
        ("selfhost", "gateway", "ISSUANCE_NATIVE_SERVICE_URL"),
    ],
)
@pytest.mark.parametrize("fault", ["missing", "wrong"])
def test_compose_owner_split_rejects_missing_or_misbound_urls(
    family, service, setting, fault
):
    _, _, base, selfhost = source_models()
    compose = base if family == "base" else selfhost
    environment = compose["services"][service]["environment"]
    if fault == "missing":
        environment.pop(setting)
    else:
        environment[setting] = (
            LEGACY_URL if setting.endswith("NATIVE_SERVICE_URL") else NATIVE_URL
        )
    with pytest.raises(AssertionError):
        assert_compose_owner_split(compose, production=family == "selfhost")


@pytest.mark.parametrize(
    ("family", "service", "dependency"),
    [
        ("base", "auth", "issuance-native"),
        ("base", "applicant", "issuance-native"),
        ("base", "presentation-policy", "issuance-native"),
        ("base", "flow", "issuance"),
        ("base", "flow", "issuance-native"),
        ("base", "gateway", "issuance"),
        ("base", "gateway", "issuance-native"),
        ("selfhost", "gateway", "issuance"),
        ("selfhost", "gateway", "issuance-native"),
    ],
)
def test_compose_owner_split_rejects_missing_health_dependency(
    family, service, dependency
):
    _, _, base, selfhost = source_models()
    compose = base if family == "base" else selfhost
    compose["services"][service]["depends_on"].pop(dependency)
    with pytest.raises(AssertionError):
        assert_compose_owner_split(compose, production=family == "selfhost")


@pytest.mark.parametrize(
    ("service", "setting"),
    [
        ("auth", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("applicant", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("presentation-policy", "ISSUANCE_NATIVE_SERVICE_URL"),
        ("flow", "ISSUANCE_NATIVE_SERVICE_URL"),
    ],
)
def test_production_rejects_native_http_consumer_reintroduction(service, setting):
    _, _, _, selfhost = source_models()
    selfhost["services"][service]["environment"][setting] = NATIVE_URL
    with pytest.raises(AssertionError):
        assert_compose_owner_split(selfhost, production=True)


@pytest.mark.parametrize(
    ("service", "dependency"),
    [
        (service, dependency)
        for service in ("auth", "applicant", "presentation-policy", "flow")
        for dependency in ("issuance", "issuance-native")
    ],
)
def test_production_rejects_issuance_dependency_reintroduction(
    service, dependency
):
    _, _, _, selfhost = source_models()
    selfhost["services"][service]["depends_on"][dependency] = {
        "condition": "service_healthy"
    }
    with pytest.raises(AssertionError):
        assert_compose_owner_split(selfhost, production=True)


def test_strict_loader_rejects_duplicate_environment_and_dependency_keys():
    for text in [
        "services:\n  flow:\n    environment:\n      ISSUANCE_SERVICE_URL: one\n      ISSUANCE_SERVICE_URL: two\n",
        "services:\n  flow:\n    depends_on:\n      issuance-native: {}\n      issuance-native: {}\n",
    ]:
        with pytest.raises(AssertionError, match="Duplicate YAML mapping key"):
            yaml.load(text, Loader=UniqueKeyLoader)
