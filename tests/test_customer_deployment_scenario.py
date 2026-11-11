"""Render a fictional customer through the real chart and separate input layers.

Synthetic image digests exist only in temporary render inputs. These checks do
not claim that the customer has DNS, SMTP, registry access, or running services.
"""

import json
from pathlib import Path
import subprocess

import pytest
import yaml

from tests.test_marty_helm_chart import (
    CHART, HELM, ROOT, UniqueLoader, installation_values, pod_specs, resources, walk,
)
from tests.test_marty_helm_smtp import configurator_environment


pytestmark = pytest.mark.skipif(HELM is None, reason="Helm 3 is required to render this chart")
PROFILE = CHART / "examples" / "customer-education.yaml"
SMTP_PROFILE = CHART / "examples" / "customer-education-smtp.yaml"
ORGANIZATION_ID = "750e8400-e29b-41d4-a716-446655440001"
NAMESPACE = "canyon-configuration-test"
SECRET_CATALOG = json.loads(
    (ROOT / "deploy-config" / "catalog" / "kubernetes-secrets.json").read_text()
)["secrets"]


def customer_layers(tmp_path: Path, *, smtp: bool = False, endpoint: dict | None = None) -> list[Path]:
    """Use Helm's actual layer merge, including independent release selection."""
    test_inputs = installation_values()
    images = tmp_path / "render-only-images.yaml"
    images.write_text(yaml.safe_dump({
        key: test_inputs[key] for key in ("images", "postgres", "redis")
    }))
    pulls = tmp_path / "render-only-pull-secrets.yaml"
    pulls.write_text(yaml.safe_dump({"imagePullSecrets": [{"name": "canyon-registry"}]}))
    aliases = {entry["name"]: "canyon-" + entry["name"] for entry in SECRET_CATALOG}
    aliases.update({"marty-redis-tls": "canyon-redis-tls", "marty-operator": "canyon-operator"})
    infrastructure = tmp_path / "render-only-secret-references.yaml"
    infrastructure.write_text(yaml.safe_dump({"existingSecrets": aliases}))
    layers = [CHART / "values-k3s-dev.yaml", images, pulls, PROFILE, infrastructure]
    if smtp:
        layers.append(SMTP_PROFILE)
    if endpoint is not None:
        override = tmp_path / "render-only-endpoint.yaml"
        override.write_text(yaml.safe_dump(endpoint))
        layers.append(override)
    return layers


def customer_command(layers: list[Path], *, lint: bool = False) -> list[str]:
    command = [HELM, "lint", "--strict", str(CHART)] if lint else [
        HELM, "template", "canyon", str(CHART), "--namespace", NAMESPACE,
    ]
    for layer in layers:
        command.extend(["-f", str(layer)])
    return command


def render_customer(tmp_path: Path, **kwargs: object) -> list[dict]:
    rendered = subprocess.run(
        customer_command(customer_layers(tmp_path, **kwargs)),
        check=True, capture_output=True, text=True,
    )
    return [document for document in yaml.load_all(rendered.stdout, Loader=UniqueLoader) if document]


@pytest.fixture()
def customer(tmp_path: Path) -> list[dict]:
    return render_customer(tmp_path)


def test_customer_examples_have_no_credentials_or_fabricated_release_selection() -> None:
    for source in (PROFILE, SMTP_PROFILE):
        values = yaml.load(source.read_text(), Loader=UniqueLoader)
        assert not ({"images", "postgres", "redis", "release", "imagePullSecrets"} & values.keys())
        assert "@sha256:" not in source.read_text()
        assert not any(
            "password" in key.lower() and key not in {"KEYCLOAK_RESET_PASSWORD_ENABLED"}
            or "token" in key.lower() or "private_key" in key.lower()
            for mapping in walk(values) for key in mapping
        )
    values = yaml.safe_load(PROFILE.read_text())
    assert values["organization"]["id"] == ORGANIZATION_ID
    assert values["publicHost"].endswith(".example")
    assert "did" not in values["organization"]
    claims = json.loads((CHART / "examples" / "customer-education-claims.json").read_text())
    assert set(claims) == {"given_name", "family_name", "organization_name",
                           "achievement_name", "achievement_description"}
    assert claims["organization_name"] == values["config"]["MARTY_ORG_NAME"]


def test_customer_profile_requires_the_verified_image_layer(tmp_path: Path) -> None:
    result = subprocess.run(customer_command([PROFILE]), capture_output=True, text=True)
    assert result.returncode != 0
    assert "sha256" in result.stderr or "images" in result.stderr
    result = subprocess.run(customer_command(customer_layers(tmp_path), lint=True),
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("endpoint", [
    None,
    {"publicHost": "192.0.2.42", "publicOrigin": "https://192.0.2.42:8443",
     "ingress": {"tlsSecretName": "canyon-lab-edge-tls"}},
])
def test_customer_identity_is_consistent_across_dns_and_fresh_lab_layers(
    tmp_path: Path, endpoint: dict | None,
) -> None:
    documents = render_customer(tmp_path, endpoint=endpoint)
    config = resources(documents, "ConfigMap")["marty-config"]["data"]
    host = endpoint["publicHost"] if endpoint else "credentials.canyon-skills.example"
    origin = endpoint["publicOrigin"] if endpoint else "https://" + host
    authority = origin.removeprefix("https://")
    did = "did:web:" + authority.replace(":", "%3A") + ":orgs:canyon-skills"
    assert config["MARTY_ORG_ID"] == ORGANIZATION_ID
    assert config["MARTY_ORG_SLUG"] == "canyon-skills"
    assert config["MARTY_ORG_DOMAIN"] == host
    assert config["MARTY_ORG_NAME"] == "Canyon Skills Academy"
    assert config["MARTY_ORG_ADMIN_EMAIL"] == "admin@canyon-skills.example"
    assert config["PUBLIC_DOMAIN"] == authority
    for name in ("PUBLIC_API_URL", "UI_BASE_URL", "ISSUER_BASE_URL", "MARTY_ISSUER_BASE_URL",
                 "KC_HOSTNAME", "CORS_ORIGINS", "OIDC_POST_LOGOUT_REDIRECT_URI"):
        assert config[name] == origin, name
    for name in ("MARTY_ISSUER_DID", "OID4VP_ISSUER_DID", "CREDENTIAL_LOGIN_ISSUER_DID"):
        assert config[name] == did, name
    assert config["OIDC_REDIRECT_URI"] == origin + "/v1/auth/callback"
    assert config["OIDC_ISSUER_URL_EXTERNAL"] == origin + "/realms/11id"
    assert config["OIDC_EXTERNAL_ISSUER_URL"] == origin + "/realms/11id"
    assert config["FLOW_CALLBACK_DESTINATIONS"].startswith(ORGANIZATION_ID + "|")
    ingress = resources(documents, "Ingress")["marty"]["spec"]
    assert ingress["tls"][0]["secretName"] == (
        endpoint["ingress"]["tlsSecretName"] if endpoint else "canyon-edge-tls"
    )
    if endpoint:
        assert "host" not in ingress["rules"][0]
        assert "hosts" not in ingress["tls"][0]
    else:
        assert ingress["rules"][0]["host"] == host
        assert ingress["tls"][0]["hosts"] == [host]


def test_customer_login_is_operator_controlled_without_smtp(customer: list[dict]) -> None:
    config = resources(customer, "ConfigMap")["marty-config"]["data"]
    for name in ("ORGANIZATION_CREATION_ENABLED", "KEYCLOAK_USER_REGISTRATION_ENABLED",
                 "KEYCLOAK_SOCIAL_LOGIN_ENABLED", "KEYCLOAK_VERIFY_EMAIL",
                 "KEYCLOAK_RESET_PASSWORD_ENABLED", "CREDENTIAL_LOGIN_CREATE_USERS"):
        assert config[name] == "false", name
    assert config["CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER"] == "true"
    assert config["SMTP_HOST"] == ""
    assert "SMTP_PASSWORD" not in config and "KEYCLOAK_SMTP_PASSWORD" not in config
    operator = configurator_environment(customer)["MARTY_ORG_ADMIN_PASSWORD"]
    assert operator["valueFrom"]["secretKeyRef"] == {"name": "canyon-operator", "key": "password"}
    realm = json.loads(resources(customer, "ConfigMap")["keycloak-realm-config"]["data"]["11id-realm.json"])
    assert all(user.get("serviceAccountClientId") and not user.get("credentials")
               for user in realm.get("users", []))


def test_all_customer_workload_references_resolve_and_secrets_stay_external(customer: list[dict]) -> None:
    assert not resources(customer, "Secret")
    assert all(document["metadata"].get("namespace") == NAMESPACE for document in customer)
    configmaps = resources(customer, "ConfigMap")
    service_accounts = resources(customer, "ServiceAccount")
    persistent_claims = resources(customer, "PersistentVolumeClaim")
    secret_keys = {"canyon-" + entry["name"]: set(entry["fields"]) for entry in SECRET_CATALOG}
    secret_keys.update({"canyon-redis-tls": {"tls.crt", "tls.key", "ca.crt"},
                        "canyon-operator": {"password"}})
    for document, pod in pod_specs(customer):
        assert pod["serviceAccountName"] in service_accounts
        assert pod["automountServiceAccountToken"] is False
        assert pod["imagePullSecrets"] == [{"name": "canyon-registry"}]
        volumes = {volume["name"] for volume in pod.get("volumes", [])}
        volumes.update(claim["metadata"]["name"] for claim in document["spec"].get("volumeClaimTemplates", []))
        for container in pod.get("containers", []) + pod.get("initContainers", []):
            assert "@sha256:" in container["image"]
            assert all(mount["name"] in volumes for mount in container.get("volumeMounts", []))
        for mapping in walk(pod):
            if "configMapRef" in mapping:
                assert mapping["configMapRef"]["name"] in configmaps
            if "configMapKeyRef" in mapping:
                reference = mapping["configMapKeyRef"]
                assert reference["key"] in configmaps[reference["name"]]["data"]
            if "configMap" in mapping:
                reference = mapping["configMap"]
                assert reference["name"] in configmaps
                configmap = configmaps[reference["name"]]
                projected_keys = set(configmap.get("data", {})) | set(configmap.get("binaryData", {}))
                assert all(item["key"] in projected_keys
                           for item in reference.get("items", []))
            if "secretKeyRef" in mapping:
                reference = mapping["secretKeyRef"]
                assert reference["name"] in secret_keys
                assert reference.get("optional") or reference["key"] in secret_keys[reference["name"]]
            if "secret" in mapping:
                reference = mapping["secret"]
                assert reference["secretName"] in secret_keys
                assert all(item["key"] in secret_keys[reference["secretName"]]
                           for item in reference.get("items", []))
            if "persistentVolumeClaim" in mapping:
                assert mapping["persistentVolumeClaim"]["claimName"] in persistent_claims


def test_customer_uses_native_issuance_and_managed_private_kms(customer: list[dict]) -> None:
    deployments = resources(customer, "Deployment")
    assert "issuance-native" in deployments and "issuance" not in deployments
    assert "canvas-sync-worker" not in deployments
    config = resources(customer, "ConfigMap")["marty-config"]["data"]
    assert config["ISSUANCE_SERVICE_URL"] == "http://issuance-native:8005"
    assert config["GRPC_INSECURE_ALLOWED"] == "false"
    assert config["MARTY_KMS_BOOTSTRAP_ENABLED"] == "true"
    kms_addresses = {name: value for name, value in config.items()
                     if name.endswith("_TLS_KMS_ADDR") or name in {"KEYCLOAK_KMS_ADDR", "BAO_ADDR"}}
    assert kms_addresses and set(kms_addresses.values()) == {"https://openbao:8200"}
    job = resources(customer, "Job")["marty-migrate-1"]["spec"]["template"]["spec"]
    bootstrap = next(container for container in job["initContainers"]
                     if container["name"] == "bootstrap-notification")
    environment = {entry["name"]: entry.get("value") for entry in bootstrap["env"]}
    assert environment["REDIS_URL"] == "rediss://redis:6379/2"
    assert environment["OPENBAO_SERVICE_TOKEN_FILE"] == "/run/secrets/openbao_bootstrap_token"
    bootstrap_volume = next(volume for volume in job["volumes"] if volume["name"] == "bootstrap-secrets")
    assert bootstrap_volume["secret"]["secretName"] == "canyon-marty-secrets"


def test_customer_datastores_are_private_and_persistent(customer: list[dict]) -> None:
    services = resources(customer, "Service")
    deployments = resources(customer, "Deployment")
    statefulsets = resources(customer, "StatefulSet")
    labels = [document["spec"]["template"]["metadata"]["labels"]
              for document in [*deployments.values(), *statefulsets.values()]]
    for service in services.values():
        assert service["spec"].get("type", "ClusterIP") == "ClusterIP"
        selector = service["spec"]["selector"]
        assert any(all(candidate.get(key) == value for key, value in selector.items()) for candidate in labels)
    for name, size in (("postgres", "10Gi"), ("redis", "1Gi")):
        claims = statefulsets[name]["spec"]["volumeClaimTemplates"]
        assert len(claims) == 1
        assert claims[0]["spec"]["accessModes"] == ["ReadWriteOnce"]
        assert claims[0]["spec"]["resources"]["requests"]["storage"] == size
        assert "storageClassName" not in claims[0]["spec"]
    applicant = resources(customer, "PersistentVolumeClaim")["applicant-data"]["spec"]
    assert applicant["accessModes"] == ["ReadWriteOnce"]
    assert applicant["resources"]["requests"]["storage"] == "1Gi"
    policies = resources(customer, "NetworkPolicy")
    internal = policies["marty-internal"]["spec"]
    assert internal["policyTypes"] == ["Ingress"]
    assert internal["ingress"] == [{"from": [{"podSelector": {}}]}]
    ui = policies["marty-ui"]["spec"]
    assert ui["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 80}]
    assert ui["ingress"][0]["from"][1]["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "kube-system",
    }
    ingress = resources(customer, "Ingress")["marty"]["spec"]
    backend = ingress["rules"][0]["http"]["paths"][0]["backend"]["service"]
    assert backend == {"name": "ui", "port": {"name": "http"}}


def test_optional_customer_email_policy_keeps_password_in_existing_secret(tmp_path: Path) -> None:
    customer = render_customer(tmp_path, smtp=True)
    config = resources(customer, "ConfigMap")["marty-config"]["data"]
    expected = yaml.safe_load(SMTP_PROFILE.read_text())["config"]
    assert all(config[name] == value for name, value in expected.items())
    assert config["KEYCLOAK_USER_REGISTRATION_ENABLED"] == "false"
    assert config["KEYCLOAK_SMTP_STARTTLS"] == "true"
    assert config["KEYCLOAK_SMTP_SSL"] == "false"
    assert "SMTP_PASSWORD" not in config and "KEYCLOAK_SMTP_PASSWORD" not in config
    assert not resources(customer, "Secret")
    smtp = configurator_environment(customer)["SMTP_PASSWORD"]
    assert smtp["valueFrom"]["secretKeyRef"] == {
        "name": "canyon-marty-secrets", "key": "SMTP_PASSWORD", "optional": False,
    }
