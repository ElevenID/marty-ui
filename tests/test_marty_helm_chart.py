"""Render the real chart to protect installation and image/Secret boundaries.

Requires Helm 3 on PATH, or MARTY_HELM_BIN. Synthetic digests are test inputs,
not installable release artifacts; the release projection verifies provenance.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "marty"
HELM = shutil.which(os.environ.get("MARTY_HELM_BIN", "helm"))
pytestmark = pytest.mark.skipif(HELM is None, reason="Helm 3 is required to render this chart")


class UniqueLoader(yaml.SafeLoader):
    """Kubernetes YAML must not silently overwrite a duplicate mapping key."""


def unique_mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        assert key not in result, f"duplicate YAML key: {key}"
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def installation_values() -> dict:
    return {
        "images": {
            role: f"ghcr.io/elevenid/marty-ui-oss/{repository}@sha256:{letter * 64}"
            for role, repository, letter in (
                ("services", "services", "a"),
                ("ui", "ui-selfhost", "b"),
                ("migrations", "migrations", "c"),
                ("keycloak", "keycloak", "d"),
            )
        },
        "postgres": {"image": f"docker.io/library/postgres@sha256:{'e' * 64}"},
        "redis": {"image": f"docker.io/library/redis@sha256:{'f' * 64}"},
        "publicHost": "marty.example.test",
        "organization": {"adminEmail": "operator@elevenid.test"},
        "ingress": {"tlsSecretName": "customer-edge-tls"},
        "imagePullSecrets": [{"name": "customer-registry"}],
    }


def helm_command(values_file: Path, command: str = "template") -> list[str]:
    assert HELM
    base = [HELM, command]
    if command == "template":
        base += ["marty-test", str(CHART), "--namespace", "isolated-install"]
    else:
        base += ["--strict", str(CHART)]
    return base + ["-f", str(CHART / "values-k3s-dev.yaml"), "-f", str(values_file)]


def render(tmp_path: Path, values: dict | None = None) -> list[dict]:
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values or installation_values()), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True, check=True)
    return [doc for doc in yaml.load_all(result.stdout, Loader=UniqueLoader) if doc]


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> list[dict]:
    return render(tmp_path_factory.mktemp("marty-helm"))


def resources(documents: list[dict], kind: str) -> dict[str, dict]:
    return {doc["metadata"]["name"]: doc for doc in documents if doc["kind"] == kind}


def pod_specs(documents: list[dict]):
    for doc in documents:
        if doc["kind"] in {"Deployment", "StatefulSet", "Job"}:
            yield doc, doc["spec"]["template"]["spec"]


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def test_chart_lints_with_verified_image_shapes(tmp_path: Path) -> None:
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(installation_values()), encoding="utf-8")
    result = subprocess.run(helm_command(values_file, "lint"), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_portable_namespace_and_complete_config_references(rendered: list[dict]) -> None:
    identities = [(doc["kind"], doc["metadata"]["name"]) for doc in rendered]
    assert len(identities) == len(set(identities))
    assert all(doc["metadata"]["namespace"] == "isolated-install" for doc in rendered)
    assert not resources(rendered, "Namespace")
    config_maps = resources(rendered, "ConfigMap")
    for obj in walk(rendered):
        if "configMapKeyRef" in obj:
            ref = obj["configMapKeyRef"]
            assert ref["key"] in config_maps[ref["name"]]["data"]
    config = config_maps["marty-config"]["data"]
    assert config["ISSUANCE_SERVICE_URL"] == "http://issuance-native:8005"
    assert config["GRPC_INSECURE_ALLOWED"] == "false"
    assert config["CREDENTIAL_LOGIN_POLICY_ID"]
    assert config["CREDENTIAL_LOGIN_ISSUER_DID"] == "did:web:marty.example.test:orgs:marty"
    assert "marty-prod.svc" not in json.dumps(rendered)
    for _, pod in pod_specs(rendered):
        assert pod["imagePullSecrets"] == [{"name": "customer-registry"}]
        assert pod["automountServiceAccountToken"] is False
        for container in pod.get("containers", []) + pod.get("initContainers", []):
            names = [env["name"] for env in container.get("env", [])]
            assert len(names) == len(set(names)), container["name"]


def test_one_native_owner_and_commands_exist_in_published_images(rendered: list[dict]) -> None:
    deployments = resources(rendered, "Deployment")
    assert "issuance-native" in deployments and "signing-keys" in deployments
    assert "issuance" not in deployments
    assert "rabbitmq" not in resources(rendered, "StatefulSet")
    assert "cloudflared" not in deployments
    source = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")
    available_roles = set(re.findall(r'MODULE_NAME" = "([a-z_]+)"', source))
    values = installation_values()
    valid_images = set(values["images"].values()) | {
        values["postgres"]["image"], values["redis"]["image"]
    }
    for doc, pod in pod_specs(rendered):
        for container in pod.get("containers", []) + pod.get("initContainers", []):
            assert container["image"] in valid_images
        if doc["kind"] == "Deployment" and doc["metadata"]["name"] not in {"keycloak", "ui"}:
            container = pod["containers"][0]
            assert container["image"] == values["images"]["services"]
            assert container["command"] == ["/app/services/entrypoint.sh"]
            env = {entry["name"]: entry for entry in container["env"]}
            assert env["SERVICE_NAME"]["value"] in available_roles
            if "DATABASE_URL" in env:
                assert env["DATABASE_URL"]["valueFrom"]["secretKeyRef"]["key"] == "DATABASE_SYNC_URL"
    assert "https://issuance:" not in json.dumps(rendered)


def test_existing_secret_renames_cover_env_and_volumes(tmp_path: Path) -> None:
    values = installation_values()
    defaults = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    values["existingSecrets"] = {
        name: f"owned-{name}" for name in defaults["existingSecrets"]
    }
    rendered = render(tmp_path, values)
    permitted_names = set(values["existingSecrets"].values())
    catalog = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_text())
    keys = {item["name"]: set(item["fields"]) for item in catalog["secrets"]}
    keys.update({
        "marty-redis-tls": {"tls.crt", "tls.key", "ca.crt"},
        "marty-operator": {"password"},
    })
    for obj in walk(rendered):
        if "secretKeyRef" in obj:
            ref = obj["secretKeyRef"]
            assert ref["name"] in permitted_names
            assert ref.get("optional") or ref["key"] in keys[ref["name"].removeprefix("owned-")]
        if "secret" in obj and isinstance(obj["secret"], dict) and "secretName" in obj["secret"]:
            ref = obj["secret"]
            assert ref["secretName"] in permitted_names
            expected_keys = keys[ref["secretName"].removeprefix("owned-")]
            assert all(item["key"] in expected_keys for item in ref.get("items", []))
    assert not resources(rendered, "Secret")


def test_ordered_bounded_migrations_wait_for_seeded_catalog(rendered: list[dict]) -> None:
    job = resources(rendered, "Job")["marty-migrate-1"]
    assert "helm.sh/hook" not in job["metadata"].get("annotations", {})
    assert job["spec"]["activeDeadlineSeconds"] <= 1800
    assert job["spec"]["backoffLimit"] <= 6
    pod = job["spec"]["template"]["spec"]
    names = [container["name"] for container in pod["initContainers"]]
    assert names.index("revocation-profile") < names.index("bootstrap-notification")
    assert names.index("organization") < names.index("credential-template")
    assert names.index("credential-template") < names.index("ready-credential-template")
    bootstrap = next(container for container in pod["initContainers"] if container["name"] == "bootstrap-notification")
    assert next(env["value"] for env in bootstrap["env"] if env["name"] == "REDIS_URL") == "rediss://redis:6379/2"
    for container in pod["initContainers"]:
        if container["name"].startswith("ready-"):
            assert "--retry-max-time" in container["command"]
            assert "--max-time" in container["command"]
    assert pod["containers"][0]["command"] == ["/usr/local/bin/marty-issuance-service", "migrate"]
    assert pod["restartPolicy"] == "OnFailure"


def test_keycloak_has_real_entrypoint_safe_realm_and_private_health(rendered: list[dict]) -> None:
    deployment = resources(rendered, "Deployment")["keycloak"]
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["/opt/keycloak/bin/kc.sh"]
    assert container["startupProbe"]["httpGet"]["port"] == "management"
    assert container["livenessProbe"]["httpGet"]["port"] == "management"
    assert container["readinessProbe"]["httpGet"]["path"].endswith("/.well-known/openid-configuration")
    assert all(port["port"] != 9000 for port in resources(rendered, "Service")["keycloak"]["spec"]["ports"])
    realm = json.loads(resources(rendered, "ConfigMap")["keycloak-realm-config"]["data"]["11id-realm.json"])
    assert realm["users"] and all(user.get("serviceAccountClientId") for user in realm["users"])
    assert not any(user.get("credentials") for user in realm["users"])
    client = next(client for client in realm["clients"] if client["clientId"] == "marty-api")
    assert client["secret"] == "${MARTY_API_CLIENT_SECRET}"
    assert resources(rendered, "ConfigMap")["marty-config"]["data"]["KEYCLOAK_SOCIAL_LOGIN_ENABLED"] == "false"
    for name in ["setup-keycloak.sh", "setup-keycloak-selfhost-production.sh", "load-secrets-env.sh"]:
        assert (CHART / "files/keycloak" / name).read_bytes() == (ROOT / "scripts" / name).read_bytes()


def test_production_redis_tls_preserves_public_trust_and_confines_private_key(rendered: list[dict]) -> None:
    config = resources(rendered, "ConfigMap")["marty-config"]["data"]
    assert config["ENVIRONMENT"] == "production"
    assert config["REDIS_URL"] == "rediss://redis:6379/0"
    redis = resources(rendered, "StatefulSet")["redis"]["spec"]["template"]["spec"]
    server = redis["containers"][0]
    assert "command" not in server  # Preserve upstream ownership/user-drop entrypoint.
    assert server["args"][server["args"].index("--port") + 1] == "0"
    assert server["args"][server["args"].index("--tls-port") + 1] == "6379"
    for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert "--tls" in server[probe]["exec"]["command"]
        assert "--cacert" in server[probe]["exec"]["command"]
    assert resources(rendered, "Service")["redis"]["spec"]["publishNotReadyAddresses"] is True
    for doc, pod in pod_specs(rendered):
        if doc["metadata"]["name"] in {"redis", "postgres", "keycloak", "ui"} or doc["metadata"]["name"].startswith("marty-keycloak-"):
            continue
        trust = next(container for container in pod["initContainers"] if container["name"] == "redis-trust")
        assert "/etc/ssl/certs/ca-certificates.crt /redis-ca/ca.crt" in trust["command"][-1]
        ca = next(volume for volume in pod["volumes"] if volume["name"] == "redis-ca")
        assert ca["secret"]["items"] == [{"key": "ca.crt", "path": "ca.crt"}]
        for container in pod["containers"] + pod.get("initContainers", []):
            if container["name"] == "redis-trust" or container["name"].startswith("ready-"):
                continue
            env = {item["name"]: item for item in container.get("env", [])}
            assert env["SSL_CERT_FILE"]["value"] == "/etc/marty/trust/ca-certificates.crt"
            if "REDIS_URL" in env and "value" in env["REDIS_URL"]:
                assert env["REDIS_URL"]["value"].startswith("rediss://redis:6379/")
            assert any(mount["name"] == "redis-trust" and mount["readOnly"] for mount in container["volumeMounts"])
    assert "redis://redis:" not in json.dumps(rendered)


def test_flow_signer_transport_and_native_issuance_credentials(rendered: list[dict]) -> None:
    deployments = resources(rendered, "Deployment")
    flow = deployments["flow"]["spec"]["template"]["spec"]
    env = {item["name"]: item for item in flow["containers"][0]["env"]}
    assert env["SIGNING_KEYS_INTERNAL_URL"]["value"] == "https://signing-keys:8018/internal"
    trust = next(container for container in flow["initContainers"] if container["name"] == "redis-trust")
    assert "/signing-ca/ca.crt" in trust["command"][-1]
    ca = next(volume for volume in flow["volumes"] if volume["name"] == "signing-ca")
    assert ca["secret"]["secretName"] == "signing-keys-integration-secret-ca"
    assert ca["secret"]["items"] == [{"key": "ca.crt", "path": "ca.crt"}]
    for name, deployment in deployments.items():
        if name != "flow":
            assert all(volume["name"] != "signing-ca" for volume in deployment["spec"]["template"]["spec"].get("volumes", []))
    for name in ["presentation-policy", "applicant"]:
        container = deployments[name]["spec"]["template"]["spec"]["containers"][0]
        env = {item["name"]: item for item in container["env"]}
        assert env["ISSUANCE_API_KEY"]["valueFrom"]["secretKeyRef"] == {"name": "marty-secrets", "key": "ISSUANCE_API_KEY"}


def test_development_requests_leave_room_for_cluster_and_openbao(rendered: list[dict]) -> None:
    cpu = memory = 0
    for doc, pod in pod_specs(rendered):
        if doc["kind"] == "Job":
            continue
        replicas = doc["spec"]["replicas"]
        for container in pod["containers"]:
            request = container["resources"]["requests"]
            cpu += replicas * (float(request["cpu"][:-1]) if request["cpu"].endswith("m") else float(request["cpu"]) * 1000)
            memory += replicas * (float(request["memory"][:-2]) * (1024 if request["memory"].endswith("Gi") else 1))
    assert cpu < 1500, cpu
    assert memory < 4096, memory
    applicant = resources(rendered, "Deployment")["applicant"]
    assert applicant["spec"]["replicas"] == 1
    assert applicant["spec"]["strategy"] == {"type": "Recreate"}
    assert applicant["spec"]["template"]["spec"]["securityContext"]["fsGroup"] == 10001
    assert resources(rendered, "PersistentVolumeClaim")["applicant-data"]["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    for stateful in resources(rendered, "StatefulSet").values():
        assert stateful["spec"]["volumeClaimTemplates"]


def test_single_replica_apps_require_a_ready_pod_without_surge(rendered: list[dict]) -> None:
    # Helm 3 waits for replicas - MaxUnavailable. A one-replica rolling update
    # with maxUnavailable=1 therefore accepts zero Ready pods. Recreate keeps
    # the no-surge budget and requires the desired Ready replica instead.
    workloads = yaml.safe_load((CHART / "files/workloads.yaml").read_text())
    deployments = resources(rendered, "Deployment")
    for name in workloads:
        spec = deployments[name]["spec"]
        assert spec["replicas"] == 1, name
        assert spec["strategy"] == {"type": "Recreate"}, name


def test_multiple_replicas_retain_rolling_updates_and_applicant_single_writer(tmp_path: Path) -> None:
    values = installation_values()
    values["apps"] = {"replicas": 3}
    deployments = resources(render(tmp_path, values), "Deployment")
    workloads = yaml.safe_load((CHART / "files/workloads.yaml").read_text())
    for name in workloads:
        spec = deployments[name]["spec"]
        if name == "applicant":
            assert spec["replicas"] == 1
            assert spec["strategy"] == {"type": "Recreate"}
        else:
            assert spec["replicas"] == 3, name
            assert spec["strategy"] == {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 0},
            }, name


def test_ip_ingress_omits_disallowed_hosts_and_preserves_https_port(tmp_path: Path) -> None:
    values = installation_values()
    values.update(publicHost="192.0.2.20", publicOrigin="https://192.0.2.20:8443")
    rendered = render(tmp_path, values)
    ingress = resources(rendered, "Ingress")["marty"]["spec"]
    assert "host" not in ingress["rules"][0]
    assert "hosts" not in ingress["tls"][0]
    config = resources(rendered, "ConfigMap")["marty-config"]["data"]
    assert config["UI_BASE_URL"] == "https://192.0.2.20:8443"
    assert config["PUBLIC_DOMAIN"] == "192.0.2.20:8443"
    assert config["KC_HOSTNAME"] == "https://192.0.2.20:8443"
    assert config["MARTY_ISSUER_DID"] == "did:web:192.0.2.20%3A8443:orgs:marty"


@pytest.mark.parametrize("public_origin", [None, "https://192.0.2.20:8443"])
def test_canvas_worker_inherits_complete_public_urls(tmp_path: Path, public_origin: str | None) -> None:
    values = installation_values()
    if public_origin:
        values.update(publicHost="192.0.2.20", publicOrigin=public_origin)
    origin = public_origin or "https://marty.example.test"
    rendered = render(tmp_path, values)
    config = resources(rendered, "ConfigMap")["marty-config"]["data"]
    expected = {
        "ISSUER_BASE_URL": origin,
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL": origin + "/console/org/deploy/canvas",
    }
    assert {name: config[name] for name in expected} == expected
    worker = resources(rendered, "Deployment")["canvas-sync-worker"]["spec"]["template"]["spec"]["containers"][0]
    assert {"configMapRef": {"name": "marty-config"}} in worker["envFrom"]
    assert set(expected).isdisjoint(entry["name"] for entry in worker["env"])


@pytest.mark.parametrize("overrides", [
    {"ISSUER_BASE_URL": "https://issuer.example.test:9443"},
    {"CANVAS_OAUTH_COMPLETION_REDIRECT_URL": "https://console.example.test/canvas-complete"},
])
def test_canvas_public_url_overrides_preserve_other_generated_defaults(tmp_path: Path, overrides: dict) -> None:
    values = installation_values()
    origin = "https://192.0.2.20:8443"
    values.update(publicHost="192.0.2.20", publicOrigin=origin, config=overrides)
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    expected = {
        "ISSUER_BASE_URL": origin,
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL": origin + "/console/org/deploy/canvas",
        **overrides,
    }
    assert {name: config[name] for name in expected} == expected


@pytest.mark.parametrize("development", [False, True])
def test_ui_organization_creation_uses_the_backend_setting(tmp_path: Path, development: bool) -> None:
    values = installation_values()
    if development:
        values["ui"] = {"development": {"enabled": True, "checkoutPath": "/opt/marty-ux"}}

    checksums = {}
    for choice in (None, "true", "false"):
        values["config"] = {} if choice is None else {"ORGANIZATION_CREATION_ENABLED": choice}
        documents = render(tmp_path, values)
        config_maps = resources(documents, "ConfigMap")
        deployments = resources(documents, "Deployment")
        ui_template = deployments["ui"]["spec"]["template"]
        ui = next(container for container in ui_template["spec"]["containers"] if container["name"] == "ui")
        gateway = deployments["gateway"]["spec"]["template"]["spec"]["containers"][0]

        # The startup hook receives this one public flag, not the server's full
        # configuration or any credentials. The gateway reads the same source.
        assert "envFrom" not in ui
        assert ui["env"] == [{
            "name": "ORGANIZATION_CREATION_ENABLED",
            "valueFrom": {"configMapKeyRef": {
                "name": "marty-config", "key": "ORGANIZATION_CREATION_ENABLED",
            }},
        }]
        reference = ui["env"][0]["valueFrom"]["configMapKeyRef"]
        assert {"configMapRef": {"name": reference["name"]}} in gateway["envFrom"]
        assert all(entry["name"] != reference["key"] for entry in gateway["env"])
        assert config_maps[reference["name"]]["data"][reference["key"]] == (choice or "false")
        checksums[choice] = ui_template["metadata"]["annotations"]["checksum/config"]

    # Changing the flag must restart nginx so its startup hook regenerates the
    # served runtime-config.js, in both static and live-reload deployments.
    assert checksums[None] == checksums["false"]
    assert checksums["true"] != checksums["false"]


@pytest.mark.parametrize("role", ["services", "ui", "migrations", "keycloak", "postgres", "redis"])
def test_mutable_image_tags_are_rejected(tmp_path: Path, role: str) -> None:
    values = installation_values()
    if role in {"postgres", "redis"}:
        values[role]["image"] = f"{role}:latest"
    else:
        values["images"][role] = f"ghcr.io/elevenid/marty-ui-oss/{role}:latest"
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0
    assert "sha256" in result.stderr


def test_development_ui_keeps_backend_tls_routes_and_public_ports_unchanged(tmp_path: Path) -> None:
    values = installation_values()
    values.update(publicHost="dev.example.test", publicOrigin="https://dev.example.test:8443")
    normal = render(tmp_path, values)
    values["ui"] = {"development": {"enabled": True, "checkoutPath": "/opt/marty-ux"}}
    development = render(tmp_path, values)
    normal_by_id = {(doc["kind"], doc["metadata"]["name"]): doc for doc in normal}
    dev_by_id = {(doc["kind"], doc["metadata"]["name"]): doc for doc in development}
    assert normal_by_id.keys() == dev_by_id.keys()
    for identity in normal_by_id:
        if identity not in {("Deployment", "ui"), ("ConfigMap", "nginx-prod-config")}:
            assert normal_by_id[identity] == dev_by_id[identity], identity

    pod = resources(development, "Deployment")["ui"]["spec"]["template"]["spec"]
    ordinary_pod = resources(normal, "Deployment")["ui"]["spec"]["template"]["spec"]
    assert ordinary_pod["containers"] == [pod["containers"][0]]
    assert "initContainers" not in ordinary_pod
    assert all("hostPath" not in volume for volume in ordinary_pod["volumes"])
    assert pod["automountServiceAccountToken"] is False
    node = pod["containers"][1]
    assert node["command"] == ["npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "3000", "--strictPort"]
    assert node["resources"]["requests"]["memory"] == "256Mi"
    assert node["resources"]["limits"]["memory"] == "4096Mi"
    assert pod["initContainers"][0]["resources"]["requests"]["memory"] == "256Mi"
    assert pod["initContainers"][0]["resources"]["limits"]["memory"] == "1536Mi"
    assert "ports" not in node
    assert node["readinessProbe"]["exec"]["command"][0] == "node"
    for container in (pod["initContainers"][0], node):
        assert "@sha256:" in container["image"]
        assert "envFrom" not in container
        assert container["securityContext"]["runAsNonRoot"] is True
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        env = {entry["name"]: entry["value"] for entry in container["env"]}
        assert "HOME" not in env
        assert env["NPM_CONFIG_CACHE"] == "/tmp/npm-cache"
        assert env["VITE_API_URL"] == ""
        assert env["VITE_DEV_PUBLIC_ORIGIN"] == values["publicOrigin"]
        assert env["VITE_UI_VARIANT"] == "selfhost"
        mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
        assert set(mounts) == {"ui-dev-source", "ui-dev-contracts", "ui-dev-dependencies", "ui-dev-tmp"}
        assert mounts["ui-dev-source"]["readOnly"] is True
        assert mounts["ui-dev-contracts"]["readOnly"] is True
    host_paths = [volume["hostPath"] for volume in pod["volumes"] if "hostPath" in volume]
    assert host_paths == [
        {"path": "/opt/marty-ux/ui", "type": "Directory"},
        {"path": "/opt/marty-ux/contracts", "type": "Directory"},
    ]

    def nginx_locations(documents):
        nginx = resources(documents, "ConfigMap")["nginx-prod-config"]["data"]["default.conf"]
        nginx = re.sub(r"(?m)^\s*#.*\n", "", nginx)
        return {name.strip(): body.strip() for name, body in re.findall(
            r"(?ms)^    location ([^\n{]+)\{(.*?)(?=^    location |^})", nginx,
        )}

    ordinary_locations = nginx_locations(normal)
    dev_locations = nginx_locations(development)
    ui_locations = {"/", "= /canvas/lti/experience"}
    assert len(ordinary_locations) >= 15
    for route in ordinary_locations.keys() - ui_locations:
        assert ordinary_locations[route] == dev_locations[route], route
    for route in ui_locations:
        assert "proxy_pass http://127.0.0.1:3000;" in dev_locations[route]
        assert "proxy_set_header Upgrade $http_upgrade;" in dev_locations[route]
        assert "proxy_set_header Host $http_host;" in dev_locations[route]
        assert "proxy_set_header X-Forwarded-Proto https;" in dev_locations[route]
    assert "try_files $uri =404;" in dev_locations["= /runtime-config.js"]


@pytest.mark.parametrize("checkout", ["", "/", "relative/path", "/opt/../root", "/opt/./repo", "/opt/repo/", "/opt//repo"])
def test_development_ui_rejects_ambiguous_checkout_paths(tmp_path: Path, checkout: str) -> None:
    values = installation_values()
    values["ui"] = {"development": {"enabled": True, "checkoutPath": checkout}}
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0
    assert "ui.development.checkoutPath" in result.stderr


def test_development_ui_rejects_mutable_node_image(tmp_path: Path) -> None:
    values = installation_values()
    values["ui"] = {"development": {
        "enabled": True, "checkoutPath": "/opt/marty-ux", "nodeImage": "node:24",
    }}
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0
    assert "sha256" in result.stderr
