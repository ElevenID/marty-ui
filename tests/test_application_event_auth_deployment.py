from __future__ import annotations

from pathlib import Path

import yaml

from marty_devops import DeploymentCatalog


ROOT = Path(__file__).resolve().parents[1]
SECRET_ID = "flow_application_event_hmac_key"
ENV_NAME = "FLOW_APPLICATION_EVENT_HMAC_KEY"


def _yaml(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_compose_key_is_scoped_to_applicant_and_flow() -> None:
    development = _yaml("docker-compose.base.yml")["services"]
    holders = {
        name
        for name, service in development.items()
        if ENV_NAME in service.get("environment", {})
    }
    assert holders == {"applicant", "flow"}
    assert "dev-flow-application-event" in development["flow"]["environment"][ENV_NAME]

    production_document = _yaml("docker-compose.selfhost.prod.yml")
    production = production_document["services"]
    file_env = f"{ENV_NAME}_FILE"
    holders = {
        name
        for name, service in production.items()
        if file_env in service.get("environment", {})
    }
    assert holders == {"applicant", "flow"}
    for name in holders:
        assert SECRET_ID in production[name]["secrets"]
        assert production[name]["environment"][file_env] == (
            "/run/secrets/flow_application_event_hmac_key"
        )
    assert production_document["secrets"][SECRET_ID]["file"].endswith(
        "/flow_application_event_hmac_key"
    )


def test_kubernetes_key_is_scoped_to_applicant_and_flow() -> None:
    documents = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    holders = set()
    for document in documents:
        if not document or document.get("kind") != "Deployment":
            continue
        deployment = document["metadata"]["name"]
        for container in document["spec"]["template"]["spec"]["containers"]:
            for item in container.get("env", []):
                if item.get("name") == ENV_NAME:
                    assert item["valueFrom"]["secretKeyRef"] == {
                        "name": "marty-secrets",
                        "key": ENV_NAME,
                    }
                    holders.add(deployment)
    assert holders == {"applicant", "flow"}


def test_production_catalog_and_deploy_script_require_the_dedicated_key() -> None:
    catalog = DeploymentCatalog.load(ROOT)
    for stack in ("selfhost-production", "kubernetes-production"):
        assert SECRET_ID in catalog.required_secrets_for_stack(stack)

    secret = catalog.secret(SECRET_ID)
    assert secret["env"] == ENV_NAME
    assert secret["file_env"] == f"{ENV_NAME}_FILE"
    assert secret["placeholder_disallowed"] is True

    deploy = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert "resolve_secret_input FLOW_APPLICATION_EVENT_HMAC_KEY" in deploy
    assert '--from-literal=FLOW_APPLICATION_EVENT_HMAC_KEY=' in deploy
