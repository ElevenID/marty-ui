"""Marty-owned deployment contracts for authenticated event ingestion."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOKEN_NAME = "NOTIFICATION_APPLICANT_EVENT_TOKEN"
PRODUCER_ID_NAME = "NOTIFICATION_EVENT_PRODUCER_ID"


def _deployment(resources: list[object], name: str) -> dict:
    return next(
        resource
        for resource in resources
        if isinstance(resource, dict)
        and resource.get("kind") == "Deployment"
        and resource["metadata"]["name"] == name
    )


def test_applicant_event_token_is_a_required_production_secret() -> None:
    catalog = json.loads(
        (ROOT / "deploy-config/catalog/secrets.json").read_text(encoding="utf-8")
    )

    assert catalog["secrets"]["notification_applicant_event_token"] == {
        "env": TOKEN_NAME,
        "file_env": "NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE",
        "compose_secret": "notification_applicant_event_token",
        "required_for": ["selfhost-production", "kubernetes-production"],
        "no_log": True,
        "placeholder_disallowed": True,
    }


def test_compose_wires_the_applicant_secret_only_to_producer_and_consumer() -> (
    None
):
    production = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    for service_name in ("applicant", "notification"):
        service = production["services"][service_name]
        assert service["environment"]["NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE"] == (
            "/run/secrets/notification_applicant_event_token"
        )
        assert "notification_applicant_event_token" in service["secrets"]
    assert production["services"]["applicant"]["environment"][PRODUCER_ID_NAME] == (
        "applicant"
    )
    assert PRODUCER_ID_NAME not in production["services"]["notification"]["environment"]
    assert (
        production["services"]["applicant"]["environment"]["NOTIFICATION_SERVICE_URL"]
        == "http://notification:8007"
    )

    development = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    assert (
        development["services"]["applicant"]["environment"]["NOTIFICATION_SERVICE_URL"]
        == "http://notification:8007"
    )
    for service_name in ("applicant", "notification"):
        assert TOKEN_NAME in development["services"][service_name]["environment"]
    assert development["services"]["applicant"]["environment"][PRODUCER_ID_NAME] == (
        "applicant"
    )
    assert PRODUCER_ID_NAME not in development["services"]["notification"]["environment"]

    for service_name, service in production["services"].items():
        if service_name not in {"applicant", "notification"}:
            assert "notification_applicant_event_token" not in service.get("secrets", [])


def test_kubernetes_wires_the_generated_token_to_producer_and_consumer() -> None:
    resources = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    for service_name in ("applicant", "notification"):
        deployment = _deployment(resources, service_name)
        env = {
            item["name"]: item
            for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert env[TOKEN_NAME]["valueFrom"]["secretKeyRef"] == {
            "name": "marty-secrets",
            "key": TOKEN_NAME,
        }
        if service_name == "applicant":
            assert env[PRODUCER_ID_NAME] == {
                "name": PRODUCER_ID_NAME,
                "value": "applicant",
            }
        else:
            assert PRODUCER_ID_NAME not in env

    deployment_names = {
        resource["metadata"]["name"]
        for resource in resources
        if isinstance(resource, dict) and resource.get("kind") == "Deployment"
    }
    for service_name in deployment_names - {"applicant", "notification"}:
        deployment = _deployment(resources, service_name)
        env_names = {
            item["name"]
            for item in deployment["spec"]["template"]["spec"]["containers"][0].get(
                "env", []
            )
        }
        assert TOKEN_NAME not in env_names

    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert f"resolve_secret_input {TOKEN_NAME}" in deploy_script
    assert (
        '--from-literal=NOTIFICATION_APPLICANT_EVENT_TOKEN="$notification_applicant_event_token"'
        in deploy_script
    )
