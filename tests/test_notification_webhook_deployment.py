"""Marty-owned deployment contracts for notification webhook signing."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_webhook_secret_is_a_required_production_catalog_secret() -> None:
    catalog = json.loads(
        (ROOT / "deploy-config/catalog/secrets.json").read_text(encoding="utf-8")
    )

    secret = catalog["secrets"]["notification_webhook_secret"]
    assert secret == {
        "env": "NOTIFICATION_WEBHOOK_SECRET",
        "file_env": "NOTIFICATION_WEBHOOK_SECRET_FILE",
        "compose_secret": "notification_webhook_secret",
        "required_for": ["selfhost-production", "kubernetes-production"],
        "no_log": True,
        "placeholder_disallowed": True,
    }


def test_selfhost_notification_mounts_the_dedicated_webhook_secret() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )

    notification = compose["services"]["notification"]
    assert notification["environment"]["NOTIFICATION_WEBHOOK_SECRET_FILE"] == (
        "/run/secrets/notification_webhook_secret"
    )
    assert "notification_webhook_secret" in notification["secrets"]
    assert compose["secrets"]["notification_webhook_secret"]["file"].endswith(
        "/notification_webhook_secret"
    )


def test_kubernetes_notification_reads_the_generated_webhook_secret() -> None:
    resources = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    deployment = next(
        resource
        for resource in resources
        if resource
        and resource.get("kind") == "Deployment"
        and resource["metadata"]["name"] == "notification"
    )
    env = {
        item["name"]: item
        for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }

    assert env["NOTIFICATION_WEBHOOK_SECRET"]["valueFrom"]["secretKeyRef"] == {
        "name": "marty-secrets",
        "key": "NOTIFICATION_WEBHOOK_SECRET",
    }
    deploy_script = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert "resolve_secret_input NOTIFICATION_WEBHOOK_SECRET" in deploy_script
    assert (
        '--from-literal=NOTIFICATION_WEBHOOK_SECRET="$notification_webhook_secret"'
        in deploy_script
    )
