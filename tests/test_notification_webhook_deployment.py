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


def test_notification_runtime_receives_openbao_token_as_a_secret_file() -> None:
    compose = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    notification = compose["services"]["notification"]
    assert notification["environment"]["NOTIFICATION_OPENBAO_TOKEN_FILE"] == (
        "/run/secrets/notification_openbao_token"
    )
    assert "notification_openbao_token" in notification["secrets"]
    assert "openbao_service_token" not in notification["secrets"]

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
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {item["name"]: item for item in container["env"]}
    assert env["NOTIFICATION_OPENBAO_TOKEN_FILE"]["value"] == (
        "/run/secrets/notification_openbao_token"
    )
    assert container["volumeMounts"] == [
        {
            "name": "notification-openbao-token",
            "mountPath": "/run/secrets",
            "readOnly": True,
        }
    ]
    assert pod["volumes"][0]["secret"]["items"] == [
        {
            "key": "NOTIFICATION_OPENBAO_TOKEN",
            "path": "notification_openbao_token",
        }
    ]


def test_openbao_provisions_a_non_exportable_purpose_specific_webhook_key() -> None:
    init_script = (ROOT / "docker/openbao-init.sh").read_text(encoding="utf-8")
    key_id = "notification-webhook-envelope-marty-aes256"

    assert f"transit/keys/{key_id}" in init_script
    assert "type=aes256-gcm96 exportable=false" in init_script
    assert f'path "transit/encrypt/{key_id}"' in init_script
    assert f'path "transit/decrypt/{key_id}"' in init_script
    assert f'path "transit/keys/{key_id}"' in init_script
    assert f'path "transit/export/{key_id}"' not in init_script
    assert init_script.count(f'path "transit/decrypt/{key_id}"') == 1
    dedicated_policy = init_script.split(
        "Writing Notification webhook envelope policy...", 1
    )[1]
    assert "notification-webhook-service" in dedicated_policy
    assert f'path "transit/decrypt/{key_id}"' in dedicated_policy


def test_notification_openbao_identity_is_required_and_bootstrapped() -> None:
    catalog = json.loads(
        (ROOT / "deploy-config/catalog/secrets.json").read_text(encoding="utf-8")
    )
    assert catalog["secrets"]["notification_openbao_token"] == {
        "env": "NOTIFICATION_OPENBAO_TOKEN",
        "file_env": "NOTIFICATION_OPENBAO_TOKEN_FILE",
        "compose_secret": "notification_openbao_token",
        "required_for": ["selfhost-production", "kubernetes-production"],
        "no_log": True,
        "placeholder_disallowed": True,
    }

    selfhost_init = (ROOT / "docker/openbao-selfhost-init.sh").read_text(
        encoding="utf-8"
    )
    external_init = (ROOT / "scripts/bootstrap-selfhost-vault.sh").read_text(
        encoding="utf-8"
    )
    deploy = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    assert "-policy=notification-webhook-service" in selfhost_init
    assert "notification_openbao_token" in external_init
    assert "-policy=notification-webhook-service" in external_init
    assert "resolve_secret_input NOTIFICATION_OPENBAO_TOKEN" in deploy
    assert '--from-literal=NOTIFICATION_OPENBAO_TOKEN="$notification_openbao_token"' in deploy
