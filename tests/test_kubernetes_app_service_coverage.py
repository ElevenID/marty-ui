"""Marty-owned production-manifest coverage tests.

These tests protect Marty deployment metadata; they are not part of the
imported protocol compliance corpus, which remains unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_CATALOG = REPO_ROOT / "deploy-config" / "catalog" / "services.json"
MICROSERVICES_MANIFEST = REPO_ROOT / "k8s" / "oracle" / "07-microservices.yaml"


def _manifest_resources() -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(MICROSERVICES_MANIFEST.read_text(encoding="utf-8"))
        if isinstance(document, dict)
    ]


def _resource_names(kind: str) -> set[str]:
    return {
        document["metadata"]["name"]
        for document in _manifest_resources()
        if document.get("kind") == kind
    }


def _catalog_app_services() -> set[str]:
    catalog = json.loads(SERVICE_CATALOG.read_text(encoding="utf-8"))
    return set(catalog["groups"]["app"])


def test_every_catalog_app_has_a_kubernetes_deployment() -> None:
    assert _catalog_app_services() <= _resource_names("Deployment")


def test_every_request_serving_app_has_a_kubernetes_service() -> None:
    request_serving_apps = _catalog_app_services() - {"canvas-sync-worker"}
    assert request_serving_apps <= _resource_names("Service")


def test_new_internal_services_have_expected_ports_and_shared_state() -> None:
    deployments = {
        document["metadata"]["name"]: document
        for document in _manifest_resources()
        if document.get("kind") == "Deployment"
    }

    revocation = deployments["revocation-profile"]["spec"]["template"]["spec"]["containers"][0]
    device = deployments["device-registration"]["spec"]["template"]["spec"]["containers"][0]
    event_stream = deployments["event-stream"]["spec"]["template"]["spec"]["containers"][0]

    assert {port["containerPort"] for port in revocation["ports"]} == {8013, 9013}
    assert {item["name"]: item.get("value") for item in revocation["env"]}["REDIS_URL"] == (
        "redis://redis:6379/4"
    )
    assert {port["containerPort"] for port in device["ports"]} == {8014}
    assert {item["name"]: item.get("value") for item in device["env"]}["REDIS_URL"] == (
        "redis://redis:6379/5"
    )
    assert {port["containerPort"] for port in event_stream["ports"]} == {8015, 9015}
