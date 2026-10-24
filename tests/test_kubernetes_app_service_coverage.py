"""Marty-owned production-manifest coverage tests.

These tests protect Marty deployment metadata; they are not part of the
imported protocol compliance corpus, which remains unchanged.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
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


def _production_resources(kind: str, resources: list[dict]) -> dict[str, dict]:
    selected: dict[str, dict] = {}
    for document in resources:
        if document.get("kind") != kind or document["metadata"].get("namespace") != "marty-prod":
            continue
        name = document["metadata"]["name"]
        assert name not in selected, f"Duplicate marty-prod {kind}: {name}"
        selected[name] = document
    return selected


def _catalog_app_services() -> set[str]:
    catalog = json.loads(SERVICE_CATALOG.read_text(encoding="utf-8"))
    return set(catalog["groups"]["app"])


def test_every_catalog_app_has_a_kubernetes_deployment() -> None:
    assert _catalog_app_services() <= _production_resources("Deployment", _manifest_resources()).keys()


def test_every_request_serving_app_has_a_kubernetes_service() -> None:
    request_serving_apps = _catalog_app_services() - {"canvas-sync-worker"}
    assert request_serving_apps <= _production_resources("Service", _manifest_resources()).keys()


def test_revocation_profile_uses_zero_downtime_rolling_updates() -> None:
    deployment = _production_resources("Deployment", _manifest_resources())["revocation-profile"]

    assert deployment["spec"]["strategy"] == {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
    }


def test_new_internal_services_have_expected_ports_and_shared_state() -> None:
    deployments = _production_resources("Deployment", _manifest_resources())

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


@pytest.mark.parametrize("kind", ["Deployment", "Service"])
def test_catalog_coverage_rejects_duplicate_production_resource(kind: str) -> None:
    resources = _manifest_resources()
    assert "gateway" in _production_resources(kind, resources)
    gateway = next(
        document
        for document in resources
        if document.get("kind") == kind and document["metadata"]["name"] == "gateway"
    )
    resources.append(deepcopy(gateway))
    with pytest.raises(AssertionError, match=f"Duplicate marty-prod {kind}: gateway"):
        _production_resources(kind, resources)


@pytest.mark.parametrize("kind", ["Deployment", "Service"])
def test_catalog_coverage_requires_production_namespace(kind: str) -> None:
    resources = _manifest_resources()
    required = _catalog_app_services()
    if kind == "Service":
        required.remove("canvas-sync-worker")
    assert required <= _production_resources(kind, resources).keys()
    gateway = next(
        document
        for document in resources
        if document.get("kind") == kind and document["metadata"]["name"] == "gateway"
    )
    gateway["metadata"]["namespace"] = "other-synthetic-namespace"
    assert not required <= _production_resources(kind, resources).keys()


def test_catalog_coverage_ignores_unrelated_namespace_decoy() -> None:
    resources = _manifest_resources()
    gateway = _production_resources("Deployment", resources)["gateway"]
    decoy = deepcopy(gateway)
    decoy["metadata"]["namespace"] = "other-synthetic-namespace"
    resources.append(decoy)
    assert _production_resources("Deployment", resources)["gateway"] is gateway
