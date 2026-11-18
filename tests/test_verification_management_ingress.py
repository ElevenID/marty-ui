"""Marty-owned deployment gates for Verification management ingress."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_production_like_stacks_disable_identityless_verification_grpc() -> None:
    selfhost = yaml.safe_load(
        (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    )
    beta = yaml.safe_load(
        (ROOT / "docker-compose.beta.yml").read_text(encoding="utf-8")
    )
    assert (
        selfhost["services"]["verification"]["environment"]["VERIF_GRPC_ENABLED"]
        == "false"
    )
    assert (
        beta["services"]["verification"]["environment"]["VERIF_GRPC_ENABLED"] == "false"
    )

    deployments = {
        document["metadata"]["name"]: document
        for document in yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
        if document and document.get("kind") == "Deployment"
    }
    [container] = deployments["verification"]["spec"]["template"]["spec"]["containers"]
    environment = {entry["name"]: entry.get("value") for entry in container["env"]}
    assert environment["VERIF_GRPC_ENABLED"] == "false"


def test_shared_envoy_has_no_identityless_verification_grpc_route() -> None:
    envoy = (ROOT / "config/envoy/envoy.yaml").read_text(encoding="utf-8")

    assert "marty.ui.verification.v1.VerificationService" not in envoy
    assert "verification_grpc" not in envoy


def test_compose_verification_waits_for_authoritative_reference_services() -> None:
    for compose_path in (
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
    ):
        compose = yaml.safe_load((ROOT / compose_path).read_text(encoding="utf-8"))
        dependencies = compose["services"]["verification"]["depends_on"]

        assert dependencies["presentation-policy"]["condition"] == "service_healthy"
        assert dependencies["credential-template"]["condition"] == "service_healthy"
