from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_dedicated_native_image_compose_target_and_ci_gate_are_present() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    compose = text("docker-compose.base.yml")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS compliance_profile" in dockerfile
    assert "target: compliance_profile" in compose
    assert "target: compliance_profile" in workflow
    assert "tags: marty-compliance-profile:ci" in workflow


def test_only_native_compliance_profile_runtime_sources_remain() -> None:
    service = ROOT / "services" / "compliance_profile"
    assert not list(service.rglob("*.py"))
    manifest = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        value
        for value in manifest["capabilities"]
        if value["id"] == "compliance-profile-service"
    )
    assert capability["status"] == "native-active"
    assert capability["legacy"] == []
    guard = next(
        value
        for value in manifest["guardrails"]["native_service_guards"]
        if value["capability_id"] == "compliance-profile-service"
    )
    assert guard["forbidden_globs"] == ["services/compliance_profile/**/*.py"]


def test_behavior_contract_and_native_crate_are_owned() -> None:
    contract = json.loads(text("contracts/compliance-profile-service-behavior.json"))
    assert contract["service"] == "compliance-profile"
    assert len(contract["routes"]) == 8
    assert len(contract["policy_sections"]) == 7
    manifest = text("rust/services/compliance-profile/Cargo.toml")
    assert 'name = "marty-compliance-profile"' in manifest
    workspace = text("rust/Cargo.toml")
    assert '"services/compliance-profile"' in workspace


def test_deployed_runtime_requires_scoped_workload_identity() -> None:
    beta = text("docker-compose.beta.yml")
    selfhost = text("docker-compose.selfhost.prod.yml")
    kubernetes = text("k8s/oracle/07-microservices.yaml")
    for deployment in (beta, selfhost, kubernetes):
        assert "compliance-profile-workload-tls" in deployment or (
            "compliance_profile_workload_client_cert" in deployment
        )
