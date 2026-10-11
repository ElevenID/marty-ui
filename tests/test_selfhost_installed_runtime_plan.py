"""Local contract tests for the unqualified extracted-runtime DAG plan."""

from __future__ import annotations

import copy
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SECRET_ROOT = ROOT / "_test_secrets"
sys.path.insert(0, str(ROOT / "scripts"))
contract = importlib.import_module("check_selfhost_installed_runtime_plan")
BETA_SERVICES = contract.BETA_SERVICES
EXPECTED_DEPENDENCIES = contract.EXPECTED_DEPENDENCIES
EXPECTED_ROLE_SECRETS = contract.EXPECTED_ROLE_SECRETS
EXPECTED_SECRET_NAMES = contract.EXPECTED_SECRET_NAMES
EXPECTED_SERVICES = contract.EXPECTED_SERVICES
plan = contract.plan


PREFLIGHT = {
    "schema": "marty.selfhost-consumer-preflight/v1",
    "qualification": "unqualified",
    "archive_sha256": "a" * 64,
    "image_lock_sha256": "c" * 64,
    "transaction_sha256": "d" * 64,
    "release": "v1.2.3",
    "source_sha": "b" * 40,
    "run_id": "123",
    "service_count": 31,
}


def model() -> dict:
    services = {name: {"profiles": ["beta-tunnel"] if name in BETA_SERVICES else [],
                       "healthcheck": {"test": ["CMD", "true"]}}
                for name in EXPECTED_SERVICES}
    for name, dependencies in EXPECTED_DEPENDENCIES.items():
        services[name]["depends_on"] = {
            peer: {"condition": condition, "required": True}
            for peer, condition in dependencies.items()}
        for peer, condition in dependencies.items():
            if condition == "service_completed_successfully":
                services[peer]["restart"] = "no"
    for name, bindings in EXPECTED_ROLE_SECRETS.items():
        services[name]["secrets"] = [
            {"source": secret, "target": f"/run/secrets/{secret}"}
            for secret in sorted(bindings)]
    return {"services": services, "secrets": {
        name: {"name": f"marty-selfhost-prod_{name}",
               "file": str(SECRET_ROOT / name)} for name in EXPECTED_SECRET_NAMES},
            "configs": {}}


def test_plan_is_exact_artifact_bound_and_covers_both_profiles() -> None:
    result = plan(model(), PREFLIGHT, SECRET_ROOT)
    assert result["qualification"] == "unqualified"
    assert result["archive_sha256"] == "a" * 64
    assert result["service_count"] == 31
    assert result["default_service_count"] == 29
    assert result["beta_tunnel_service_count"] == 2
    assert result["dependency_count"] == sum(map(len, EXPECTED_DEPENDENCIES.values()))
    layers = result["startup_layers"]
    assert sum(map(len, layers)) == 31
    assert next(i for i, layer in enumerate(layers) if "db-migrate" in layer) < next(
        i for i, layer in enumerate(layers) if "signing-keys" in layer)


@pytest.mark.parametrize("change", [
    lambda m: m["services"].pop("issuance-native"),
    lambda m: m["services"]["edge"]["depends_on"].update({
        "missing": {"condition": "service_healthy", "required": True}}),
    lambda m: m["services"]["gateway"].update({"depends_on": {
        "edge": {"condition": "service_healthy", "required": True}}}),
    lambda m: m["services"]["edge"].update({"profiles": ["beta-tunnel"]}),
    lambda m: m["services"]["edge"].update({"depends_on": {
        "cloudflared-beta": {"condition": "service_healthy", "required": True}}}),
    lambda m: m["services"]["redis"].pop("healthcheck"),
    lambda m: m["services"]["redis"].update({"healthcheck": {}}),
    lambda m: m["services"]["redis"].update({"healthcheck": {"disable": True}}),
    lambda m: m["services"]["redis"].update({"healthcheck": {"test": ["NONE"]}}),
    lambda m: m["services"]["redis"].update({"healthcheck": {"test": []}}),
    lambda m: m["services"]["db-migrate"].update({"restart": "always"}),
    lambda m: m["services"]["gateway"]["depends_on"].pop("auth"),
    lambda m: m["services"]["signing-keys"].update({"secrets": [{"source": "undeclared"}]}),
    lambda m: m["services"]["gateway"]["secrets"].pop(),
    lambda m: m["secrets"].pop("issuance_api_key"),
    lambda m: m["secrets"].update({"extra": {"name": "extra", "file": str(SECRET_ROOT / "extra")}}),
    lambda m: m["secrets"]["issuance_api_key"].update({"file": str(ROOT / "outside")}),
    lambda m: m["services"]["gateway"]["secrets"][0].update({"target": "/tmp/key"}),
    lambda m: m.update({"configs": {"extra": {"file": str(ROOT / "outside")}}}),
])
def test_plan_rejects_dag_and_declaration_drift(change) -> None:
    changed = model()
    change(changed)
    with pytest.raises(ValueError):
        plan(changed, PREFLIGHT, SECRET_ROOT)


def test_plan_rejects_unbound_preflight() -> None:
    changed = copy.deepcopy(PREFLIGHT)
    changed["service_count"] = 29
    with pytest.raises(ValueError, match="preflight"):
        plan(model(), changed, SECRET_ROOT)


def test_source_compose_has_reviewed_full_dag() -> None:
    env = {**os.environ, "SELFHOST_STATE_DIR": str(ROOT / "_test_state"),
           "SELFHOST_SECRET_DIR": str(ROOT / "_test_secrets")}
    completed = subprocess.run(
        ["docker", "compose", "--profile", "*", "--env-file",
         ".env.selfhost.production.example", "-f", "docker-compose.selfhost.prod.yml",
         "-f", "docker-compose.selfhost.bundle.override.yml", "config", "--format", "json"],
        cwd=ROOT, env=env, check=True, capture_output=True, text=True,
    )
    result = plan(json.loads(completed.stdout), PREFLIGHT, SECRET_ROOT)
    assert result["service_count"] == 31
    assert result["dependency_count"] > 30
