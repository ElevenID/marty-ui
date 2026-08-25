from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contract() -> dict[str, object]:
    return json.loads(text("contracts/gateway-rust-cutover.json"))


def test_only_the_native_gateway_runtime_remains() -> None:
    behavior = contract()
    runtime_owner = ROOT / str(behavior["runtime_owner"])
    python_runtime = ROOT / str(behavior["python_runtime_removed"])
    entrypoint = text("services/entrypoint.sh")

    assert runtime_owner.is_dir()
    assert not python_runtime.exists()
    assert 'if [ "$MODULE_NAME" = "gateway" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-gateway" in entrypoint
    assert behavior["python_runtime_fallback"] is False


def test_language_neutral_gateway_contracts_are_the_runtime_boundary() -> None:
    behavior = contract()
    rust_contract = text("rust/services/gateway/src/contract.rs")

    for field in (
        "route_contract",
        "authorization_contract",
        "middleware_contract",
        "runtime_contract",
    ):
        assert (ROOT / str(behavior[field])).is_file()
    assert 'include_str!("../../../../contracts/gateway-routes.json")' in rust_contract
    assert "EXPECTED_ROUTE_COUNT: usize = 434" in rust_contract
    assert not (ROOT / "scripts/gateway_route_contract.py").exists()


def test_native_gateway_has_shared_and_dedicated_image_paths() -> None:
    behavior = contract()
    binary = str(behavior["required_binary"])
    target = str(behavior["required_ci_target"])
    shared = text("services/Dockerfile")
    native = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")

    assert f"-p marty-gateway --bin {binary}" in shared
    assert f"/build/rust/target/release/{binary} /usr/local/bin/{binary}" in shared
    assert f"FROM runtime AS {target}" in native
    assert f"target: {target}" in workflow
    assert "tags: marty-gateway:ci" in workflow
    assert "Smoke-test gateway image" in workflow


def test_deployed_manifests_require_distributed_gateway_state() -> None:
    behavior = contract()
    base = text("docker-compose.base.yml")
    beta = text("docker-compose.beta.yml")
    selfhost = text("docker-compose.selfhost.prod.yml")
    config = text("rust/services/gateway/src/config.rs")

    base_gateway = base.split("\n  gateway:\n", 1)[1].split("\n  auth:\n", 1)[0]
    beta_gateway = beta.split("\n  gateway:\n", 1)[1].split("\n  auth:\n", 1)[0]
    selfhost_gateway = selfhost.split("\n  gateway:\n", 1)[1].split(
        "\n  auth:\n", 1
    )[0]

    assert behavior["production_requires_redis"] is True
    assert "REDIS_URL: redis://redis:6379" in base_gateway
    assert "REDIS_DB_GATEWAY:" in base_gateway
    assert "ENVIRONMENT: beta" in beta_gateway
    assert "REDIS_PASSWORD must be set for beta" in beta_gateway
    assert "REDIS_URL: redis://redis:6379" in selfhost_gateway
    assert 'value(values, "REDIS_URL")' in config
    assert 'url::Url::parse(raw).map_err(|_| error("REDIS_URL is invalid"))' in config


def test_deleted_python_gateway_cannot_reenter_ownership_inventory() -> None:
    ownership = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        item for item in ownership["capabilities"] if item["id"] == "gateway-service"
    )

    assert capability["status"] == "native-active"
    assert capability["canonical"]["paths"] == ["rust/services/gateway"]
    assert capability["legacy"] == []
    assert not any(
        str(item.get("path", "")).startswith("services/gateway")
        for item in ownership["guardrails"]["approved_imports"]
    )
