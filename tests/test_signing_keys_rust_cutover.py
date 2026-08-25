from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_shared_service_image_dispatches_signing_keys_to_rust() -> None:
    dockerfile = read("services/Dockerfile")
    entrypoint = read("services/entrypoint.sh")

    assert "-p marty-signing-keys --bin marty-signing-keys" in dockerfile
    assert "target/release/marty-signing-keys" in dockerfile
    assert 'if [ "$MODULE_NAME" = "signing_keys" ]' in entrypoint
    assert "exec /usr/local/bin/marty-signing-keys" in entrypoint


def test_superseded_python_signing_and_gateway_adapters_are_deleted() -> None:
    assert not list((ROOT / "services" / "signing_keys").glob("*.py"))
    assert not (ROOT / "services" / "gateway").exists()


def test_gateway_signing_compatibility_is_native_and_contract_driven() -> None:
    compatibility = read("rust/services/gateway/src/signing_compat.rs")
    runtime = read("rust/services/gateway/src/runtime.rs")

    assert "gateway-internal-signing-behavior.json" in compatibility
    assert "internal_signing_compatibility_handler" in runtime
    assert "constant_time_header_matches" in runtime
    assert '"Invalid internal API key"' in runtime
    assert "signing_service_request" in runtime


def test_signing_key_kernels_and_internal_http_surface_have_one_rust_owner() -> None:
    http = read("rust/services/signing-keys/src/http.rs")
    registry = read("rust/services/signing-keys/src/registry.rs")
    documents = read("rust/services/signing-keys/src/documents.rs")
    profiles = read("rust/services/signing-keys/src/profiles.rs")

    for path in (
        "/internal/kms/sign",
        "/internal/kms/public-key",
        "/internal/kms/verify",
        "/internal/config/validate",
        "/internal/registry/catalog",
        "/internal/registry/normalize-service",
        "/internal/registry/normalize",
        "/internal/registry/resolve",
        "/internal/documents/certificate/inspect",
        "/internal/documents/certificate-alerts",
        "/internal/profiles/{organization_id}/normalize",
        "/internal/profiles/{organization_id}/validate-binding",
        "/internal/profiles/{organization_id}/find",
        "/internal/profiles/{organization_id}/find-duplicate",
    ):
        assert path in http
    assert "pub struct RegistryStore" in registry
    assert "pub struct DocumentStore" in documents
    assert "pub struct ProfileStore" in profiles


def test_base_stack_wires_gateway_to_the_internal_rust_signing_keys_service() -> None:
    compose = read("docker-compose.base.yml")

    assert "SIGNING_KEYS_SERVICE_URL: http://signing-keys:8017" in compose
    assert 'SIGNING_KEYS_SERVICE_PORT: "8017"' in compose
    assert "SIGNING_KEYS_INTERNAL_API_KEY:" in compose
    assert "BAO_TOKEN:" in compose
    assert "SERVICE_NAME: signing-keys" in compose
    assert "SIGNING_KEYS_REDIS_URL: redis://redis:6379/2" in compose


def test_base_stack_keeps_signing_keys_on_the_internal_network() -> None:
    compose = read("docker-compose.base.yml")
    signing_keys = compose.split("\n  signing-keys:\n", 1)[1].split("\n  flow:\n", 1)[0]

    assert "\n    ports:" not in signing_keys
    assert "\n    networks:\n      - marty-network" in signing_keys


def test_beta_stack_authenticates_signing_keys_to_redis() -> None:
    compose = read("docker-compose.beta.yml")
    signing_keys = compose.split("\n  signing-keys:\n", 1)[1].split(
        "\n  flow:\n", 1
    )[0]

    assert (
        "SIGNING_KEYS_REDIS_URL: redis://:${REDIS_PASSWORD:?REDIS_PASSWORD must be set for beta}@redis:6379/2"
        in signing_keys
    )


def test_selfhost_stack_runs_rust_signing_keys_with_secret_files() -> None:
    compose = read("docker-compose.selfhost.prod.yml")

    assert "  signing-keys:\n" in compose
    assert "SIGNING_KEYS_INTERNAL_API_KEY_FILE: /run/secrets/issuance_api_key" in compose
    assert "BAO_TOKEN_FILE: /run/secrets/openbao_service_token" in compose
    assert "SIGNING_KEYS_REDIS_URL: redis://redis:6379/2" in compose
    assert 'test: ["CMD", "curl", "-f", "http://localhost:8017/health"]' in compose
