from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_shared_service_image_dispatches_signing_keys_to_rust() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "cargo build --locked --release -p marty-signing-keys" in dockerfile
    assert "target/release/marty-signing-keys" in dockerfile
    assert 'if [ "$MODULE_NAME" = "signing_keys" ]' in entrypoint
    assert "exec /usr/local/bin/marty-signing-keys" in entrypoint


def test_superseded_python_signing_keys_scaffold_is_deleted() -> None:
    assert not list((ROOT / "services" / "signing_keys").glob("*.py"))


def test_superseded_python_kms_provider_kernel_is_deleted() -> None:
    adapter_package = ROOT / "services" / "gateway" / "kms_adapters"
    assert not list(adapter_package.glob("*.py"))
    route = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    assert "gateway.kms_adapters" not in route
    assert "der_to_raw_ecdsa" not in route


def test_gateway_calls_authenticated_rust_kms_endpoints() -> None:
    adapter = (ROOT / "services" / "gateway" / "native_signing_keys.py").read_text(
        encoding="utf-8"
    )
    for path in (
        "/internal/kms/sign",
        "/internal/kms/public-key",
        "/internal/kms/verify",
    ):
        assert path in adapter
    assert 'headers={"X-API-Key": _internal_api_key()}' in adapter


def test_service_registration_validation_has_one_rust_owner() -> None:
    route = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    adapter = (ROOT / "services" / "gateway" / "native_signing_keys.py").read_text(
        encoding="utf-8"
    )
    assert "validate_native_signing_service(body)" in route
    assert "/internal/config/validate" in adapter
    for superseded_name in (
        "_run_service_validation",
        "_append_baseline_validation_checks",
        "_validate_provider_key_reference",
        "_run_cloud_validator_probe",
        "_validate_transit_provider",
    ):
        assert superseded_name not in route


def test_base_stack_wires_gateway_to_the_rust_signing_keys_service() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")

    assert "SIGNING_KEYS_SERVICE_URL: http://signing-keys:8017" in compose
    assert 'SIGNING_KEYS_SERVICE_PORT: "8017"' in compose
    assert "SIGNING_KEYS_INTERNAL_API_KEY:" in compose
    assert "BAO_TOKEN:" in compose
    assert "SERVICE_NAME: signing-keys" in compose


def test_selfhost_stack_runs_rust_signing_keys_with_secret_files() -> None:
    compose = (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")

    assert "  signing-keys:\n" in compose
    assert "SIGNING_KEYS_INTERNAL_API_KEY_FILE: /run/secrets/issuance_api_key" in compose
    assert "BAO_TOKEN_FILE: /run/secrets/openbao_service_token" in compose
    assert 'test: ["CMD", "curl", "-f", "http://localhost:8017/health"]' in compose
