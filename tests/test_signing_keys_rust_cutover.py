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


def test_registry_normalization_resolution_and_storage_have_one_rust_owner() -> None:
    route = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    adapter = (ROOT / "services" / "gateway" / "native_signing_keys.py").read_text(
        encoding="utf-8"
    )
    rust_registry = (
        ROOT / "rust" / "services" / "signing-keys" / "src" / "registry.rs"
    ).read_text(encoding="utf-8")

    for path in (
        "/internal/registry/catalog",
        "/internal/registry/normalize-service",
        "/internal/registry/normalize",
        "/internal/registry/resolve",
        "/internal/registry/{quote(organization_id, safe='')}",
    ):
        assert path in adapter
    for superseded_name in (
        "KEY_MANAGEMENT_SERVICE_TYPES",
        "_registry_from_legacy_body",
        "def _service_type_definition",
    ):
        assert superseded_name not in route
    assert "pub struct RegistryStore" in rust_registry
    assert 'format!("org:{organization_id}:signing-key-services")' in rust_registry


def test_certificate_jwks_and_did_documents_have_one_rust_owner() -> None:
    route = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    adapter = (ROOT / "services" / "gateway" / "native_signing_keys.py").read_text(
        encoding="utf-8"
    )
    rust_documents = (
        ROOT / "rust" / "services" / "signing-keys" / "src" / "documents.rs"
    ).read_text(encoding="utf-8")

    for path in (
        "/internal/documents/certificate/inspect",
        "/internal/documents/certificate-alerts",
        "/certificates/{quote(service_id, safe='')}",
        "/jwks/{quote(service_id, safe='')}",
        "/did/{quote(service_id, safe='')}",
        "/internal/documents/did-web/{quote(slug, safe='')}",
    ):
        assert path in adapter
    for superseded_name in (
        "_jwks_storage_key",
        "_service_certificates_storage_key",
        "_did_doc_storage_key",
        "_did_web_slug_key",
        "_claim_did_web_slug",
        "_load_did_registry_document",
        "_extract_cert_expiry_date",
    ):
        assert superseded_name not in route
    for owner in (
        "pub struct DocumentStore",
        "pub fn inspect_certificate",
        "pub fn certificate_alerts",
        "pub fn build_jwks_document",
        "pub fn build_did_document",
    ):
        assert owner in rust_documents


def test_issuer_profile_policy_selection_and_storage_have_one_rust_owner() -> None:
    route = (ROOT / "services" / "gateway" / "routes" / "signing_keys.py").read_text(
        encoding="utf-8"
    )
    adapter = (ROOT / "services" / "gateway" / "native_signing_keys.py").read_text(
        encoding="utf-8"
    )
    rust_profiles = (
        ROOT / "rust" / "services" / "signing-keys" / "src" / "profiles.rs"
    ).read_text(encoding="utf-8")

    for path in (
        "/internal/profiles/{quote(organization_id, safe='')}/normalize",
        "/internal/profiles/{quote(organization_id, safe='')}/validate-binding",
        "/internal/profiles/{quote(organization_id, safe='')}/find",
        "/internal/profiles/{quote(organization_id, safe='')}/find-duplicate",
    ):
        assert path in adapter
    for superseded_name in (
        "_issuer_profiles_storage_key",
        "_normalize_key_attestation_policy",
        "_assert_issuer_profile_service_compatible",
        "_assert_issuer_profile_key_compatible",
        "KEY_PURPOSE_CREDENTIAL_FORMATS",
        "PROTOCOL_CREDENTIAL_FORMAT_TO_WIRE",
    ):
        assert superseded_name not in route
    for owner in (
        "pub struct ProfileStore",
        "pub fn normalize_profile",
        "pub fn validate_binding",
        "pub fn duplicate_profile",
        "pub fn find_profiles",
    ):
        assert owner in rust_profiles
    assert 'format!("org:{organization_id}:issuer-profiles")' in rust_profiles


def test_base_stack_wires_gateway_to_the_rust_signing_keys_service() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")

    assert "SIGNING_KEYS_SERVICE_URL: http://signing-keys:8017" in compose
    assert 'SIGNING_KEYS_SERVICE_PORT: "8017"' in compose
    assert "SIGNING_KEYS_INTERNAL_API_KEY:" in compose
    assert "BAO_TOKEN:" in compose
    assert "SERVICE_NAME: signing-keys" in compose
    assert "SIGNING_KEYS_REDIS_URL: redis://redis:6379/2" in compose


def test_base_stack_keeps_signing_keys_on_the_internal_network() -> None:
    compose = (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    signing_keys = compose.split("\n  signing-keys:\n", 1)[1].split("\n  flow:\n", 1)[0]

    assert "\n    ports:" not in signing_keys
    assert "\n    networks:\n      - marty-network" in signing_keys


def test_selfhost_stack_runs_rust_signing_keys_with_secret_files() -> None:
    compose = (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")

    assert "  signing-keys:\n" in compose
    assert (
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE: /run/secrets/issuance_api_key" in compose
    )
    assert "BAO_TOKEN_FILE: /run/secrets/openbao_service_token" in compose
    assert "SIGNING_KEYS_REDIS_URL: redis://redis:6379/2" in compose
    assert 'test: ["CMD", "curl", "-f", "http://localhost:8017/health"]' in compose
