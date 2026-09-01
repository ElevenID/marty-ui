"""The shared service image must expose only allowlisted Rust executables."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUST_SERVICES = {
    "applicant": "marty-applicant",
    "auth": "marty-auth",
    "compliance_profile": "marty-compliance-profile",
    "credential_template": "marty-credential-template",
    "deployment_profile": "marty-deployment-profile",
    "device_registration": "marty-device-registration",
    "event_stream": "marty-event-stream",
    "flow": "marty-flow",
    "gateway": "marty-gateway",
    "issuance_native": "marty-issuance-service",
    "notification": "marty-notification",
    "organization": "marty-organization",
    "presentation_policy": "marty-presentation-policy",
    "revocation_profile": "marty-revocation-profile",
    "signing_keys": "marty-signing-keys",
    "trust_profile": "marty-trust-profile",
    "verification": "marty-verification-service",
}
UNROUTED_RUST_BINARIES = {
    "marty-canvas-sync-worker",
    "marty-verifier-positive-gate",
}
ALL_RUST_BINARIES = set(RUST_SERVICES.values()) | UNROUTED_RUST_BINARIES


def test_shared_service_image_builds_all_rust_binaries_once() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("RUN cargo build --locked --release") == 1
    assert dockerfile.count(" --bin marty-") == len(ALL_RUST_BINARIES)
    assert dockerfile.count("COPY --from=rust-service-builder") == len(
        ALL_RUST_BINARIES
    )


def test_container_entrypoint_is_the_exact_closed_rust_allowlist() -> None:
    script = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "python" not in script.lower()
    assert "service_runner" not in script
    assert "Unsupported SERVICE_NAME" in script
    assert "exit 64" in script
    assert script.count('if [ "$MODULE_NAME" = ') == len(RUST_SERVICES)
    assert script.count("exec /usr/local/bin/marty-") == len(RUST_SERVICES)
    for service_name, binary in RUST_SERVICES.items():
        assert f'if [ "$MODULE_NAME" = "{service_name}" ]; then' in script
        assert f"exec /usr/local/bin/{binary}" in script
    for binary in UNROUTED_RUST_BINARIES:
        assert f"exec /usr/local/bin/{binary}" not in script


def test_every_allowlisted_binary_is_built_and_copied() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    for binary in ALL_RUST_BINARIES:
        assert f"--bin {binary}" in dockerfile
        assert (
            f"/build/rust/target/release/{binary} /usr/local/bin/{binary}"
            in dockerfile
        )


def test_deleted_python_service_directories_do_not_return() -> None:
    for service_name in RUST_SERVICES:
        service_dir = ROOT / "services" / service_name
        if service_dir.is_dir():
            assert not list(service_dir.rglob("*.py"))


def test_registry_builder_separates_rust_services_from_python_migrations() -> None:
    script = (ROOT / "scripts" / "build-push-registry.sh").read_text(encoding="utf-8")
    service_args = script.split('"services/Dockerfile"', maxsplit=1)[1].split(
        "done < <(catalog_services app)", maxsplit=1
    )[0]
    migration_args = script.split('"services/Dockerfile.migrations"', maxsplit=1)[1].split(
        '"docker/ui.Dockerfile"', maxsplit=1
    )[0]

    assert "MARTY_RS_URI" not in service_args
    assert "MARTY_COMMON_URI" not in service_args
    for marker in (
        "MARTY_RS_URI",
        "MARTY_RS_DIGEST",
        "MARTY_VERIFICATION_URI",
        "MARTY_VERIFICATION_DIGEST",
        "MARTY_ISO18013_URI",
        "MARTY_ISO18013_DIGEST",
        "MARTY_COMMON_URI",
        "MARTY_COMMON_DIGEST",
    ):
        assert marker in migration_args
