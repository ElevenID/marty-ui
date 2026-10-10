"""The shared service image must expose only allowlisted Rust executables."""

from pathlib import Path
import re

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
RUST_SERVICES = {
    "applicant": "marty-applicant",
    "auth": "marty-auth",
    "canvas_sync_worker": "marty-canvas-sync-worker",
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
    "passport_beta_bureau": "marty-passport-beta-bureau",
    "passport_provider_ingress": "marty-passport-provider-ingress",
    "passport_callback_signer": "marty-passport-callback-signer",
    "passport_callback_signer_supported": "marty-passport-callback-signer-supported",
    "presentation_policy": "marty-presentation-policy",
    "revocation_profile": "marty-revocation-profile",
    "signing_keys": "marty-signing-keys",
    "trust_profile": "marty-trust-profile",
    "verification": "marty-verification-service",
}
UNROUTED_RUST_BINARIES = {
    "marty-verifier-positive-gate",
    "marty-passport-acceptance-api-key",
}
ALL_RUST_BINARIES = set(RUST_SERVICES.values()) | UNROUTED_RUST_BINARIES


def test_shared_service_image_builds_all_rust_binaries_once() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    build_script = (ROOT / "scripts" / "build-rust-service-binaries.sh").read_text(
        encoding="utf-8"
    )

    assert build_script.count('exec cargo build --locked --release "$@"') == 1
    assert build_script.count(" --bin marty-") == len(ALL_RUST_BINARIES)
    assert (
        dockerfile.count("run-public-rust-build build-rust-service-binaries default")
        == 1
    )
    assert "PASSPORT_SELF_SIGNED_TEST" not in dockerfile
    assert dockerfile.count("COPY --from=rust-service-builder") == len(
        ALL_RUST_BINARIES
    )


def test_public_builder_cooks_dependencies_before_copying_all_source() -> None:
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    dependencies = dockerfile.split(
        "FROM rust-service-cache AS rust-service-dependencies", 1
    )[1]
    builder = dockerfile.split(
        "FROM rust-service-dependencies AS rust-service-builder", 1
    )[1]
    assert "FROM rust:1.95-bookworm@sha256:" in dockerfile
    assert "cargo install cargo-chef --locked --version 0.1.78" in dockerfile
    assert (
        "ADD --checksum=sha256:aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588"
        in dockerfile
    )
    assert (
        "COPY --from=rust-service-planner /build/rust/recipe.json recipe.json"
        in dependencies
    )
    assert "COPY --from=rust-service-planner /build/rust/third_party" in dependencies
    assert dependencies.index(
        "cargo chef cook --locked --release --workspace"
    ) < dependencies.index("FROM rust-service-dependencies AS rust-service-builder")
    assert builder.index("COPY rust /build/rust") < builder.index(
        "run-public-rust-build build-rust-service-binaries default"
    )
    assert (
        builder.count("run-public-rust-build build-rust-service-binaries default") == 1
    )
    assert builder.count("RUN --mount=type=cache,id=marty-public-cargo-registry") == 1
    assert dependencies.count("--mount=type=secret,id=sccache_token") == 2
    assert "RUSTFLAGS" not in dockerfile
    assert "ENV SCCACHE" not in dockerfile
    wrapper = (ROOT / "scripts/ci/run-public-rust-build.sh").read_text(encoding="utf-8")
    assert "export RUSTC_WRAPPER=sccache" in wrapper
    assert "READ_ONLY|READ_WRITE" in wrapper
    assert '"$@"' in wrapper


def test_public_builder_context_keeps_embedded_runtime_inputs_but_not_tests() -> None:
    ignore = (
        (ROOT / "services/Dockerfile.dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    for entry in (
        "!rust/**",
        "!proto/**",
        "!contracts/**",
        "!services/auth/assets/**",
        "!services/entrypoint.sh",
        "!scripts/build-rust-service-binaries.sh",
        "!scripts/ci/run-public-rust-build.sh",
        "!scripts/load-secrets-env.sh",
        "rust/services/*/tests",
        "rust/crates/*/tests",
    ):
        assert entry in ignore
    assert "rust/third_party" not in ignore
    assert "contracts/*-oracle.json" not in ignore


def test_public_builder_preserves_supported_amd64_and_arm64_registry_builds() -> None:
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    registry = (ROOT / "scripts/build-push-registry.sh").read_text(encoding="utf-8")
    assert "ARG TARGETARCH" in dockerfile
    assert "amd64) archive=/tmp/sccache.tar.gz; target=x86_64" in dockerfile
    assert "arm64) archive=/tmp/sccache-aarch64.tar.gz; target=aarch64" in dockerfile
    assert (
        "ADD --checksum=sha256:aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588"
        in dockerfile
    )
    assert (
        "ADD --checksum=sha256:f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784"
        in dockerfile
    )
    assert "linux/arm64" in registry
    assert '"services/Dockerfile"' in registry


def test_public_build_cache_is_read_only_in_ci_and_written_only_by_main_release() -> (
    None
):
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    cd = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text(encoding="utf-8"))
    warm = yaml.safe_load(
        (ROOT / ".github/workflows/warm-ci-caches.yml").read_text(encoding="utf-8")
    )
    ci_steps = ci["jobs"]["test-rust-services"]["steps"]
    public = [
        step
        for step in ci_steps
        if step.get("name") == "Build public selfhost image"
    ]
    assert len(public) == 1
    for step in public:
        config = step["with"]
        assert config["file"] == "services/Dockerfile"
        assert config["cache-from"] == "type=gha,scope=marty-ui-public-services"
        assert "cache-to" not in config
        assert config["secret-envs"] == (
            "sccache_token=SCCACHE_GHA_RUNTIME_TOKEN\n"
            "sccache_url=SCCACHE_GHA_CACHE_URL\n"
            "sccache_mode=SCCACHE_GHA_RW_MODE\n"
        )
    ci_credential = next(
        step
        for step in ci_steps
        if step.get("name") == "Expose public image compiler cache credentials"
    )
    assert "'SCCACHE_GHA_RW_MODE', 'READ_ONLY'" in ci_credential["with"]["script"]
    release = cd["jobs"]["build-services"]
    release_steps = release["steps"]
    release_credential = next(
        step
        for step in release_steps
        if step.get("name") == "Expose public image compiler cache credentials"
    )
    assert "'SCCACHE_GHA_RW_MODE', 'READ_ONLY'" in release_credential["with"]["script"]
    release_build = next(step for step in release_steps if step.get("id") == "services")
    config = release_build["with"]
    assert config["cache-from"] == "type=gha,scope=marty-ui-public-services"
    assert "cache-to" not in config
    assert config["sbom"] is True
    assert config["provenance"] == "mode=max"
    warmer = warm["jobs"]["public-services"]
    assert warmer["if"] == "github.ref == 'refs/heads/main'"
    assert warmer["permissions"] == {"actions": "write", "contents": "read"}
    warm_build = next(
        step
        for step in warmer["steps"]
        if step.get("name") == "Warm public service dependency layers"
    )
    assert warm_build["with"]["target"] == "rust-service-dependencies"
    assert (
        warm_build["with"]["cache-to"]
        == "type=gha,mode=max,scope=marty-ui-public-services,ignore-error=true"
    )
    release_warm = next(
        step
        for step in warmer["steps"]
        if step.get("name") == "Warm public service release-binary compiler outputs"
    )
    assert warmer["steps"].index(warm_build) < warmer["steps"].index(release_warm)
    assert release_warm["uses"] == warm_build["uses"]
    release_config = release_warm["with"]
    assert release_config["file"] == "services/Dockerfile"
    assert release_config["target"] == "rust-service-builder"
    assert release_config["cache-from"] == "type=gha,scope=marty-ui-public-services"
    assert release_config["secret-envs"] == warm_build["with"]["secret-envs"]
    assert release_config["push"] is False
    assert release_config["provenance"] is False
    assert "cache-to" not in release_config


def assert_closed_rust_dispatch(script: str) -> None:
    assert "python" not in script.lower()
    assert "service_runner" not in script
    assert "Unsupported SERVICE_NAME" in script
    assert "exit 64" in script
    assert script.count('if [ "$MODULE_NAME" = ') == len(RUST_SERVICES)
    assert script.count("exec /usr/local/bin/marty-") == len(RUST_SERVICES)
    branches = re.findall(
        r'^if \[ "\$MODULE_NAME" = "([a-z_]+)" \]; then\n(.*?)^fi$',
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert len(branches) == len(RUST_SERVICES)
    assert {name for name, _ in branches} == set(RUST_SERVICES)
    for service_name, body in branches:
        expected = f"exec /usr/local/bin/{RUST_SERVICES[service_name]}"
        if service_name == "verification":
            expected += ' "$@"'
        assert [
            line.strip()
            for line in body.splitlines()
            if line.strip().startswith("exec ")
        ] == [expected]
    for binary in UNROUTED_RUST_BINARIES:
        assert f"exec /usr/local/bin/{binary}" not in script


def test_container_entrypoint_is_the_exact_closed_rust_allowlist() -> None:
    script = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")
    assert_closed_rust_dispatch(script)


def test_closed_allowlist_rejects_swapped_dispatch_bodies() -> None:
    script = (ROOT / "services" / "entrypoint.sh").read_text(encoding="utf-8")
    swapped = script.replace("/usr/local/bin/marty-auth", "SYNTHETIC_SWAP")
    swapped = swapped.replace(
        "/usr/local/bin/marty-gateway", "/usr/local/bin/marty-auth"
    )
    swapped = swapped.replace("SYNTHETIC_SWAP", "/usr/local/bin/marty-gateway")
    assert swapped != script
    with pytest.raises(AssertionError):
        assert_closed_rust_dispatch(swapped)


def test_every_allowlisted_binary_is_built_and_copied() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    build_script = (ROOT / "scripts" / "build-rust-service-binaries.sh").read_text(
        encoding="utf-8"
    )

    for binary in ALL_RUST_BINARIES:
        assert f"--bin {binary}" in build_script
        assert (
            f"/build/rust/target/release/{binary} /usr/local/bin/{binary}" in dockerfile
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
    migration_args = script.split('"services/Dockerfile.migrations"', maxsplit=1)[
        1
    ].split('"docker/ui.Dockerfile"', maxsplit=1)[0]

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
