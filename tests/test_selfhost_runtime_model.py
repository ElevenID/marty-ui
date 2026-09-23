"""Keep stage A attached to actual generated/extracted bundle acceptance."""

from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = "rust/crates/selfhost-bundle/tests/executable_bundle.rs"
SHARED = "rust/crates/selfhost-bundle/tests/support/extracted_bundle.rs"
ADAPTER = "rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs"
NAME = (
    "actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references"
)


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def compact(value):
    return re.sub(r"\s+", "", value)


def assert_connected(reader):
    source = reader(EXECUTABLE)
    matches = re.findall(
        rf"(?P<attributes>(?:^#\[[^\n]*\]\s*)+)^fn {NAME}\(\) \{{(?P<body>.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert len(matches) == 1
    attributes, body = matches[0]
    assert attributes.strip() == "#[test]"
    assert "return" not in body
    assert (
        '#[path = "support/resolved_selfhost_runtime.rs"]\nmod resolved_selfhost_runtime;'
        in source
    )
    assert body.count("resolved_selfhost_runtime::qualify(&repo, &extracted);") == 1
    assert body.index("ExtractedBundle::create(&repo, command())") < body.index(
        "resolved_selfhost_runtime::qualify"
    )
    shared = reader(SHARED)
    assert "ZipArchive::new" in shared
    assert "assert_contained_references(&extracted, &rendered)" in shared
    adapter = reader(ADAPTER)
    for required in [
        "marty_selfhost_bundle::process::compose",
        "ClosedSelfhostModel::from_rendered(&expected, actual, &secret_directory)",
        "negative_controls(model, &expected, secret_directory, &endpoints)",
        "let prepared = prepare(repo, extracted)",
        "normalize_model(raw_model.clone(), extracted)",
        "prepared.verify_sources()",
        "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE",
        "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be",
        '"docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml"',
        '&["docker-compose.yml"]',
        "self.source_hashes, hashes(&self.source_root)",
    ]:
        assert compact(required) in compact(adapter)
    workflow = reader(".github/workflows/ci.yml")
    assert "cargo test --locked --workspace" in workflow
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s" in workflow
    assert "install-compose-renderer.sh" in workflow


def test_actual_extracted_runtime_model_is_mandatory():
    assert_connected(read)


def assert_public_image_loader_connected(reader):
    source = reader("rust/services/issuance/tests/canvas_published_schema_contract.rs")
    runtime = reader("rust/services/issuance/tests/support/selfhost_packaged_runtime.rs")
    sidecar = reader("rust/services/issuance/tests/support/selfhost_runtime_sidecar.rs")
    runner = reader("scripts/ci/run-published-canvas-contracts.sh")
    workflow = yaml.safe_load(reader(".github/workflows/ci.yml"))
    for name in [
        "selfhost_public_image_loader_isolated",
        "selfhost_public_image_loader_child",
    ]:
        assert source.count(f"fn {name}()") == 1
        line = f'"${{executables[0]}}" --list | grep -Fx \'{name}: test\''
        assert runner.splitlines().count(line) == 1
    for required in [
        "selfhost_packaged_runtime::run_isolated_child()",
        "PendingOperation::begin",
        "PublishedDatabase::start_with_scope",
        "after_database_checkpoint",
    ]:
        assert required in source
    for required in [
        "ChildCase::TimeoutAfterDatabase",
        "ChildCase::ExitAfterDatabase",
        "require_no_pending_operation",
        "PublishedDatabase::recover_scope",
        "recover_parent_scope",
        "MARTY_SELFHOST_TEST_IMAGE",
        "ALTER SCHEMA issuance_service OWNER TO marty",
        "namespace.nspname = 'issuance_service'",
        "'ALTER %s %I.%I OWNER TO marty'",
        "pg_get_userbyid(datdba) = 'marty'",
        "pg_get_userbyid(nspowner) = 'marty'",
        "object.relkind IN ('r', 'p', 'S')",
        'record_database_stage("transfer-ownership")',
        'record_database_stage("inspect-ownership")',
        'record_database_stage("verify-ownership")',
        "seed(&check).await?;",
    ]:
        assert required in runtime
    assert "REASSIGN OWNED BY CURRENT_USER TO marty" not in runtime
    for required in [
        "create_new(true)",
        "validate_pending_operation",
        "PendingKind::NativeCreate",
        "PendingKind::NativeStart",
        "PendingKind::NativeCleanup",
    ]:
        assert required in sidecar
    job = workflow["jobs"]["test-rust-services"]
    steps = job["steps"]
    matches = [
        (index, step)
        for index, step in enumerate(steps)
        if step.get("name") == "Prepare public selfhost image loader acceptance"
    ]
    assert len(matches) == 1
    index, step = matches[0]
    assert set(step) == {"name", "shell", "run"}
    assert step["shell"] == "bash"
    body = step["run"]
    for required in [
        "set -euo pipefail",
        "cargo build --locked --manifest-path rust/Cargo.toml",
        "-p marty-selfhost-bundle --bin package-selfhost-bundle",
        "--file services/Dockerfile",
        "--tag marty-selfhost-public:contract",
        "--build-arg SERVICE_NAME=issuance_native",
        "docker image inspect --format '{{.Id}}' marty-selfhost-public:contract",
        "MARTY_SELFHOST_TEST_PACKAGER_BINARY",
        "MARTY_SELFHOST_TEST_IMAGE",
        "MARTY_SELFHOST_TEST_REVISION",
    ]:
        assert required in body
    names = [step.get("name") for step in steps]
    assert names.index("Compile reusable Rust test executables") < index
    assert index < names.index("Run isolated database contract suites concurrently")


def test_public_image_loader_is_a_mandatory_exact_source_image_gate():
    assert_public_image_loader_connected(read)


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "runner",
        "workflow",
        "dockerfile",
        "image",
        "revision",
        "pending",
        "ownership",
        "ownership-proof",
        "ownership-seed",
        "ownership-stage",
    ],
)
def test_public_image_loader_refuses_disconnected_or_weakened_gates(fault):
    def changed(name):
        source = read(name)
        replacements = {
            "source": (
                "rust/services/issuance/tests/canvas_published_schema_contract.rs",
                "selfhost_packaged_runtime::run_isolated_child()",
            ),
            "runner": (
                "scripts/ci/run-published-canvas-contracts.sh",
                '"${executables[0]}" --list | grep -Fx \'selfhost_public_image_loader_isolated: test\'',
            ),
            "workflow": (
                ".github/workflows/ci.yml",
                "Prepare public selfhost image loader acceptance",
            ),
            "dockerfile": (".github/workflows/ci.yml", "--file services/Dockerfile"),
            "image": (".github/workflows/ci.yml", "MARTY_SELFHOST_TEST_IMAGE"),
            "revision": (".github/workflows/ci.yml", "MARTY_SELFHOST_TEST_REVISION"),
            "pending": (
                "rust/services/issuance/tests/support/selfhost_runtime_sidecar.rs",
                "create_new(true)",
            ),
            "ownership": (
                "rust/services/issuance/tests/support/selfhost_packaged_runtime.rs",
                "ALTER SCHEMA issuance_service OWNER TO marty",
            ),
            "ownership-proof": (
                "rust/services/issuance/tests/support/selfhost_packaged_runtime.rs",
                "pg_get_userbyid(datdba) = 'marty'",
            ),
            "ownership-seed": (
                "rust/services/issuance/tests/support/selfhost_packaged_runtime.rs",
                "seed(&check).await?;",
            ),
            "ownership-stage": (
                "rust/services/issuance/tests/support/selfhost_packaged_runtime.rs",
                'record_database_stage("transfer-ownership")',
            ),
        }
        target, value = replacements[fault]
        return source.replace(value, "ABSENT", 1) if name == target else source

    with pytest.raises(AssertionError):
        assert_public_image_loader_connected(changed)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "ignored",
        "disconnected",
        "module",
        "fake-render",
        "no-negatives",
        "no-source",
        "no-extracted",
        "pin",
        "export",
        "workspace",
    ],
)
def test_disconnected_or_weakened_runtime_model_gate_refuses(fault):
    def changed(name):
        source = read(name)
        if name == EXECUTABLE:
            if fault == "missing":
                return source.replace(f"fn {NAME}", "fn absent")
            if fault == "ignored":
                return source.replace(f"fn {NAME}", f"#[ignore]\nfn {NAME}")
            if fault == "disconnected":
                return source.replace(
                    "resolved_selfhost_runtime::qualify(&repo, &extracted);", ""
                )
            if fault == "module":
                return source.replace("mod resolved_selfhost_runtime;", "")
        if name == ADAPTER:
            for key, original in {
                "fake-render": "marty_selfhost_bundle::process::compose",
                "no-negatives": "negative_controls(model, &expected, secret_directory, &endpoints)",
                "no-source": '"docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml"',
                "no-extracted": '&["docker-compose.yml"]',
                "pin": "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be",
            }.items():
                if fault == key:
                    return compact(source).replace(compact(original), "absent")
        if name == ".github/workflows/ci.yml":
            if fault == "export":
                return source.replace(
                    "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s", "ABSENT=%s"
                )
            if fault == "workspace":
                return source.replace(
                    "cargo test --locked --workspace", "cargo test -p marty-gateway"
                )
        return source

    with pytest.raises(AssertionError):
        assert_connected(changed)
