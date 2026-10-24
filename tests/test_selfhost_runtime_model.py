"""Keep stage A attached to actual generated/extracted bundle acceptance."""

from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = "rust/crates/selfhost-bundle/tests/executable_bundle.rs"
SHARED = "rust/crates/selfhost-bundle/tests/support/extracted_bundle.rs"
ADAPTER = "rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs"
PACKAGED = "rust/crates/selfhost-acceptance/tests/support/selfhost_packaged_runtime.rs"
SIDECAR = "rust/crates/selfhost-acceptance/tests/support/selfhost_runtime_sidecar.rs"
OWNER = "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs"
NAME = (
    "actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references"
)


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def compact(value):
    return re.sub(r"\s+", "", value)


def rust_function(source, name, indent=""):
    matches = re.findall(
        rf"^{indent}(?:pub\(super\) )?fn {name}\(.*?^{indent}\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert len(matches) == 1
    return compact(matches[0])


def assert_log_boundary_connected(sidecar):
    classifier = rust_function(sidecar, "log_boundary_status")
    for required in [
        "serde_json::from_str::<Value>(line)",
        'event["fields"]["message"] == message',
        'event["fields"][field] == value',
    ]:
        assert compact(required) in classifier
    secret_check = compact(
        "let secrets_absent = secrets.iter().all(|value| "
        "!value.is_empty() && !log.contains(value));"
    )
    reject_leak = compact(
        "if !secrets_absent { return LogBoundaryStatus::SecretExposed; }"
    )
    assert secret_check in classifier
    assert reject_leak in classifier
    assert classifier.index(reject_leak) < classifier.index(
        "letexpected_present=match"
    )
    assert compact(
        "if expected_present { LogBoundaryStatus::Satisfied } "
        "else { LogBoundaryStatus::ExpectedMissing }"
    ) in classifier
    assert compact(
        "log_boundary_status(log, secrets, expected) == LogBoundaryStatus::Satisfied"
    ) in rust_function(sidecar, "log_satisfies_boundary")

    waiter = rust_function(sidecar, "wait_for_log_boundary")
    for required in [
        "require(secrets.iter().all(|value| !value.is_empty()))?;",
        "let deadline = Instant::now().checked_add(budget).ok_or(ERROR)?;",
        "let remaining = deadline.saturating_duration_since(Instant::now()); "
        "require(!remaining.is_zero())?; let bytes = read_log(remaining)?;",
        "let log = String::from_utf8(bytes).map_err(|_| ERROR)?;",
        "match log_boundary_status(&log, secrets, expected)",
        "LogBoundaryStatus::SecretExposed => return Err(ERROR.into()),",
        "LogBoundaryStatus::Satisfied => return require(Instant::now() < deadline),",
        "LogBoundaryStatus::ExpectedMissing => { "
        "let remaining = deadline.saturating_duration_since(Instant::now()); "
        "require(!remaining.is_zero())?; "
        "std::thread::sleep(Duration::from_millis(100).min(remaining)); }",
    ]:
        assert compact(required) in waiter
    owned = rust_function(sidecar, "verify_log_boundary", "    ")
    assert compact("self.checked(&inspect(id)?, id)?;") in owned
    assert compact(
        "wait_for_log_boundary(secrets, expected, Duration::from_secs(5), |remaining|"
    ) in owned
    assert compact(
        'docker_output_with_timeout(&["logs", id], remaining, 1024 * 1024,)?'
    ) in owned


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
    source = reader(OWNER)
    runtime = reader(PACKAGED)
    sidecar = reader(SIDECAR)
    root_ignore = reader(".dockerignore")
    for test_only in (OWNER, PACKAGED, SIDECAR):
        assert root_ignore.splitlines().count(test_only) == 1
    assert '#[path = "support/selfhost_packaged_runtime.rs"]' in source
    assert '#[path = "support/selfhost_runtime_sidecar.rs"]' in source
    main = reader("rust/services/issuance/src/main.rs")
    runner = reader("scripts/ci/run-published-canvas-contracts.sh")
    workflow = yaml.safe_load(reader(".github/workflows/ci.yml"))
    for name in [
        "selfhost_public_image_loader_isolated",
        "selfhost_public_image_loader_child",
    ]:
        assert source.count(f"fn {name}()") == 1
        line = f"  printf '%s\\n' \"$all_test_names\" | grep -Fx '{name}: test'"
        assert runner.splitlines().count(line) == 1
    assert 'require_selfhost_tests "$("$selfhost_executable" --list)"' in runner
    assert "17 passed; 0 failed; 0 ignored" in runner
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
        "COALESCE(to_jsonb(t)->'access_token_expires_at', 'null'::jsonb)",
        "matches!(case, SecretCase::Correct | SecretCase::CrLf)",
        "issuance startup database authentication failed",
        "LogExpectation::Structured",
        'field: "database_sqlstate"',
        'value: "28P01"',
    ]:
        assert compact(required) in compact(runtime)
    assert_log_boundary_connected(sidecar)
    assert compact(
        "service.verify_log_boundary("
        "&secrets.iter().map(String::as_str).collect::<Vec<_>>(), expected, )}"
    ) in rust_function(runtime, "run_service")
    for required in [
        'database_sqlstate = "28P01"',
        'code == "28P01"',
        "issuance startup database authentication failed",
    ]:
        assert required in main
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
    assert set(step) == {"name", "if", "shell", "run"}
    assert step["if"] == "matrix.lane == 'selfhost'"
    assert step["shell"] == "bash"
    body = step["run"]
    build = steps[index - 1]
    assert build["if"] == "matrix.lane == 'selfhost'"
    assert build["name"] == "Build public selfhost image"
    assert build["with"]["file"] == "services/Dockerfile"
    assert build["with"]["tags"] == "marty-selfhost-public:contract"
    assert "SERVICE_NAME=issuance_native" in build["with"]["build-args"]
    assert build["with"]["load"] is True
    for required in [
        "set -euo pipefail",
        "cargo build --locked --manifest-path rust/Cargo.toml",
        "-p marty-selfhost-bundle --bin package-selfhost-bundle",
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
    ("original", "replacement"),
    [
        ("serde_json::from_str::<Value>(line)", "disconnected_parser(line)"),
        ('event["fields"]["message"] == message', "true"),
        ('event["fields"][field] == value', "true"),
        ("!value.is_empty() && !log.contains(value)", "true"),
        (
            "if !secrets_absent {\n        return LogBoundaryStatus::SecretExposed;",
            "if !secrets_absent {\n        return LogBoundaryStatus::ExpectedMissing;",
        ),
        (
            "if expected_present {\n        LogBoundaryStatus::Satisfied",
            "if !expected_present {\n        LogBoundaryStatus::Satisfied",
        ),
        (
            "log_boundary_status(log, secrets, expected) == LogBoundaryStatus::Satisfied",
            "true",
        ),
        (
            "String::from_utf8(bytes).map_err(|_| ERROR)?",
            "String::from_utf8_lossy(&bytes)",
        ),
        ("read_log(remaining)?", "read_log(remaining).unwrap_or_default()"),
        (
            "return require(Instant::now() < deadline)",
            "return Ok(())",
        ),
        ("require(!remaining.is_zero())?;", ""),
        (".min(remaining)", ""),
        (
            "wait_for_log_boundary(secrets, expected, Duration::from_secs(5)",
            "disconnected_waiter(secrets, expected, Duration::from_secs(5)",
        ),
        (
            '&["logs", id],\n                remaining,',
            '&["logs", id],\n                Duration::from_secs(5),',
        ),
    ],
)
def test_log_boundary_connectivity_rejects_weakened_retry_paths(
    original, replacement
):
    source = read(SIDECAR)
    assert original in source
    changed = source.replace(original, replacement, 1)
    assert changed != source
    with pytest.raises(AssertionError):
        assert_log_boundary_connected(changed)


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
        "migration-owned-projection",
        "wrong-password-running",
        "wrong-password-marker",
        "wrong-password-sqlstate",
        "wrong-password-structured",
        "log-boundary-call",
        "log-boundary-summary",
    ],
)
def test_public_image_loader_refuses_disconnected_or_weakened_gates(fault):
    def changed(name):
        source = read(name)
        replacements = {
            "source": (
                OWNER,
                "selfhost_packaged_runtime::run_isolated_child()",
            ),
            "runner": (
                "scripts/ci/run-published-canvas-contracts.sh",
                "printf '%s\\n' \"$all_test_names\" | grep -Fx 'selfhost_public_image_loader_isolated: test'",
            ),
            "workflow": (
                ".github/workflows/ci.yml",
                "Prepare public selfhost image loader acceptance",
            ),
            "dockerfile": (".github/workflows/ci.yml", "file: services/Dockerfile"),
            "image": (".github/workflows/ci.yml", "MARTY_SELFHOST_TEST_IMAGE"),
            "revision": (".github/workflows/ci.yml", "MARTY_SELFHOST_TEST_REVISION"),
            "pending": (
                SIDECAR,
                "create_new(true)",
            ),
            "ownership": (
                PACKAGED,
                "ALTER SCHEMA issuance_service OWNER TO marty",
            ),
            "ownership-proof": (
                PACKAGED,
                "pg_get_userbyid(datdba) = 'marty'",
            ),
            "ownership-seed": (
                PACKAGED,
                "seed(&check).await?;",
            ),
            "ownership-stage": (
                PACKAGED,
                'record_database_stage("transfer-ownership")',
            ),
            "migration-owned-projection": (
                PACKAGED,
                "COALESCE(to_jsonb(t)->'access_token_expires_at', 'null'::jsonb)",
            ),
            "wrong-password-running": (
                PACKAGED,
                "matches!(case, SecretCase::Correct | SecretCase::CrLf)",
            ),
            "wrong-password-marker": (
                PACKAGED,
                "issuance startup database authentication failed",
            ),
            "wrong-password-sqlstate": (
                "rust/services/issuance/src/main.rs",
                'database_sqlstate = "28P01"',
            ),
            "wrong-password-structured": (
                PACKAGED,
                "LogExpectation::Structured",
            ),
            "log-boundary-call": (PACKAGED, "service.verify_log_boundary("),
            "log-boundary-summary": (
                "scripts/ci/run-published-canvas-contracts.sh",
                "17 passed; 0 failed; 0 ignored",
            ),
        }
        target, value = replacements[fault]
        if fault == "dockerfile" and name == target:
            public_build = (
                "file: services/Dockerfile\n"
                "          load: true\n"
                "          push: false\n"
                "          tags: marty-selfhost-public:contract"
            )
            assert source.count(public_build) == 1
            weakened = public_build.replace(value, "file: ABSENT")
            return source.replace(public_build, weakened, 1)
        if fault == "wrong-password-marker" and name == target:
            return source.replace(value, "ABSENT")
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
