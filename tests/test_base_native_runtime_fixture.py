"""Closed renderer/launch ownership guards; runtime evidence is a separate gate."""

from copy import deepcopy
from pathlib import Path
import re
import runpy

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = runpy.run_path(str(ROOT / "scripts/render_base_native_runtime_fixture.py"))


@pytest.fixture
def spec(tmp_path):
    (tmp_path / "ca.pem").write_text("synthetic stat-only CA control")
    (tmp_path / "didcomm-encryption-policy.json").write_text(
        "synthetic stat-only policy control"
    )
    return {
        "inputs": dict.fromkeys(FIXTURE["INPUT_KEYS"], "synthetic"),
        "http_port": 28105,
        "grpc_port": 29105,
        "gateway_port": 28100,
        "database_url": "postgresql://synthetic:owned@127.0.0.1:25432/owned",
        "redis_url": "redis://127.0.0.1:26379",
        "peer_origin": "http://127.0.0.1:28500",
        "legacy_origin": "http://127.0.0.1:28501",
        "ca_file": str(tmp_path / "ca.pem"),
        "policy_directory": str(tmp_path),
        "authcrypt": True,
        "allow_private_ips": False,
    }


def test_spec_has_only_owned_explicit_addresses_and_paths(spec):
    FIXTURE["validate_spec"](spec)


@pytest.mark.parametrize(
    "field,value",
    [
        ("http_port", True),
        ("http_port", 0),
        ("grpc_port", 28105),
        ("gateway_port", 65536),
        ("allow_private_ips", "false"),
        ("database_url", "postgresql://production.example/db"),
        ("redis_url", "redis://production.example:6379"),
        ("peer_origin", "http://user:password@127.0.0.1:28500"),
        ("legacy_origin", "http://127.0.0.1:28500"),
        ("ca_file", "absent"),
        ("policy_directory", "relative"),
    ],
)
def test_spec_rejects_unowned_or_ambiguous_inputs(spec, field, value):
    spec[field] = value
    with pytest.raises(AssertionError):
        FIXTURE["validate_spec"](spec)


@pytest.mark.parametrize(
    "fault", ["extra-input", "missing-input", "newline", "extra-spec"]
)
def test_spec_rejects_ambient_configuration_and_env_file_injection(spec, fault):
    if fault == "extra-input":
        spec["inputs"]["BAO_TOKEN"] = "synthetic"
    elif fault == "missing-input":
        spec["inputs"].pop("TOKEN_HMAC_KEY")
    elif fault == "newline":
        spec["inputs"]["PUBLIC_API_URL"] = "synthetic\nBAO_TOKEN=injected"
    else:
        spec["operator_env_file"] = ".env"
    with pytest.raises(AssertionError):
        FIXTURE["validate_spec"](spec)


def model():
    gateway = dict.fromkeys(
        FIXTURE["GATEWAY_PEER_URLS"]
        | {"ISSUANCE_SERVICE_URL", "ISSUANCE_NATIVE_SERVICE_URL"},
        "http://synthetic:8000",
    )
    gateway["REDIS_DB_GATEWAY"] = "2"
    gateway["GATEWAY_REQUIRED_READY_SERVICES"] = "preserved-roster"
    return {
        "services": {
            "gateway": {"environment": gateway},
            "issuance-native": {
                "environment": {
                    "DIDCOMM_ALLOW_PRIVATE_IPS": "false",
                    "ISSUANCE_GRPC_ENABLED": "true",
                }
            },
            "flow": {"environment": {"ISSUANCE_GRPC_TARGET": "issuance:9005"}},
        },
        "volumes": {"preserved": {}},
    }


def test_fixture_overlay_is_addresses_and_paths_not_new_service_graph(spec):
    selected = model()
    overlay = FIXTURE["fixture_overlay"](spec, selected)
    actual = deepcopy(selected)
    for name, service in overlay["services"].items():
        actual["services"][name]["environment"].update(service["environment"])
    FIXTURE["assert_fixture_delta"](selected, actual, overlay, spec)
    assert (
        "DIDCOMM_ALLOW_PRIVATE_IPS"
        not in overlay["services"]["issuance-native"]["environment"]
    )
    assert "REDIS_DB_GATEWAY" not in overlay["services"]["gateway"]["environment"]
    assert (
        "GATEWAY_REQUIRED_READY_SERVICES"
        not in overlay["services"]["gateway"]["environment"]
    )
    for name, key, value in (
        ("issuance-native", "TOKEN_HMAC_KEY", "foreign"),
        ("issuance-native", "DIDCOMM_ALLOW_PRIVATE_IPS", "true"),
        ("issuance-native", "ISSUANCE_GRPC_ENABLED", "false"),
        ("gateway", "REDIS_DB_GATEWAY", "0"),
        ("gateway", "GATEWAY_REQUIRED_READY_SERVICES", "issuance-native"),
    ):
        changed, changed_overlay = deepcopy(actual), deepcopy(overlay)
        changed["services"][name]["environment"][key] = value
        changed_overlay["services"][name]["environment"][key] = value
        with pytest.raises(AssertionError):
            FIXTURE["assert_fixture_delta"](selected, changed, changed_overlay, spec)


def test_native_launch_has_no_post_render_smoke_overrides():
    renderer = (
        ROOT / "rust/services/issuance/tests/support/rendered_base_process.rs"
    ).read_text()
    text = (
        ROOT / "rust/services/issuance/tests/support/resolved_runtime.rs"
    ).read_text()
    assert re.search(r"\.env_clear\(\)\s*\.envs\(environment\)", text)
    assert "isolated_smoke_command" not in text + renderer
    assert "MARTY_BASE_COMPOSE_BINARY" in renderer
    assert "native_environment: self.native_environment" in renderer
    assert "gateway_environment: self.gateway_environment" in renderer
    assert "Isolation::Base" in renderer
    assert "Some(system_root)" in text
    assert '"required exact test binary is built"' in text


RUNTIME_GATES = {
    "base_profile_native_renewal_uses_actual_rendered_configuration": "renewal_fresh_main::run_rendered",
    "base_profile_gateway_composition_isolated": "base_runtime_container::run",
    "base_profile_gateway_composition_child": "renewal_fresh_main::run_gateway",
}


def runtime_registration(script, source, name):
    line = f"\"${{executables[0]}}\" --list | grep -Fx '{name}: test'"
    assert script.splitlines().count(line) == 1
    match = re.search(
        rf"#\[tokio::test\]\s*async fn {name}\(\) \{{(.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert match
    body = match.group(1)
    assert RUNTIME_GATES[name] in body
    if name.endswith("_isolated"):
        for required in (
            "std::env::consts::OS,",
            '"linux"',
            "PublishedDatabase::start()",
            "assert_constructor_timeout_cleanup(&owned)",
            "start_in_published_namespace(&owned)",
            "base_runtime_container::source_assets()",
            "redis.close_verified().unwrap()",
            "owned.close_verified().unwrap()",
            "result.unwrap()",
        ):
            assert required in body
    if name.endswith("_child"):
        assert 'std::env::var("MARTY_BASE_RUNTIME_CHILD")' in body
        assert "MARTY_BASE_COMPOSITION_COMPLETE_V1" in body
        assert (
            "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test"
            in body
        )
        assert '"redis://127.0.0.1:6379"' in body


@pytest.mark.parametrize("name", RUNTIME_GATES)
@pytest.mark.parametrize(
    "fault", [None, "missing", "duplicate", "ignored", "disconnected"]
)
def test_runtime_names_require_exact_owned_composition(name, fault):
    script = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text()
    source = (
        ROOT / "rust/services/issuance/tests/canvas_published_schema_contract.rs"
    ).read_text()
    runtime_registration(script, source, name)
    line = f"\"${{executables[0]}}\" --list | grep -Fx '{name}: test'"
    if fault == "missing":
        script = script.replace(line, "")
    elif fault == "duplicate":
        script += "\n" + line
    elif fault == "ignored":
        source = source.replace(f"async fn {name}", f"#[ignore]\nasync fn {name}")
    elif fault == "disconnected":
        source = source.replace(RUNTIME_GATES[name], "disconnected_owner")
    if fault:
        with pytest.raises(AssertionError):
            runtime_registration(script, source, name)


def runtime_ci(workflow):
    job = workflow["jobs"]["test-rust-services"]
    assert job["runs-on"] == "ubuntu-latest"
    assert not job.get("continue-on-error", False)
    name = "Prepare required rendered base executable acceptance"
    matches = [
        (i, item) for i, item in enumerate(job["steps"]) if item.get("name") == name
    ]
    assert len(matches) == 1
    index, step = matches[0]
    assert set(step) == {"name", "shell", "run"}
    assert step["shell"] == "bash"
    lines = step["run"].splitlines()
    assert lines == [
        "set -euo pipefail",
        "bash scripts/ci/install-compose-renderer.sh",
        "test -x rust/target/debug/marty-issuance-service",
        "test -x rust/target/debug/marty-gateway",
        "test -x rust/target/debug/marty-flow",
        "docker pull redis:7-alpine",
        "# Resolve the actual source Dockerfile build to a local immutable ID.",
        "# This is runtime identity evidence, not release provenance.",
        "docker build --tag marty-envoy:native-contract config/envoy",
        'envoy_image_id="$(docker image inspect --format \'{{.Id}}\' marty-envoy:native-contract)"',
        'printf \'MARTY_ENVOY_TEST_IMAGE=%s\\n\' "$envoy_image_id" >> "$GITHUB_ENV"',
        'printf \'MARTY_BASE_COMPOSE_BINARY=%s\\n\' "$RUNNER_TEMP/compose-render-v5.4.0" >> "$GITHUB_ENV"',
        'printf \'MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s\\n\' "$RUNNER_TEMP/compose-render-v5.4.0" >> "$GITHUB_ENV"',
        'printf \'MARTY_DIDCOMM_TEST_PYTHON=%s\\n\' "$(command -v python3)" >> "$GITHUB_ENV"',
    ]
    names = [item.get("name") for item in job["steps"]]
    assert names.index("Compile reusable Rust test executables") < index
    assert index < names.index("Run safe Rust contract groups concurrently")


def compatibility_ci(workflow):
    job = workflow["jobs"]["test-rust-services"]
    name = "Compile Bookworm-compatible base runtime acceptance"
    matches = [
        (index, step)
        for index, step in enumerate(job["steps"])
        if step.get("name") == name
    ]
    assert len(matches) == 1
    index, step = matches[0]
    assert set(step) == {"name", "shell", "run"}
    assert step["shell"] == "bash"
    script = step["run"]
    required = (
        "set -euo pipefail",
        'awk \'$1 == "FROM" && $3 == "AS" && $4 == "rust-service-builder" { print $2 }\' services/Dockerfile',
        '[[ ${#builder_images[@]} == 1 ]]',
        '^rust:1\\.95-bookworm@sha256:[a-f0-9]{64}$',
        'docker pull "$bookworm_builder"',
        'compat_target="$RUNNER_TEMP/marty-bookworm-target"',
        'compat_artifacts="$RUNNER_TEMP/marty-bookworm-artifacts.json"',
        "docker run --rm --network none --read-only",
        '--user "$(id -u):$(id -g)"',
        '--volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro"',
        '--volume "$compat_target:$compat_target"',
        '--workdir "$GITHUB_WORKSPACE/rust"',
        "cargo build --locked --offline --quiet -p marty-issuance-service --bin marty-issuance-service",
        "cargo build --locked --offline --quiet -p marty-gateway --bin marty-gateway",
        "--test canvas_published_schema_contract --no-run --message-format=json",
        'select(.target.name == "canvas_published_schema_contract")',
        '[[ "$(dirname "$compat_executable")" == "$compat_target/debug/deps" ]]',
        '^canvas_published_schema_contract-[a-f0-9]{16}$',
        'test -x "$compat_target/debug/marty-issuance-service"',
        'test -x "$compat_target/debug/marty-gateway"',
        "MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE=%s",
        '>> "$GITHUB_ENV"',
    )
    for value in required:
        assert value in script
    assert script.count("--network none") == 1
    assert script.count("MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE=%s") == 1
    names = [step.get("name") for step in job["steps"]]
    assert names.index("Compile reusable Rust test executables") < index
    assert index < names.index("Prepare required rendered base executable acceptance")
    source = (
        ROOT / "rust/services/issuance/tests/support/base_runtime_container.rs"
    ).read_text()
    assert (
        'const COMPAT_TEST_EXECUTABLE: &str = '
        '"MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE";'
        in source
    )
    assert "compatible_executable_paths(Path::new(&test))?" in source
    assert 'strip_prefix("canvas_published_schema_contract-")' in source
    assert 'Some("deps")' in source


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "duplicate",
        "optional",
        "conditional",
        "builder",
        "network",
        "workspace",
        "gateway",
        "selector",
    ],
)
def test_runtime_ci_builds_closed_bookworm_compatible_child_artifacts(fault):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    compatibility_ci(workflow)
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    step = next(
        item
        for item in steps
        if item.get("name") == "Compile Bookworm-compatible base runtime acceptance"
    )
    if fault == "missing":
        steps.remove(step)
    elif fault == "duplicate":
        steps.append(deepcopy(step))
    elif fault == "optional":
        step["continue-on-error"] = True
    elif fault == "conditional":
        step["if"] = "false"
    elif fault == "builder":
        step["run"] = step["run"].replace("services/Dockerfile", "unowned")
    elif fault == "network":
        step["run"] = step["run"].replace("--network none", "--network host")
    elif fault == "workspace":
        step["run"] = step["run"].replace(
            '--volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro"',
            '--volume "$GITHUB_WORKSPACE:/workspace:ro"',
        )
    elif fault == "gateway":
        step["run"] = step["run"].replace(
            "cargo build --locked --offline --quiet -p marty-gateway --bin marty-gateway",
            "true",
        )
    elif fault == "selector":
        step["run"] = step["run"].replace(
            "MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE", "UNCONNECTED_EXECUTABLE"
        )
    if fault:
        with pytest.raises(AssertionError):
            compatibility_ci(workflow)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "duplicate",
        "optional",
        "conditional",
        "renderer",
        "gateway",
        "flow",
        "bundle_renderer",
    ],
)
def test_runtime_ci_requires_renderer_and_exact_executable_artifacts(fault):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    runtime_ci(workflow)
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    step = next(
        item
        for item in steps
        if item.get("name") == "Prepare required rendered base executable acceptance"
    )
    if fault == "missing":
        steps.remove(step)
    elif fault == "duplicate":
        steps.append(deepcopy(step))
    elif fault == "optional":
        step["continue-on-error"] = True
    elif fault == "conditional":
        step["if"] = "false"
    elif fault == "renderer":
        step["run"] = step["run"].replace(
            "bash scripts/ci/install-compose-renderer.sh", "echo skipped"
        )
    elif fault == "gateway":
        step["run"] = step["run"].replace(
            "test -x rust/target/debug/marty-gateway", "true"
        )
    elif fault == "flow":
        step["run"] = step["run"].replace(
            "test -x rust/target/debug/marty-flow", "true"
        )
    elif fault == "bundle_renderer":
        step["run"] = step["run"].replace(
            "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE", "UNCONNECTED_BUNDLE_RENDERER"
        )
    if fault:
        with pytest.raises(AssertionError):
            runtime_ci(workflow)


def test_shared_renderer_bootstrap_retains_frozen_hash_and_verifies_before_execution():
    script = (ROOT / "scripts/ci/install-compose-renderer.sh").read_text()
    assert "set -euo pipefail" in script
    assert (
        "https://github.com/docker/compose/releases/download/v5.4.0/docker-compose-linux-x86_64"
        in script
    )
    assert "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be" in script
    assert (
        script.index("curl --fail")
        < script.index("sha256sum --check --strict")
        < script.index("chmod +x")
    )
    assert 'compose_renderer="$RUNNER_TEMP/compose-render-v5.4.0"' in script


@pytest.mark.parametrize(
    "owner", ["base_runtime_didcomm", "base_runtime_ordinary", "base_runtime_canvas"]
)
def test_inner_acceptance_roster_cannot_drop_a_capability(owner):
    source = (
        ROOT / "rust/services/issuance/tests/support/renewal_fresh_main.rs"
    ).read_text()

    def check(text):
        for required in (
            "base_runtime_didcomm",
            "base_runtime_ordinary",
            "base_runtime_canvas",
        ):
            assert f"super::{required}::run(" in text
        assert "GatewayFixture::start(" in text
        assert ".native_unavailable(" in text
        assert ".assert_no_fallback()" in text

    check(source)
    with pytest.raises(AssertionError):
        check(source.replace(f"super::{owner}::run(", "disconnected_owner("))


def test_renewal_fixtures_compare_post_migration_state_and_unique_notifications():
    renewal = (
        ROOT / "rust/services/issuance/tests/support/renewal_fresh_main.rs"
    ).read_text(encoding="utf-8")

    def check(source):
        ready = 'Some(json!({"status":"healthy","service":"issuance-service"}))'
        pre_start = "let source_before_startup = stored(&pool, &source_tx_id).await;"
        not_before = "let startup_migration_not_before: chrono::DateTime<chrono::Utc> ="
        spawn = "let mut child = ChildGuard(command.spawn().unwrap());"
        snapshot = "let source_before = stored(&pool, &source_tx_id).await;"
        not_after = "let startup_migration_not_after: chrono::DateTime<chrono::Utc> ="
        gateway = "let gateway_fixture = if gateway {"
        for marker in [pre_start, not_before, spawn, ready, not_after, snapshot, gateway]:
            assert marker in source
        assert (
            source.index(pre_start)
            < source.index(not_before)
            < source.index(spawn)
            < source.index(ready)
            < source.index(not_after)
            < source.index(snapshot)
            < source.index(gateway)
        )
        conjunctive_bound = (
            "backfilled_expiry >= startup_migration_not_before + legacy_token_lifetime\n"
            "                && backfilled_expiry <= startup_migration_not_after + legacy_token_lifetime"
        )
        for required in [
            'const LEGACY_ACCESS_TOKEN: &str = "synthetic-legacy-access-token";',
            "Hmac::<Sha256>::new_from_slice(TOKEN_HMAC_KEY.as_bytes())",
            "hmac.update(token.as_bytes());",
            "hex::encode(hmac.finalize().into_bytes())",
            "let legacy_access_token_digest = access_token_digest(LEGACY_ACCESS_TOKEN);",
            'SET access_token=$1\n             WHERE id=$2 AND organization_id=$3',
            ".bind(&legacy_access_token_digest)\n"
            "        .bind(&source_tx_id)\n"
            "        .bind(ORGANIZATION)",
            'assert_eq!(\n            seeded.rows_affected(),\n            1,',
            'assert_eq!(\n            source_before_startup["transaction"]["access_token"], legacy_access_token_digest,',
            'assert_ne!(\n            source_before_startup["transaction"]["access_token"], LEGACY_ACCESS_TOKEN,',
            "legacy access token must remain one-way hashed at rest",
            'source_before_startup["transaction"]["access_token_expires_at"].is_null()',
            'sqlx::query_scalar("SELECT clock_timestamp()")',
            "let legacy_token_lifetime = chrono::Duration::seconds(1800);",
            "backfilled_expiry >= startup_migration_not_before + legacy_token_lifetime",
            "backfilled_expiry <= startup_migration_not_after + legacy_token_lifetime",
            'expected_after_startup["transaction"]["access_token_expires_at"] =',
            'source_before["transaction"]["access_token_expires_at"].clone();',
            "assert_eq!(\n            source_before, expected_after_startup,",
            "startup migration changed seeded renewal domain state",
        ]:
            assert required in source
        assert conjunctive_bound in source
        assert source.count('sqlx::query_scalar("SELECT clock_timestamp()")') == 2
        assert (
            'expected_after_startup["transaction"]["access_token_expires_at"] = Value::Null;'
            not in source
        )

    check(renewal)
    for weakened in [
        renewal.replace(
            ".bind(&legacy_access_token_digest)", ".bind(LEGACY_ACCESS_TOKEN)"
        ),
        renewal.replace(
            "WHERE id=$2 AND organization_id=$3", "WHERE id=$2"
        ),
        renewal.replace(
            ".bind(&source_tx_id)\n        .bind(ORGANIZATION)",
            ".bind(&source_id)\n        .bind(ORGANIZATION)",
        ),
        renewal.replace(
            ".bind(&source_tx_id)\n        .bind(ORGANIZATION)",
            ".bind(&source_tx_id)\n        .bind(\"foreign-org\")",
        ),
        renewal.replace(
            "seeded.rows_affected(),\n            1,",
            "seeded.rows_affected(),\n            0,",
        ),
        renewal.replace(
            "chrono::Duration::seconds(1800)", "chrono::Duration::seconds(3600)"
        ),
        renewal.replace(
            'source_before["transaction"]["access_token_expires_at"].clone()',
            "Value::Null",
        ),
        renewal.replace(
            "source_before, expected_after_startup", "source_before, source_before"
        ),
        renewal.replace(
            "                && backfilled_expiry <=",
            "                || backfilled_expiry <=",
        ),
        renewal.replace(
            "let startup_migration_not_before: chrono::DateTime<chrono::Utc> =",
            "let displaced_startup_migration_not_before: chrono::DateTime<chrono::Utc> =",
        ),
    ]:
        with pytest.raises(AssertionError):
            check(weakened)

    canvas = (
        ROOT / "rust/services/issuance/tests/support/renewal_canvas_binding.rs"
    ).read_text(encoding="utf-8")
    for required in [
        'format!("notification-renewal-canvas-{}", transaction.id)',
        ".finalize(&claimed, &credential, &notification_id)",
        "assert_eq!(persisted.notification_id, notification_id);",
    ]:
        assert required in canvas
