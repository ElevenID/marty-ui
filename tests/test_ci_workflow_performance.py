from __future__ import annotations

import ast
from contextlib import nullcontext

import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def test_canvas_native_oracle_decodes_artifacts_and_child_output_as_utf8() -> None:
    source = (ROOT / "scripts/run_canvas_timeout_consumer_oracle.py").read_text(
        encoding="utf-8"
    )
    native = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    reads = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_text"
    ]
    children = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert len(reads) == 2 and len(children) == 1
    for call in reads + children:
        assert any(
            keyword.arg == "encoding"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "utf-8"
            for keyword in call.keywords
        )


def test_canvas_native_oracle_preserves_unicode_line_separators(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (ROOT / "scripts/run_canvas_timeout_consumer_oracle.py").read_text(
        encoding="utf-8"
    )
    native = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    case = {"name": "synthetic_unicode_record"}
    observation = {
        "name": case["name"],
        "status": 403,
        "body": {"body_excerpt": "NEL\u0085LINE\u2028PARA\u2029"},
    }
    (contracts / "canvas-timeout-consumer-scenarios.json").write_text(
        json.dumps({"cases": [case]}), encoding="utf-8"
    )
    (contracts / "canvas-timeout-consumer-oracle.json").write_text(
        json.dumps({"cases": [observation]}, ensure_ascii=False), encoding="utf-8"
    )
    child = SimpleNamespace(
        returncode=0,
        stderr="",
        stdout="CANVAS_TIMEOUT_NATIVE="
        + json.dumps(observation, ensure_ascii=False)
        + "\n",
    )
    namespace = {
        "__file__": str(tmp_path / "scripts" / "oracle.py"),
        "Path": Path,
        "json": json,
        "os": SimpleNamespace(environ={}),
        "subprocess": SimpleNamespace(run=lambda *args, **kwargs: child),
        "loopback_tls": lambda: nullcontext(
            ("https://127.0.0.1:1", None, tmp_path / "synthetic.pem")
        ),
    }
    exec(
        compile(
            ast.Module(body=[native], type_ignores=[]), "<owned-native-oracle>", "exec"
        ),
        namespace,
    )
    namespace["run_native"](tmp_path / "never-executed")
    assert json.loads(capsys.readouterr().out) == {
        "native_timeout_cases": 1,
        "status": "passed",
    }


def _workflow(path: Path) -> tuple[str, dict[str, object]]:
    source = path.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def test_pull_request_classifier_is_conservative_and_merge_queue_is_complete() -> None:
    source, document = _workflow(CI_PATH)
    jobs = document["jobs"]
    changes = jobs["changes"]

    assert changes["name"] == "Classify Changes"
    assert set(changes["outputs"]) == {
        "all",
        "ui",
        "python",
        "rust",
        "release",
        "verification",
        "security",
    }
    assert 'if [[ "${{ github.event_name }}" == merge_group ]]' in source
    assert "Unknown paths deliberately receive the complete suite." in source

    conditional_jobs = {
        "fast-feedback",
        "test-ui",
        "test-services",
        "test-rust-services",
        "rust-lint-policy",
        "test-rust-service-images",
        "public-protocol-contract",
        "test-release-contracts",
        "test-credential-lifecycle-browser",
        "security",
        "rust-supply-chain",
    }
    for name in conditional_jobs:
        assert jobs[name]["needs"] == "changes"
        assert jobs[name]["if"]

    gate_needs = set(jobs["ci-gate"]["needs"])
    assert gate_needs == conditional_jobs | {"changes", "lint"}
    assert '[[ "$result" == success || "$result" == skipped ]]' in source
    assert 'test "$result" = success' in source


def test_published_canvas_schema_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Run isolated database contract suites concurrently"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert gate["run"] == "python3 ../scripts/ci/run-db-contract-groups.py"
    published = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    assert 'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"' in published
    assert "canvas-worker-consumer-range-oracle.json" in published
    assert "canvas_published_schema_contract" in published
    assert '"${executables[0]}" --list' in published
    assert "grep -Fx 'heartbeat_readiness_matches_published_python: test'" in published
    assert "grep -Fx 'operations_match_frozen_published_python: test'" in published
    assert (
        "grep -Fx 'operations_reads_match_frozen_published_python: test'" in published
    )
    assert (
        "grep -Fx 'operations_inputs_match_frozen_published_python: test'" in published
    )
    assert "grep -Fx 'operations_jobs_match_frozen_published_python: test'" in published
    assert "grep -Fx 'operations_jobs_are_atomic_and_concurrent: test'" in published
    assert "grep -Fx 'enqueue_inputs_match_frozen_published_python: test'" in published
    assert (
        "grep -Fx 'operations_resolution_matches_corrected_published_schema: test'"
        in published
    )
    assert (
        "grep -Fx 'operations_resolution_fences_and_lifecycle_delegate: test'"
        in published
    )
    assert "grep -Fx 'review_inputs_match_published_python: test'" in published
    assert "grep -Fx 'review_lifecycle_matches_published_python: test'" in published
    assert "grep -Fx 'status_provider_matches_published_python: test'" in published
    assert "grep -Fx 'status_provider_matches_frozen_protocol: test'" in published
    assert (
        "grep -Fx 'status_runtime_matches_utf7_full_credential_routes: test'"
        in published
    )
    assert (
        "grep -Fx 'status_provider_matches_json_consumer_reference: test'" in published
    )
    assert (
        "grep -Fx 'status_runtime_matches_json_full_credential_routes: test'"
        in published
    )
    assert "grep -Fx 'status_provider_matches_json_depth_reference: test'" in published
    assert (
        "grep -Fx 'worker_rest_reference_matches_published_process: test'" in published
    )
    assert "grep -Fx 'worker_rest_matches_frozen_published_process: test'" in published
    assert "grep -Fx 'worker_rest_native_child: test'" in published
    assert "grep -Fx 'worker_retry_matches_frozen_published_process: test'" in published
    assert (
        "grep -Fx 'worker_provider_recovery_matches_frozen_published_process: test'"
        in published
    )
    assert "grep -Fx 'worker_provider_recovery_native_child: test'" in published
    assert "grep -Fx 'worker_provider_final_native_child: test'" in published
    assert (
        "grep -Fx 'worker_provider_final_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_final_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_recovery_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_signals_match_frozen_published_process: test'"
        in published
    )
    assert "grep -Fx 'worker_provider_signals_native_child: test'" in published
    assert (
        "grep -Fx 'worker_provider_signals_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_retry_reference_matches_published_process: test'" in published
    )
    assert "grep -Fx 'worker_facts_match_frozen_published_process: test'" in published
    assert (
        "grep -Fx 'worker_facts_reference_matches_published_process: test'" in published
    )
    assert (
        "grep -Fx 'worker_startup_matches_published_process_and_idle_heartbeat: test'"
        in published
    )
    assert (
        "grep -Fx 'status_runtime_matches_json_depth_full_credential_routes: test'"
        in published
    )
    for decoder in ("unicode", "charset", "iso2022", "ordinal", "utf7_label"):
        assert (
            f"grep -Fx 'status_runtime_preserves_{decoder}_failures_and_recovery: test'"
            in published
        )
    assert (
        "grep -Fx 'provider_configuration_matches_published_helpers: test'" in published
    )
    assert "grep -Fx 'validation_boundary_matches_published_http: test'" in published
    assert (
        "grep -Fx 'json_consumer_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'json_depth_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'timeout_consumer_matches_published_socket_behavior: test'"
        in published
    )
    assert (
        "grep -Fx 'utf7_consumer_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'status_runtime_preserves_credential_and_delivery_effects: test'"
        in published
    )
    assert (
        "grep -Fx 'cancelled_pool_release_does_not_wait_for_blocked_query: test'"
        in published
    )
    assert '"${executables[0]}" --nocapture --test-threads=1' in published
    assert "[[ ${#executables[@]} == 1" in published


def test_native_canvas_socket_timeout_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Test native Canvas operation timeout TLS parity"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert (
        "grep -Fx 'canvas_operation_http::tests::native_socket_case: test'"
        in gate["run"]
    )
    assert "--native-executable" in gate["run"]
    assert "select(.profile.test == true)" in gate["run"]
    assert "httpx==0.26.0 cryptography==44.0.3" in gate["run"]


def test_canvas_lti_https_gate_requires_real_linux_parent_test() -> None:
    _source, document = _workflow(CI_PATH)
    gate = next(
        step
        for step in document["jobs"]["test-rust-services"]["steps"]
        if step.get("name") == "Test native Canvas AGS/NRPS over real HTTPS"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert "python3 --version" in gate["run"] and "openssl version" in gate["run"]
    assert "canvas_oauth_behavior" in gate["run"]
    assert "length == 1" in gate["run"]
    assert "actual_ags_nrps_https_uses_child_scoped_trust" in gate["run"]
    assert '"$https_executable" --list' in gate["run"]
    assert (
        '"$https_executable" "$https_test" --exact --nocapture --test-threads=1'
        in gate["run"]
    )


def test_rust_contracts_reuse_local_executables_without_artifact_transfer() -> None:
    source, document = _workflow(CI_PATH)
    rust_job = document["jobs"]["test-rust-services"]
    step_names = {step.get("name") for step in rust_job["steps"]}

    assert rust_job["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
    assert "Run safe Rust contract groups concurrently" in step_names
    assert "Run Flow database contract after workspace suite" in step_names
    assert "Run isolated database contract suites concurrently" in step_names
    orchestrator = (ROOT / "scripts/ci/run-db-contract-groups.py").read_text(
        encoding="utf-8"
    )
    assert "run-published-canvas-contracts.sh" in orchestrator
    assert "run-rust-db-contracts.sh" in orchestrator
    assert "test-rust-db-contracts" not in document["jobs"]
    assert "rust-db-test-bundle" not in source
    assert "actions/upload-artifact" not in "\n".join(
        str(step) for step in rust_job["steps"]
    )
    for group in ("workspace", "verification", "gateway"):
        assert f"rust-{group}.status" in source
    assert "target/debug/flow-postgres-contract --test-threads=1" in source
    assert "target/debug/verification-postgres-contract" in source
    assert "target/debug/gateway-redis-contract" in source
    assert (
        "FLOW_POSTGRES_TEST_URL: postgresql://postgres:postgres@127.0.0.1:5432/marty_atomic_test"
        in source
    )
    assert "FLOW_CONTRACT_POSTGRES_URL" not in source
    assert "POSTGRES_DB=marty_atomic_test" not in source
    assert "cargo test --locked -p marty-flow --test postgres_integration" not in source


def test_released_native_backend_is_verified_without_rebuilding_it() -> None:
    source, document = _workflow(CI_PATH)
    service_job = document["jobs"]["test-services"]
    service_source = "\n".join(str(step) for step in service_job["steps"])

    assert "Verify released native trust-registry backend" in service_source
    assert '"trust_registry_sync"' in service_source
    assert "maturin" not in service_source
    assert "ElevenID/marty-core" not in service_source
    assert "MARTY_CORE_TRUST_REGISTRY_REF" not in source


def test_ui_timing_refresh_runs_after_the_required_ci_gate() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )

    assert "workflow_run:" in source
    assert "workflows: [CI]" in source
    refresh = document["jobs"]["refresh"]
    assert refresh["if"] == "github.event.workflow_run.conclusion == 'success'"
    assert (
        "refresh-ui-test-timings"
        not in yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"]
    )


@pytest.mark.parametrize(
    "scenario",
    ["missing", "empty", "unrelated", "nested", "malformed", "not_directory"],
)
def test_ui_timing_refresh_checks_actual_reports(tmp_path: Path, scenario: str) -> None:
    _, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )
    steps = document["jobs"]["refresh"]["steps"]
    guard = next(step for step in steps if step.get("id") == "observations")
    assert guard["if"] == "steps.download.outcome == 'success'"
    for name in ("Produce refreshed timing plan", "Upload refreshed timing plan"):
        step = next(step for step in steps if step.get("name") == name)
        assert step["if"] == "steps.observations.outputs.available == 'true'"

    reports = tmp_path / "reports"
    output = tmp_path / "github-output"
    if scenario == "not_directory":
        reports.write_text("not a directory", encoding="utf-8")
    elif scenario != "missing":
        reports.mkdir()
        if scenario == "unrelated":
            (reports / "notes.txt").write_text("no reports", encoding="utf-8")
            (reports / "directory.json").mkdir()
        elif scenario in {"nested", "malformed"}:
            nested = reports / "shard-1"
            nested.mkdir()
            report = {
                "testResults": [
                    {
                        "name": "/home/runner/work/marty-ui/marty-ui/ui/src/refresh.test.ts",
                        "startTime": 100,
                        "endTime": 150,
                    }
                ]
            }
            (nested / "results.json").write_text(
                json.dumps(report) if scenario == "nested" else "not JSON",
                encoding="utf-8",
            )

    script = guard["run"].split("<<'NODE'\n", 1)[1].rsplit("\nNODE", 1)[0]
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        env={
            **os.environ,
            "TIMINGS_DIRECTORY": str(reports),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
    )
    if scenario == "not_directory":
        assert result.returncode != 0
        assert not output.exists()
        return
    assert result.returncode == 0, result.stderr
    available = scenario in {"nested", "malformed"}
    assert (
        output.read_text(encoding="utf-8").strip()
        == f"available={str(available).lower()}"
    )
    if not available:
        assert "skipping timing refresh" in result.stdout
        return

    plan = tmp_path / "plan.json"
    refresh = subprocess.run(
        [
            "node",
            str(ROOT / "ui/scripts/update-vitest-timings.mjs"),
            str(reports),
            "--output",
            str(plan),
        ],
        capture_output=True,
        text=True,
    )
    if scenario == "malformed":
        assert refresh.returncode != 0
        assert not plan.exists()
    else:
        assert refresh.returncode == 0, refresh.stderr
        assert (
            json.loads(plan.read_text(encoding="utf-8"))["tests"]["src/refresh.test.ts"]
            == 50
        )


def test_advanced_codeql_keeps_full_merge_and_scheduled_coverage() -> None:
    rust_source, rust_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-rust.yml"
    )
    actions_source, actions_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-actions.yml"
    )
    production = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-production.yml").read_text(
            encoding="utf-8"
        )
    )
    full = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-full.yml").read_text(encoding="utf-8")
    )
    policy = json.loads(
        (ROOT / ".github" / "stack-tag-policy.json").read_text(encoding="utf-8")
    )

    assert "merge_group:" in rust_source
    assert "merge_group:" in actions_source
    assert "schedule:" in rust_source
    assert "schedule:" in actions_source
    assert "github.event_name == 'schedule'" in rust_source
    rust_events = rust_workflow.get("on") or rust_workflow[True]
    actions_events = actions_workflow.get("on") or actions_workflow[True]
    assert rust_events["pull_request"] == {"branches": ["main"]}
    assert actions_events["pull_request"] == {"branches": ["main"]}
    rust_job = rust_workflow["jobs"]["analyze-rust"]
    actions_job = actions_workflow["jobs"]["analyze-actions"]
    for job in (rust_job, actions_job):
        assert "if" not in job
        assert job["env"]["CODEQL_ADVANCED_ENABLED"] == (
            "${{ vars.CODEQL_ADVANCED_ENABLED }}"
        )
        guard = job["steps"][0]
        assert guard["name"] == "Require the completed advanced CodeQL cutover"
        assert 'test "$CODEQL_ADVANCED_ENABLED" = "true"' in guard["run"]
        assert job["permissions"]["pull-requests"] == "read"
        scope = job["steps"][1]
        assert scope["id"] == "scope"
        assert "github.paginate(github.rest.pulls.listFiles" in scope["with"]["script"]
        assert "context.eventName !== 'pull_request'" in scope["with"]["script"]
        assert any(
            step.get("name") == "Record scoped analysis skip" for step in job["steps"]
        )
        analysis_steps = [
            step for step in job["steps"] if step.get("name", "").startswith("Analyze")
        ]
        assert analysis_steps
        assert all(
            step["if"] == "steps.scope.outputs.analyze == 'true'"
            for step in analysis_steps
        )
    assert "filename.startsWith('rust/')" in rust_source
    assert "filename.startsWith('.github/codeql/')" in rust_source
    assert "filename === '.github/workflows/codeql-rust.yml'" in rust_source
    assert "filename.startsWith('.github/')" in actions_source
    assert production["paths"] == ["rust/crates/**", "rust/services/**"]
    assert "rust/third_party/**" in production["paths-ignore"]
    assert full["paths"] == ["rust/**"]
    required = policy["required_workflows"]
    assert {
        "path": ".github/workflows/codeql-rust.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": ".github/workflows/codeql-actions.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": "dynamic/github-code-scanning/codeql",
        "event": "dynamic",
    } not in required


def test_warm_cache_uses_the_same_rust_test_profile() -> None:
    _source, document = _workflow(ROOT / ".github" / "workflows" / "warm-ci-caches.yml")
    assert document["jobs"]["rust"]["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0


def test_closed_pull_request_cache_cleanup_is_rate_limit_safe() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "cleanup-ci-caches.yml"
    )
    cleanup = document["jobs"]["cleanup"]
    script = cleanup["steps"][0]["with"]["script"]

    assert "Promise.all" not in script
    assert "await delay(500)" in script
    assert "error.status === 429 || error.status === 403" in script
    assert "const maxAttempts = 7" in script
    assert "retry-after" in script
    assert "2_000 * (2 ** attempt)" in script
    assert "maxDeletions = 2000" in source


def test_compiler_cache_writes_are_reserved_for_trusted_main() -> None:
    _, ci = _workflow(CI_PATH)
    _, warm = _workflow(ROOT / ".github/workflows/warm-ci-caches.yml")
    for name in ("test-rust-services", "rust-lint-policy"):
        assert ci["jobs"][name]["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    for job in warm["jobs"].values():
        assert job["if"] == "github.ref == 'refs/heads/main'"
    for job, mode in (
        (ci["jobs"]["test-rust-service-images"], "READ_ONLY"),
        (warm["jobs"]["images"], "READ_WRITE"),
    ):
        credential_step = next(
            step
            for step in job["steps"]
            if step.get("name", "").startswith("Expose compiler")
        )
        script = credential_step["with"]["script"]
        assert "core.setSecret(token)" in script
        assert f"'SCCACHE_GHA_RW_MODE', '{mode}'" in script
        build = next(
            step for step in job["steps"] if "secret-envs" in step.get("with", {})
        )
        assert "sccache_token=SCCACHE_GHA_RUNTIME_TOKEN" in build["with"]["secret-envs"]
        assert "SCCACHE" not in build["with"].get("build-args", "")
    assert all(
        "cache-to" not in step.get("with", {})
        for step in ci["jobs"]["test-rust-service-images"]["steps"]
    )
    dockerfile = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    assert (
        "ADD --checksum=sha256:aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588"
        in dockerfile
    )
    assert "--mount=type=secret,id=sccache_token" in dockerfile
    assert "export RUSTC_WRAPPER=sccache" in dockerfile
    assert "cargo build --locked --release" in dockerfile
    assert "sccache --stop-server" in dockerfile
    assert "ENV SCCACHE_GHA_RUNTIME_TOKEN" not in dockerfile
    assert 'ACTIONS_RESULTS_URL="$(cat /run/secrets/sccache_url)"' in dockerfile
    assert 'ACTIONS_RUNTIME_TOKEN="$(cat /run/secrets/sccache_token)"' in dockerfile
    assert "sccache --start-server && sccache --stop-server" in dockerfile
    assert "FROM compiler_cache AS builder" in dockerfile
    assert dockerfile.count("ACTIONS_CACHE_SERVICE_V2=true") == 3
    assert dockerfile.index("FROM compiler_cache AS builder") < dockerfile.index(
        "cargo chef cook"
    )


def test_release_cache_probe_is_main_only_and_cannot_invalidate_builder() -> None:
    _, warm = _workflow(ROOT / ".github/workflows/warm-ci-caches.yml")
    job = warm["jobs"]["images"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    probe = next(
        step
        for step in job["steps"]
        if step.get("with", {}).get("target") == "cache_probe"
    )
    assert "continue-on-error" not in probe
    assert "github.run_id" in probe["with"]["build-args"]
    assert "github.run_attempt" in probe["with"]["build-args"]
    dockerfile = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    assert "FROM compiler_cache AS cache_probe" in dockerfile
    builder = dockerfile.split("FROM compiler_cache AS builder", 1)[1]
    assert "CACHE_PROBE_NONCE" not in builder
    assert "--from=cache_probe" not in builder
    script = (ROOT / "scripts/ci/verify-release-cache.sh").read_text(encoding="utf-8")
    assert "ACTIONS_CACHE_SERVICE_V2=true" in script
    assert script.index("SCCACHE_GHA_RW_MODE=READ_WRITE") < script.index(
        "SCCACHE_GHA_RW_MODE=READ_ONLY"
    )
    assert script.count("sccache rustc") == 2
    assert script.count("--emit=link,dep-info") == 2
    assert script.count("sccache --stop-server") == 2
    assert "exit !hit" in script


def test_image_context_excludes_integration_tests_but_keeps_build_inputs() -> None:
    ignore = (ROOT / "rust/services/Dockerfile.ci.dockerignore").read_text(
        encoding="utf-8"
    )
    for item in (
        "!rust/**",
        "!proto/**",
        "!contracts/**",
        "!scripts/load-secrets-env.sh",
        "!scripts/ci/verify-release-cache.sh",
        "rust/services/*/tests",
        "rust/crates/*/tests",
        "rust/**/target",
        "rust/**/.env*",
    ):
        assert item in ignore.splitlines()
    # Never drop embedded production contracts or vendored build-script inputs.
    assert "rust/third_party" not in ignore
    assert "contracts/*-oracle.json" not in ignore


def test_every_issuance_integration_test_remains_registered() -> None:
    directory = ROOT / "rust/services/issuance"
    manifest = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["package"]["autotests"] is False
    targets = manifest["test"]
    assert len({target["name"] for target in targets}) == len(targets)
    registered = [target["path"] for target in targets]
    harness = (directory / "tests/behavior_suite.rs").read_text(encoding="utf-8")
    grouped = re.findall(r'#\[path = "([^"]+)"\]', harness)
    assert len(grouped) == 6
    registered.extend(f"tests/{name}" for name in grouped)
    actual = {
        path.relative_to(directory).as_posix()
        for path in (directory / "tests").glob("*.rs")
    }
    assert len(registered) == len(set(registered))
    assert set(registered) == actual, (
        "new test files must be registered, never silently skipped"
    )
    assert all(
        "postgres" not in path and "executable_smoke" not in path for path in grouped
    )


@pytest.mark.parametrize("event", ["pull_request", "workflow_dispatch"])
@pytest.mark.parametrize("reopened", [False, True])
def test_cache_cleanup_includes_queue_refs_but_preserves_active_and_main(
    event: str, reopened: bool
) -> None:
    _, document = _workflow(ROOT / ".github/workflows/cleanup-ci-caches.yml")
    script = document["jobs"]["cleanup"]["steps"][0]["with"]["script"]
    harness = (
        r"""
      const deleted = [];
      const entries = [
        {id: 1, ref: 'refs/pull/23/merge'},
        {id: 2, ref: 'refs/heads/gh-readonly-queue/main/pr-23-abcdef'},
        {id: 3, ref: 'refs/heads/main'},
        {id: 4, ref: 'refs/pull/24/merge'},
        {id: 5, ref: 'refs/heads/gh-readonly-queue/main/pr-24-abcdef'},
        {id: 6, ref: 'refs/heads/feature'},
      ];
      const github = {
        request: async (_, params) => {
          if (params.ref) throw new Error('ref filter hides queue caches');
          return {data: {actions_caches: entries}};
        },
        rest: {
          pulls: {get: async ({pull_number}) => ({data: {state: pull_number === 23 && !REOPENED ? 'closed' : 'open'}})},
          actions: {deleteActionsCacheById: async ({cache_id}) => { deleted.push(cache_id); }},
        },
      };
      const summary = {addHeading() {return this}, addRaw() {return this}, async write() {}};
      const core = {info() {}, warning() {}, summary};
      const context = {repo: {owner: 'test', repo: 'test'}, eventName: EVENT,
        payload: {pull_request: {number: 23}}};
      const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
      await new AsyncFunction('github', 'context', 'core', 'setTimeout', SCRIPT)(
        github, context, core, callback => callback());
      if (JSON.stringify(deleted) !== (REOPENED ? '[]' : '[1,2]')) throw new Error(JSON.stringify(deleted));
    """.replace("EVENT", json.dumps(event))
        .replace("REOPENED", json.dumps(reopened))
        .replace("SCRIPT", json.dumps(script))
    )
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", harness],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "scenario", ["valid", "empty", "negative", "huge", "traversal", "malformed"]
)
def test_reviewed_timing_adoption_validates_data_and_preserves_tests(
    tmp_path: Path, scenario: str
) -> None:
    paths = sorted(
        path.relative_to(ROOT / "ui").as_posix()
        for path in (ROOT / "ui/src").rglob("*")
        if path.is_file() and re.search(r"\.(test|spec)\.(ts|tsx)$", path.name)
    )
    plan = {"defaultMilliseconds": 500, "tests": {paths[0]: 123}}
    if scenario == "empty":
        plan["tests"] = {}
    elif scenario in {"negative", "huge"}:
        plan["tests"][paths[0]] = -1 if scenario == "negative" else 3_600_001
    elif scenario == "traversal":
        plan["tests"]["src/../../outside.test.ts"] = 1
    source = tmp_path / "observations.json"
    source.write_text(
        "not JSON" if scenario == "malformed" else json.dumps(plan), encoding="utf-8"
    )
    output = tmp_path / "review.json"
    result = subprocess.run(
        [
            "node",
            str(ROOT / "ui/scripts/adopt-vitest-timings.mjs"),
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    if scenario != "valid":
        assert result.returncode != 0
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        adopted = json.loads(output.read_text(encoding="utf-8"))
        assert set(adopted["tests"]) == set(paths)
        assert adopted["tests"][paths[0]] == 123


def test_renewal_matrix_preserves_real_deadlines_and_all_combinations() -> None:
    source = (
        ROOT
        / "rust/services/issuance/tests/support/canvas_worker_renewal_job_outcomes.rs"
    ).read_text(encoding="utf-8")
    assert "tokio::join!(" in source
    for stage in ("lease", "target", "process"):
        assert f'isolated_group(pool, "{stage}")' in source
    assert "Uuid::new_v4().simple()" in source
    assert "catch_unwind().await" in source.replace("\n", "").replace(" ", "")
    assert "pool.close().await" in source
    assert "Duration::from_secs(20)" in source
    assert "Duration::from_secs(30)" in source
    assert "sum::<usize>(),60" in re.sub(r"\s+", "", source)
