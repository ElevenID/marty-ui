"""Keep the Canvas compile narrow without weakening its executable contract."""

import json
import runpy
import shlex
from pathlib import Path

import pytest
import tomllib
import yaml

ROOT = Path(__file__).parents[1]
VERIFY = runpy.run_path(str(ROOT / "scripts/ci/verify-canvas-test-artifacts.py"))
TEST_TARGETS = VERIFY["TEST_TARGETS"]
BIN_TARGETS = VERIFY["BIN_TARGETS"]


def test_canvas_compile_selectors_preserve_complete_contracts_lane() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    by_name = {step.get("name"): step for step in steps}
    compile_step = by_name["Compile reusable Rust test executables"]
    compile_run = compile_step["run"]
    owner_branch = compile_run.split(
        'if [[ "${{ matrix.lane }}" == worker || "${{ matrix.lane }}" == flow || "${{ matrix.lane }}" == selfhost ]]; then', 1
    )[1].split('elif [[ "${{ matrix.lane }}" == contracts ]]; then', 1)[0]
    worker_branch = owner_branch.split('worker)\n', 1)[1].split(';;\n', 1)[0]
    flow_branch = owner_branch.split('flow)\n', 1)[1].split(';;\n', 1)[0]
    selfhost_branch = owner_branch.split('selfhost)\n', 1)[1].split(';;\n', 1)[0]
    assert worker_branch.count("--message-format=json") == 2
    assert "-p marty-canvas-worker-acceptance" in worker_branch
    assert "--test canvas_published_worker_contract" in worker_branch
    assert "-p marty-issuance-service" in worker_branch
    assert "--bin marty-canvas-sync-worker" in worker_branch
    assert '--worker-only "$artifacts" target' in owner_branch
    assert '--flow-only "$artifacts" target' in owner_branch
    assert '--selfhost-only "$artifacts" target' in owner_branch
    assert "rust:1\\.95-bookworm@sha256:" in owner_branch
    assert "docker run --rm --network none --read-only" in owner_branch
    for unrelated in (
        "marty-canvas-acceptance",
        "canvas_published_schema_contract",
        "marty-gateway",
        "marty-flow",
        "marty-issuance-service --bin marty-issuance-service",
    ):
        assert unrelated not in worker_branch
    assert flow_branch.count("--message-format=json") == 3
    assert "-p marty-flow-acceptance" in flow_branch
    assert "--test flow_published_schema_contract" in flow_branch
    assert "--bin marty-issuance-service" in flow_branch
    assert "--bin marty-flow" in flow_branch
    assert selfhost_branch.count("--message-format=json") == 1
    assert "-p marty-selfhost-acceptance" in selfhost_branch
    assert "--test selfhost_public_image_contract" in selfhost_branch
    assert "--no-run" in selfhost_branch
    for unrelated in ("marty-canvas-acceptance", "marty-gateway", "marty-flow", "--bin"):
        assert unrelated not in selfhost_branch
    contracts_branch, canvas_branch = compile_run.split(
        'elif [[ "${{ matrix.lane }}" == contracts ]]; then', 1
    )[1].split("else\n", 1)
    assert '[[ "${{ matrix.lane }}" == contracts ]]' in compile_run
    assert "cargo test --locked --workspace --no-run" in contracts_branch
    assert "--workspace" not in canvas_branch
    for package, target, kind in (*TEST_TARGETS, *BIN_TARGETS):
        assert f"-p {package}" in canvas_branch
        assert (
            "--bin " if kind == "bin" else "--test " if kind == "test" else "--lib"
        ) in canvas_branch
        if kind != "lib":
            assert target in canvas_branch
    assert "verify-canvas-test-artifacts.py" in canvas_branch
    assert "cargo fetch --locked" in canvas_branch
    assert "docker run --rm --network none --read-only" in canvas_branch
    assert '--volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro"' in canvas_branch
    assert (
        '--volume "$GITHUB_WORKSPACE/rust/target:$GITHUB_WORKSPACE/rust/target:rw"'
        in canvas_branch
    )
    assert '"$bookworm_builder"' in canvas_branch
    assert '--env "CARGO_TARGET_DIR=$GITHUB_WORKSPACE/rust/target"' in canvas_branch
    assert (
        '[[ -z "$(find target -mindepth 1 -maxdepth 1 -print -quit)" ]]'
        in canvas_branch
    )
    assert canvas_branch.count("--message-format=json") == 4
    # Test packages resolve together. Real binaries keep their independently
    # resolved features; preserve every exact target/profile/artifact flag.
    timed_commands = [
        shlex.split(line.strip())
        for line in canvas_branch.replace("\\\n", " ").splitlines()
        if line.strip().startswith(("run_cargo_phase ", "cargo test ", "cargo build "))
    ]
    assert [command[:2] for command in timed_commands] == [
        ["run_cargo_phase", "tests"],
        ["run_cargo_phase", "issuance_binaries"],
        ["run_cargo_phase", "gateway_binary"],
        ["run_cargo_phase", "flow_binary"],
    ]
    commands = [command[2:] for command in timed_commands]
    assert commands == [
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "marty-canvas-acceptance",
            "-p",
            "marty-canvas-worker-acceptance",
            "-p",
            "marty-flow-acceptance",
            "-p",
            "marty-selfhost-acceptance",
            "-p",
            "marty-issuance-service",
            "--lib",
            "--test",
            "canvas_published_worker_contract",
            "--test",
            "canvas_published_schema_contract",
            "--test",
            "flow_published_schema_contract",
            "--test",
            "selfhost_public_image_contract",
            "--test",
            "canvas_oauth_behavior",
            "--test",
            "issuance-behavior",
            "--no-run",
            "--timings",
            "--message-format=json",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "--offline",
            "-p",
            "marty-issuance-service",
            "--bin",
            "marty-issuance-service",
            "--bin",
            "marty-canvas-sync-worker",
            "--message-format=json",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "--offline",
            "-p",
            "marty-gateway",
            "--bin",
            "marty-gateway",
            "--message-format=json",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "--offline",
            "-p",
            "marty-flow",
            "--bin",
            "marty-flow",
            "--message-format=json",
        ],
    ]
    assert by_name["Prepare database contract executables"]["if"] == (
        "matrix.lane == 'contracts'"
    )
    group_run = by_name["Run isolated database contract suites concurrently"]["run"]
    assert "run-db-contract-groups.py worker-preflights" in group_run
    assert "run-db-contract-groups.py worker-canvas" in group_run
    assert (
        "run-db-contract-groups.py "
        "${{ matrix.lane == 'canvas' && 'canvas' || 'rust-db' }}"
    ) in group_run
    assert "if" not in by_name["Run isolated database contract suites concurrently"]
    assert (
        "cargo test --locked --workspace"
        in by_name["Run safe Rust contract groups concurrently"]["run"]
    )


def test_canvas_execution_has_one_mandatory_owner_without_lost_targets() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["test-rust-services"]
    assert job["if"] == "needs.changes.outputs.rust == 'true'"
    matrix = job["strategy"]["matrix"]["lane"]
    assert "github.event_name == 'pull_request'" in matrix
    assert "ci-worker-diagnostic" in matrix
    assert "needs.changes.outputs.rust_runtime == 'true'" in matrix
    assert '\'["canvas","contracts","worker"]\'' in matrix
    assert "|| needs.changes.outputs.rust_matrix) }}" in matrix
    changes = workflow["jobs"]["changes"]
    assert (
        changes["outputs"]["rust_matrix"] == "${{ steps.classify.outputs.rust_matrix }}"
    )
    classifier = next(step for step in changes["steps"] if step.get("id") == "classify")
    assert 'rust_matrix=\'["canvas","contracts"]\'' in classifier["run"]
    assert "rust_matrix='[\"contracts\"]'" in classifier["run"]
    assert "rust_matrix='[\"worker\"]'" in classifier["run"]
    assert "--emit-verified-worker-tests" in classifier["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Start digest-pinned Rust test services after registry setup"]["if"] == (
        "matrix.lane != 'selfhost'"
    )
    assert steps["Remove owned Rust test services and volumes"]["if"] == (
        "always() && matrix.lane != 'selfhost'"
    )
    selfhost_source = (
        ROOT / "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs"
    ).read_text(encoding="utf-8")
    assert "PublishedDatabase::start_with_scope" in selfhost_source
    assert "MARTY_RUST_CI_POSTGRES_ID" not in selfhost_source
    assert "MARTY_RUST_CI_REDIS_ID" not in selfhost_source
    compile_run = steps["Compile reusable Rust test executables"]["run"]
    assert "cargo test --locked --workspace --no-run" in compile_run
    assert "--exclude" not in compile_run
    execution = steps["Run safe Rust contract groups concurrently"]
    assert execution["if"] == "matrix.lane == 'contracts'"
    assert (
        "cargo test --locked --workspace --exclude marty-canvas-acceptance "
        "--exclude marty-canvas-worker-acceptance "
        "--exclude marty-selfhost-acceptance "
        "--exclude marty-flow-acceptance >"
        in execution["run"]
    )
    assert execution["run"].count("--exclude") == 4

    gate = workflow["jobs"]["ci-gate"]
    assert "test-rust-services" in gate["needs"]
    assert gate["env"]["RUST_SERVICES_RESULT"] == (
        "${{ needs.test-rust-services.result }}"
    )
    assert any(
        'require_selected test-rust-services "$RUST_SERVICES_RESULT" "$RUST_SELECTED"'
        in step.get("run", "")
        for step in gate["steps"]
    )
    gate_script = gate["steps"][0]["run"]
    assert '\'true:true:["canvas","contracts"]\'' in gate_script
    assert "'true:false:[\"contracts\"]'" in gate_script
    assert "'true:false:[\"worker\"]'" in gate_script
    assert '"$RUST_MATRIX" == \'["canvas","contracts"]\' ]]' in gate_script

    packages = {
        "canvas-acceptance": (
            "canvas_published_schema_contract",
            "//! Ownership boundary for published Canvas composition acceptance.",
        ),
        "canvas-worker-acceptance": (
            "canvas_published_worker_contract",
            "//! Ownership boundary for published Canvas worker acceptance.",
        ),
        "flow-acceptance": (
            "flow_published_schema_contract",
            "//! Ownership marker for published-schema Flow acceptance.",
        ),
        "selfhost-acceptance": (
            "selfhost_public_image_contract",
            "//! Ownership boundary for published self-host image acceptance.",
        ),
    }
    for directory, (target, marker) in packages.items():
        package = ROOT / "rust/crates" / directory
        manifest = tomllib.loads((package / "Cargo.toml").read_text(encoding="utf-8"))
        assert manifest["package"]["autotests"] is False
        assert {entry["name"] for entry in manifest["test"]} == {target}
        assert not any(key in manifest for key in ("bin", "example", "bench"))
        assert not (package / "src/bin").exists()
        assert not (package / "src/main.rs").exists()
        assert not (package / "examples").exists()
        assert not (package / "benches").exists()
        # New library tests need an explicit execution owner before this package
        # can remain excluded from contracts.
        assert (package / "src/lib.rs").read_text(encoding="utf-8").strip() == marker
    runner = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    for target in (target for target, _ in packages.values()):
        assert target in runner
    assert '"$composition_executable" --skip' in runner
    assert '"$flow_executable" --nocapture --test-threads=4' in runner
    assert '"$worker_executable" --skip' in runner
    assert '"$selfhost_executable" --nocapture' in runner


def test_selfhost_diagnostic_is_additive_and_uses_the_full_image_contract() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["test-rust-services"]
    matrix = job["strategy"]["matrix"]["lane"]
    assert "ci-selfhost-diagnostic" in matrix
    assert "needs.changes.outputs.rust_runtime == 'true'" in matrix
    assert '\'["canvas","contracts","selfhost"]\'' in matrix
    assert '\'["canvas","contracts","worker","selfhost"]\'' in matrix
    assert "|| needs.changes.outputs.rust_matrix) }}" in matrix
    steps = {step.get("name"): step for step in job["steps"]}
    for name in (
        "Expose public image compiler cache credentials",
        "Build public selfhost image",
        "Prepare public selfhost image loader acceptance",
    ):
        assert steps[name]["if"] == "matrix.lane == 'canvas' || matrix.lane == 'selfhost'"
        assert not steps[name].get("continue-on-error", False)
    renderer = steps["Prepare pinned standalone Compose renderer for Rust contracts"]
    assert "matrix.lane == 'selfhost'" in renderer["if"]
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE" in renderer["run"]
    suite = steps["Run isolated database contract suites concurrently"]
    assert '[[ "${{ matrix.lane }}" == selfhost ]]' in suite["run"]
    assert "run-db-contract-groups.py selfhost-canvas" in suite["run"]
    assert "export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=\"1\"" in (
        ROOT / "scripts/ci/run-published-canvas-contracts.sh"
    ).read_text(encoding="utf-8")
    runner = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    selfhost_branch = runner.split('if [[ "$mode" == selfhost-only ]]; then', 1)[1].split(
        "\nfi\ncomposition_executable=", 1
    )[0]
    assert "require_selfhost_tests" in selfhost_branch
    assert "MARTY_SELFHOST_TEST_PACKAGER_BINARY" in selfhost_branch
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE" in selfhost_branch
    assert "MARTY_SELFHOST_TEST_IMAGE" in selfhost_branch
    assert "MARTY_SELFHOST_TEST_REVISION" in selfhost_branch
    assert "pull_published_postgres" in selfhost_branch
    assert "--nocapture --test-threads=4" in selfhost_branch
    assert "10 passed; 0 failed; 0 ignored" in selfhost_branch
    assert runner.count("selfhost_public_image_loader_isolated: test") == 2


def _records(tmp_path: Path) -> tuple[Path, Path, list[dict]]:
    target_dir = tmp_path / "target"
    deps = target_dir / "debug/deps"
    deps.mkdir(parents=True)
    records = []
    for package, target, kind in (*TEST_TARGETS, *BIN_TARGETS):
        is_test = kind != "bin"
        path = (
            deps / f"{target}-0123456789abcdef"
            if is_test
            else target_dir / "debug" / target
        )
        path.write_text("fixture", encoding="utf-8")
        path.chmod(0o755)
        records.append(
            {
                "reason": "compiler-artifact",
                "package_id": f"path+file:///fixture#{package}@0.1.0",
                "target": {"name": target, "kind": [kind]},
                "profile": {"test": is_test},
                "executable": str(path),
            }
        )
    return tmp_path / "artifacts.json", target_dir, records


def _verify(artifacts: Path, target_dir: Path, records: list[dict]) -> None:
    artifacts.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    VERIFY["verify"](artifacts, target_dir)


def test_exact_canvas_artifacts_are_accepted(tmp_path: Path) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    _verify(artifacts, target_dir, records)


def test_worker_only_artifacts_require_real_worker_without_composition(
    tmp_path: Path,
) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    worker = [records[0], records[len(TEST_TARGETS) + 1]]
    artifacts.write_text(
        "".join(json.dumps(record) + "\n" for record in worker), encoding="utf-8"
    )
    VERIFY["verify"](artifacts, target_dir, worker_only=True)
    with pytest.raises(ValueError, match="Expected exactly one"):
        VERIFY["verify"](artifacts, target_dir)
    for invalid in (
        [worker[0]],
        [worker[0], {**worker[1], "profile": {"test": True}}],
        [*worker, {**worker[1], "executable": str(target_dir / "debug/other-worker")}],
    ):
        artifacts.write_text(
            "".join(json.dumps(record) + "\n" for record in invalid),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Expected exactly one"):
            VERIFY["verify"](artifacts, target_dir, worker_only=True)


def test_flow_only_artifacts_require_real_flow_and_issuance_binaries(
    tmp_path: Path,
) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    flow = [records[2], records[len(TEST_TARGETS)], records[-1]]
    artifacts.write_text(
        "".join(json.dumps(record) + "\n" for record in flow), encoding="utf-8"
    )
    VERIFY["verify"](artifacts, target_dir, flow_only=True)
    with pytest.raises(ValueError, match="Expected exactly one"):
        VERIFY["verify"](artifacts, target_dir)
    for invalid in (
        flow[:2],
        flow[1:],
        [flow[0], {**flow[1], "profile": {"test": True}}, flow[2]],
        [*flow, {**flow[2], "executable": str(target_dir / "debug/other-flow")}],
    ):
        artifacts.write_text(
            "".join(json.dumps(record) + "\n" for record in invalid),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Expected exactly one"):
            VERIFY["verify"](artifacts, target_dir, flow_only=True)
    with pytest.raises(ValueError, match="one owner"):
        VERIFY["verify"](artifacts, target_dir, worker_only=True, flow_only=True)


def test_selfhost_only_artifacts_require_exact_test_harness(tmp_path: Path) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    selfhost = records[3]
    artifacts.write_text(json.dumps(selfhost) + "\n", encoding="utf-8")
    VERIFY["verify"](artifacts, target_dir, selfhost_only=True)
    with pytest.raises(ValueError, match="Expected exactly one"):
        VERIFY["verify"](artifacts, target_dir)
    for invalid, error in (
        ({**selfhost, "profile": {"test": False}}, "Expected exactly one"),
        ({**selfhost, "target": {"name": "other", "kind": ["test"]}}, "Expected exactly one"),
        ({**selfhost, "package_id": "path+file:///fixture#marty-canvas-acceptance@0.1.0"}, "Expected exactly one"),
        ({**selfhost, "executable": str(target_dir / "debug/other-test")}, "Expected a test harness"),
    ):
        artifacts.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match=error):
            VERIFY["verify"](artifacts, target_dir, selfhost_only=True)
    for other_scope in ("worker_only", "flow_only"):
        with pytest.raises(ValueError, match="one owner"):
            VERIFY["verify"](
                artifacts, target_dir, selfhost_only=True, **{other_scope: True}
            )


@pytest.mark.parametrize("index", [0, 5, 6, 9])
@pytest.mark.parametrize(
    "profile", [{}, {"test": None}, {"test": "false"}, {"test": 0}, {"test": 1}]
)
def test_canvas_artifact_requires_explicit_boolean_profile(
    tmp_path: Path, index: int, profile: dict
) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    records[index]["profile"] = profile
    with pytest.raises(ValueError, match="Expected exactly one"):
        _verify(artifacts, target_dir, records)


def test_real_worker_is_selected_when_cargo_also_reports_its_test_harness(
    tmp_path: Path,
) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    harness = dict(
        next(
            record
            for record in records
            if record["target"]["name"] == "marty-canvas-sync-worker"
        )
    )
    harness["profile"] = {"test": True}
    harness["executable"] = str(target_dir / "debug/deps/marty-canvas-sync-worker-test")
    _verify(artifacts, target_dir, [*records, harness])


@pytest.mark.parametrize("index", [0, 2, 5, 6, 9])
def test_missing_canvas_artifact_fails_closed(tmp_path: Path, index: int) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    with pytest.raises(ValueError, match="Expected exactly one"):
        _verify(artifacts, target_dir, records[:index] + records[index + 1 :])


def test_duplicate_canvas_artifact_fails_closed(tmp_path: Path) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    duplicate = dict(records[0])
    duplicate["executable"] = str(target_dir / "debug/deps/other-0123456789abcdef")
    with pytest.raises(ValueError, match="Expected exactly one"):
        _verify(artifacts, target_dir, [*records, duplicate])


@pytest.mark.parametrize("bad_field", ["profile", "executable"])
def test_test_harness_cannot_substitute_for_real_worker_binary(
    tmp_path: Path, bad_field: str
) -> None:
    artifacts, target_dir, records = _records(tmp_path)
    worker = next(
        record
        for record in records
        if record["target"]["name"] == "marty-canvas-sync-worker"
    )
    if bad_field == "profile":
        worker["profile"] = {"test": True}
    else:
        worker["executable"] = str(
            target_dir / "debug/deps/marty-canvas-sync-worker-0123456789abcdef"
        )
    with pytest.raises(ValueError, match="Expected exactly one|real, non-test"):
        _verify(artifacts, target_dir, records)
