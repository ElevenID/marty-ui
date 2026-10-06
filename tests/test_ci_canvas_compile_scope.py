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
    contracts_branch, canvas_branch = compile_run.split("else\n", 1)
    assert '[[ "${{ matrix.lane }}" == contracts ]]' in contracts_branch
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
    # Test packages resolve together. Real binaries keep their independently
    # resolved features; preserve every exact target/profile/artifact flag.
    commands = [
        shlex.split(line.strip())
        for line in canvas_branch.replace("\\\n", " ").splitlines()
        if line.strip().startswith("cargo ")
    ]
    assert commands == [
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "marty-canvas-acceptance",
            "-p",
            "marty-issuance-service",
            "--lib",
            "--test",
            "canvas_published_worker_contract",
            "--test",
            "canvas_published_schema_contract",
            "--test",
            "canvas_oauth_behavior",
            "--test",
            "issuance-behavior",
            "--no-run",
            "--timings",
            "--message-format=json",
            ">>",
            "$artifacts",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "marty-issuance-service",
            "--bin",
            "marty-issuance-service",
            "--bin",
            "marty-canvas-sync-worker",
            "--message-format=json",
            ">>",
            "$artifacts",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "marty-gateway",
            "--bin",
            "marty-gateway",
            "--message-format=json",
            ">>",
            "$artifacts",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "marty-flow",
            "--bin",
            "marty-flow",
            "--message-format=json",
            ">>",
            "$artifacts",
        ],
    ]
    assert by_name["Prepare database contract executables"]["if"] == (
        "matrix.lane == 'contracts'"
    )
    assert (
        by_name["Run isolated database contract suites concurrently"]["run"]
        == "python3 ../scripts/ci/run-db-contract-groups.py "
        "${{ matrix.lane == 'canvas' && 'canvas' || 'rust-db' }}"
    )
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
    assert job["strategy"]["matrix"] == {
        "lane": "${{ fromJSON(needs.changes.outputs.rust_matrix) }}"
    }
    changes = workflow["jobs"]["changes"]
    assert (
        changes["outputs"]["rust_matrix"] == "${{ steps.classify.outputs.rust_matrix }}"
    )
    classifier = next(step for step in changes["steps"] if step.get("id") == "classify")
    assert 'rust_matrix=\'["canvas","contracts"]\'' in classifier["run"]
    assert "rust_matrix='[\"contracts\"]'" in classifier["run"]
    steps = {step.get("name"): step for step in job["steps"]}
    compile_run = steps["Compile reusable Rust test executables"]["run"]
    assert "cargo test --locked --workspace --no-run" in compile_run
    assert "--exclude" not in compile_run
    execution = steps["Run safe Rust contract groups concurrently"]
    assert execution["if"] == "matrix.lane == 'contracts'"
    assert (
        "cargo test --locked --workspace --exclude marty-canvas-acceptance "
        in execution["run"]
    )
    assert execution["run"].count("--exclude") == 1

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
    assert '"$RUST_MATRIX" == \'["canvas","contracts"]\' ]]' in gate_script

    package = ROOT / "rust/crates/canvas-acceptance"
    manifest = tomllib.loads((package / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["package"]["autotests"] is False
    targets = {entry["name"] for entry in manifest["test"]}
    assert targets == {
        "canvas_published_worker_contract",
        "canvas_published_schema_contract",
    }
    assert not any(key in manifest for key in ("bin", "example", "bench"))
    assert not (package / "src/bin").exists()
    assert not (package / "src/main.rs").exists()
    assert not (package / "examples").exists()
    assert not (package / "benches").exists()
    # The library is an ownership marker only. New library tests need an explicit
    # execution owner before this package can remain excluded from contracts.
    assert (package / "src/lib.rs").read_text(encoding="utf-8").strip() == (
        "//! Ownership boundary for published Canvas worker and composition acceptance."
    )
    runner = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    for target in targets:
        assert target in runner
    assert '"$composition_executable" --skip' in runner
    assert '"$worker_executable" --skip' in runner


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


@pytest.mark.parametrize("index", [0, 4, 5, 8])
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


@pytest.mark.parametrize("index", [0, 2, 4, 5, 8])
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
