"""Keep the Canvas compile narrow without weakening its executable contract."""

import json
from pathlib import Path
import runpy

import pytest
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
    with pytest.raises(ValueError, match="real, non-test"):
        _verify(artifacts, target_dir, records)
