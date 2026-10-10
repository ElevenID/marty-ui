"""Guard current JSON-depth probe inputs; never authorize historical or CI skips."""

import ast
import json
import re
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci.canvas_oracle_current_inputs import json_references, normalized_sha256

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts/canvas-json-depth-current-inputs.json"
CONSTRUCTOR = "rust/services/issuance/tests/support/canvas_published_database.rs"
SCRIPTS = frozenset(
    {
        "scripts/prepare_canvas_published_schema.py",
        "scripts/run_canvas_json_depth_oracle.py",
        "scripts/run_canvas_status_provider_oracle.py",
        "scripts/run_canvas_validation_boundary_oracle.py",
        "scripts/canvas_json_tree_observation.py",
        "scripts/canvas_observation_values.py",
    }
)
INPUTS = SCRIPTS | {
    CONSTRUCTOR,
    "contracts/canvas-worker-consumer-range-oracle.json",
    "contracts/canvas-json-depth-scenarios.json",
    "contracts/canvas-issued-review-scenarios.json",
    "contracts/canvas-review-recovery-migration.json",
    "contracts/fixtures/canvas_review_recovery_claim.py",
}
DIRECT_IMPORTS = {
    "scripts/run_canvas_json_depth_oracle.py": {
        "scripts/run_canvas_status_provider_oracle.py",
        "scripts/run_canvas_validation_boundary_oracle.py",
        "scripts/canvas_json_tree_observation.py",
        "scripts/canvas_observation_values.py",
    },
}
ISSUANCE_IMAGE = (
    "ghcr.io/elevenid/marty-credentials-issuance@sha256:"
    "9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"
)
POSTGRES_IMAGE = (
    "postgres@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
)


def _assert_inputs(evidence: dict, root: Path) -> None:
    assert set(evidence) == {"schema", "purpose", "normalization", "sha256"}
    assert evidence["schema"] == "marty.canvas-json-depth-current-inputs/v1"
    assert "do not attest historical capture provenance" in evidence["purpose"]
    assert "authorize skipping a live oracle" in evidence["purpose"]
    assert evidence["normalization"] == (
        "UTF-8 text with CRLF and CR converted to LF before SHA-256"
    )
    assert set(evidence["sha256"]) == INPUTS, "JSON-depth inputs need review"
    for name, digest in evidence["sha256"].items():
        assert Path(name).as_posix() == name and ".." not in Path(name).parts
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        assert normalized_sha256(root / name) == digest, (
            f"JSON-depth input drift: {name}"
        )
    # Match the existing REST guard's literal JSON reference policy. Every
    # referenced contract must be explicitly pinned, even after a reviewed
    # update to the referring file's digest.
    for source in (name for name in INPUTS if name.endswith(".json")):
        value = json.loads((root / source).read_text(encoding="utf-8"))
        for reference in json_references(value):
            filename = reference.partition("#")[0]
            assert filename.endswith(".json") and Path(filename).name == filename, (
                f"Unsafe JSON-depth reference: {reference}"
            )
            assert f"contracts/{filename}" in evidence["sha256"], (
                f"JSON-depth transitive JSON input needs review: {reference}"
            )


def _local_imports(source: str, root: Path) -> set[str]:
    tree = ast.parse((root / source).read_text(encoding="utf-8"))
    imported = set()
    dynamic_names = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"importlib", "runpy"}:
            dynamic_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in {"import_module", "run_path"}
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"Review relative local import in {source}"
            names = [node.module] if node.module else []
        elif isinstance(node, ast.Call):
            function = node.func
            assert not (
                isinstance(function, ast.Name)
                and function.id in dynamic_names
                or isinstance(function, ast.Attribute)
                and function.attr in {"import_module", "run_path"}
            ), f"Review dynamic local import in {source}"
            continue
        else:
            continue
        for name in names:
            base = name.split(".", 1)[0]
            assert not (root / "scripts" / base).is_dir(), (
                f"Review local package import in {source}: {name}"
            )
            path = f"scripts/{base}.py"
            if (root / path).is_file():
                imported.add(path)
    return imported


def test_current_json_depth_probe_inputs_and_selector() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    _assert_inputs(evidence, ROOT)

    fixture = json.loads(
        (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text()
    )
    assert fixture["observed_image"] == ISSUANCE_IMAGE
    assert fixture["observed_postgres_image"] == POSTGRES_IMAGE
    assert (
        fixture["schema_preparer_source_sha256"]
        == evidence["sha256"]["scripts/prepare_canvas_published_schema.py"]
    )
    recovery = json.loads(
        (ROOT / "contracts/canvas-review-recovery-migration.json").read_text()
    )
    assert (
        recovery["sha256"]
        == evidence["sha256"]["contracts/fixtures/canvas_review_recovery_claim.py"]
    )
    assert recovery["parent"] == fixture["migration_revisions"][0]
    assert recovery["source"].endswith(
        "/20260905_1900_allow_canvas_review_recovery_claim.py"
    )

    constructor = (ROOT / CONSTRUCTOR).read_text(encoding="utf-8")
    depth = constructor.split("pub async fn start_with_json_depth()", 1)[1].split(
        "pub async fn start_with_worker_startup()", 1
    )[0]
    assert (
        '"json_depth",\n                "json-depth",\n                "json_depth",'
        in depth
    )
    assert '"MARTY_CANVAS_JSON_DEPTH_ORACLE=1"' in depth
    assert 'Some("canvas-issued-review-scenarios.json")' in depth
    assert "true," in depth  # recovery_schema selects the test-only overlay
    assert '"utf7_consumer" | "json_consumer" | "json_depth"' in constructor
    helper_branch = constructor.split(
        'if matches!(script, "utf7_consumer" | "json_consumer" | "json_depth")', 1
    )[1].split(".into_iter()", 1)[0]
    assert set(re.findall(r'"([a-z_]+\.py)"', helper_branch)) == {
        "run_canvas_validation_boundary_oracle.py",
        "run_canvas_status_provider_oracle.py",
        "canvas_observation_values.py",
        "canvas_json_tree_observation.py",
    }
    assert 'format!("scripts/run_canvas_{script}_oracle.py")' in constructor
    assert 'root.join("scripts/prepare_canvas_published_schema.py")' in constructor
    for name in (
        "canvas-worker-consumer-range-oracle.json",
        "canvas-review-recovery-migration.json",
        "canvas_review_recovery_claim.py",
    ):
        assert name in constructor
    assert 'format!("contracts/canvas-{scenario}-scenarios.json")' in constructor
    assert 'root.join("contracts").join(name)' in constructor
    assert 'fixture["observed_image"]' in constructor
    assert 'fixture["observed_postgres_image"]' in constructor

    preparer = (ROOT / "scripts/prepare_canvas_published_schema.py").read_text()
    assert '"MARTY_CANVAS_JSON_DEPTH_ORACLE", "json_depth", "json_depth"' in preparer
    assert 'f"/verification/scripts/run_canvas_{name}_oracle.py"' in preparer
    depth_runner = (ROOT / "scripts/run_canvas_json_depth_oracle.py").read_text()
    assert '"/verification/contracts/canvas-json-depth-scenarios.json"' in depth_runner
    provider = (ROOT / "scripts/run_canvas_status_provider_oracle.py").read_text()
    assert '"canvas-issued-review-scenarios.json"' in provider
    assert "if cases is None:" in provider  # depth supplies generated cases

    # The preparer dispatches many unrelated modes behind their own flags; its
    # complete bytes are pinned above, while this import closure is depth-only.
    for script in SCRIPTS - {"scripts/prepare_canvas_published_schema.py"}:
        assert _local_imports(script, ROOT) == DIRECT_IMPORTS.get(script, set()), (
            f"Review static local imports of {script}"
        )


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_each_current_input_change_invalidates_evidence(
    tmp_path: Path, name: str
) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in INPUTS:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\nchanged\n")
    with pytest.raises(AssertionError, match="JSON-depth input drift"):
        _assert_inputs(evidence, tmp_path)


def test_missing_current_input_requires_review() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    del evidence["sha256"]["contracts/canvas-issued-review-scenarios.json"]
    with pytest.raises(AssertionError, match="need review"):
        _assert_inputs(evidence, ROOT)


def test_depth_phase_diagnostics_stay_outside_frozen_observation(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    namespace = runpy.run_path(str(ROOT / "scripts/run_canvas_json_depth_oracle.py"))
    globals_ = namespace["run"].__globals__
    globals_["Path"] = lambda _path: SimpleNamespace(
        read_text=lambda: json.dumps(
            {
                "schema": "marty.canvas-json-depth-scenarios/v1",
                "leaf_json": "0",
                "shapes": ["array", "object"],
                "statuses": [200, 403],
                "depths": [1],
            }
        )
    )

    async def observe(cases, **_kwargs):
        return {"case_names": [case["name"] for case in cases]}

    monkeypatch.setattr(globals_["validation"], "observe", observe)
    monkeypatch.setattr(globals_["provider"], "observe", observe)
    result = namespace["run"]()
    assert result["oracle"]["validation"]["case_names"] == [
        "json_depth_array_1_200",
        "json_depth_array_1_403",
        "json_depth_object_1_200",
        "json_depth_object_1_403",
    ]
    assert (
        result["oracle"]["provider"]["case_names"]
        == result["oracle"]["validation"]["case_names"]
    )
    assert "ci_phase_timing" not in result["oracle"]
    assert [row["name"] for row in result["ci_phase_timing"]] == [
        "json_depth.setup",
        "json_depth.validation",
        "json_depth.provider",
        "json_depth.encoding",
    ]
    assert all(set(row) == {"name", "duration_ms"} for row in result["ci_phase_timing"])


def test_new_transitive_json_reference_requires_review_after_hash_refresh(
    tmp_path: Path,
) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in INPUTS:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    scenario = tmp_path / "contracts/canvas-json-depth-scenarios.json"
    value = json.loads(scenario.read_text(encoding="utf-8"))
    value["additional_fixture"] = "canvas-unreviewed-scenarios.json"
    scenario.write_text(json.dumps(value), encoding="utf-8")
    evidence["sha256"]["contracts/canvas-json-depth-scenarios.json"] = (
        normalized_sha256(scenario)
    )
    with pytest.raises(AssertionError, match="transitive JSON input needs review"):
        _assert_inputs(evidence, tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        "from . import helper\n",
        "importlib.import_module('helper')\n",
        "__import__('helper')\n",
        "from importlib import import_module as load\nload('helper')\n",
        "from runpy import run_path as run\nrun('helper.py')\n",
    ],
)
def test_nonstatic_local_import_requires_review(tmp_path: Path, source: str) -> None:
    script = tmp_path / "scripts/probe.py"
    script.parent.mkdir(parents=True)
    script.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="Review .* local import"):
        _local_imports("scripts/probe.py", tmp_path)


def test_new_local_package_import_requires_review(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    package = scripts / "new_helper"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (scripts / "probe.py").write_text(
        "from new_helper import nested\n", encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="Review local package import"):
        _local_imports("scripts/probe.py", tmp_path)
