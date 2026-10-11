"""Keep historical producers and frozen native corpus owners exhaustive."""

import ast
import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import json_references


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
SCRIPTS = ROOT / "scripts"
MANIFEST = CONTRACTS / "canvas-worker-oracle-producers.json"
PREPARER = SCRIPTS / "prepare_canvas_published_schema.py"


def preparer_worker_runners(source):
    """Read the two current worker-dispatch forms without executing the preparer."""
    tree = ast.parse(source)
    direct = {
        f"{node.module}.py"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("run_canvas_worker_")
    }
    dispatch_loops = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Tuple)
        and len(node.target.elts) == 3
        and all(isinstance(item, ast.Name) for item in node.target.elts)
        and [item.id for item in node.target.elts] == ["flag", "name", "key"]
    ]
    assert len(dispatch_loops) == 1, "Review published preparer dispatch shape"
    loop = dispatch_loops[0]
    assert isinstance(loop.iter, ast.List), "Review published preparer dispatch source"
    names = []
    for entry in loop.iter.elts:
        assert isinstance(entry, ast.Tuple) and len(entry.elts) == 3
        name = entry.elts[1]
        assert isinstance(name, ast.Constant) and isinstance(name.value, str), (
            "Review dynamic published preparer dispatch"
        )
        names.append(name.value)
    templates = [
        node
        for node in ast.walk(loop)
        if isinstance(node, ast.JoinedStr)
        and any(
            isinstance(part, ast.Constant)
            and "/verification/scripts/run_canvas_" in str(part.value)
            for part in node.values
        )
    ]
    assert len(templates) == 1, "Review published preparer script dispatch"
    assert ast.unparse(templates[0]) == (
        "f'/verification/scripts/run_canvas_{name}_oracle.py'"
    ), "Review published preparer script template"
    return direct | {
        f"run_canvas_{name}_oracle.py" for name in names if name.startswith("worker_")
    }


def test_oracle_producer_inventory_covers_every_corpus_once():
    inventory = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert inventory["schema"] == "marty.canvas-worker-oracle-producers/v3"
    assert set(inventory) == {
        "schema",
        "purpose",
        "retired_from_preparer",
        "frozen_native_corpora",
        "direct_runner_corpora",
        "shared_runner_corpora",
        "external_fixture_corpora",
        "standalone_scenarios",
    }

    direct = inventory["direct_runner_corpora"]
    retired = set(inventory["retired_from_preparer"])
    assert retired == {
        "run_canvas_worker_rest_oracle.py",
        "run_canvas_worker_startup_oracle.py",
    }
    shared = inventory["shared_runner_corpora"]
    frozen = inventory["frozen_native_corpora"]
    metadata = inventory["external_fixture_corpora"]
    listed = (
        direct
        + [name for names in shared.values() for name in names]
        + frozen
        + list(metadata)
    )
    actual = {path.name for path in CONTRACTS.glob("canvas-worker-*-oracle.json")}

    assert len(listed) == len(set(listed)), (
        "Each corpus needs exactly one producer or frozen native owner class"
    )
    assert set(listed) == actual, "New or removed corpora require an inventory review"
    assert direct == sorted(direct)
    assert frozen == sorted(frozen)
    assert list(metadata) == sorted(metadata)
    assert all(names == sorted(names) and names for names in shared.values())
    assert all(name.endswith(".json") for name in listed)

    for name in direct:
        runner = "run_" + name.removesuffix(".json").replace("-", "_") + ".py"
        assert (SCRIPTS / runner).is_file(), f"Missing direct producer: {runner}"
        scenario = name.replace("-oracle.json", "-scenarios.json")
        assert (CONTRACTS / scenario).is_file(), f"Missing direct scenario: {scenario}"
    for runner in shared:
        assert (SCRIPTS / runner).is_file(), f"Missing shared producer: {runner}"
    for source_doc in metadata.values():
        assert (ROOT / source_doc).is_file(), (
            f"Missing external-source record: {source_doc}"
        )

    tiers = json.loads(
        (CONTRACTS / "canvas-worker-tier-obligations.json").read_text(encoding="utf-8")
    )
    oauth = tiers["native_oauth_replays"]
    assert len(oauth) == 10
    assert {entry["scenario"] for entry in tiers["native_replays"]} == {
        "rest", "facts", "retry"
    }
    assert len(frozen) == 14
    assert set(frozen) == {
        f"canvas-worker-{entry['scenario']}-oracle.json"
        for entry in tiers["native_replays"]
        if entry["scenario"] != "rest"
    } | {
        f"canvas-worker-{entry['scenario']}-oracle.json" for entry in oauth
    } | {
        "canvas-worker-logging-oracle.json",
        "canvas-worker-validation-oracle.json",
    }, "Frozen corpora need native Rust owners"
    assert tiers["native_validation"]["test"] == (
        "worker_validation_matches_frozen_published_process"
    )
    for name in frozen:
        assert (CONTRACTS / name.replace("-oracle.json", "-scenarios.json")).is_file()

    mapped_runners = {
        "run_" + name.removesuffix(".json").replace("-", "_") + ".py" for name in direct
    } | set(shared)
    actual_runners = {
        path.name for path in SCRIPTS.glob("run_canvas_worker_*_oracle.py")
    }
    assert mapped_runners == actual_runners, (
        "New producers need corpus ownership review"
    )
    assert preparer_worker_runners(PREPARER.read_text(encoding="utf-8")) == (
        mapped_runners - retired
    ), "Published preparer worker dispatch needs producer-ownership review"


def test_preparer_worker_dispatch_guard_rejects_unmapped_runner():
    source = PREPARER.read_text(encoding="utf-8")
    existing = "from run_canvas_worker_lease_expiry_oracle import run"
    assert source.count(existing) == 1
    changed = source.replace(
        existing,
        existing + "\n            from run_canvas_worker_new_oracle import run",
    )
    assert "run_canvas_worker_new_oracle.py" in preparer_worker_runners(changed)
    assert "run_canvas_worker_new_oracle.py" not in preparer_worker_runners(source)
    removed = source.replace(existing, "")
    assert "run_canvas_worker_lease_expiry_oracle.py" not in preparer_worker_runners(
        removed
    )


def _check_json_pointer(data, fragment, reference):
    assert fragment.startswith("/"), f"Invalid JSON pointer: {reference}"
    for encoded in fragment[1:].split("/"):
        assert "~" not in encoded.replace("~1", "").replace("~0", ""), (
            f"Invalid JSON pointer escape: {reference}"
        )
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(data, dict):
            assert token in data, f"Missing JSON pointer target: {reference}"
            data = data[token]
        elif isinstance(data, list):
            assert token.isdecimal() and (token == "0" or not token.startswith("0"))
            assert int(token) < len(data), f"Missing JSON pointer index: {reference}"
            data = data[int(token)]
        else:
            raise AssertionError(f"Non-container JSON pointer target: {reference}")


def test_json_pointer_references_are_not_silently_ignored():
    reference = "canvas-worker-provider-final-scenarios.json#/initial_job_seed"
    assert list(json_references({"initial_history": reference})) == [reference]
    _check_json_pointer(
        {"initial_job_seed": ["seed"]}, "/initial_job_seed/0", reference
    )
    with pytest.raises(AssertionError, match="Missing JSON pointer target"):
        _check_json_pointer({"different_seed": []}, "/initial_job_seed", reference)


def test_canvas_scenario_references_are_complete_and_acyclic():
    inventory = json.loads(MANIFEST.read_text(encoding="utf-8"))
    corpus_scenarios = {
        name.replace("-oracle.json", "-scenarios.json")
        for name in inventory["direct_runner_corpora"]
    }
    corpus_scenarios.update(
        name.replace("-oracle.json", "-scenarios.json")
        for names in inventory["shared_runner_corpora"].values()
        for name in names
    )
    corpus_scenarios.update(
        name.replace("-oracle.json", "-scenarios.json")
        for name in inventory["frozen_native_corpora"]
    )
    standalone = inventory["standalone_scenarios"]
    assert corpus_scenarios.isdisjoint(standalone)
    assert list(standalone) == sorted(standalone)
    assert corpus_scenarios | set(standalone) == {
        path.name for path in CONTRACTS.glob("canvas-worker-*-scenarios.json")
    }, "Every Canvas worker scenario needs a declared owner"

    for scenario, owner in standalone.items():
        assert (ROOT / owner).is_file(), f"Missing standalone scenario owner: {owner}"
        assert scenario in (ROOT / owner).read_text(encoding="utf-8")

    visited = set()
    visiting = set()

    def visit(scenario):
        assert scenario not in visiting, f"Scenario reference cycle at {scenario}"
        if scenario in visited:
            return
        assert Path(scenario).name == scenario, f"Unsafe scenario reference: {scenario}"
        path = CONTRACTS / scenario
        assert path.is_file(), f"Missing scenario: {scenario}"
        visiting.add(scenario)
        data = json.loads(path.read_text(encoding="utf-8"))
        for reference in json_references(data):
            filename, marker, fragment = reference.partition("#")
            assert filename.endswith(".json") and Path(filename).name == filename, (
                f"Unsafe JSON reference: {reference}"
            )
            target = CONTRACTS / filename
            assert target.is_file(), (
                f"Missing JSON reference: {scenario} -> {reference}"
            )
            if marker:
                _check_json_pointer(
                    json.loads(target.read_text(encoding="utf-8")), fragment, reference
                )
            if filename.endswith("-scenarios.json"):
                visit(filename)
        visiting.remove(scenario)
        visited.add(scenario)

    for scenario in sorted(corpus_scenarios | set(standalone)):
        visit(scenario)
