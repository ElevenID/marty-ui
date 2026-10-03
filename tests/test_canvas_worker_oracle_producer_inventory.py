"""Keep the historical corpus-to-producer inventory exhaustive before reuse work."""

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
SCRIPTS = ROOT / "scripts"
MANIFEST = CONTRACTS / "canvas-worker-oracle-producers.json"


def test_oracle_producer_inventory_covers_every_corpus_once():
    inventory = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert inventory["schema"] == "marty.canvas-worker-oracle-producers/v1"
    assert set(inventory) == {
        "schema",
        "purpose",
        "direct_runner_corpora",
        "shared_runner_corpora",
        "external_fixture_corpora",
        "standalone_scenarios",
    }

    direct = inventory["direct_runner_corpora"]
    shared = inventory["shared_runner_corpora"]
    metadata = inventory["external_fixture_corpora"]
    listed = (
        direct + [name for names in shared.values() for name in names] + list(metadata)
    )
    actual = {path.name for path in CONTRACTS.glob("canvas-worker-*-oracle.json")}

    assert len(listed) == len(set(listed)), (
        "Each corpus needs exactly one producer class"
    )
    assert set(listed) == actual, "New or removed corpora require an inventory review"
    assert direct == sorted(direct)
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

    # The OAuth runner emits ten kinds through one entry point. Keep the
    # manifest's extra nine corpora aligned with its declared dispatch set.
    oauth_runner = SCRIPTS / "run_canvas_worker_oauth_revocation_oracle.py"
    tree = ast.parse(oauth_runner.read_text(encoding="utf-8"))
    run = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    kind_guards = [
        node.comparators[0]
        for node in ast.walk(run)
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "kind"
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Set)
    ]
    assert len(kind_guards) == 1, "Review OAuth kind dispatch when its shape changes"
    kinds = {
        value.value for value in kind_guards[0].elts if isinstance(value, ast.Constant)
    }
    assert len(kinds) == len(kind_guards[0].elts)
    assert {f"canvas-worker-{kind}-oracle.json" for kind in kinds} == (
        {"canvas-worker-oauth-revocation-oracle.json"} | set(shared[oauth_runner.name])
    )
    for kind in kinds:
        assert (CONTRACTS / f"canvas-worker-{kind}-scenarios.json").is_file()

    mapped_runners = {
        "run_" + name.removesuffix(".json").replace("-", "_") + ".py" for name in direct
    } | set(shared)
    actual_runners = {
        path.name for path in SCRIPTS.glob("run_canvas_worker_*_oracle.py")
    }
    assert mapped_runners == actual_runners, (
        "New producers need corpus ownership review"
    )


def _json_references(value):
    if isinstance(value, str) and (value.endswith(".json") or ".json#" in value):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_references(item)


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
        for reference in _json_references(data):
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
