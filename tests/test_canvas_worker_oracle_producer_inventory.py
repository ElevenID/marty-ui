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
