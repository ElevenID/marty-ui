"""Inventory local Python script edges of the historical Canvas capture runners.

This is a review guard for one input layer, not a qualification-reuse key.
"""

import ast
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PRODUCERS = ROOT / "contracts/canvas-worker-oracle-producers.json"
IMPORTS = ROOT / "contracts/canvas-worker-oracle-script-imports.json"


def local_imports(source: Path, scripts: Path) -> list[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    dynamic_names = {"__import__", "import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "importlib":
            dynamic_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "import_module"
            )

    dependencies = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
            isinstance(node.func, ast.Name)
            and node.func.id in dynamic_names
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
        ):
            raise AssertionError(f"Review dynamic import in {source.name}")
        if isinstance(node, ast.Import):
            modules = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"Review relative import in {source.name}")
            modules = (node.module,) if node.module else ()
        else:
            continue
        for module in modules:
            root = module.split(".", 1)[0]
            if (scripts / root).is_dir():
                raise AssertionError(f"Review local package import in {source.name}")
            candidate = scripts / f"{root}.py"
            if candidate.is_file():
                dependencies.add(candidate.name)
    return sorted(dependencies)


def launched_scripts(source: Path, scripts: Path) -> list[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    prefix = "/verification/scripts/"
    launched = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if not node.value.startswith(prefix) or not node.value.endswith(".py"):
            continue
        name = node.value.removeprefix(prefix)
        assert Path(name).name == name, f"Review process script path in {source.name}"
        assert (scripts / name).is_file(), f"Missing process script: {name}"
        launched.add(name)
    return sorted(launched)


def capture_script_graph(
    runners: set[str], scripts: Path
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    imports = {}
    launches = {}
    pending = list(runners)
    while pending:
        name = pending.pop()
        if name in imports:
            continue
        assert Path(name).name == name and name.endswith(".py")
        source = scripts / name
        assert source.is_file(), f"Missing capture script: {name}"
        dependencies = local_imports(source, scripts)
        children = launched_scripts(source, scripts)
        imports[name] = dependencies
        if children:
            launches[name] = children
        pending.extend(dependencies + children)
    return dict(sorted(imports.items())), dict(sorted(launches.items()))


def test_historical_capture_script_import_graph_is_reviewed():
    producers = json.loads(PRODUCERS.read_text(encoding="utf-8"))
    runners = {
        "run_" + name.removesuffix(".json").replace("-", "_") + ".py"
        for name in producers["direct_runner_corpora"]
    } | set(producers["shared_runner_corpora"])
    inventory = json.loads(IMPORTS.read_text(encoding="utf-8"))
    assert set(inventory) == {
        "schema", "purpose", "direct_imports", "launched_scripts"
    }
    assert inventory["schema"] == "marty.canvas-worker-oracle-script-imports/v1"
    assert inventory["purpose"] == (
        "Inventory only. This is not complete capture-input closure or permission "
        "to reuse historical qualification."
    )
    actual_imports, actual_launches = capture_script_graph(runners, SCRIPTS)
    assert inventory["direct_imports"] == actual_imports, (
        "A capture runner or helper changed local imports; review its closure"
    )
    assert inventory["launched_scripts"] == actual_launches, (
        "A capture runner or helper changed process scripts; review its closure"
    )


def test_import_graph_detects_transitive_and_dynamic_inputs(tmp_path):
    (tmp_path / "runner.py").write_text("from helper import VALUE\n", encoding="utf-8")
    (tmp_path / "helper.py").write_text("from deep import VALUE\n", encoding="utf-8")
    (tmp_path / "deep.py").write_text("VALUE = 1\n", encoding="utf-8")
    imports, launches = capture_script_graph({"runner.py"}, tmp_path)
    assert imports == {
        "deep.py": [],
        "helper.py": ["deep.py"],
        "runner.py": ["helper.py"],
    }
    assert launches == {}
    (tmp_path / "helper.py").write_text(
        'CHILD = "/verification/scripts/child.py"\n', encoding="utf-8"
    )
    (tmp_path / "child.py").write_text("VALUE = 2\n", encoding="utf-8")
    imports, launches = capture_script_graph({"runner.py"}, tmp_path)
    assert imports["child.py"] == []
    assert launches == {"helper.py": ["child.py"]}
    (tmp_path / "helper.py").write_text(
        "from importlib import import_module as load\nload('deep')\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="Review dynamic import"):
        capture_script_graph({"runner.py"}, tmp_path)
