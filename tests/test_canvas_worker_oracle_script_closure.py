"""Inventory capture-script edges and bounded published-process path syntax.

These are review guards for bounded input layers, not a complete mount closure
or a qualification-reuse key.
"""

import ast
import json
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PRODUCERS = ROOT / "contracts/canvas-worker-oracle-producers.json"
IMPORTS = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
HARNESS = ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs"


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


def scenario_inputs(source: Path) -> tuple[list[str], list[str]]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    literals = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        name = Path(node.value).name
        if not name.startswith("canvas-worker-") or not name.endswith(
            "-scenarios.json"
        ):
            continue
        assert node.value in {name, f"/verification/contracts/{name}"}, (
            f"Review scenario input path in {source.name}: {node.value}"
        )
        literals.add(name)
    templates = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if not any(
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and "-scenarios.json" in value.value
            for value in node.values
        ):
            continue
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif (
                isinstance(value, ast.FormattedValue)
                and isinstance(value.value, ast.Name)
                and value.conversion == -1
                and value.format_spec is None
            ):
                parts.append("{" + value.value.id + "}")
            else:
                raise AssertionError(f"Review formatted capture input in {source.name}")
        template = "".join(parts)
        name = Path(template).name
        if name.startswith("canvas-worker-") and name.endswith(
            "-scenarios.json"
        ):
            assert template in {name, f"/verification/contracts/{name}"}, (
                f"Review scenario template path in {source.name}: {template}"
            )
            templates.add(name)
    return sorted(literals), sorted(templates)


def harness_mount_inputs(source: str) -> dict[str, list[str]]:
    # This inventories syntax in one builder, not values passed by its callers,
    # mounts built elsewhere, or qualification evidence for reuse.
    start = "    async fn start_probe_with_scope("
    end = "    fn cleanup("
    assert source.count(start) == source.count(end) == 1
    body = source.split(start, 1)[1].split(end, 1)[0]
    paths = set(re.findall(r'"((?:scripts|contracts)/[^"\n]+\.(?:py|json))"', body))
    literals = sorted(path for path in paths if "{" not in path)
    templates = sorted(paths - set(literals))
    joins = re.findall(r"root\.join\([^()\n]*\)(?:\.join\([^()\n]*\))?", body)
    assert len(joins) == body.count("root.join("), "Review new harness mount expression"
    dynamic_joins = set()
    for join in joins:
        literal = re.fullmatch(r'root\.join\("([^"]+)"\)', join)
        if literal:
            assert literal.group(1) in literals, f"Review mount source: {join}"
        else:
            dynamic_joins.add(join)
    return {
        "literal_paths": literals,
        "template_paths": templates,
        "dynamic_joins": sorted(dynamic_joins),
    }


def harness_extra_scenario_mounts(source: str) -> list[dict[str, object]]:
    """Inventory the explicit scenario-dependent mounts in the probe builder.

    This deliberately recognizes only the current static match-arm shape. A new
    expression must be reviewed instead of disappearing from the inventory.
    """
    start = "        let extra_scenarios: &[&str] = match script {"
    end = "        for path in extra_scenarios {"
    assert source.count(start) == source.count(end) == 1
    body = source.split(start, 1)[1].split(end, 1)[0]
    assert body.rstrip().endswith("};")
    body = body.rstrip()[:-2]
    arm_pattern = re.compile(
        r"(?s)(.*?)\s*=>\s*(?:&\[(.*?)\]|\{\s*&\[(.*?)\]\s*\})\s*,?"
    )
    arms = list(arm_pattern.finditer(body))
    assert len(arms) == body.count("=>"), "Review new extra-scenario match syntax"
    assert "".join(arm.group(0) for arm in arms).strip() == body.strip(), (
        "Review unmatched extra-scenario mount syntax"
    )
    inventory = []
    for arm in arms:
        selector = " ".join(arm.group(1).split())
        paths_source = arm.group(2) if arm.group(2) is not None else arm.group(3)
        paths = re.findall(r'"((?:scripts|contracts)/[^"\n]+)"', paths_source)
        residue = re.sub(r'"(?:scripts|contracts)/[^"\n]+"', "", paths_source)
        assert not residue.strip(" \t\r\n,"), (
            f"Review nonliteral extra-scenario mount for {selector}"
        )
        assert all(".." not in Path(path).parts for path in paths), (
            f"Review noncanonical extra-scenario mount for {selector}"
        )
        assert all((ROOT / path).is_file() for path in paths), (
            f"Missing extra-scenario mount for {selector}"
        )
        inventory.append({"when": selector, "paths": paths})
    return inventory


def harness_dynamic_helper_mounts(source: str) -> list[list[str]]:
    """Inventory helper filenames interpolated into published-process mounts.

    The existing path-syntax inventory sees ``root.join(&path)`` and
    ``root.join("scripts").join(name)``, but not the list values that supply
    those variables. This guard covers only the bounded consumer-helper block.
    """
    start = "        let mut consumer_helpers: Vec<String> ="
    end = "        let extra_scenarios: &[&str] = match script {"
    assert source.count(start) == source.count(end) == 1
    body = source.split(start, 1)[1].split(end, 1)[0]
    arrays = re.findall(r"\[\s*((?:\"[^\"\n]+\"\s*,?\s*)+)\]\s*\.into_iter\(\)", body)
    paths = re.findall(r'let path = "([^"\n]+)";', body)
    assert len(arrays) == 3 and len(paths) == 2, "Review consumer-helper mount shape"
    assert body.count(".into_iter()") == 3
    assert body.count("consumer_helpers.push(") == 2
    assert body.count("consumer_helpers.extend(") == 1
    assert body.count("root.join(&path)") == 1
    assert body.count('root.join("scripts").join(name)') == 1
    assert body.count("root.join(path)") == 3
    groups = []
    for index, array in enumerate(arrays):
        names = re.findall(r'"([^"\n]+)"', array)
        assert names and len(names) == len(set(names))
        if index < 2:
            # Both list branches interpolate basenames beneath scripts/.
            assert all(Path(name).name == name and name.endswith(".py") for name in names)
            names = [f"scripts/{name}" for name in names]
        groups.append(names)
    groups.append(paths)
    for group in groups:
        assert all(path.startswith(("scripts/", "contracts/")) for path in group)
        assert all(".." not in Path(path).parts and (ROOT / path).is_file() for path in group)
    return groups


def test_historical_capture_input_graph_is_reviewed():
    producers = json.loads(PRODUCERS.read_text(encoding="utf-8"))
    runners = {
        "run_" + name.removesuffix(".json").replace("-", "_") + ".py"
        for name in producers["direct_runner_corpora"]
    } | set(producers["shared_runner_corpora"])
    inventory = json.loads(IMPORTS.read_text(encoding="utf-8"))
    assert set(inventory) == {
        "schema", "purpose", "direct_imports", "launched_scripts",
        "scenario_literals", "scenario_templates", "harness_path_syntax",
        "harness_extra_scenarios",
    }
    assert inventory["schema"] == "marty.canvas-worker-oracle-script-imports/v4"
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
    literal_inputs = {}
    template_inputs = {}
    for name in actual_imports:
        literals, templates = scenario_inputs(SCRIPTS / name)
        if literals:
            literal_inputs[name] = literals
        if templates:
            template_inputs[name] = templates
    assert inventory["scenario_literals"] == literal_inputs, (
        "A capture script changed scenario literals; review its input closure"
    )
    assert inventory["scenario_templates"] == template_inputs, (
        "A capture script changed scenario templates; review its input closure"
    )
    owned = {
        name.replace("-oracle.json", "-scenarios.json")
        for name in producers["direct_runner_corpora"]
    } | {
        name.replace("-oracle.json", "-scenarios.json")
        for names in producers["shared_runner_corpora"].values()
        for name in names
    } | set(producers["standalone_scenarios"])
    assert {name for names in literal_inputs.values() for name in names} <= owned
    assert template_inputs == {
        "run_canvas_worker_oauth_revocation_oracle.py": [
            "canvas-worker-{kind}-scenarios.json"
        ]
    }, "Review dynamic scenario dispatch before reusing historical qualification"
    harness = harness_mount_inputs(HARNESS.read_text(encoding="utf-8"))
    assert inventory["harness_path_syntax"] == {
        "scope": (
            "Static path literals and root.join syntax inside start_probe_with_scope "
            "only; caller-supplied values and mounts built elsewhere are not "
            "inventoried. This is not complete host-mount closure."
        ),
        **harness,
    }, (
        "Published-process harness path syntax changed; review the bounded inventory"
    )
    for path in harness["literal_paths"]:
        assert (ROOT / path).is_file(), f"Missing listed harness path: {path}"
    assert harness_dynamic_helper_mounts(HARNESS.read_text(encoding="utf-8")) == [
        [
            "scripts/run_canvas_validation_boundary_oracle.py",
            "scripts/run_canvas_status_provider_oracle.py",
            "scripts/canvas_observation_values.py",
            "scripts/canvas_json_tree_observation.py",
        ],
        [
            "scripts/run_canvas_worker_startup_oracle.py",
            "scripts/test_canvas_lti_https.py",
            "scripts/canvas_worker_https_fixture.py",
        ],
        [
            "scripts/run_canvas_worker_rest_oracle.py",
            "contracts/canvas-worker-rest-scenarios.json",
        ],
        [
            "scripts/run_canvas_worker_provider_signals_oracle.py",
            "scripts/run_canvas_worker_provider_recovery_oracle.py",
        ],
    ], "Published-process dynamic helper mounts changed; review their inputs"
    assert inventory["harness_extra_scenarios"] == harness_extra_scenario_mounts(
        HARNESS.read_text(encoding="utf-8")
    ), "Scenario-dependent harness mounts changed; review the inventory"


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


def test_scenario_inputs_detect_literals_and_templates(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        'FIRST = "canvas-worker-first-scenarios.json"\n'
        'SECOND = f"canvas-worker-{kind}-scenarios.json"\n',
        encoding="utf-8",
    )
    assert scenario_inputs(source) == (
        ["canvas-worker-first-scenarios.json"],
        ["canvas-worker-{kind}-scenarios.json"],
    )
    source.write_text(
        'SECOND = f"canvas-worker-{kind!r}-scenarios.json"\n', encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="Review formatted capture input"):
        scenario_inputs(source)
    source.write_text(
        'FIRST = "elsewhere/canvas-worker-first-scenarios.json"\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="Review scenario input path"):
        scenario_inputs(source)
    source.write_text(
        'SECOND = f"elsewhere/canvas-worker-{kind}-scenarios.json"\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="Review scenario template path"):
        scenario_inputs(source)


def test_harness_mount_inventory_detects_new_paths_and_expressions():
    source = (
        "    async fn start_probe_with_scope(\n"
        '        let mount = root.join("scripts/fixture.py");\n'
        "    fn cleanup(\n"
    )
    assert harness_mount_inputs(source) == {
        "literal_paths": ["scripts/fixture.py"],
        "template_paths": [],
        "dynamic_joins": [],
    }
    changed = source.replace("scripts/fixture.py", "scripts/new_fixture.py")
    assert harness_mount_inputs(changed)["literal_paths"] == [
        "scripts/new_fixture.py"
    ]
    changed = source.replace('root.join("scripts/fixture.py")', 'root.join(input())')
    with pytest.raises(AssertionError, match="Review new harness mount expression"):
        harness_mount_inputs(changed)
    changed = source.replace("scripts/fixture.py", "untracked/path")
    with pytest.raises(AssertionError, match="Review mount source"):
        harness_mount_inputs(changed)


def test_harness_extra_scenario_inventory_fails_closed_on_new_syntax():
    source = (
        "        let extra_scenarios: &[&str] = match script {\n"
        '            "worker_deadline" => &["scripts/canvas_worker_output_capture.py"],\n'
        "            _ => &[],\n"
        "        };\n"
        "        for path in extra_scenarios {\n"
    )
    assert harness_extra_scenario_mounts(source) == [
        {
            "when": '"worker_deadline"',
            "paths": ["scripts/canvas_worker_output_capture.py"],
        },
        {"when": "_", "paths": []},
    ]
    changed = source.replace(
        '"scripts/canvas_worker_output_capture.py"', "dynamic_mount()"
    )
    with pytest.raises(AssertionError, match="Review nonliteral"):
        harness_extra_scenario_mounts(changed)
    changed = source.replace(
        '"scripts/canvas_worker_output_capture.py"',
        '"scripts/missing_fixture.py"',
    )
    with pytest.raises(AssertionError, match="Missing extra-scenario mount"):
        harness_extra_scenario_mounts(changed)
    changed = source.replace(
        '"scripts/canvas_worker_output_capture.py"',
        '"scripts/../scripts/canvas_worker_output_capture.py"',
    )
    with pytest.raises(AssertionError, match="Review noncanonical"):
        harness_extra_scenario_mounts(changed)


def test_dynamic_helper_mount_inventory_rejects_unreviewed_inputs():
    source = HARNESS.read_text(encoding="utf-8")
    groups = harness_dynamic_helper_mounts(source)
    assert "scripts/test_canvas_lti_https.py" in groups[1]
    changed = source.replace(
        '"test_canvas_lti_https.py",', '"unreviewed_helper.py",', 1
    )
    with pytest.raises(AssertionError):
        harness_dynamic_helper_mounts(changed)
    changed = source.replace(
        '"test_canvas_lti_https.py",', 'dynamic_helper_name(),', 1
    )
    with pytest.raises(AssertionError, match="Review consumer-helper mount shape"):
        harness_dynamic_helper_mounts(changed)
