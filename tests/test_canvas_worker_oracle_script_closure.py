"""Inventory capture-script edges and bounded published-process path syntax.

These are review guards for bounded input layers, not a complete mount closure
or a qualification-reuse key.
"""

import ast
import json
from pathlib import Path
import re
import subprocess

import pytest

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_inputs,
    expanded_inputs,
    normalized_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PRODUCERS = ROOT / "contracts/canvas-worker-oracle-producers.json"
IMPORTS = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
HARNESS = ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs"
PROVIDER_INPUTS = ROOT / "contracts/canvas-worker-provider-recovery-current-inputs.json"
REST_INPUTS = ROOT / "contracts/canvas-worker-rest-current-inputs.json"
MOUNTED_INPUTS = frozenset(
    {
        "scripts/prepare_canvas_published_schema.py",
        "contracts/fixtures/canvas_worker_test_trust.py",
    }
)


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
        if name.startswith("canvas-worker-") and name.endswith("-scenarios.json"):
            assert template in {name, f"/verification/contracts/{name}"}, (
                f"Review scenario template path in {source.name}: {template}"
            )
            templates.add(name)
    return sorted(literals), sorted(templates)


def harness_mount_inputs(source: str) -> dict[str, list[str]]:
    # This inventories syntax in one builder, not values passed by its callers,
    # mounts built elsewhere, or qualification evidence for reuse.
    implementation = "impl PublishedDatabase {"
    destructor = "impl Drop for PublishedDatabase {"
    if implementation in source:
        assert source.count(implementation) == source.count(destructor) == 1
        source = source.split(implementation, 1)[1].split(destructor, 1)[0]
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
    basename_branch, worker_branch = body.split("} else if worker_https {", 1)
    worker_branch, _ = worker_branch.split("} else {", 1)
    assert basename_branch.count('let path = format!("scripts/{name}");') == 1, (
        "Review consumer-helper basename source directory"
    )
    assert basename_branch.count("target=/verification/{path},readonly") == 1
    assert basename_branch.count("root.join(&path)") == 1
    assert worker_branch.count("target=/verification/scripts/{name},readonly") == 1
    assert worker_branch.count('root.join("scripts").join(name)') == 1
    groups = []
    for index, array in enumerate(arrays):
        names = re.findall(r'"([^"\n]+)"', array)
        assert names and len(names) == len(set(names))
        if index < 2:
            # Both list branches interpolate basenames beneath scripts/.
            assert all(
                Path(name).name == name and name.endswith(".py") for name in names
            )
            names = [f"scripts/{name}" for name in names]
        groups.append(names)
    groups.append(paths)
    for group in groups:
        assert all(path.startswith(("scripts/", "contracts/")) for path in group)
        assert all(
            ".." not in Path(path).parts and (ROOT / path).is_file() for path in group
        )
    return groups


def published_image_oracle_mounts(source: str) -> list[dict[str, str]]:
    """Inventory the separate, network-none published-image oracle mounts."""
    marker = "pub(super) async fn provider_configuration_image_oracle()"
    assert source.count(marker) == 1, "Review published-image oracle owner"
    body = source.split(marker, 1)[1]
    sources = dict(re.findall(r'let (\w+)_source = root\s*\.join\("([^"]+)"\)', body))
    assert len(sources) == len(re.findall(r"\.join\s*\(", body)), (
        "Review published-image oracle source paths"
    )
    assert set(sources) == {"script", "scenarios"}
    mounts = re.findall(
        r"let (\w+)_mount = format!\(\s*"
        r'"type=bind,source=\{\},target=\{(PROVIDER_ORACLE_\w+)\},readonly",\s*'
        r"(\w+)_source\s*\)",
        body,
    )
    assert len(mounts) == body.count("type=bind,source=") == 2, (
        "Review published-image oracle mount shape"
    )
    consts = dict(
        re.findall(r'const (PROVIDER_ORACLE_\w+): &str =\s*"([^"]+)";', source)
    )
    create = body.split("let id = docker(&[", 1)[1].split("])?;", 1)[0]
    assert create.count('"--mount"') == 2, (
        "Review published-image oracle Docker mount count"
    )
    assert re.findall(r'"--mount",\s*&(\w+)_mount,', create) == [
        "script",
        "scenarios",
    ], "Review published-image oracle Docker mounts"
    result = []
    for name, constant, source_name in mounts:
        assert name == source_name and constant in consts
        path = sources[name]
        target = consts[constant]
        assert path.startswith(("scripts/", "contracts/"))
        candidate = ROOT / path
        assert ".." not in Path(path).parts and candidate.is_file()
        assert not candidate.is_symlink(), f"Review symlinked oracle input: {path}"
        staged = subprocess.run(
            ["git", "ls-files", "--stage", "--", path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert re.fullmatch(rf"100644 [0-9a-f]{{40}} 0\t{re.escape(path)}", staged), (
            f"Review non-regular or untracked oracle input: {path}"
        )
        assert target == f"/verification/{path}"
        result.append({"source": path, "target": target})
    return result


def published_image_oracle_invocation(source: str) -> dict[str, str]:
    """Witness the Python invocation against the separately inventoried mount."""
    mounts = published_image_oracle_mounts(source)
    commands = re.findall(
        r'pub\(super\) const PROVIDER_ORACLE_COMMAND: &str = r#"(.*?)"#;',
        source,
        flags=re.DOTALL,
    )
    assert len(commands) == 1, "Review published-image oracle command owner"
    command = commands[0]
    call = re.fullmatch(
        r"import json,runpy; print\(json.dumps\(runpy.run_path\('([^']+)'\)"
        r"\['([^']+)'\]\(\), sort_keys=True\)\)",
        command,
    )
    assert call is not None, "Review published-image oracle Python invocation"
    script_target, callable_name = call.groups()
    assert script_target == mounts[0]["target"], (
        "Published-image oracle command must execute its mounted script"
    )

    checked = source.split("impl PublishedImageOracle {", 1)[1].split(
        "    fn cleanup(", 1
    )[0]
    assert checked.count('serde_json::json!(["python"])') == 1, (
        "Review published-image oracle checked entrypoint"
    )
    assert checked.count('serde_json::json!(["-c", PROVIDER_ORACLE_COMMAND])') == 1, (
        "Review published-image oracle checked command"
    )
    body = source.split("pub(super) async fn provider_configuration_image_oracle()", 1)[
        1
    ]
    create = body.split("let id = docker(&[", 1)[1].split("])?;", 1)[0]
    assert re.findall(
        r'"--entrypoint",\s*"([^"]+)",\s*image,\s*"([^"]+)",\s*(\w+),',
        create,
    ) == [("python", "-c", "PROVIDER_ORACLE_COMMAND")], (
        "Review published-image oracle Docker invocation"
    )
    assert body.count("owner.checked(&inspect(&id)?, &id)?;") == 1, (
        "Review published-image oracle post-create identity check"
    )
    assert body.count("owner.checked(&state, &id)?;") == 1, (
        "Review published-image oracle poll identity check"
    )
    cleanup = source.split("impl PublishedImageOracle {", 1)[1].split(
        "impl Drop for PublishedImageOracle", 1
    )[0]
    assert cleanup.count("self.checked(&inspect(id)?, id)?;") == 1, (
        "Review published-image oracle cleanup identity check"
    )
    return {
        "entrypoint": "python",
        "mode": "-c",
        "command": command,
        "script_target": script_target,
        "callable": callable_name,
    }


def published_image_oracle_child_invocation(
    harness_source: str, script_source: str
) -> dict[str, object]:
    """Witness the mounted oracle's separate full-import child process."""
    mounted = published_image_oracle_mounts(harness_source)[0]
    invoked = published_image_oracle_invocation(harness_source)
    assert mounted["target"] == invoked["script_target"]
    assert mounted["source"] == "scripts/run_canvas_provider_configuration_oracle.py"
    tree = ast.parse(script_source, filename=mounted["source"])
    runs = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == invoked["callable"]
    ]
    assert len(runs) == 1, "Review published-image oracle callable"
    assert [argument.arg for argument in runs[0].args.args] == ["source"]
    assert len(runs[0].args.defaults) == 1
    assert ast.unparse(runs[0].args.defaults[0]) == "None"
    assert ast.unparse(runs[0].body[0]) == "published_image = source is None"
    assert (
        sum(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == "published_image"
            for node in ast.walk(runs[0])
        )
        == 1
    ), "Review published-image branch assignment"
    published = [
        node
        for node in runs[0].body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "published_image"
    ]
    assert len(published) == 1, "Review published-image child-process branch"
    branch = published[0]
    assert len(branch.body) == 3 and ast.unparse(branch.body[0]) == "imports = []"
    loop = branch.body[1]
    assert isinstance(loop, ast.For)
    assert ast.unparse(loop.target) == "case"
    assert ast.unparse(loop.iter) == "fixture['timeouts']"
    assert len(loop.body) == 2
    child = loop.body[0]
    assert isinstance(child, ast.Assign) and ast.unparse(child.targets[0]) == "child"
    call = child.value
    assert isinstance(call, ast.Call) and ast.unparse(call.func) == "subprocess.run"
    assert len(call.args) == 1
    assert ast.unparse(call.args[0]) == (
        "[sys.executable, __file__, '--observe-import']"
    ), "Child must re-execute the mounted script"
    options = {option.arg: ast.unparse(option.value) for option in call.keywords}
    assert options == {
        "input": "json.dumps(case)",
        "text": "True",
        "capture_output": "True",
        "check": "True",
        "timeout": "30",
    }, "Review child input, capture, failure, and deadline semantics"
    assert ast.unparse(loop.body[1]) == "imports.append(json.loads(child.stdout))"
    assert isinstance(branch.body[2], ast.Assert)
    assert ast.unparse(branch.body[2].test) == "imports == timeouts"

    mains = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "__name__ == '__main__'"
    ]
    assert len(mains) == 1, "Review published-image child dispatch owner"
    dispatch = [
        node
        for node in mains[0].body
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "arguments.observe_import"
    ]
    assert len(dispatch) == 1 and len(dispatch[0].body) == 2
    assert ast.unparse(dispatch[0].body[0]) == (
        "print(json.dumps(observe_import(json.load(sys.stdin)), sort_keys=True))"
    ), "Child must parse its own stdin and observe the full import"
    assert ast.unparse(dispatch[0].body[1]) == "raise SystemExit(0)"
    flags = [
        node
        for node in mains[0].body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "parser.add_argument"
        and node.value.args
        and ast.unparse(node.value.args[0]) == "'--observe-import'"
    ]
    assert len(flags) == 1
    assert ast.unparse(flags[0]) == (
        "parser.add_argument('--observe-import', action='store_true')"
    )
    parses = [
        node
        for node in mains[0].body
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == "arguments"
    ]
    assert len(parses) == 1 and ast.unparse(parses[0]) == (
        "arguments = parser.parse_args()"
    ), "Child dispatch must use the parsed flag"
    assert (
        mains[0].body.index(flags[0])
        < mains[0].body.index(parses[0])
        < mains[0].body.index(dispatch[0])
    ), "Child flag must be registered, parsed, then dispatched"
    return {
        "mounted_source": mounted["source"],
        "mounted_target": mounted["target"],
        "callable_default": "source=None",
        "published_guard": "published_image = source is None",
        "child_command": ast.unparse(call.args[0]),
        "child_input": options["input"],
        "child_stdout": ast.unparse(loop.body[1]),
        "timeout_seconds": 30,
        "child_flag_parse": ast.unparse(parses[0]),
        "dispatch": ast.unparse(dispatch[0].body[0]),
    }


def test_historical_capture_input_graph_is_reviewed():
    producers = json.loads(PRODUCERS.read_text(encoding="utf-8"))
    runners = {
        "run_" + name.removesuffix(".json").replace("-", "_") + ".py"
        for name in producers["direct_runner_corpora"]
    } | set(producers["shared_runner_corpora"])
    harness_source = HARNESS.read_text(encoding="utf-8")
    harness = harness_mount_inputs(harness_source)
    mounted_roots = {
        "canvas_worker_dispatch_hooks.py",
        "prepare_canvas_published_schema.py",
    }
    assert {f"scripts/{name}" for name in mounted_roots} <= set(
        harness["literal_paths"]
    ), "Review mounted capture entrypoint roots"
    entrypoint_roots = mounted_roots
    # The preparer also has a literal process edge to the operations oracle.
    # This is a bounded static graph, not dynamic or host/image input closure.
    runners |= entrypoint_roots
    inventory = json.loads(IMPORTS.read_text(encoding="utf-8"))
    assert set(inventory) == {
        "schema",
        "purpose",
        "entrypoint_roots",
        "direct_imports",
        "launched_scripts",
        "scenario_literals",
        "scenario_templates",
        "harness_path_syntax",
        "harness_extra_scenarios",
        "published_image_oracle_mounts",
        "published_image_oracle_invocation",
        "published_image_oracle_child_invocation",
    }
    assert inventory["schema"] == "marty.canvas-worker-oracle-script-imports/v8"
    assert inventory["purpose"] == (
        "Inventory only. This is not complete capture-input closure or permission "
        "to reuse historical qualification."
    )
    assert inventory["entrypoint_roots"] == sorted(entrypoint_roots), (
        "A standalone launcher or mounted entrypoint changed; review its roots"
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
    owned = (
        {
            name.replace("-oracle.json", "-scenarios.json")
            for name in producers["direct_runner_corpora"]
        }
        | {
            name.replace("-oracle.json", "-scenarios.json")
            for names in producers["shared_runner_corpora"].values()
            for name in names
        }
        | {
            name.replace("-oracle.json", "-scenarios.json")
            for name in producers["frozen_native_corpora"]
        }
        | set(producers["standalone_scenarios"])
    )
    assert {name for names in literal_inputs.values() for name in names} <= owned
    assert template_inputs == {}, (
        "Review dynamic scenario dispatch before reusing historical qualification"
    )
    assert inventory["harness_path_syntax"] == {
        "scope": (
            "Static path literals and root.join syntax inside start_probe_with_scope "
            "only; caller-supplied values and other mounts remain outside this "
            "bounded inventory. This is not complete host-mount closure."
        ),
        **harness,
    }, "Published-process harness path syntax changed; review the bounded inventory"
    for path in harness["literal_paths"]:
        assert (ROOT / path).is_file(), f"Missing listed harness path: {path}"
    assert harness_dynamic_helper_mounts(harness_source) == [
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
        harness_source
    ), "Scenario-dependent harness mounts changed; review the inventory"
    assert inventory["published_image_oracle_mounts"] == published_image_oracle_mounts(
        harness_source
    ), "Published-image oracle mounts changed; review their inputs"
    assert inventory["published_image_oracle_invocation"] == (
        published_image_oracle_invocation(harness_source)
    ), "Published-image oracle invocation changed; review its inputs"
    script_source = (
        ROOT / "scripts/run_canvas_provider_configuration_oracle.py"
    ).read_text(encoding="utf-8")
    assert inventory["published_image_oracle_child_invocation"] == (
        published_image_oracle_child_invocation(harness_source, script_source)
    ), "Published-image child process changed; review its inputs"


@pytest.mark.parametrize(
    "entrypoint",
    [
        "prepare_canvas_published_schema.py",
        "canvas_worker_dispatch_hooks.py",
    ],
)
def test_new_entrypoint_local_import_requires_inventory_review(tmp_path, entrypoint):
    source = tmp_path / entrypoint
    source.write_text("VALUE = 1\n", encoding="utf-8")
    before, _ = capture_script_graph({entrypoint}, tmp_path)
    (tmp_path / "new_helper.py").write_text("VALUE = 2\n", encoding="utf-8")
    source.write_text("from new_helper import VALUE\n", encoding="utf-8")
    after, _ = capture_script_graph({entrypoint}, tmp_path)
    assert before != after
    assert after[entrypoint] == ["new_helper.py"]
    assert after["new_helper.py"] == []


def test_preparer_process_script_change_requires_inventory_review(tmp_path):
    preparer = tmp_path / "prepare_canvas_published_schema.py"
    preparer.write_text(
        'CHILD = "/verification/scripts/run_canvas_operations_oracle.py"\n',
        encoding="utf-8",
    )
    (tmp_path / "run_canvas_operations_oracle.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )
    _, before = capture_script_graph({preparer.name}, tmp_path)
    assert before == {preparer.name: ["run_canvas_operations_oracle.py"]}

    preparer.write_text(
        'CHILD = "/verification/scripts/new_process_oracle.py"\n',
        encoding="utf-8",
    )
    (tmp_path / "new_process_oracle.py").write_text("VALUE = 2\n", encoding="utf-8")
    _, after = capture_script_graph({preparer.name}, tmp_path)
    assert after != before
    assert after == {preparer.name: ["new_process_oracle.py"]}


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
    assert harness_mount_inputs(changed)["literal_paths"] == ["scripts/new_fixture.py"]
    changed = source.replace('root.join("scripts/fixture.py")', "root.join(input())")
    with pytest.raises(AssertionError, match="Review new harness mount expression"):
        harness_mount_inputs(changed)
    changed = source.replace("scripts/fixture.py", "untracked/path")
    with pytest.raises(AssertionError, match="Review mount source"):
        harness_mount_inputs(changed)


def test_harness_mount_inventory_bounds_cleanup_to_the_database_owner():
    database = (
        "impl PublishedDatabase {\n"
        "    async fn start_probe_with_scope(\n"
        '        let mount = root.join("scripts/fixture.py");\n'
        "    fn cleanup(\n"
        "}\nimpl Drop for PublishedDatabase {\n}\n"
    )
    image_owner = "impl PublishedImageOracle {\n    fn cleanup(\n}\n"
    assert harness_mount_inputs(database + image_owner) == harness_mount_inputs(
        database
    )
    # A second boundary *inside* the inventoried owner remains ambiguous.
    duplicate = database.replace("    fn cleanup(\n", "    fn cleanup(\n" * 2)
    with pytest.raises(AssertionError):
        harness_mount_inputs(duplicate + image_owner)
    with pytest.raises(AssertionError):
        harness_mount_inputs(database.replace("impl Drop for PublishedDatabase {", ""))


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
    changed = source.replace('"test_canvas_lti_https.py",', "dynamic_helper_name(),", 1)
    with pytest.raises(AssertionError, match="Review consumer-helper mount shape"):
        harness_dynamic_helper_mounts(changed)
    changed = source.replace(
        'let path = format!("scripts/{name}");',
        'let path = format!("contracts/{name}");',
        1,
    )
    with pytest.raises(AssertionError, match="Review consumer-helper basename source"):
        harness_dynamic_helper_mounts(changed)
    changed = source.replace(
        "target=/verification/scripts/{name},readonly",
        "target=/verification/other/{name},readonly",
        1,
    )
    with pytest.raises(AssertionError):
        harness_dynamic_helper_mounts(changed)


def test_published_image_oracle_mount_inventory_rejects_unreviewed_inputs(
    monkeypatch,
):
    source = HARNESS.read_text(encoding="utf-8")
    mounts = published_image_oracle_mounts(source)
    assert [item["source"] for item in mounts] == [
        "scripts/run_canvas_provider_configuration_oracle.py",
        "contracts/canvas-provider-configuration-scenarios.json",
    ]
    changed = source.replace(
        '.join("scripts/run_canvas_provider_configuration_oracle.py")',
        '.join("scripts/unreviewed_oracle.py")',
        1,
    )
    with pytest.raises(AssertionError):
        published_image_oracle_mounts(changed)
    changed = source.replace("        &scenarios_mount,\n", "", 1)
    with pytest.raises(AssertionError, match="Docker mounts"):
        published_image_oracle_mounts(changed)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: (
            path.name == "run_canvas_provider_configuration_oracle.py"
            or original_is_symlink(path)
        ),
    )
    with pytest.raises(AssertionError, match="symlinked oracle input"):
        published_image_oracle_mounts(source)


def test_published_image_oracle_invocation_rejects_unreviewed_changes():
    source = HARNESS.read_text(encoding="utf-8")
    invocation = published_image_oracle_invocation(source)
    assert invocation["script_target"] == (
        "/verification/scripts/run_canvas_provider_configuration_oracle.py"
    )
    assert invocation["callable"] == "run"

    changed = source.replace(
        "runpy.run_path('/verification/scripts/run_canvas_provider_configuration_oracle.py')",
        "runpy.run_path('/verification/scripts/other_oracle.py')",
        1,
    )
    with pytest.raises(AssertionError, match="mounted script"):
        published_image_oracle_invocation(changed)
    changed = source.replace("['run']()", "['other']()", 1)
    assert published_image_oracle_invocation(changed) != invocation
    changed = source.replace(
        '        "-c",\n        PROVIDER_ORACLE_COMMAND,',
        '        "-m",\n        PROVIDER_ORACLE_COMMAND,',
        1,
    )
    with pytest.raises(AssertionError, match="Docker invocation"):
        published_image_oracle_invocation(changed)
    changed = source.replace(
        "        PROVIDER_ORACLE_COMMAND,\n    ])?;",
        "        OTHER_COMMAND,\n    ])?;",
        1,
    )
    with pytest.raises(AssertionError, match="Docker invocation"):
        published_image_oracle_invocation(changed)
    changed = source.replace(
        'serde_json::json!(["-c", PROVIDER_ORACLE_COMMAND])',
        'serde_json::json!(["-m", PROVIDER_ORACLE_COMMAND])',
        1,
    )
    with pytest.raises(AssertionError, match="checked command"):
        published_image_oracle_invocation(changed)
    changed = source.replace("    owner.checked(&inspect(&id)?, &id)?;\n", "", 1)
    with pytest.raises(AssertionError, match="post-create identity check"):
        published_image_oracle_invocation(changed)
    changed = source.replace("        owner.checked(&state, &id)?;\n", "", 1)
    with pytest.raises(AssertionError, match="poll identity check"):
        published_image_oracle_invocation(changed)
    changed = source.replace("            self.checked(&inspect(id)?, id)?;\n", "", 1)
    with pytest.raises(AssertionError, match="cleanup identity check"):
        published_image_oracle_invocation(changed)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("def run(source=None):", "def run(source='local'):"),
        ("published_image = source is None", "published_image = False"),
        (
            '[sys.executable, __file__, "--observe-import"]',
            '[sys.executable, "other.py", "--observe-import"]',
        ),
        (
            '[sys.executable, __file__, "--observe-import"]',
            '[sys.executable, __file__, "--other"]',
        ),
        ("input=json.dumps(case)", "input=json.dumps({})"),
        (
            "capture_output=True,\n                check=True",
            "capture_output=False,\n                check=True",
        ),
        (
            "check=True,\n                timeout=30",
            "check=False,\n                timeout=30",
        ),
        ("timeout=30", "timeout=31"),
        ("imports.append(json.loads(child.stdout))", "imports.append({})"),
        ("json.load(sys.stdin)", "json.loads('{}')"),
        ("arguments = parser.parse_args()", "arguments = None"),
        ("raise SystemExit(0)", "raise SystemExit(1)"),
        ('for case in fixture["timeouts"]:', "for case in []:"),
    ],
)
def test_published_image_oracle_child_invocation_rejects_unreviewed_changes(
    before, after
):
    harness_source = HARNESS.read_text(encoding="utf-8")
    source = (SCRIPTS / "run_canvas_provider_configuration_oracle.py").read_text(
        encoding="utf-8"
    )
    assert source.count(before) == 1
    published_image_oracle_child_invocation(harness_source, source)
    with pytest.raises(AssertionError):
        published_image_oracle_child_invocation(
            harness_source, source.replace(before, after, 1)
        )


def test_published_image_oracle_child_invocation_rejects_late_flag_registration():
    harness_source = HARNESS.read_text(encoding="utf-8")
    source = (SCRIPTS / "run_canvas_provider_configuration_oracle.py").read_text(
        encoding="utf-8"
    )
    before = (
        'parser.add_argument("--observe-import", action="store_true")\n'
        "    arguments = parser.parse_args()"
    )
    after = (
        "arguments = parser.parse_args()\n"
        '    parser.add_argument("--observe-import", action="store_true")'
    )
    assert source.count(before) == 1
    with pytest.raises(AssertionError, match="registered, parsed, then dispatched"):
        published_image_oracle_child_invocation(
            harness_source, source.replace(before, after, 1)
        )
def copy_inherited_rest_input_sources(root: Path, evidence: dict, rest: dict) -> None:
    for source in rest["sha256"] | evidence["sha256"]:
        target = root / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())


def provider_input_records() -> tuple[dict, dict, dict, dict]:
    return (
        json.loads(PROVIDER_INPUTS.read_text(encoding="utf-8")),
        json.loads(REST_INPUTS.read_text(encoding="utf-8")),
        json.loads(PRODUCERS.read_text(encoding="utf-8")),
        json.loads(IMPORTS.read_text(encoding="utf-8")),
    )


def check_provider_current_inputs(
    evidence: dict, rest: dict, producers: dict, graph: dict, root: Path
) -> None:
    assert set(evidence) == {
        "schema", "purpose", "normalization", "inherited_inputs", "runners", "sha256"
    }
    assert evidence["inherited_inputs"] == "contracts/canvas-worker-rest-current-inputs.json"
    assert rest["schema"] == "marty.canvas-worker-rest-current-inputs/v2"
    assert set(rest) == {"schema", "purpose", "normalization", "sha256"}
    assert evidence["normalization"] == rest["normalization"]
    for name, pinned in rest["sha256"].items():
        assert normalized_sha256(root / name) == pinned, f"REST input drift: {name}"
    for name, pinned in evidence["sha256"].items():
        assert normalized_sha256(root / name) == pinned, (
            f"Provider recovery input drift: {name}"
        )
    corpora = sorted(
        name for name in producers["direct_runner_corpora"]
        if name.startswith("canvas-worker-provider-")
        or name.startswith("canvas-worker-reclaimers")
    )
    runners = tuple(
        name.replace("canvas-worker-", "run_canvas_worker_", 1)
        .replace("-oracle.json", "_oracle.py")
        .replace("-", "_")
        for name in corpora
    )
    assert evidence["runners"] == list(runners), "Provider producer family needs input review"
    for runner, corpus in zip(runners, corpora, strict=True):
        scenario = corpus.replace("-oracle.json", "-scenarios.json")
        assert graph["scenario_literals"][runner] == [scenario], (
            "Provider scenario selection needs input review"
        )
        assert runner not in graph["scenario_templates"], (
            "Provider scenario template needs input review"
        )
    assert not (set(evidence["sha256"]) & set(rest["sha256"]))
    expected = set(MOUNTED_INPUTS)
    for runner in runners:
        expected.update(expanded_inputs(graph, runner, root))
    assert set(evidence["sha256"]) == expected - set(rest["sha256"]), (
        "Provider-specific inputs need input review"
    )
    combined = {key: evidence[key] for key in ("schema", "purpose", "normalization")}
    combined["sha256"] = {
        name: pinned for name, pinned in rest["sha256"].items() if name in expected
    } | evidence["sha256"]
    assert_current_inputs(
        combined, graph, root,
        entrypoint=runners,
        schema="marty.canvas-worker-provider-recovery-current-inputs/v1",
        label="Provider recovery",
        disclaimer="do not attest historical provider recovery corpora",
        additional_inputs=MOUNTED_INPUTS,
    )


def test_current_provider_recovery_inputs_cover_all_direct_runners() -> None:
    check_provider_current_inputs(*provider_input_records(), ROOT)


@pytest.mark.parametrize(
    "name", json.loads(PROVIDER_INPUTS.read_text(encoding="utf-8"))["sha256"]
)
def test_provider_specific_input_change_invalidates_evidence(
    tmp_path: Path, name: str
) -> None:
    evidence, rest, producers, graph = provider_input_records()
    copy_inherited_rest_input_sources(tmp_path, evidence, rest)
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="Provider recovery input drift"):
        check_provider_current_inputs(evidence, rest, producers, graph, tmp_path)


def test_provider_inherited_rest_change_invalidates_evidence(tmp_path: Path) -> None:
    evidence, rest, producers, graph = provider_input_records()
    copy_inherited_rest_input_sources(tmp_path, evidence, rest)
    target = tmp_path / "scripts/test_canvas_worker_rest_https.py"
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="REST input drift"):
        check_provider_current_inputs(evidence, rest, producers, graph, tmp_path)


def test_provider_new_corpus_or_scenario_needs_input_review() -> None:
    evidence, rest, producers, graph = provider_input_records()
    producers["direct_runner_corpora"].append("canvas-worker-provider-new-oracle.json")
    with pytest.raises(AssertionError, match="Provider producer family needs input review"):
        check_provider_current_inputs(evidence, rest, producers, graph, ROOT)
    producers = provider_input_records()[2]
    graph["scenario_literals"][evidence["runners"][0]].append("new.json")
    with pytest.raises(AssertionError, match="Provider scenario selection needs input review"):
        check_provider_current_inputs(evidence, rest, producers, graph, ROOT)


def test_provider_new_local_helper_needs_input_review() -> None:
    evidence, rest, producers, graph = provider_input_records()
    graph["direct_imports"][evidence["runners"][0]].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        check_provider_current_inputs(evidence, rest, producers, graph, ROOT)


def test_provider_new_transitive_scenario_needs_input_review(tmp_path: Path) -> None:
    evidence, rest, producers, graph = provider_input_records()
    copy_inherited_rest_input_sources(tmp_path, evidence, rest)
    scenario = tmp_path / "contracts/canvas-worker-provider-recovery-scenarios.json"
    content = json.loads(scenario.read_text(encoding="utf-8"))
    content["new_reference"] = "new-transitive-scenario.json"
    scenario.write_text(json.dumps(content), encoding="utf-8")
    (tmp_path / "contracts/new-transitive-scenario.json").write_text(
        "{}", encoding="utf-8"
    )
    evidence["sha256"]["contracts/canvas-worker-provider-recovery-scenarios.json"] = (
        normalized_sha256(scenario)
    )
    with pytest.raises(AssertionError, match="need input review"):
        check_provider_current_inputs(evidence, rest, producers, graph, tmp_path)
