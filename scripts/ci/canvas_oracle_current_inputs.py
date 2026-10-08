"""Check current Canvas capture inputs without attesting historical captures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def json_references(value):
    """Find the same literal JSON references guarded by the scenario inventory."""
    if isinstance(value, str) and (value.endswith(".json") or ".json#" in value):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from json_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from json_references(item)


def expanded_inputs(graph: dict, entrypoint: str, root: Path) -> set[str]:
    """Expand static scripts and transitive JSON inputs of literal scenarios."""
    pending = [entrypoint]
    scripts = set()
    while pending:
        script = pending.pop()
        if script in scripts:
            continue
        assert script in graph["direct_imports"], f"Unreviewed capture script: {script}"
        scripts.add(script)
        pending.extend(graph["direct_imports"][script])
        pending.extend(graph["launched_scripts"].get(script, []))
    assert not any(script in graph["scenario_templates"] for script in scripts), (
        "Review dynamic capture scenario paths"
    )
    scenario_roots = {
        scenario
        for script in scripts
        for scenario in graph["scenario_literals"].get(script, [])
    }
    scenarios = set()
    pending = list(scenario_roots)
    while pending:
        scenario = pending.pop()
        if scenario in scenarios:
            continue
        assert Path(scenario).name == scenario, f"Unsafe capture scenario: {scenario}"
        path = root / "contracts" / scenario
        assert path.is_file(), f"Missing capture scenario input: {scenario}"
        scenarios.add(scenario)
        for reference in json_references(json.loads(path.read_text(encoding="utf-8"))):
            filename = reference.partition("#")[0]
            assert filename.endswith(".json") and Path(filename).name == filename, (
                f"Unsafe capture JSON reference: {reference}"
            )
            pending.append(filename)
    return {f"scripts/{script}" for script in scripts} | {
        f"contracts/{scenario}" for scenario in scenarios
    }


def normalized_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assert_current_inputs(
    evidence: dict,
    graph: dict,
    root: Path,
    *,
    entrypoint: str,
    schema: str,
    label: str,
    disclaimer: str,
    additional_inputs: frozenset[str] = frozenset(),
) -> None:
    assert evidence["schema"] == schema
    assert set(evidence) == {"schema", "purpose", "normalization", "sha256"}
    assert disclaimer in evidence["purpose"]
    assert evidence["normalization"] == (
        "UTF-8 text with CRLF and CR converted to LF before SHA-256"
    )
    for name, pinned in evidence["sha256"].items():
        assert Path(name).as_posix() == name and ".." not in Path(name).parts
        assert len(pinned) == 64 and all(c in "0123456789abcdef" for c in pinned)
        assert normalized_sha256(root / name) == pinned, f"{label} input drift: {name}"
    assert set(evidence["sha256"]) == (
        expanded_inputs(graph, entrypoint, root) | additional_inputs
    ), f"{label} script, local imports, children, and scenarios need input review"
