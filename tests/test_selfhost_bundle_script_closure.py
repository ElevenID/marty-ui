"""Bundled operator scripts must carry their local Python imports."""

from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bundled_operator_scripts_include_local_import_closure() -> None:
    manifest = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(
        encoding="utf-8"))
    assets = set(manifest["assets"])
    missing: set[tuple[str, str]] = set()
    for asset in assets:
        if not asset.startswith("scripts/") or not asset.endswith(".py"):
            continue
        source = ast.parse((ROOT / asset).read_text(encoding="utf-8"))
        for node in ast.walk(source):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            elif isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            else:
                continue
            for module in modules:
                candidate = f"scripts/{module.split('.')[0]}.py"
                if (ROOT / candidate).is_file() and candidate not in assets:
                    missing.add((asset, candidate))
    assert not missing, f"bundled scripts omit local imports: {sorted(missing)}"
