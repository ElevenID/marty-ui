from __future__ import annotations

import ast
from pathlib import Path


VERSIONS = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
)


def test_deployment_profile_migrations_have_one_head() -> None:
    revisions: set[str] = set()
    parents: set[str] = set()

    for path in VERSIONS.glob("*.py"):
        assignments = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in ast.parse(path.read_text(encoding="utf-8")).body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"revision", "down_revision"}
        }
        revisions.add(assignments["revision"])
        down_revision = assignments["down_revision"]
        if isinstance(down_revision, tuple):
            parents.update(down_revision)
        elif down_revision is not None:
            parents.add(down_revision)

    assert revisions - parents == {"20260716_0001"}
