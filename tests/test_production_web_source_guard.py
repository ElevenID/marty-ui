"""Execute the actual child guard before any production web build or upload."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shlex
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/production-web-release.yml"


def selected_job(expression, context):
    """Evaluate this workflow's boolean admission subset without executing code."""
    source = re.sub(r"!(?!=)", "not ", expression.replace("&&", "and").replace("||", "or"))

    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return context[node.id]
        if isinstance(node, ast.Attribute):
            return value(node.value)[node.attr]
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            return (all if isinstance(node.op, ast.And) else any)(value(item) for item in node.values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not value(node.operand)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = value(node.left), value(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise AssertionError(f"Unsupported workflow admission expression: {ast.dump(node)}")

    return value(ast.parse(source, mode="eval"))


@pytest.mark.parametrize("event,mode,override,allowed", [
    ("workflow_dispatch", "combined", {}, {"release"}),
    ("workflow_dispatch", "website", {}, {"release"}),
    ("workflow_dispatch", "compose", {}, {"compose"}),
    ("push", "", {}, {"compose"}),
    ("push", "website", {}, {"compose"}),
    ("push", "", {"repository": "Elsewhere/marty-ui"}, set()),
    ("push", "", {"repository_id": "999"}, set()),
    ("push", "", {"ref": "refs/heads/feature"}, set()),
    ("push", "", {"ref": "refs/tags/main"}, set()),
    ("push", "", {"ref_protected": False}, set()),
    ("push", "", {"event": {"deleted": True}}, set()),
    ("pull_request", "compose", {}, set()),
    ("workflow_run", "compose", {}, set()),
])
def test_manifest_push_admits_only_the_original_repository_protected_main_composer(event, mode, override, allowed):
    workflow = yaml.safe_load(WORKFLOW.read_text())
    context = {
        "github": {
            "repository": "ElevenID/marty-ui", "repository_id": "1140864197",
            "event_name": event, "ref": "refs/heads/main", "ref_protected": True,
            "event": {"deleted": False}, **override,
        },
        "inputs": {"mode": mode},
    }
    assert {name for name, job in workflow["jobs"].items() if selected_job(job["if"], context)} == allowed


@pytest.mark.parametrize("job_name", ["release", "compose"])
@pytest.mark.parametrize(("expected", "actual", "allowed"), [
    ("a" * 40, "a" * 40, True),
    ("", "a" * 40, True),  # Existing standalone dispatch remains supported.
    ("a" * 40, "b" * 40, False),  # Main advanced after the parent's read.
    ("main", "a" * 40, False),
    ("A" * 40, "a" * 40, False),
    ("a" * 40 + "\n", "a" * 40, False),
])
def test_child_refuses_foreign_expected_source_before_other_work(
    tmp_path: Path, job_name: str, expected: str, actual: str, allowed: bool,
) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"][job_name]["steps"]
    guard = steps[1]
    assert steps[0]["uses"].startswith("actions/checkout@")
    assert guard["name"].startswith("Require the exact protected-main")
    assert guard["env"]["EXPECTED_SOURCE_SHA"] == "${{ inputs.expected_source_sha }}"
    # A local inert git stub makes the full shell step executable without a
    # remote connection. Refusal must happen before even this read-only probe.
    executable = tmp_path / "git"
    probe = tmp_path / "git-calls"
    executable.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$PROBE_LOG"\n'
        'if [ "$1" = rev-parse ]; then printf "%s\\n" "$GITHUB_SHA"; fi\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
                       PROBE_LOG=str(probe), GITHUB_REF="refs/heads/main", GITHUB_SHA=actual,
                       EXPECTED_SOURCE_SHA=expected, MODE="website", BACKEND_TAG="")
    result = subprocess.run(["bash", "--noprofile", "--norc"], input=guard["run"],
                            env=environment, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) is allowed, result.stderr
    assert probe.exists() is allowed


def test_push_manifest_validation_follows_source_guard_and_precedes_credentials() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["compose"]["steps"]
    assert steps[0]["with"] == {
        "ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False,
    }
    assert steps[1]["name"] == "Require the exact protected-main composition source"
    manifest = steps[2]
    assert manifest["id"] == "composition_manifest"
    assert manifest["if"] == "github.event_name == 'push'"
    assert manifest["env"] == {"COMPOSITION_PUSH_DELETED": "${{ github.event.deleted }}"}
    commands = manifest["run"].replace("\\\n", " ").splitlines()
    assert commands[0] == "set -euo pipefail"
    assert shlex.split(" ".join(commands[1:])) == [
        "python", "scripts/web_composition_manifest.py", "--manifest",
        ".github/release-inputs/website-composition.json", ">>", "$GITHUB_OUTPUT",
    ]
    assert steps[3]["name"] == "Prepare pinned verification tools and dependencies"
    for step in steps[:3]:
        assert "secrets." not in str(step)
        assert "github.token" not in str(step)
    login = next(index for index, step in enumerate(steps)
                 if step.get("uses", "").startswith("docker/login-action@"))
    assert login > 3
