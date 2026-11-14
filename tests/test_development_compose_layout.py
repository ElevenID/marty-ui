"""Development overlay layout checks; render tests use synthetic base services.

No containers are started, images pulled, or release qualification asserted.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from scripts.dev import worktree_stack

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_ROOT = ROOT / "deploy" / "compose"
DEVELOPMENT = COMPOSE_ROOT / "development"
OVERLAYS = (
    "docker-compose.worktree-dev.yml",
    "docker-compose.passport-supported-disposable-watch.yml",
)


def assert_unique_keys(node: yaml.Node, location: str = "root") -> None:
    """Inspect YAML nodes without losing duplicates or Compose-specific tags."""
    if isinstance(node, MappingNode):
        seen = set()
        for key, value in node.value:
            assert isinstance(key, ScalarNode), f"non-scalar key at {location}"
            assert key.value not in seen, f"duplicate key at {location}.{key.value}"
            seen.add(key.value)
            assert_unique_keys(value, f"{location}.{key.value}")
    elif isinstance(node, SequenceNode):
        for index, value in enumerate(node.value):
            assert_unique_keys(value, f"{location}[{index}]")


@pytest.mark.parametrize("name", OVERLAYS)
def test_development_overlays_have_one_canonical_location(name):
    assert (DEVELOPMENT / name).is_file()
    assert not (DEVELOPMENT / name).is_symlink()
    assert not (ROOT / name).exists()
    assert not (ROOT / name).is_symlink()


def test_nested_compose_files_keep_duplicate_key_coverage():
    paths = sorted({*COMPOSE_ROOT.rglob("*.yml"), *COMPOSE_ROOT.rglob("*.yaml")})
    assert paths, "nested Compose definitions must not silently disappear"
    for path in paths:
        document = yaml.compose(path.read_text(encoding="utf-8"))
        assert isinstance(document, MappingNode), f"empty/non-mapping Compose file: {path}"
        assert_unique_keys(document, str(path.relative_to(ROOT)))


def test_duplicate_key_check_rejects_nested_duplicates_with_compose_tags():
    document = yaml.compose(
        'services:\n  probe:\n    ports: !override []\n    ports: !reset []\n'
    )
    with pytest.raises(AssertionError, match="duplicate key.*probe.ports"):
        assert_unique_keys(document)


def test_worktree_command_keeps_repository_base_and_overlay_order(tmp_path, monkeypatch):
    root = tmp_path / "checkout with spaces"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    command = worktree_stack.compose_command(root, "marty-wt-layout")
    assert command == [
        "docker", "compose", "--project-name", "marty-wt-layout",
        "--project-directory", str(root),
        "-f", str(root / "docker-compose.base.yml"),
        "-f", str(root / "docker-compose.profile.dev.yml"),
        "-f", str(root / "deploy/compose/development" / OVERLAYS[0]),
    ]


def test_watch_launcher_selects_the_relocated_overlay():
    # This is a static caller check, not a passport bootstrap simulation.
    tree = ast.parse((ROOT / "scripts/passport_local_watch.py").read_text(encoding="utf-8"))
    assignments = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "watch" for target in node.targets)
    ]
    assert len(assignments) == 1
    expected = ast.parse(f'ROOT / "deploy/compose/development/{OVERLAYS[1]}"', mode="eval").body
    assert ast.dump(assignments[0]) == ast.dump(expected)


@pytest.mark.parametrize("name", OVERLAYS)
def test_overlay_relocation_preserves_fixture_render(name, tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker CLI is unavailable; render equivalence was not exercised")
    version = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, text=True, timeout=30,
    )
    if version.returncode:
        pytest.skip("Docker Compose plugin is unavailable")

    root = tmp_path / "checkout with spaces"
    root.mkdir()
    caller = tmp_path / "outside-checkout"
    caller.mkdir()
    content = (DEVELOPMENT / name).read_bytes()
    old = root / name
    new = root / "deploy/compose/development" / name
    new.parent.mkdir(parents=True)
    old.write_bytes(content)
    new.write_bytes(content)
    document = yaml.compose(content.decode("utf-8"))
    services = next(value for key, value in document.value if key.value == "services")
    worktree = name == OVERLAYS[0]
    base = {
        "services": {
            key.value: {
                "image": "example.invalid/layout-test:unused",
                "networks": ["marty-network"] if worktree else ["private", "ingress"],
                **({"ports": ["127.0.0.1:49999:9999"]} if worktree else {}),
            }
            for key, _ in services.value
        },
        "networks": (
            {"marty-network": {"name": "${MARTY_NETWORK_NAME}"}}
            if worktree else {"private": {}, "ingress": {}}
        ),
    }
    base_file = root / "base.yml"
    base_file.write_text(yaml.safe_dump(base), encoding="utf-8")
    env_file = root / "empty.env"
    env_file.write_text("", encoding="utf-8")
    env = worktree_stack.environment(root, "marty-layout-test", 28000)
    command = ["docker", "compose", "--project-name", "marty-layout-test"]
    if worktree:
        command.extend(["--project-directory", str(root)])
    else:
        # The passport launcher retains its root-level first file and explicit env file.
        command.extend(["--env-file", str(env_file)])
    command.extend(["-f", str(base_file)])

    def render(overlay):
        result = subprocess.run(
            [*command, "-f", str(overlay), "config", "--format", "json"],
            cwd=caller, env=env, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    before = render(old)
    old.unlink()  # The new render must work without a root-level compatibility copy.
    after = render(new)
    assert after == before
    if worktree:
        worktree_stack.validate_config([*command, "-f", str(new)], env)
    else:
        for service in after["services"].values():
            assert Path(service["build"]["context"]).resolve() == root.resolve()
            assert service["build"]["dockerfile"] == "services/Dockerfile.passport-watch"
            mount = next(item for item in service["volumes"] if item["target"] == "/workspace")
            assert Path(mount["source"]).resolve() == root.resolve()
            assert mount["read_only"] is True
