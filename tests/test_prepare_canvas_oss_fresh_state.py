from __future__ import annotations

from pathlib import Path

import pytest

from scripts.prepare_canvas_oss_fresh_state import (
    EXTERNAL_TUNNEL_NETWORK,
    PROJECT,
    DockerSnapshot,
    FreshStateError,
    cleanup_command,
    validate_fresh_state,
)


def snapshot(
    *,
    project_containers: set[str] | None = None,
    project_volumes: set[str] | None = None,
    project_networks: set[str] | None = None,
    running: set[str] | None = None,
    tunnel_id: str = "network-id",
    tunnel_members: set[str] | None = None,
) -> DockerSnapshot:
    return DockerSnapshot(
        project_containers=frozenset(project_containers or set()),
        project_volumes=frozenset(project_volumes or set()),
        project_networks=frozenset(project_networks or set()),
        non_project_running_containers=frozenset(running or set()),
        tunnel_network_id=tunnel_id,
        non_project_tunnel_members=frozenset(tunnel_members or set()),
    )


def test_cleanup_command_is_fixed_to_only_the_acceptance_project(tmp_path: Path) -> None:
    compose = tmp_path / "canvas.yml"
    command = cleanup_command(compose)

    assert command[:5] == ["docker", "compose", "--project-name", PROJECT, "--file"]
    assert command[5] == str(compose.resolve())
    assert command[6:] == ["down", "--volumes", "--remove-orphans", "--timeout", "30"]
    assert EXTERNAL_TUNNEL_NETWORK not in command
    assert "system" not in command
    assert "prune" not in command


def test_fresh_state_accepts_only_target_removal_and_preserved_beta() -> None:
    before = snapshot(
        project_containers={"old-web", "old-orphan"},
        project_volumes={"old-db"},
        project_networks={"old-private"},
        running={"beta", "selfhost", "tunnel"},
        tunnel_members={"beta", "selfhost", "tunnel"},
    )
    after = snapshot(
        running={"beta", "selfhost", "tunnel"},
        tunnel_members={"beta", "selfhost", "tunnel"},
    )

    validate_fresh_state(before, after)


@pytest.mark.parametrize(
    "after, message",
    [
        (snapshot(project_volumes={"stale"}), "resources remain"),
        (snapshot(tunnel_id="replacement"), "tunnel network changed"),
        (snapshot(running={"beta"}), "outside the Canvas acceptance project"),
        (snapshot(running={"beta", "selfhost"}, tunnel_members={"beta"}), "tunnel attachment"),
    ],
)
def test_fresh_state_fails_closed_on_scope_or_cleanup_drift(
    after: DockerSnapshot,
    message: str,
) -> None:
    before = snapshot(
        running={"beta", "selfhost"},
        tunnel_members={"beta", "selfhost"},
    )

    with pytest.raises(FreshStateError, match=message):
        validate_fresh_state(before, after)


def test_workflow_runs_fresh_state_gate_before_monitor_and_lifecycle() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")

    gate = workflow.index("Require fresh isolated Canvas Compose state")
    monitor = workflow.index("Start beta continuity monitor")
    lifecycle = workflow.index("Bootstrap stock Canvas lifecycle and start LMS")
    assert gate < monitor < lifecycle
    assert "prepare_canvas_oss_fresh_state.py" in workflow
    assert "fresh-state-audit.json" in workflow
