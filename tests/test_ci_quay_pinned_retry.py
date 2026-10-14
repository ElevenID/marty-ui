"""A transient Quay failure may retry only the identical pinned image fetch."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import sys
from unittest import mock

import pytest
import yaml

from scripts import probe_signing_keys_openbao_policy as policy


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/pull-pinned-quay-openbao.sh"


def test_policy_probe_retries_only_pinned_pull() -> None:
    with mock.patch.object(policy, "docker", side_effect=[
        subprocess.CompletedProcess([], 1),
        subprocess.CompletedProcess([], 1),
        subprocess.CompletedProcess([], 0),
    ]) as docker, mock.patch.object(policy.time, "sleep") as pause:
        policy.pull_pinned_openbao()
    assert docker.call_args_list == [
        mock.call("image", "inspect", policy.IMAGE),
        mock.call("pull", policy.IMAGE),
        mock.call("pull", policy.IMAGE),
    ]
    pause.assert_called_once_with(1)


def test_policy_probe_retries_a_timed_out_pinned_pull() -> None:
    with mock.patch.object(policy, "docker", side_effect=[
        subprocess.CompletedProcess([], 1),
        subprocess.TimeoutExpired(["docker", "pull", policy.IMAGE], 120),
        subprocess.CompletedProcess([], 0),
    ]) as docker, mock.patch.object(policy.time, "sleep") as pause:
        policy.pull_pinned_openbao()
    assert docker.call_args_list == [
        mock.call("image", "inspect", policy.IMAGE),
        mock.call("pull", policy.IMAGE),
        mock.call("pull", policy.IMAGE),
    ]
    pause.assert_called_once_with(1)


def test_policy_probe_fails_closed_after_three_attempts() -> None:
    with mock.patch.object(
        policy, "docker", return_value=subprocess.CompletedProcess([], 1)
    ) as docker, mock.patch.object(policy.time, "sleep") as pause:
        with pytest.raises(RuntimeError, match="image is unavailable"):
            policy.pull_pinned_openbao()
    assert docker.call_count == 4
    assert [call.args[0] for call in pause.call_args_list] == [1, 2]


def test_policy_probe_fails_closed_after_three_pull_timeouts() -> None:
    timeout = subprocess.TimeoutExpired(["docker", "pull", policy.IMAGE], 120)
    with mock.patch.object(policy, "docker", side_effect=[
        subprocess.CompletedProcess([], 1), timeout, timeout, timeout,
    ]) as docker, mock.patch.object(policy.time, "sleep") as pause:
        with pytest.raises(RuntimeError, match="image is unavailable"):
            policy.pull_pinned_openbao()
    assert docker.call_count == 4
    assert [call.args[0] for call in pause.call_args_list] == [1, 2]


def test_policy_probe_reuses_exact_local_image() -> None:
    with mock.patch.object(
        policy, "docker", return_value=subprocess.CompletedProcess([], 0)
    ) as docker:
        policy.pull_pinned_openbao()
    docker.assert_called_once_with("image", "inspect", policy.IMAGE)


def test_canvas_ci_uses_the_bounded_pinned_pull() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    start = next(step for step in steps if step.get("name") ==
                 "Start digest-pinned Rust test services after registry setup")
    assert "bash scripts/ci/pull-pinned-quay-openbao.sh" in start["run"]
    assert "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878" in start["run"]
    assert 'timeout 120s docker pull "$1"' in SCRIPT.read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("bash") is None, reason="Bash unavailable")
def test_pull_script_rejects_mutable_tag_without_contacting_docker() -> None:
    result = subprocess.run(
        ["bash", "scripts/ci/pull-pinned-quay-openbao.sh",
         "quay.io/openbao/openbao:latest"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert "digest-pinned" in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX executable fixture")
@pytest.mark.parametrize("succeed_on,expected_status", [(2, 0), (4, 1)])
def test_pull_script_retries_bounded_exact_digest(
    tmp_path: Path, succeed_on: int, expected_status: int,
) -> None:
    binary = tmp_path / "bin"
    binary.mkdir()
    calls = tmp_path / "calls"
    pauses = tmp_path / "pauses"
    docker = binary / "docker"
    docker.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MOCK_CALLS"\n'
        'count=$(wc -l < "$MOCK_CALLS")\n'
        'test "$count" -ge "$MOCK_SUCCEED_ON"\n', encoding="utf-8",
    )
    docker.chmod(0o755)
    sleep = binary / "sleep"
    sleep.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$1" >> "$MOCK_PAUSES"\n',
        encoding="utf-8",
    )
    sleep.chmod(0o755)
    reference = "quay.io/openbao/openbao@sha256:" + "a" * 64
    result = subprocess.run(
        ["bash", str(SCRIPT), reference], cwd=ROOT,
        env={**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
             "MOCK_CALLS": str(calls), "MOCK_PAUSES": str(pauses),
             "MOCK_SUCCEED_ON": str(succeed_on)},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == expected_status
    assert calls.read_text(encoding="utf-8").splitlines() == [
        f"pull {reference}"
    ] * min(succeed_on, 3)
    assert pauses.read_text(encoding="utf-8").splitlines() == [
        "1", "2"
    ][:min(succeed_on - 1, 2)]
