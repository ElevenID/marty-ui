from __future__ import annotations

import json
import importlib.util
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_verification_candidate_backend",
    ROOT / "scripts" / "check_verification_candidate_backend.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load verification candidate backend checker")
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)


def valid_node() -> dict[str, object]:
    return {
        "name": "builder-node-0",
        "endpoint": "setup-docker-action",
        "driver-opts": [backend.EXPECTED_DRIVER_OPTION],
        "status": "running",
        "buildkit": backend.EXPECTED_BUILDKIT,
        "platforms": "linux/amd64,linux/amd64/v2,linux/386",
    }


class BackendRunner:
    def __init__(self, *, inspect_failure: bool = False) -> None:
        self.inspect_failure = inspect_failure
        self.checked: list[tuple[str, ...]] = []
        self.text_calls: list[tuple[str, ...]] = []

    def text(self, command: Sequence[str]) -> str:
        key = tuple(command)
        self.text_calls.append(key)
        outputs = {
            ("docker", "version", "--format", "{{.Server.Version}}"): "29.7.2\n",
            ("docker", "buildx", "version"): (
                "github.com/docker/buildx v0.36.1 exact-commit\n"
            ),
            ("docker", "info", "--format", "{{json .DriverStatus}}"): (
                '[["driver-type","io.containerd.snapshotter.v1"]]\n'
            ),
        }
        return outputs[key]

    def check(self, command: Sequence[str]) -> None:
        key = tuple(command)
        self.checked.append(key)
        if self.inspect_failure:
            raise subprocess.CalledProcessError(7, command)


@pytest.mark.parametrize("indent", [None, 2], ids=["compact", "pretty"])
def test_exact_single_node_backend_accepts_json_alignment(indent: int | None) -> None:
    runner = BackendRunner()
    backend.require_exact_backend(
        json.dumps([valid_node()], indent=indent),
        backend.EXPECTED_DRIVER,
        run_text=runner.text,
        run_check=runner.check,
    )
    assert runner.checked == [("docker", "buildx", "inspect", "--bootstrap")]
    assert runner.text_calls[-1] == (
        "docker",
        "info",
        "--format",
        "{{json .DriverStatus}}",
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda nodes: nodes.clear(), "exactly one node"),
        (lambda nodes: nodes.append(valid_node()), "exactly one node"),
        (lambda nodes: nodes[0].pop("buildkit"), "BuildKit version"),
        (lambda nodes: nodes[0].update(buildkit="v0.32.1"), "BuildKit version"),
        (lambda nodes: nodes[0].update(status="stopped"), "not running"),
        (lambda nodes: nodes[0].update(platforms="linux/arm64"), "linux/amd64"),
        (lambda nodes: nodes[0].update(**{"driver-opts": []}), "image selection"),
    ],
)
def test_node_metadata_mutations_fail_closed(mutation: object, message: str) -> None:
    nodes = [valid_node()]
    mutation(nodes)  # type: ignore[operator]
    runner = BackendRunner()
    with pytest.raises(backend.BackendContractError, match=message):
        backend.require_exact_backend(
            json.dumps(nodes),
            backend.EXPECTED_DRIVER,
            run_text=runner.text,
            run_check=runner.check,
        )


def test_nonzero_live_inspection_cannot_be_masked_by_valid_metadata() -> None:
    runner = BackendRunner(inspect_failure=True)
    with pytest.raises(subprocess.CalledProcessError):
        backend.require_exact_backend(
            json.dumps([valid_node()]),
            backend.EXPECTED_DRIVER,
            run_text=runner.text,
            run_check=runner.check,
        )
    assert runner.checked == [("docker", "buildx", "inspect", "--bootstrap")]


def test_oversized_or_malformed_node_metadata_fails_closed() -> None:
    runner = BackendRunner()
    for value, message in [
        ("{" + " " * backend.MAX_NODES_JSON_BYTES, "too large"),
        ("not-json", "invalid"),
        (json.dumps({"buildkit": backend.EXPECTED_BUILDKIT}), "metadata changed"),
    ]:
        with pytest.raises(backend.BackendContractError, match=message):
            backend.require_exact_backend(
                value,
                backend.EXPECTED_DRIVER,
                run_text=runner.text,
                run_check=runner.check,
            )
