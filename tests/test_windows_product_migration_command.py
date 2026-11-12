"""Native migration preparation cannot fall through to the ordinary server."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import selfhost_windows_product_deploy as deploy  # noqa: E402


def model():
    return {
        "services": {
            "issuance-native": {
                "image": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64,
                "environment": {"SERVICE_NAME": "issuance_native"},
                "entrypoint": ["/app/services/entrypoint.sh"],
                "command": [],
            }
        }
    }


class Docker:
    def __init__(self):
        self.calls = []

    def compose(self, project, env, source):
        self.calls.append((project, env, source))
        return [
            "docker",
            "--context",
            "synthetic-engine",
            "compose",
            "--project-name",
            project,
            "--env-file",
            str(env),
            "--file",
            str(source),
        ]


@pytest.mark.parametrize("entrypoint", [None, ["/app/services/entrypoint.sh"]])
@pytest.mark.parametrize("service_name", ["issuance_native", "issuance-native"])
def test_explicit_native_cli_replaces_the_argument_ignoring_entrypoint(
    tmp_path, entrypoint, service_name
):
    docker = Docker()
    candidate = model()
    candidate["services"]["issuance-native"]["entrypoint"] = entrypoint
    candidate["services"]["issuance-native"]["environment"]["SERVICE_NAME"] = (
        service_name
    )
    project = "marty-selfhost-synthetic"
    env, source = tmp_path / "selected.env", tmp_path / "new.compose.json"
    result = deploy.issuance_migration_command(
        docker, project, env, source, candidate, "b" * 32
    )
    assert docker.calls == [(project, env, source)]
    command = result["command"]
    assert command[-4:] == [
        "/bin/sh",
        "issuance-native",
        "-c",
        deploy.ISSUANCE_MIGRATION_SHELL,
    ]
    assert command[-5] == "--entrypoint"
    assert (
        "--no-deps" in command
        and "--interactive=false" in command
        and "--no-tty" in command
    )
    assert command[command.index("--pull") + 1] == "never"
    assert (
        command[command.index("--name") + 1]
        == result["name"]
        == project + "-issuance-migrate-" + "b" * 32
    )
    assert result["image"] == candidate["services"]["issuance-native"]["image"]
    assert (
        deploy.ISSUANCE_MIGRATION_SHELL
        == "set -e; . /app/load-secrets-env.sh; exec /usr/local/bin/marty-issuance-service migrate"
    )
    assert (
        not env.exists() and not source.exists()
    )  # Preparation neither reads nor writes caller files.


@pytest.mark.parametrize(
    "fault",
    [
        "role",
        "image-tag",
        "foreign-image",
        "entrypoint",
        "command",
        "environment",
        "service-name",
        "project",
        "cycle",
        "relative-env",
        "relative-source",
    ],
)
def test_unsupported_configuration_refuses_before_compose_preparation(tmp_path, fault):
    docker = Docker()
    candidate = deepcopy(model())
    service = candidate["services"]["issuance-native"]
    project, cycle = "marty-production-synthetic", "b" * 32
    env, source = tmp_path / "selected.env", tmp_path / "new.compose.json"
    if fault == "role":
        candidate["services"]["other"] = candidate["services"].pop("issuance-native")
    elif fault == "image-tag":
        service["image"] = "ghcr.io/elevenid/marty-ui-oss/services:latest"
    elif fault == "foreign-image":
        service["image"] = "example.invalid/other@sha256:" + "a" * 64
    elif fault == "entrypoint":
        service["entrypoint"] = ["/unexpected-wrapper"]
    elif fault == "command":
        service["command"] = ["unexpected-server-mode"]
    elif fault == "environment":
        service["environment"] = ["SERVICE_NAME=issuance_native"]
    elif fault == "service-name":
        service["environment"]["SERVICE_NAME"] = "organization"
    elif fault == "project":
        project = "marty-production-synthetic;injected"
    elif fault == "cycle":
        cycle = "not-a-unique-attempt"
    elif fault == "relative-env":
        env = Path("relative.env")
    else:
        source = Path("relative.compose.json")
    with pytest.raises(ValueError):
        deploy.issuance_migration_command(
            docker, project, env, source, candidate, cycle
        )
    assert not docker.calls
