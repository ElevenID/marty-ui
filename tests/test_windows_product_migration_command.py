"""Native migration preparation cannot fall through to the ordinary server."""

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

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


@pytest.mark.skipif(
    os.environ.get("MARTY_RUN_PRODUCT_NATIVE_STARTUP_TEST") != "1",
    reason="explicit isolated native Docker qualification",
)
def test_real_compose_oneoff_does_not_restart_or_start_dependencies(tmp_path):
    """Qualify flags/lifecycle only; exit0 replaces the separately tested body.

    No database, ports, binds or volumes. On uncertain creation, preserve the
    intent/resources rather than adopting or retrying an unacknowledged helper.
    """

    def require(condition):
        if not condition:
            raise RuntimeError(
                "Isolated lifecycle identity refused; preserve resources and intent"
            )

    context = os.environ["MARTY_PRODUCT_NATIVE_TEST_CONTEXT"]
    engine = os.environ["MARTY_PRODUCT_SCHEMA_TEST_ENGINE_ID"]
    image = os.environ["MARTY_PRODUCT_NATIVE_TEST_NEW_IMAGE"]
    revision = os.environ["MARTY_PRODUCT_NATIVE_TEST_NEW_SOURCE"]
    require(not os.environ.get("DOCKER_HOST"))
    require(
        re.fullmatch(
            r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}", image
        )
    )
    require(re.fullmatch(r"[0-9a-f]{40}", revision))
    prefix = ["docker", "--context", context]

    def call(args):
        result = subprocess.run(prefix + args, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(
                "Isolated Compose lifecycle operation failed; preserve evidence"
            )
        return result.stdout

    require(call(["context", "show"]).decode().strip() == context)
    info = json.loads(call(["info", "--format", "{{json .}}"]))
    require(info["ID"] == engine and info["OSType"] == "linux")
    metadata = json.loads(call(["image", "inspect", image]))[0]
    require(image in metadata["RepoDigests"] and metadata["Architecture"] == "amd64")
    require(
        metadata["Config"]["Labels"]["org.opencontainers.image.revision"] == revision
    )
    require(not metadata["Config"].get("Volumes"))
    nonce = uuid.uuid4().hex
    project = "marty-selfhost-compose-probe-" + nonce[:12]
    labels = {
        "elevenid.owner": "native-migration-compose-test",
        "elevenid.test.attempt": nonce,
    }
    candidate = model()
    service = candidate["services"]["issuance-native"]
    service.update(
        image=image,
        restart="always",
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        mem_limit="64m",
        pids_limit=32,
        logging={"driver": "none"},
        tmpfs=["/tmp:rw,noexec,nosuid,size=1048576"],
        labels=labels,
        depends_on={"guard": {"condition": "service_started"}},
    )
    candidate["services"]["guard"] = dict(
        service, entrypoint=["/bin/sh"], command=["-c", "exit 91"], depends_on={}
    )
    candidate["networks"] = {"default": {"internal": True, "labels": labels}}
    source, env = tmp_path / "oneoff.compose.json", tmp_path / "selected.env"
    source.write_text(json.dumps(candidate), encoding="utf-8")
    env.write_text("", encoding="utf-8")

    class SelectedDocker:
        def compose(self, selected_project, selected_env, selected_source):
            require(
                (selected_project, selected_env, selected_source)
                == (
                    project,
                    env,
                    source,
                )
            )
            return prefix + [
                "compose",
                "--project-name",
                project,
                "--env-file",
                str(env),
                "--file",
                str(source),
            ]

    prepared = deploy.issuance_migration_command(
        SelectedDocker(), project, env, source, candidate, nonce
    )
    name = prepared["name"]
    require(
        not call(
            ["ps", "-aq", "--filter", "label=com.docker.compose.project=" + project]
        ).strip()
    )
    require(
        not call(
            [
                "network",
                "ls",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        ).strip()
    )
    intent = {
        "project": project,
        "name": name,
        "nonce": nonce,
        "image": image,
        "image_id": metadata["Id"],
        "source": str(source),
        "scope": "isolated flag/lifecycle observation; no migration or admission",
    }
    with (tmp_path / "oneoff.intent.json").open("x", encoding="utf-8") as stream:
        json.dump(intent, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    command = [*prepared["command"][:-1], "exit 0"]
    response = subprocess.run(command, capture_output=True, timeout=30)
    cid = response.stdout.decode().strip()
    if response.returncode or not re.fullmatch(r"[0-9a-f]{64}", cid):
        pytest.fail(
            "Unknown isolated creation outcome; preserve intent/resources, do not retry"
        )

    def owned():
        row = json.loads(call(["inspect", cid]))[0]
        actual_labels = row["Config"]["Labels"]
        require(
            row["Id"] == cid
            and row["Name"] == "/" + name
            and row["Image"] == metadata["Id"]
        )
        require(
            row["Config"]["Image"] == image
            and row["Config"]["Entrypoint"] == ["/bin/sh"]
        )
        require(row["Config"]["Cmd"] == ["-c", "exit 0"])
        require(all(actual_labels.get(key) == value for key, value in labels.items()))
        require(actual_labels.get("com.docker.compose.project") == project)
        require(actual_labels.get("com.docker.compose.service") == "issuance-native")
        require(actual_labels.get("com.docker.compose.oneoff") == "True")
        require(
            not row["HostConfig"]["Binds"] and not row["HostConfig"]["PortBindings"]
        )
        require(
            not row["HostConfig"]["Privileged"]
            and row["HostConfig"]["ReadonlyRootfs"] is True
        )
        require(all(mount["Type"] == "tmpfs" for mount in row["Mounts"]))
        require(len(row["NetworkSettings"]["Networks"]) == 1)
        return row

    report = dict(
        intent, container_id=cid, production_admission=False, production_data_used=False
    )
    try:
        require(call(["wait", cid]).decode().strip() == "0")
        row = owned()
        report["restart_policy"] = row["HostConfig"]["RestartPolicy"]
        require(report["restart_policy"] == {"Name": "no", "MaximumRetryCount": 0})
        time.sleep(1)
        row = owned()
        require(row["State"]["Status"] == "exited" and row["State"]["ExitCode"] == 0)
        require(row["RestartCount"] == 0 and not row["State"]["OOMKilled"])
        require(
            call(
                [
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    "label=com.docker.compose.project=" + project,
                ]
            )
            .decode()
            .split()
            == [cid]
        )
        report["dependency_started"] = False
        report["passed"] = True
    finally:
        row = owned()
        networks = row["NetworkSettings"]["Networks"]
        call(["stop", "--time", "1", cid])
        owned()
        call(["rm", cid])
        require(not call(["ps", "-aq", "--no-trunc", "--filter", "id=" + cid]).strip())
        for network in networks.values():
            actual = json.loads(call(["network", "inspect", network["NetworkID"]]))[0]
            require(actual["Internal"] and not actual["Containers"])
            require(
                all(actual["Labels"].get(key) == value for key, value in labels.items())
            )
            require(actual["Labels"].get("com.docker.compose.project") == project)
            call(["network", "rm", actual["Id"]])
            require(
                not call(
                    ["network", "ls", "-q", "--filter", "id=" + actual["Id"]]
                ).strip()
            )
        report["cleanup_complete"] = True
        (tmp_path / "oneoff.result.json").write_text(
            json.dumps(report, sort_keys=True), encoding="utf-8"
        )
    print(json.dumps(report, sort_keys=True))
