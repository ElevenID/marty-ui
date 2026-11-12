"""Transient helper shape boundaries; full storage proof remains separately tested.

Only the existing ProductContext.check transport is replaced here. No engine,
Compose, migration, signature admission or production operation is performed.
"""

from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parents[1] / "scripts"),
    str(Path(__file__).resolve().parent),
]
import selfhost_windows_product as product  # noqa: E402
import selfhost_windows_product_deploy as deploy  # noqa: E402
from test_windows_product_transition import candidate, runtime_candidate  # noqa: E402

PROJECT = "marty-production-synthetic"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
CYCLE = "b" * 32
CID = "c" * 64


def fixture(tmp_path):
    before, *_ = runtime_candidate(tmp_path)
    old, admitted = candidate(tmp_path)
    old["services"]["issuance-native"] = {
        "image": "example.invalid/issuer@sha256:" + "1" * 64,
        "environment": {
            "SERVICE_NAME": "issuance_native",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        },
        "entrypoint": ["/app/services/entrypoint.sh"],
        "command": [],
        "read_only": True,
    }
    admitted["images"]["issuance-native"] = IMAGE
    new = product.product_model(old, admitted)
    original = deepcopy(
        next(row for row in before if product.renewal._service(row) == "gateway")
    )
    original.update(Id="d" * 64, Name="/" + PROJECT + "-issuance-native-1")
    original["Config"].update(Image=old["services"]["issuance-native"]["image"])
    original["Config"]["Labels"]["com.docker.compose.service"] = "issuance-native"
    original["HostConfig"] = {
        "Privileged": False,
        "ReadonlyRootfs": True,
        "PidMode": "",
        "NetworkMode": PROJECT + "_default",
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"],
    }
    original["NetworkSettings"] = {
        "Networks": {PROJECT + "_default": {"NetworkID": "9" * 64}}
    }
    before.append(original)
    ids = {
        product.renewal._service(row): "sha256:" + "2" * 64
        for row in before
        if product.renewal._service(row) not in product.HISTORICAL_ROLES
    }
    hashes = {"old": {}, "new": {}}
    for row in before:
        role = product.renewal._service(row)
        if role not in product.HISTORICAL_ROLES:
            hashes["old"][role] = "3" * 64
            hashes["new"][role] = "4" * 64
            row["Config"]["Labels"]["com.docker.compose.config-hash"] = "3" * 64

    class Docker:
        prefix = ["docker", "--context", "synthetic-engine"]

        def __init__(self):
            self.items = deepcopy(before)
            self.hashes_result = deepcopy(hashes["new"])
            self.image = {
                "Id": ids["issuance-native"],
                "Os": "linux",
                "Architecture": "amd64",
                "RepoDigests": [IMAGE],
                "Config": {"Env": ["PATH=/usr/bin"], "User": "", "WorkingDir": "/app"},
            }

        def compose(self, project, env, source):
            return [
                *self.prefix,
                *product.renewal.compose_args(project, env, source)[1:],
            ]

        def hashes(self, _command):
            return deepcopy(self.hashes_result)

        def json(self, args):
            if args == ["image", "inspect", IMAGE]:
                return [deepcopy(self.image)]
            assert args[-5:] == ["--profile", "*", "config", "--format", "json"]
            return deepcopy(new)

    docker = Docker()
    context = product.ProductContext(
        docker,
        PROJECT,
        before,
        {},
        "synthetic-helper",
        old_model=old,
        new_model=new,
        admitted=admitted,
        image_ids=ids,
        configuration_hashes=hashes,
    )

    def shape_only(**kwargs):
        context._candidate(
            docker.items, before_intent=kwargs.get("before_intent", False)
        )
        return deepcopy(docker.items)

    context.check = shape_only
    return context, docker, original


def prepare(context, tmp_path):
    return context.prepare_issuance_helper(
        tmp_path / "selected.env", tmp_path / "new.compose.json", CYCLE
    )


def helper(context, original):
    plan = context._issuance_helper
    row = deepcopy(original)
    row.update(
        Id=CID,
        Name="/" + plan["name"],
        Image=plan["image_id"],
        RestartCount=0,
        Created="2026-11-12T00:00:00Z",
    )
    row["Config"].update(
        Image=IMAGE,
        Entrypoint=["/bin/sh"],
        Cmd=["-c", deploy.ISSUANCE_MIGRATION_SHELL],
        Env=[key + "=" + value for key, value in plan["environment"].items()],
        User="",
        WorkingDir="/app",
        Tty=False,
        OpenStdin=False,
    )
    row["Config"]["Labels"].update(
        {"com.docker.compose.oneoff": "True", "marty.windows.product-migration": CYCLE}
    )
    row["HostConfig"].update(
        RestartPolicy={"Name": "no", "MaximumRetryCount": 0},
        AutoRemove=False,
        PortBindings={},
        PublishAllPorts=False,
    )
    row["State"] = {
        "Status": "running",
        "Running": True,
        "StartedAt": "2026-11-12T00:00:01.000000000Z",
        "ExitCode": 0,
        "Pid": 123,
        "OOMKilled": False,
        "Paused": False,
        "Dead": False,
        "Error": "",
    }
    return row


def test_acknowledged_oneoff_is_visible_until_confirmed_removal(tmp_path):
    context, docker, original = fixture(tmp_path)
    prepared = prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    with pytest.raises(ValueError):
        context._candidate(docker.items, before_intent=False)  # Never adopt by name.
    context.acknowledge_issuance_helper(CID)
    assert context.issuance_helper_witness()["id"] == CID
    with pytest.raises(ValueError):
        context.issuance_helper_witness(completed=True)
    row["State"].update(
        Status="exited", Running=False, Pid=0, FinishedAt="2026-11-12T00:00:02Z"
    )
    witness = context.issuance_helper_witness(completed=True)
    assert witness["observation_sha256"] == product.digest(row)
    assert prepared["image"] == witness["image"] and witness["exit_code"] == 0
    docker.items.remove(row)
    with pytest.raises(ValueError):
        context.check()  # Unexpected disappearance is not a cleanup receipt.
    context.issuance_helper_removed(CID)
    assert context._candidate(docker.items, before_intent=False)
    with pytest.raises(ValueError):
        prepare(context, tmp_path)  # No second migration in the same context.


@pytest.mark.parametrize(
    "fault",
    [
        "image",
        "reference",
        "entrypoint",
        "command",
        "nonce",
        "project",
        "role",
        "oneoff",
        "environment",
        "duplicate-env",
        "user",
        "workdir",
        "tty",
        "stdin",
        "storage",
        "secret-rw",
        "network",
        "extra-network",
        "privileged",
        "readonly",
        "host-pid",
        "network-mode",
        "capabilities",
        "restart-policy",
        "auto-remove",
        "ports",
        "publish-all",
        "restarts",
        "bool-restarts",
        "oom",
        "paused",
        "running-state",
        "pid",
        "missing",
        "replacement",
        "duplicate-id",
    ],
)
def test_helper_cannot_hide_unqualified_identity_execution_or_storage(tmp_path, fault):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    context.acknowledge_issuance_helper(CID)
    if fault == "image":
        row["Image"] = "sha256:" + "f" * 64
    elif fault == "reference":
        row["Config"]["Image"] = "other:latest"
    elif fault == "entrypoint":
        row["Config"]["Entrypoint"] = ["/unexpected"]
    elif fault == "command":
        row["Config"]["Cmd"] = ["-c", "unexpected"]
    elif fault == "nonce":
        row["Config"]["Labels"]["marty.windows.product-migration"] = "f" * 32
    elif fault == "project":
        row["Config"]["Labels"]["com.docker.compose.project"] = "foreign"
    elif fault == "role":
        row["Config"]["Labels"]["com.docker.compose.service"] = "gateway"
    elif fault == "oneoff":
        row["Config"]["Labels"]["com.docker.compose.oneoff"] = "False"
    elif fault == "environment":
        row["Config"]["Env"].append("UNDECLARED=value")
    elif fault == "duplicate-env":
        row["Config"]["Env"].append("PATH=/other")
    elif fault == "user":
        row["Config"]["User"] = "unexpected"
    elif fault == "workdir":
        row["Config"]["WorkingDir"] = "/other"
    elif fault == "tty":
        row["Config"]["Tty"] = True
    elif fault == "stdin":
        row["Config"]["OpenStdin"] = True
    elif fault == "storage":
        row["Mounts"][0]["Source"] = "/foreign"
    elif fault == "secret-rw":
        row["Mounts"][1]["RW"] = True
    elif fault == "network":
        next(iter(row["NetworkSettings"]["Networks"].values()))["NetworkID"] = "f" * 64
    elif fault == "extra-network":
        row["NetworkSettings"]["Networks"]["foreign"] = {"NetworkID": "f" * 64}
    elif fault == "privileged":
        row["HostConfig"]["Privileged"] = True
    elif fault == "readonly":
        row["HostConfig"]["ReadonlyRootfs"] = False
    elif fault == "host-pid":
        row["HostConfig"]["PidMode"] = "host"
    elif fault == "network-mode":
        row["HostConfig"]["NetworkMode"] = "host"
    elif fault == "capabilities":
        row["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
    elif fault == "restart-policy":
        row["HostConfig"]["RestartPolicy"]["Name"] = "always"
    elif fault == "auto-remove":
        row["HostConfig"]["AutoRemove"] = True
    elif fault == "ports":
        row["HostConfig"]["PortBindings"] = {"80/tcp": [{"HostPort": "80"}]}
    elif fault == "publish-all":
        row["HostConfig"]["PublishAllPorts"] = True
    elif fault == "restarts":
        row["RestartCount"] = 1
    elif fault == "bool-restarts":
        row["RestartCount"] = False
    elif fault == "oom":
        row["State"]["OOMKilled"] = True
    elif fault == "paused":
        row["State"]["Paused"] = True
    elif fault == "running-state":
        row["State"]["Running"] = False
    elif fault == "pid":
        row["State"]["Pid"] = 0
    elif fault == "missing":
        docker.items.remove(row)
    elif fault == "replacement":
        row["Id"] = "f" * 64
    else:
        docker.items.append(deepcopy(row))
    with pytest.raises(ValueError):
        context._candidate(docker.items, before_intent=False)


@pytest.mark.parametrize(
    "fault", ["hash", "image", "platform", "image-env", "image-volume"]
)
def test_prepare_requires_current_config_and_cached_qualified_image(tmp_path, fault):
    context, docker, _original = fixture(tmp_path)
    if fault == "hash":
        docker.hashes_result["issuance-native"] = "f" * 64
    elif fault == "image":
        docker.image["Id"] = "sha256:" + "f" * 64
    elif fault == "platform":
        docker.image["Architecture"] = "arm64"
    elif fault == "image-env":
        docker.image["Config"]["Env"].append("PATH=/other")
    else:
        docker.image["Config"]["Volumes"] = {"/undeclared": {}}
    with pytest.raises(ValueError):
        prepare(context, tmp_path)
    assert context._issuance_helper is None


def test_filter_retains_foreign_observations_and_refuses_preintent_use(tmp_path):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    context.acknowledge_issuance_helper(CID)
    foreign = deepcopy(original)
    foreign["Id"] = "e" * 64
    foreign["Config"]["Labels"]["com.docker.compose.project"] = "foreign"
    docker.items.append(foreign)
    filtered = context._without_issuance_helper(docker.items, False)
    assert foreign in filtered and row not in filtered
    with pytest.raises(ValueError):
        context._candidate(docker.items, before_intent=True)


@pytest.mark.parametrize(
    "fault",
    [
        "created",
        "started",
        "pid",
        "terminal-start",
        "terminal-running",
        "terminal-end",
        "terminal-code",
    ],
)
def test_same_cid_manual_restart_or_terminal_rewrite_is_not_a_new_migration(
    tmp_path, fault
):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    context.acknowledge_issuance_helper(CID)
    if fault.startswith("terminal-"):
        row["State"].update(
            Status="exited", Running=False, Pid=0, FinishedAt="2026-11-12T00:00:02Z"
        )
        context.issuance_helper_witness(completed=True)
    if fault == "created":
        row["Created"] = "2026-11-12T00:00:03Z"
    elif fault == "started":
        row["State"]["StartedAt"] = "2026-11-12T00:00:03Z"
    elif fault == "pid":
        row["State"]["Pid"] = 456
    elif fault == "terminal-start":
        row["State"].update(
            Status="running", Running=True, Pid=456, StartedAt="2026-11-12T00:00:03Z"
        )
    elif fault == "terminal-running":
        row["State"].update(Status="running", Running=True, Pid=123)
    elif fault == "terminal-end":
        row["State"]["FinishedAt"] = "2026-11-12T00:00:03Z"
    else:
        row["State"]["ExitCode"] = 1
    assert row["Id"] == CID and row["RestartCount"] == 0
    with pytest.raises(ValueError):
        context.issuance_helper_witness()


@pytest.mark.parametrize(
    "field,value",
    [
        ("Created", None),
        ("Created", "not-a-timestamp"),
        ("StartedAt", "0001-01-01T00:00:00Z"),
        ("StartedAt", "2026-11-12T00:00:01"),
    ],
)
def test_acknowledgement_requires_observed_creation_and_start_identity(
    tmp_path, field, value
):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    if field == "Created":
        row[field] = value
    else:
        row["State"][field] = value
    with pytest.raises(ValueError):
        context.acknowledge_issuance_helper(CID)


def test_helper_that_exits_before_first_observation_remains_terminal(tmp_path):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    row["State"].update(
        Status="exited", Running=False, Pid=0, FinishedAt="2026-11-12T00:00:02Z"
    )
    docker.items.append(row)
    context.acknowledge_issuance_helper(CID)
    witness = context.issuance_helper_witness(completed=True)
    assert witness["execution"]["started_at"] == row["State"]["StartedAt"]
    assert witness["terminal"]["finished_at"] == row["State"]["FinishedAt"]
    row["State"].update(
        Status="running", Running=True, Pid=456, StartedAt="2026-11-12T00:00:03Z"
    )
    with pytest.raises(ValueError):
        context.check()


@pytest.mark.parametrize("exit_code", [None, 1, 0])
def test_removal_acknowledgement_cannot_skip_successful_completion_proof(
    tmp_path, exit_code
):
    context, docker, original = fixture(tmp_path)
    prepare(context, tmp_path)
    row = helper(context, original)
    docker.items.append(row)
    context.acknowledge_issuance_helper(CID)
    if exit_code is not None:
        row["State"].update(
            Status="exited",
            Running=False,
            Pid=0,
            ExitCode=exit_code,
            FinishedAt="2026-11-12T00:00:02Z",
        )
        context.issuance_helper_witness()  # Generic observation grants no cleanup phase.
    docker.items.remove(row)
    with pytest.raises(ValueError):
        context.issuance_helper_removed(CID)
