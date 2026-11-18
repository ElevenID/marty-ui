"""Completed ceremonies must not rerun; foreign or failed custody must not resume."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from scripts import conformance_stack as stack

PROJECT = "marty-conformance-resume-test"
IMAGE = "example.invalid/openbao@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
SERVICES = sorted(stack.KMS_BOOTSTRAP_SERVICES)
IDS = {service: str(i + 1) * 64 for i, service in enumerate(SERVICES)}
CONFIG = {"services": {
    **{name: {"image": IMAGE} for name in SERVICES},
    "postgres": {}, "db-migrate": {}, "issuance-native": {},
    "oidf-tls-proxy": {"profiles": ["oidf"]},
    "disabled": {"profiles": ["unselected"]},
}}
COMMAND = ["docker", "compose", "--project-name", PROJECT, "--profile", "oidf"]


def records():
    return {name: {
        "Id": IDS[name],
        "Image": IMAGE_ID,
        "Config": {"Image": IMAGE, "Labels": {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": name,
        }},
        "State": ({"Status": "running", "Running": True,
                   "Health": {"Status": "healthy"}, "OOMKilled": False}
                  if name == "openbao" else
                  {"Status": "exited", "ExitCode": 0, "OOMKilled": False}),
    } for name in SERVICES}


def invocation(values, fault=None):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        assert kwargs["capture_output"] and kwargs["timeout"] == 30
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(returncode=1 if fault == "image-unavailable" else 0,
                                   stdout="invalid" if fault == "image-invalid" else IMAGE_ID)
        if command[1] == "ps":
            name = command[-1].split("=", 2)[-1]
            assert f"label=com.docker.compose.project={PROJECT}" in command
            ids = [] if fault == "missing" else [IDS[name]]
            if fault == "ambiguous":
                ids.append("f" * 64)
            return SimpleNamespace(returncode=0, stdout="\n".join(ids))
        name = next(name for name, identity in IDS.items() if identity == command[-1])
        return SimpleNamespace(returncode=0, stdout=("invalid json" if fault == "json"
                               else json.dumps([values[name]])))

    return runner, calls


def test_completed_bootstrap_resumes_runtime_without_starting_ceremonies():
    runner, calls = invocation(records())
    args = stack.runtime_up_arguments(COMMAND, deepcopy(CONFIG), PROJECT,
                                      resume=True, runner=runner)
    assert args == ["up", "--detach", "--no-build", "--no-deps",
                    "db-migrate", "issuance-native", "oidf-tls-proxy", "postgres"]
    assert len(calls) == 7
    assert all(c[1] in {"ps", "container", "image"} for c in calls)


@pytest.mark.parametrize("fault", [
    "missing", "ambiguous", "json", "foreign-project", "foreign-service", "image",
    "identity", "failed-ceremony", "running-ceremony", "unhealthy", "stopped-kms", "oom",
    "stale-image-id", "image-unavailable", "image-invalid",
])
def test_resume_fails_before_any_runtime_mutation(fault):
    values = records()
    row = values["openbao-init"]
    if fault == "foreign-project":
        row["Config"]["Labels"]["com.docker.compose.project"] = "another-project"
    elif fault == "foreign-service":
        row["Config"]["Labels"]["com.docker.compose.service"] = "another-service"
    elif fault == "image":
        row["Config"]["Image"] = "openbao:latest"
    elif fault == "stale-image-id":
        row["Image"] = "sha256:" + "c" * 64
    elif fault == "identity":
        row["Id"] = "f" * 64
    elif fault == "failed-ceremony":
        row["State"]["ExitCode"] = 1
    elif fault == "running-ceremony":
        row["State"]["Status"] = "running"
    elif fault == "unhealthy":
        values["openbao"]["State"]["Health"]["Status"] = "unhealthy"
    elif fault == "stopped-kms":
        values["openbao"]["State"]["Running"] = False
    elif fault == "oom":
        row["State"]["OOMKilled"] = True
    runner, calls = invocation(values, fault)
    with pytest.raises(ValueError, match="KMS bootstrap"):
        stack.runtime_up_arguments(COMMAND, CONFIG, PROJECT, resume=True, runner=runner)
    assert all(c[1] in {"ps", "container", "image"} for c in calls)


def test_fresh_start_does_not_reuse_existing_kms_custody():
    def forbidden(*args, **kwargs):
        raise AssertionError("fresh startup must run its normal ceremony")

    assert stack.runtime_up_arguments(COMMAND, CONFIG, PROJECT, resume=False,
                                      runner=forbidden) == ["up", "--detach", "--no-build"]
