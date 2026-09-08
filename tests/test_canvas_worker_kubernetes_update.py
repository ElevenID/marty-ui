"""Closed native transition checks; actual Bash uses only a fake kubectl."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_canvas_worker_kubernetes_update.py"
SPEC = importlib.util.spec_from_file_location("worker_update_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
NAMESPACE = "synthetic-test-namespace"
PRIVATE = "synthetic-private-payload-must-not-be-disclosed"


def deployment():
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "canvas-sync-worker", "namespace": NAMESPACE},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "canvas-sync-worker",
                            "command": ["/usr/local/bin/marty-canvas-sync-worker"],
                            "env": [
                                {"name": "SERVICE_NAME", "value": "canvas_sync_worker"},
                                {"name": "CANVAS_SYNC_PROCESSOR", "value": ""},
                                {"name": "SYNTHETIC_PRIVATE", "value": PRIVATE},
                            ],
                        }
                    ]
                }
            }
        },
    }


def worker(value):
    return value["spec"]["template"]["spec"]["containers"][0]


@pytest.mark.parametrize("args", [None, []])
def test_exact_native_launch_accepts_absent_or_empty_args(args):
    value = deployment()
    if args is not None:
        worker(value)["args"] = args
    GUARD.check_bytes(json.dumps(value).encode(), NAMESPACE)


def test_actual_manifest_is_accepted_without_interpolation():
    documents = yaml.safe_load_all(
        (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
    )
    matches = [
        item
        for item in documents
        if item and item.get("metadata", {}).get("name") == "canvas-sync-worker"
    ]
    assert len(matches) == 1
    GUARD.validate_deployment(matches[0], "marty-prod")


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", None),
        ("command", []),
        ("command", " /usr/local/bin/marty-canvas-sync-worker"),
        ("command", ["python"]),
        ("command", ["/bin/sh", "-c"]),
        ("command", ["/app/services/entrypoint.sh"]),
        ("command", ["/usr/local/bin/marty-canvas-sync-worker", "extra"]),
        ("args", None),
        ("args", ["-m", "issuance.canvas_worker"]),
        ("args", ""),
        ("env", None),
        ("env", {}),
        ("env", []),
    ],
)
def test_rejects_legacy_missing_or_ambiguous_launch(field, value):
    candidate = deployment()
    worker(candidate)[field] = value
    with pytest.raises(ValueError, match="^$"):
        GUARD.validate_deployment(candidate, NAMESPACE)


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("mutation", ["absent", "duplicate", "wrong", "reference"])
def test_explicit_closed_selector_overrides_are_required(index, mutation):
    candidate = deployment()
    entries = worker(candidate)["env"]
    if mutation == "absent":
        entries.pop(index)
    elif mutation == "duplicate":
        entries.append(copy.deepcopy(entries[index]))
    elif mutation == "wrong":
        entries[index]["value"] = PRIVATE
    else:
        entries[index]["valueFrom"] = {"secretKeyRef": {"name": PRIVATE}}
    with pytest.raises(ValueError, match="^$"):
        GUARD.validate_deployment(candidate, NAMESPACE)


@pytest.mark.parametrize(
    "mutation",
    ["namespace", "name", "kind", "version", "spec", "duplicate", "no-worker"],
)
def test_deployment_identity_and_container_uniqueness(mutation):
    candidate = deployment()
    if mutation in {"namespace", "name"}:
        candidate["metadata"][mutation] = PRIVATE
    elif mutation == "kind":
        candidate["kind"] = "Pod"
    elif mutation == "version":
        candidate["apiVersion"] = "v1"
    elif mutation == "spec":
        candidate["spec"] = []
    elif mutation == "duplicate":
        candidate["spec"]["template"]["spec"]["containers"].append(
            copy.deepcopy(worker(candidate))
        )
    else:
        worker(candidate)["name"] = "other"
    with pytest.raises(ValueError, match="^$"):
        GUARD.validate_deployment(candidate, NAMESPACE)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"\xff",
        b'{"kind":"Deployment","kind":"Deployment"}',
        b'{"number":NaN}',
        b" " * (GUARD.MAX_DEPLOYMENT_BYTES + 1),
    ],
    ids=["empty", "truncated", "encoding", "duplicate", "nonfinite", "oversized"],
)
def test_malformed_input_is_rejected(raw):
    with pytest.raises(ValueError):
        GUARD.check_bytes(raw, NAMESPACE)


def test_cli_does_not_expose_private_malformed_input():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--namespace", NAMESPACE],
        input=(PRIVATE + "{"),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == GUARD.REFUSAL


@pytest.mark.parametrize(
    "number,accepted", [("1e2", True), ("1e999", False), ("-1e999", False)]
)
def test_numeric_exponent_bounds_through_bytes_and_cli(number, accepted):
    raw = json.dumps(deployment())[:-1] + ',"unrelated":' + number + "}"
    if accepted:
        GUARD.check_bytes(raw.encode(), NAMESPACE)
    else:
        with pytest.raises(ValueError, match="^$"):
            GUARD.check_bytes(raw.encode(), NAMESPACE)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--namespace", NAMESPACE],
        input=raw,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == (0 if accepted else 1)
    assert result.stdout == ""
    assert result.stderr.strip() == ("" if accepted else GUARD.REFUSAL)


def extracted_update():
    source = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    matches = re.findall(r"^cmd_update_images\(\) \{\n.*?^\}", source, re.M | re.S)
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("case", ["native", "legacy", "missing", "get-failed"])
def test_actual_bash_guard_precedes_every_image_write(case, tmp_path):
    bash = shutil.which("bash")
    if os.name == "nt":
        bash = "C:/Program Files/Git/bin/bash.exe"
    if not bash or not Path(bash).is_file():
        pytest.skip("Bash is required for the extracted non-deployment control")
    candidate = deployment()
    if case == "legacy":
        worker(candidate)["command"] = ["python"]
    raw = "" if case == "missing" else json.dumps(candidate)
    env = {
        # Absolute Bash/Python only; even a future `command kubectl` bypass
        # cannot reach the operator's installed cluster client.
        "PATH": tmp_path.as_posix(),
        "REPO_ROOT": ROOT.as_posix(),
        "PYTHON_BIN": Path(sys.executable).as_posix(),
        "NAMESPACE": NAMESPACE,
        "IMAGE_TAG": "synthetic-tag",
        "IMAGE_REGISTRY": "synthetic.invalid/owned",
        "FIXTURE_JSON": raw,
        "PRIVATE_DIAGNOSTIC": PRIVATE,
        "GET_EXIT": "1" if case == "get-failed" else "0",
    }
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
    prelude = r"""
set -euo pipefail
step() { :; }
success() { :; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; exit 1; }
catalog_services() { printf '%s\n' gateway canvas-sync-worker issuance; }
command_not_found_handle() { return 91; }
kubectl() {
  case "$1:$2" in
    get:deployment)
      [[ $# == 8 && "$3" == canvas-sync-worker && "$4" == -n && "$5" == "$NAMESPACE" && "$6" == -o && "$7" == json && "$8" == --request-timeout=10s ]] || return 92
      printf '%s\n' "$PRIVATE_DIAGNOSTIC" >&2
      printf '%s' "$FIXTURE_JSON"
      return "$GET_EXIT" ;;
    set:image)
      [[ $# == 6 && "$5" == -n && "$6" == "$NAMESPACE" ]] || return 93
      if [[ "$3" == deployment/canvas-sync-worker ]]; then
        [[ "$4" == "canvas-sync-worker=${IMAGE_REGISTRY}/marty-ui/canvas-sync-worker:${IMAGE_TAG}" ]] || return 95
      fi
      printf 'WRITE:%s\n' "$3" ;;
    rollout:status) printf 'ROLLOUT\n' ;;
    *) return 94 ;;
  esac
}
readonly -f kubectl
"""
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input=prelude + extracted_update() + "\ncmd_update_images\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert PRIVATE not in result.stdout + result.stderr
    if case == "native":
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == [
            "WRITE:deployment/gateway",
            "WRITE:deployment/canvas-sync-worker",
            "WRITE:deployment/issuance",
            "WRITE:deployment/ui",
            "WRITE:deployment/cloudflared",
            "ROLLOUT",
        ]
    else:
        assert result.returncode != 0
        assert result.stdout == ""
        assert "full-manifest cutover first" in result.stderr
