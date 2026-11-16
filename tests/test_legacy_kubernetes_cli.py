"""Exercise legacy operator argument and failure handling without a cluster."""

from __future__ import annotations

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
SCRIPT = ROOT / "scripts/deploy-kubernetes.sh"


def test_legacy_redis_retains_identity_state_without_raising_memory_limit():
    resources = yaml.safe_load_all((ROOT / "k8s/oracle/04-redis-rabbitmq.yaml").read_text())
    redis = next(item for item in resources if item and item.get("kind") == "StatefulSet"
                 and item["metadata"]["name"] == "redis")
    container = redis["spec"]["template"]["spec"]["containers"][0]
    command = container["command"]
    assert command[command.index("--maxmemory-policy") + 1] == "noeviction"
    assert command[command.index("--maxmemory") + 1] == "256mb"
    assert command[command.index("--appendonly") + 1] == "yes"
    assert container["resources"]["limits"]["memory"] == "384Mi"


def bash() -> str:
    value = shutil.which("bash")
    if os.name == "nt":
        value = "C:/Program Files/Git/bin/bash.exe"
    if not value or not Path(value).is_file():
        pytest.skip("Bash is unavailable")
    return value


@pytest.fixture
def cli(tmp_path):
    calls = tmp_path / "kubectl.jsonl"
    executable = tmp_path / "kubectl"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['TEST_KUBECTL_CALLS'], 'a') as out:\n"
        "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1:3] == ['config', 'current-context']:\n"
        "    print('synthetic-context')\n"
        "if sys.argv[1:3] == ['get', os.environ.get('TEST_GET_FAILURE')]:\n"
        "    print('synthetic read refused', file=sys.stderr)\n"
        "    sys.exit(19)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    env = {
        "PATH": str(tmp_path) + os.pathsep + os.environ.get("PATH", ""),
        "ENV_FILE": str(tmp_path / "absent.env"),
        "TEST_KUBECTL_CALLS": str(calls),
    }
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]

    def run(*args, **overrides):
        result = subprocess.run(
            [bash(), "--noprofile", "--norc", str(SCRIPT), *args],
            env={**env, **overrides}, capture_output=True, text=True, timeout=15,
        )
        recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result, recorded

    return run


def test_help_does_not_source_configuration_or_contact_cluster(cli, tmp_path):
    poison = tmp_path / "poison.env"
    poison.write_text("exit 97\n", encoding="utf-8")
    result, calls = cli("--env-file", str(poison), "--help")
    assert result.returncode == 0, result.stderr
    assert "kubernetes-installation-configuration.md" in result.stdout
    assert calls == []


@pytest.mark.parametrize("option", [
    "--tag", "--env-file", "--k8s-dir", "--namespace", "--version-file",
    "--registry", "--registry-host", "--registry-username", "--image-pull-secret",
    "--region", "--oci-namespace", "--registry-namespace",
])
@pytest.mark.parametrize("suffix", [[], ["--help"], [""]])
def test_missing_option_value_refuses_before_configuration_and_cluster(cli, option, suffix):
    result, calls = cli(option, *suffix)
    assert result.returncode != 0
    assert f"{option} requires a value" in result.stdout + result.stderr
    assert "unbound variable" not in result.stderr
    assert calls == []


def test_conflicting_commands_refuse_before_cluster(cli):
    result, calls = cli("status", "deploy")
    assert result.returncode != 0
    assert "exactly one subcommand" in result.stdout
    assert calls == []


def test_status_needs_no_registry_release_or_secret_file(cli):
    result, calls = cli("status", "--namespace", "canyon-audit")
    assert result.returncode == 0, result.stdout + result.stderr
    reads = [args for args in calls if args[0] == "get"]
    assert len(reads) == 4
    assert all(args[2:4] == ["-n", "canyon-audit"] for args in reads)
    assert all(args[0] in {"cluster-info", "config", "get"} for args in calls)


def test_explicit_namespace_wins_over_sourced_file_and_stale_registry(cli, tmp_path):
    config = tmp_path / "operator.env"
    config.write_text(
        "NAMESPACE=wrong-from-file\nIMAGE_REGISTRY=\nOCI_REGION=retired-region\n"
        "OCIR_TENANCY_NAMESPACE=unused\n", encoding="utf-8",
    )
    result, calls = cli("--namespace", "canyon-audit", "--env-file", str(config), "status")
    assert result.returncode == 0, result.stdout + result.stderr
    reads = [args for args in calls if args[0] == "get"]
    assert len(reads) == 4
    assert all(args[2:4] == ["-n", "canyon-audit"] for args in reads)


def test_status_reports_failure_and_still_inspects_remaining_resources(cli):
    result, calls = cli("status", TEST_GET_FAILURE="pods")
    assert result.returncode != 0
    assert "synthetic read refused" in result.stderr
    assert [args[1] for args in calls if args[0] == "get"] == ["pods", "services", "statefulset", "jobs"]


def test_reference_environment_loads_literal_callback_template():
    result = subprocess.run(
        [bash(), "--noprofile", "--norc", "-c",
         'set -euo pipefail; source "$1"; printf "%s" "$FLOW_CALLBACK_DESTINATIONS"',
         "test", str(ROOT / ".env.production.example")],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "00000000-0000-0000-0000-000000000001|"
        "http://auth:8001/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__"
    )


def function(name):
    matches = re.findall(rf"^{name}\(\) \{{\n.*?^\}}", SCRIPT.read_text(), re.M | re.S)
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("failure", ["none", "app-image", "ui-image", "rollout"])
def test_update_does_not_hide_required_image_or_rollout_failure(failure, tmp_path):
    # Preflight and live selection have already passed in this harness. Exercise
    # the actual command's writes and final exit, including pipeline error paths.
    native = tmp_path / "native"
    native.write_text("#!/bin/sh\ncat >/dev/null\n", encoding="utf-8")
    native.chmod(0o755)
    harness = r'''
set -euo pipefail
step() { :; }
info() { :; }
success() { printf '%s\n' "$*"; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; return 1; }
prepare_kubernetes_native_issuance() { :; }
catalog_services() { printf '%s\n' gateway canvas-sync-worker issuance; }
resolve_secret_input() { printf ''; }
is_placeholder_secret() { return 0; }
kubectl() {
  case "$1:$2" in
    get:*) printf '{}';;
    set:image)
      printf 'WRITE:%s\n' "$3"
      [[ "$TEST_FAILURE:$3" != app-image:deployment/canvas-sync-worker && "$TEST_FAILURE:$3" != ui-image:deployment/ui ]] ;;
    rollout:status)
      [[ "$TEST_FAILURE:$3" != rollout:deployment ]] ;;
    *) return 98;;
  esac
}
'''
    env = {
        **os.environ, "TEST_FAILURE": failure, "NAMESPACE": "canyon-audit",
        "REPO_ROOT": str(ROOT), "K8S_DIR": str(ROOT / "k8s/oracle"),
        "K8S_NATIVE_ISSUANCE_BIN": str(native), "PYTHON_BIN": str(native),
        "MARTY_KEYCLOAK_KMS_IMAGE": "synthetic.invalid/keycloak@sha256:" + "b" * 64,
        "MARTY_SERVICES_IMAGE": "synthetic.invalid/services@sha256:" + "a" * 64,
        "IMAGE_REGISTRY": "synthetic.invalid", "IMAGE_TAG": "v1.2.3",
        "K8S_ISSUANCE_NATIVE_ENABLED": "true",
    }
    result = subprocess.run(
        [bash(), "--noprofile", "--norc", "-s"],
        input=harness + function("cmd_update_images") + "\ncmd_update_images\n",
        env=env, capture_output=True, text=True, timeout=15,
    )
    assert (result.returncode == 0) == (failure == "none"), result.stdout + result.stderr
    if failure == "app-image":
        assert "required deployment 'canvas-sync-worker'" in result.stderr
        assert "WRITE:deployment/ui" not in result.stdout
    elif failure == "ui-image":
        assert "required deployment 'ui'" in result.stderr
    elif failure == "rollout":
        assert "rollout did not complete" in result.stderr


@pytest.mark.parametrize("failure", ["none", "auth", "cloudflared", "all"])
def test_full_deploy_never_announces_success_after_failed_rollout(failure, tmp_path):
    harness = r'''
set -euo pipefail
step() { :; }
info() { :; }
success() { printf '%s\n' "$*"; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; return 1; }
prepare_kubernetes_native_issuance() { :; }
require_kubernetes_passport_selection() { :; }
catalog_required_secret_envs() { printf 'SYNTHETIC_SECRET\n'; }
apply_manifest() { :; }
cmd_setup_secrets() { :; }
resolve_secret_input() { printf 'synthetic-connector'; }
is_placeholder_secret() { return 1; }
kubectl() {
  if [[ "$1:$2" == rollout:status ]]; then
    [[ "$TEST_FAILURE:$3" != auth:deployment/auth && "$TEST_FAILURE:$3" != cloudflared:deployment/cloudflared && "$TEST_FAILURE:$3" != all:deployment ]]
  else
    return 0
  fi
}
'''
    result = subprocess.run(
        [bash(), "--noprofile", "--norc", "-s"],
        input=harness + function("cmd_deploy") + "\ncmd_deploy\n",
        env={**os.environ, "TEST_FAILURE": failure, "K8S_STACK_NAME": "kubernetes-production",
             "K8S_DIR": str(tmp_path), "REPO_ROOT": str(tmp_path), "NAMESPACE": "canyon-audit",
             "K8S_ISSUANCE_NATIVE_ENABLED": "true", "UI_BASE_URL": "https://canyon.example.org",
             "PUBLIC_API_URL": "https://canyon.example.org", "OIDC_ISSUER_URL_EXTERNAL": "https://canyon.example.org/realms/11id"},
        capture_output=True, text=True, timeout=15,
    )
    assert (result.returncode == 0) == (failure == "none"), result.stdout + result.stderr
    assert ("Deploy complete!" in result.stdout) == (failure == "none")
