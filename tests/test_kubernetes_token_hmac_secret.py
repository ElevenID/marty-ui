"""Actual secret helpers with synthetic inputs and closed kubectl doubles."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-existing-shared-token-$literal;not-a-command"
FUNCTIONS = (
    "catalog_required_secret_envs",
    "is_placeholder_secret",
    "resolve_secret_input",
    "require_resolved_secret",
    "require_catalog_required_secrets",
    "create_image_pull_secret",
    "cmd_setup_secrets",
)


def extracted_functions():
    source = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    result = []
    for name in FUNCTIONS:
        matches = re.findall(rf"^{name}\(\) \{{\n.*?^\}}", source, re.M | re.S)
        assert len(matches) == 1, "Expected one actual deploy helper definition"
        result.append(matches[0])
    return "\n".join(result)


def token_catalog():
    return json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text())[
        "secrets"
    ]


def test_shared_token_catalog_and_template_are_required_not_generated():
    entry = token_catalog()["token_hmac_key"]
    assert entry == {
        "env": "TOKEN_HMAC_KEY",
        "file_env": "TOKEN_HMAC_KEY_FILE",
        "compose_secret": "token_hmac_key",
        "required_for": ["selfhost-production", "kubernetes-production"],
        "no_log": True,
        "placeholder_disallowed": True,
    }
    documents = yaml.safe_load_all(
        (ROOT / "k8s/oracle/02-secrets-template.yaml").read_text(encoding="utf-8")
    )
    secret = next(
        item for item in documents if item["metadata"]["name"] == "marty-secrets"
    )
    assert secret["stringData"]["TOKEN_HMAC_KEY"].startswith("CHANGE_ME")
    assert "TOKEN_HMAC_KEY" not in secret.get("data", {})


@pytest.fixture
def harness(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git, "Git Bash is required for the shell contract"
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash and Path(bash).is_file()
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    operator_root = tmp_path / "operator"
    operator_scripts = operator_root / "scripts"
    operator_scripts.mkdir(parents=True)
    catalog_double = operator_scripts / "marty-deploy.sh"
    catalog_double.write_bytes(
        b'#!/bin/sh\n'
        b'[ "$1" = secrets ] && [ "$3" = --field ] && [ "$4" = env ] || exit 96\n'
        b'[ "${TEST_CATALOG_FAIL:-}" != 1 ] || exit 97\n'
        b'[ "${TEST_CATALOG_EMPTY:-}" != 1 ] || exit 0\n'
        b'printf "%s\\n" "$TEST_REQUIRED_SECRET_ENVS"\n'
    )
    catalog_double.chmod(0o755)
    env = {
        "PATH": empty_path.as_posix(),
        "PYTHON_BIN": "catalog_python",
        "TEST_PYTHON": sys.executable.replace("\\", "/"),
        "REPO_ROOT": operator_root.as_posix(),
        "TEST_ROOT": tmp_path.as_posix(),
        "NAMESPACE": "synthetic-owned-namespace",
        "K8S_STACK_NAME": "kubernetes-production",
        "REGISTRY_AUTH_TOKEN": "synthetic-registry-token",
        "REGISTRY_USERNAME": "synthetic-registry-user",
        "REGISTRY_HOST": "registry.example.invalid",
        "IMAGE_PULL_SECRET_NAME": "synthetic-pull-secret",
        "FLOW_WEBHOOK_SECRET": "synthetic-flow-webhook-at-least-thirty-two-bytes",
        "SIGNING_KEYS_WORKLOAD_SERVER_CERT": "synthetic-signing-keys-server-certificate",
        "SIGNING_KEYS_WORKLOAD_SERVER_KEY": "synthetic-signing-keys-server-private-key",
        "PYTHONPATH": str(ROOT / "packages"),
        "TEST_REQUIRED_SECRET_ENVS": "\n".join(
            entry["env"] for entry in token_catalog().values()
            if "kubernetes-production" in entry.get("required_for", [])
        ),
    }
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
    for entry in token_catalog().values():
        if "kubernetes-production" in entry.get("required_for", []):
            env.setdefault(
                entry["env"], "synthetic-required-value-at-least-thirty-two-bytes"
            )
    env["DEVICE_REGISTRATION_GATEWAY_KEY"] = (
        "synthetic-distinct-device-gateway-key-at-least-thirty-two-bytes"
    )
    env["DEVICE_REGISTRATION_SIGNING_KEYS_KEY"] = (
        "synthetic-distinct-device-signing-key-at-least-thirty-two-bytes"
    )
    env["ISSUANCE_API_KEY"] = "synthetic-distinct-issuance-api-key-at-least-thirty-two-bytes"
    env["SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY"] = (
        "synthetic-distinct-service-sign-gateway-key-at-least-thirty-two-bytes"
    )
    env["SIGNING_KEYS_ISSUER_SIGN_KEY"] = (
        "synthetic-distinct-issuer-sign-key-at-least-thirty-two-bytes"
    )
    env["OPENBAO_BOOTSTRAP_TOKEN"] = (
        "synthetic-distinct-migration-bootstrap-token-at-least-thirty-two-bytes"
    )
    for role in (
        "FLOW_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN",
        "GATEWAY_SIGN_GRANT_MINT_TOKEN",
        "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN",
        "SIGNING_KEYS_GRANT_VERIFY_TOKEN",
    ):
        env[role] = f"synthetic-distinct-{role.lower()}-credential"
    env.pop("TOKEN_HMAC_KEY")
    prelude = r"""
set -euo pipefail
step() { :; }
success() { :; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; exit 1; }
tr() {
  /usr/bin/tr "$@"
  if [[ -n "${TEST_FILE_NEXT+x}" ]]; then
    # The actual resolver has consumed its redirected file. Mutate only the
    # test-owned token file before its next read, without replacing validation.
    local read_count=0
    if [[ -f "$TEST_ROOT/token-file-reads" ]]; then
      read -r read_count < "$TEST_ROOT/token-file-reads"
    fi
    read_count=$((read_count + 1))
    printf '%s\n' "$read_count" > "$TEST_ROOT/token-file-reads"
    if [[ "$read_count" == 1 ]]; then
      printf '%s\n' "$TEST_FILE_NEXT" > "$TEST_ROOT/synthetic-token.txt"
    fi
  fi
}
# The test-owned script models the Rust CLI output and failure status.
command_not_found_handle() { printf 'Unexpected external command\n' >&2; return 91; }
kubectl() {
  case "$1:$2:${3:-}" in
    create:namespace:synthetic-owned-namespace) ;;
    create:secret:docker-registry)
      [[ "$4" == synthetic-pull-secret ]] || return 92 ;;
    create:secret:generic)
      case "$4" in
        marty-secrets|signing-keys-integration-secret-server-tls|signing-keys-integration-secret-ca|presentation-policy-workload-tls|flow-workload-tls|flow-server-workload-tls|auth-workload-tls|applicant-workload-tls|verification-workload-tls|deployment-profile-workload-tls|compliance-profile-workload-tls) ;;
        *) return 93 ;;
      esac ;;
    apply:-f:-) [[ $# == 3 ]] || return 94 ;;
    *) return 95 ;;
  esac
  printf '%s\0' "$@" > "$TEST_ROOT/call-$BASHPID"
  if [[ "$1" == apply ]]; then
    while IFS= read -r line; do [[ "$line" == synthetic-manifest ]] || return 96; done
  else
    printf 'synthetic-manifest\n'
  fi
}
readonly -f kubectl
"""

    def run(changes=None, *, operation="setup", file_bytes=None, next_file_value=None):
        selected = dict(env)
        if file_bytes is not None:
            path = tmp_path / "synthetic-token.txt"
            path.write_bytes(file_bytes)
            selected["TOKEN_HMAC_KEY_FILE"] = path.as_posix()
        if next_file_value is not None:
            assert file_bytes is not None
            selected["TEST_FILE_NEXT"] = next_file_value
        selected.update(changes or {})
        suffix = {
            "setup": "cmd_setup_secrets",
            "resolve": 'value="$(resolve_secret_input TOKEN_HMAC_KEY)"\nrequire_resolved_secret TOKEN_HMAC_KEY "$value"\nprintf "%s" "$value"',
        }[operation]
        result = subprocess.run(
            [bash, "--noprofile", "--norc", "-s"],
            input=prelude + extracted_functions() + "\n" + suffix + "\n",
            text=True,
            capture_output=True,
            cwd=tmp_path,
            env=selected,
            timeout=20,
            check=False,
        )
        calls = [
            path.read_bytes().decode().rstrip("\0").split("\0")
            for path in tmp_path.glob("call-*")
        ]
        return result, calls

    return run


def applications(calls):
    return [
        call
        for call in calls
        if call[:4] == ["create", "secret", "generic", "marty-secrets"]
    ]


@pytest.mark.parametrize(
    "first,second",
    [
        ("FLOW_SIGN_GRANT_MINT_TOKEN", "GATEWAY_SIGN_GRANT_MINT_TOKEN"),
        ("GATEWAY_SIGN_GRANT_MINT_TOKEN", "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN"),
        ("GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN", "SIGNING_KEYS_GRANT_VERIFY_TOKEN"),
        ("FLOW_SIGN_GRANT_MINT_TOKEN", "SIGNING_KEYS_GRANT_VERIFY_TOKEN"),
        ("ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN", "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN"),
        ("ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN", "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN"),
        ("ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN", "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN"),
        ("ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN", "SIGNING_KEYS_GRANT_VERIFY_TOKEN"),
        ("ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN", "OPENBAO_SERVICE_TOKEN"),
        ("ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN", "OPENBAO_BOOTSTRAP_TOKEN"),
        ("GATEWAY_SIGN_GRANT_MINT_TOKEN", "SIGNING_KEYS_GRANT_VERIFY_TOKEN"),
        ("FLOW_SIGN_GRANT_MINT_TOKEN", "OPENBAO_SERVICE_TOKEN"),
        ("GATEWAY_SIGN_GRANT_MINT_TOKEN", "SIGNING_KEYS_OPENBAO_TOKEN"),
        ("SIGNING_KEYS_GRANT_VERIFY_TOKEN", "DIDCOMM_ISSUANCE_OPENBAO_TOKEN"),
    ],
)
def test_signing_grant_roles_reject_shared_openbao_credentials(harness, first, second):
    shared = f"synthetic-shared-{first.lower()}-credential"
    result, calls = harness({"TOKEN_HMAC_KEY": TOKEN, first: shared, second: shared})
    assert result.returncode != 0
    assert "must be distinct" in result.stderr or "must differ" in result.stderr
    assert not applications(calls)


def test_migration_bootstrap_token_cannot_reuse_runtime_openbao_token(harness):
    shared = "synthetic-shared-runtime-and-migration-openbao-token"
    result, calls = harness({
        "TOKEN_HMAC_KEY": TOKEN,
        "OPENBAO_SERVICE_TOKEN": shared,
        "OPENBAO_BOOTSTRAP_TOKEN": shared,
    })
    assert result.returncode != 0
    assert "must differ from the runtime OpenBao token" in result.stderr
    assert not applications(calls)


@pytest.mark.parametrize("source", ["environment", "file", "empty-env-with-file"])
def test_setup_publishes_same_existing_token_once_without_echo(harness, source):
    if source == "environment":
        result, calls = harness({"TOKEN_HMAC_KEY": TOKEN})
    else:
        result, calls = harness(
            {"TOKEN_HMAC_KEY": ""} if source == "empty-env-with-file" else {},
            file_bytes=(TOKEN + "\r\n").encode(),
        )
    assert result.returncode == 0, result.stderr
    assert TOKEN not in result.stdout + result.stderr
    records = applications(calls)
    assert len(records) == 1
    token_fields = [
        arg for arg in records[0] if arg.startswith("--from-literal=TOKEN_HMAC_KEY=")
    ]
    assert token_fields == ["--from-literal=TOKEN_HMAC_KEY=" + TOKEN]
    assert len([call for call in calls if call[:2] == ["create", "namespace"]]) == 1
    assert (
        len(
            [
                call
                for call in calls
                if call[:3] == ["create", "secret", "docker-registry"]
            ]
        )
        == 1
    )
    assert (
        len([call for call in calls if call[:3] == ["create", "secret", "generic"]])
        == 11
    )


@pytest.mark.parametrize("source", ["environment", "file"])
def test_actual_resolver_preserves_literal_key_and_file_line_endings(harness, source):
    arguments = {"operation": "resolve"}
    if source == "file":
        arguments["file_bytes"] = (TOKEN + "\r\n").encode()
        changes = {}
    else:
        changes = {"TOKEN_HMAC_KEY": TOKEN}
    result, calls = harness(changes, **arguments)
    assert result.returncode == 0
    assert result.stdout == TOKEN
    assert result.stderr == ""
    assert calls == []


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "change-me-existing",
        "CHANGE_ME_existing",
        "replace-me-existing",
        "REPLACE_ME_existing",
    ],
)
@pytest.mark.parametrize("source", ["environment", "file"])
def test_missing_or_placeholder_prevents_application_secret_not_prior_setup(
    harness, value, source
):
    if source == "file" and value is not None:
        result, calls = harness(file_bytes=(value + "\r\n").encode())
    else:
        result, calls = harness({} if value is None else {"TOKEN_HMAC_KEY": value})
    assert result.returncode != 0
    assert "TOKEN_HMAC_KEY must be set to a non-placeholder value" in result.stderr
    assert not applications(calls)
    assert any(call[:2] == ["create", "namespace"] for call in calls)
    assert any(call[:3] == ["create", "secret", "docker-registry"] for call in calls)
    if value:
        assert value not in result.stdout + result.stderr


@pytest.mark.parametrize("operation", ["resolve", "setup"])
def test_conflicting_environment_and_file_fail_without_value_disclosure(
    harness, operation
):
    result, calls = harness(
        {"TOKEN_HMAC_KEY": TOKEN},
        operation=operation,
        file_bytes=b"synthetic-other-key",
    )
    assert result.returncode != 0
    assert "Both TOKEN_HMAC_KEY and TOKEN_HMAC_KEY_FILE are set" in result.stderr
    assert TOKEN not in result.stdout + result.stderr
    assert "synthetic-other-key" not in result.stdout + result.stderr
    assert not applications(calls)


@pytest.mark.parametrize("operation", ["resolve", "setup"])
def test_nonexistent_owned_file_cannot_fall_back_to_a_generated_key(harness, operation):
    result, calls = harness(
        {"TOKEN_HMAC_KEY_FILE": "nonexistent-synthetic-token-file"}, operation=operation
    )
    assert result.returncode != 0
    assert "TOKEN_HMAC_KEY_FILE is not readable" in result.stderr
    assert not applications(calls)


def test_captured_placeholder_rejected_even_when_later_file_becomes_valid(
    harness, tmp_path
):
    placeholder = "CHANGE_ME_synthetic-captured-token"
    result, calls = harness(
        file_bytes=(placeholder + "\n").encode(), next_file_value=TOKEN
    )
    assert result.returncode != 0
    assert "TOKEN_HMAC_KEY must be set to a non-placeholder value" in result.stderr
    assert not applications(calls)
    assert (tmp_path / "token-file-reads").read_text().strip() == "1"
    assert (tmp_path / "synthetic-token.txt").read_text().strip() == TOKEN
    assert placeholder not in result.stdout + result.stderr
    assert TOKEN not in result.stdout + result.stderr


def test_second_valid_file_read_cannot_replace_validated_captured_key(
    harness, tmp_path
):
    later = "synthetic-different-key-after-first-read"
    result, calls = harness(file_bytes=(TOKEN + "\n").encode(), next_file_value=later)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "token-file-reads").read_text().strip() == "2"
    assert (tmp_path / "synthetic-token.txt").read_text().strip() == later
    records = applications(calls)
    assert len(records) == 1
    fields = [
        arg for arg in records[0] if arg.startswith("--from-literal=TOKEN_HMAC_KEY=")
    ]
    assert fields == ["--from-literal=TOKEN_HMAC_KEY=" + TOKEN]
    # Both real manifests select the one captured entry, not independent values.
    documents = yaml.safe_load_all(
        (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
    )
    selected = {}
    for document in documents:
        if not document or document.get("kind") != "Deployment":
            continue
        name = document["metadata"]["name"]
        if name in ("issuance", "canvas-sync-worker"):
            container = document["spec"]["template"]["spec"]["containers"][0]
            entries = [
                item for item in container["env"] if item["name"] == "TOKEN_HMAC_KEY"
            ]
            assert len(entries) == 1
            assert entries[0]["valueFrom"]["secretKeyRef"] == {
                "name": "marty-secrets",
                "key": "TOKEN_HMAC_KEY",
            }
            selected[name] = fields[0].split("=", 2)[2]
    assert selected == {"issuance": TOKEN, "canvas-sync-worker": TOKEN}
    assert TOKEN not in result.stdout + result.stderr
    assert later not in result.stdout + result.stderr


@pytest.mark.parametrize("failure", ["exit", "empty"])
def test_catalog_failure_blocks_every_secret_mutation(harness, failure):
    flag = "TEST_CATALOG_FAIL" if failure == "exit" else "TEST_CATALOG_EMPTY"
    result, calls = harness({flag: "1"}, file_bytes=(TOKEN + "\n").encode())
    assert result.returncode != 0
    assert "Deployment catalog" in result.stderr
    assert calls == []


def test_setup_secrets_dispatch_rejects_catalog_failure_before_kubectl_write(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash
    source_sha = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True,
    ).strip()
    binary = tmp_path / "marty-deploy"
    binary.write_bytes(
        ("#!/bin/sh\n"
         "if [ \"$1\" = --build-identity ]; then\n"
         f"  printf '%s\\n' '{source_sha}:v1.1.246'\n"
         "elif [ \"$3\" = validate ]; then\n"
         "  printf 'catalog valid\\n'\n"
         "else\n"
         "  exit 97\n"
         "fi\n").encode()
    )
    binary.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl = bin_dir / "kubectl"
    kubectl.write_bytes(
        b'#!/bin/sh\n'
        b'case "$1" in\n'
        b'  cluster-info) exit 0 ;;\n'
        b'  config) printf "synthetic-context\\n" ;;\n'
        b'  *) printf "WRITE:%s\\n" "$1" >> "$KUBECTL_WRITES"; exit 98 ;;\n'
        b'esac\n'
    )
    kubectl.chmod(0o755)
    env_file = tmp_path / "operator.env"
    env_file.write_bytes(b"IMAGE_REGISTRY=synthetic.invalid/owned\n")
    writes = tmp_path / "writes.log"
    result = subprocess.run(
        [bash, str(ROOT / "scripts/deploy-kubernetes.sh"), "setup-secrets",
         "--env-file", str(env_file)],
        env={**os.environ,
             "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
             "MARTY_DEPLOY_BIN": str(binary),
             "MARTY_DEPLOY_BIN_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
             "MARTY_DEPLOY_SOURCE_SHA": source_sha,
             "MARTY_DEPLOY_RELEASE_TAG": "v1.1.246",
             "KUBECTL_WRITES": str(writes)},
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "Deployment catalog secret lookup failed" in result.stderr + result.stdout
    assert not writes.exists()


@pytest.mark.parametrize("failure", ["exit", "empty"])
def test_full_deploy_rejects_catalog_failure_before_first_manifest(tmp_path, failure):
    if os.name == "nt":
        git = shutil.which("git")
        assert git
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash
    source = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    function = re.findall(r"^cmd_deploy\(\) \{\n.*?^\}", source, re.M | re.S)
    assert len(function) == 1
    failure_script = "return 97" if failure == "exit" else "return 0"
    harness = (
        "set -euo pipefail\n"
        "K8S_STACK_NAME=kubernetes-production\n"
        "K8S_DIR=/synthetic/manifests\n"
        "prepare_kubernetes_native_issuance() { :; }\n"
        "require_kubernetes_passport_selection() { :; }\n"
        f"catalog_required_secret_envs() {{ {failure_script}; }}\n"
        "apply_manifest() { printf 'APPLY:%s\\n' \"$1\"; }\n"
        "cmd_setup_secrets() { printf 'SECRET-WRITE\\n'; }\n"
        "error() { printf '%s\\n' \"$*\" >&2; return 1; }\n"
        + function[0] + "\ncmd_deploy\n"
    )
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"], input=harness,
        text=True, encoding="utf-8", capture_output=True, cwd=tmp_path, timeout=30,
    )
    assert result.returncode != 0
    assert "Deployment catalog" in result.stderr
    assert "APPLY:" not in result.stdout
    assert "SECRET-WRITE" not in result.stdout
