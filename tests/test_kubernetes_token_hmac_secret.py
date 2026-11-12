"""Actual secret helpers with synthetic inputs and closed kubectl doubles."""

from __future__ import annotations

import json
import hashlib
import base64
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-existing-shared-token-$literal;not-a-command"
METADATA_COMMANDS = ("kubernetes-secrets-contract", "kubernetes-application-token-contract",
                     "kubernetes-application-activation-contract", "kubernetes-renewal-contract",
                     "kubernetes-renewal-activation-contract")
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


@pytest.fixture(scope="module")
def native_tools(tmp_path_factory):
    directory = tmp_path_factory.mktemp("native-kubernetes")
    subprocess.run(["cargo", "+1.95.0", "build", "--locked", "--manifest-path",
                    str(ROOT / "rust/Cargo.toml"), "-p", "marty-deployment-catalog",
                    "--bin", "marty-deploy"], cwd=ROOT, check=True, capture_output=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "rust/target"))
    binary = (target / "debug" / ("marty-deploy.exe" if os.name == "nt" else "marty-deploy")).resolve()
    # A closed executable double: no Docker, cluster, shell interpretation or network.
    source = directory / "kubectl.rs"
    source.write_text(r'''use std::{env,fs::{self,OpenOptions},io::{self,Read,Write}};
fn main() {
    assert_eq!(env::args().skip(1).collect::<Vec<_>>(), ["apply","-f","-"]);
    let mut bytes=Vec::new(); io::stdin().read_to_end(&mut bytes).unwrap();
    let root=std::path::PathBuf::from(env::var("TEST_ROOT").unwrap());
    let mut file=OpenOptions::new().create(true).append(true).open(root.join("native-manifest.json")).unwrap(); file.write_all(&bytes).unwrap(); file.write_all(b"\n").unwrap(); drop(file);
    if let Ok(value)=env::var("TEST_FILE_NEXT") { fs::write(root.join("synthetic-token.txt"),value).unwrap(); }
    if let Ok(binary)=env::var("TEST_REAL_KUBECTL") {
        use std::process::{Command,Stdio};
        let mut child=Command::new(binary).args(["apply","--validate=false","--request-timeout=3s","--server",&env::var("TEST_API_SERVER").unwrap(),"--kubeconfig",&env::var("TEST_KUBECONFIG").unwrap(),"--cache-dir",&root.join("kube-cache").to_string_lossy(),"-f","-"]).stdin(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        std::process::exit(child.wait().unwrap().code().unwrap_or(1));
    }
    let fail_name=env::var("TEST_APPLY_FAIL_NAME").ok();
    if env::var("TEST_APPLY_FAIL").is_ok() || fail_name.is_some_and(|name| String::from_utf8_lossy(&bytes).contains(&format!("\"name\":\"{name}\""))) {
        eprintln!("synthetic-sensitive-diagnostic"); std::process::exit(1);
    }
}''', encoding="utf-8")
    kubectl = directory / ("kubectl.exe" if os.name == "nt" else "kubectl")
    subprocess.run(["rustc", "+1.95.0", str(source), "-o", str(kubectl)], check=True, capture_output=True)
    return binary, kubectl


@pytest.mark.parametrize("command", METADATA_COMMANDS)
def test_native_publication_contract_is_compiled_and_needs_no_inputs_repo_or_cluster(
    native_tools, tmp_path, command,
):
    misleading = tmp_path / "deploy-config/catalog"
    misleading.mkdir(parents=True)
    (misleading / "kubernetes-secrets.json").write_text('{"required":[],"secrets":[]}')
    (misleading / "kubernetes-application-tokens.json").write_text('{"tokens":[]}')
    environment = {
        "PATH": str(native_tools[1].parent), "TEST_ROOT": str(tmp_path),
        "MARTY_REPO_ROOT": str(tmp_path), "KUBECONFIG": str(tmp_path / "absent-kubeconfig"),
        # Any attempt to resolve credentials would fail on this deliberately
        # conflicting source; metadata must not inspect either source.
        "POSTGRES_PASSWORD": "PRIVATE_METADATA_CREDENTIAL_CANARY",
        "POSTGRES_PASSWORD_FILE": str(tmp_path / "absent-private-input"),
        "SIGNING_KEYS_OPENBAO_TOKEN": "PRIVATE_APPLICATION_CREDENTIAL_CANARY",
        "SIGNING_KEYS_OPENBAO_TOKEN_FILE": str(tmp_path / "absent-application-input"),
    }
    if os.name == "nt":
        environment["SystemRoot"] = os.environ["SystemRoot"]
    result = subprocess.run(
        [str(native_tools[0]), command], cwd=tmp_path,
        env=environment, input="PRIVATE_STDIN_CANARY", capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    expected = (
        {"schema": "marty.kubernetes-secret-publication/v1",
         "catalog": json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())}
        if command == "kubernetes-secrets-contract"
        else json.loads((ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())
    )
    if command == "kubernetes-application-activation-contract":
        application = json.loads((ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())
        expected = {
            "schema": "marty.kubernetes-application-activation/v1",
            "destination": "marty-secrets",
            "activationAnnotation": "marty.elevenid.com/application-activation",
            "minimumTtlSeconds": 1800,
            "inputs": sorted(({"input": entry["input"], "file": entry["file"], "key": entry["input"]}
                              for entry in application["tokens"] if entry["replacementRole"] is not None),
                             key=lambda entry: entry["input"]),
        }
    if command in {"kubernetes-renewal-contract", "kubernetes-renewal-activation-contract"}:
        sys.path.insert(0, str(ROOT / "scripts"))
        from passport_remote_tls import SELFHOST_TLS_FILES
        keycloak_files = {"keycloak_signing_kms_token"}
        for realm in ("master", "11id"):
            keycloak_files.add(f"keycloak_{realm}_rs256_cert")
            keycloak_files.update(f"keycloak_{realm}_{purpose}_token" for purpose in ("cookie", "ciba"))
        expected = {
            "schema": "marty.kubernetes-renewal/v1",
            "enrollmentOperation": "kubernetes-renewal-enroll",
            "stagingOperation": "kubernetes-renewal-stage",
            "bindingSchema": "marty.kubernetes-renewal-binding/v1",
            "identityFiles": ["renewal-leaf-policies.json", "renewal-role-id", "renewal-secret-id"],
            "minimumTtlSeconds": 3600, "operationBudgetSeconds": 900,
            "renewableFiles": sorted(set(SELFHOST_TLS_FILES) | keycloak_files),
            "unchangedFiles": ["workload_identity_ca_cert"], "changedFiles": 39,
            "scopedLeafTokens": 21, "tlsMetadataFile": "selfhost-tls-kms-roles.json",
        }
        if command == "kubernetes-renewal-activation-contract":
            catalog = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())
            files = (set(SELFHOST_TLS_FILES) | keycloak_files) - {"workload_identity_ca_cert"}
            mappings = [
                {"input": file.upper(), "file": file, "secret": secret["name"], "key": key}
                for file in files for secret in catalog["secrets"]
                for key, field in secret["fields"].items() if field == {"env": file.upper()}
            ]
            assert len(mappings) == 39
            assert len({entry["secret"] for entry in mappings}) == 33
            expected = {
                "schema": "marty.kubernetes-renewal-activation/v1",
                "minimumTtlSeconds": 3600, "secretCount": 33, "changedFiles": 39,
                "activationAnnotation": "marty.elevenid.com/renewal-activation",
                "inputs": sorted(mappings, key=lambda entry: entry["input"]),
            }
    assert json.loads(result.stdout) == expected
    assert "PRIVATE_" not in result.stdout
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.mark.parametrize("arguments", [
    ["unexpected"], ["--repo-root", "/invalid"], ["--help", "unexpected"],
])
@pytest.mark.parametrize("command", METADATA_COMMANDS)
def test_native_publication_contract_rejects_extra_parameters_without_catalog_or_cluster(
    native_tools, tmp_path, arguments, command,
):
    environment = {"PATH": str(native_tools[1].parent), "TEST_ROOT": str(tmp_path),
                   "MARTY_REPO_ROOT": str(tmp_path / "absent-repo")}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ["SystemRoot"]
    result = subprocess.run(
        [str(native_tools[0]), command, *arguments],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert f"usage: marty-deploy {command}" in result.stderr
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.mark.parametrize("prefix", [["--repo-root", "/invalid"], ["--repo-root=/invalid"]])
@pytest.mark.parametrize("suffix", [[], ["--help"]])
@pytest.mark.parametrize("command", METADATA_COMMANDS)
def test_native_publication_contract_rejects_repository_prefix_before_help_or_catalog(
    native_tools, tmp_path, prefix, suffix, command,
):
    environment = {"PATH": str(native_tools[1].parent), "TEST_ROOT": str(tmp_path),
                   "MARTY_REPO_ROOT": str(tmp_path / "absent-repo")}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ["SystemRoot"]
    result = subprocess.run(
        [str(native_tools[0]), *prefix, command, *suffix],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert f"usage: marty-deploy {command}" in result.stderr
    assert "/invalid" not in result.stderr
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.fixture
def application_publication(tmp_path):
    if os.name != "posix":
        pytest.skip("Private application activation uses POSIX operator custody")
    sys.path.insert(0, str(ROOT / "scripts"))
    import bootstrap_kubernetes_openbao as bootstrap

    tmp_path.chmod(0o700)
    current, candidate = tmp_path / "current", tmp_path / "candidate"
    current.mkdir(mode=0o700)
    candidate.mkdir(mode=0o700)
    application = json.loads((ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())
    replacements = {entry["file"]: entry["input"] for entry in application["tokens"]
                    if entry["replacementRole"] is not None}
    names = set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES | set(bootstrap.TOKEN_FILES.values())
    before, after = {}, {}
    for name in names:
        before[name] = ("PRIVATE_CURRENT_CANARY_" + name).encode()
        after[name] = (("PRIVATE_CANDIDATE_CANARY_" + name).encode()
                       if name in replacements else before[name])
        for directory, payload in ((current, before[name]), (candidate, after[name])):
            (directory / name).write_bytes(payload)
            (directory / name).chmod(0o600)
    secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
              "metadata": {"name": "marty-secrets", "namespace": "marty-test",
                           "uid": "69c5c551-e49f-43c7-a4d5-83d0e385b225", "resourceVersion": "41",
                           "annotations": {"example.test/preserve": "original"}},
              "data": {key: base64.b64encode(before[name]).decode()
                       for name, key in replacements.items()}}
    secret["data"]["TOKEN_HMAC_KEY"] = base64.b64encode(b"PRIVATE_PRESERVED_HMAC_CANARY").decode()
    source = tmp_path / "before.json"
    source.write_text(json.dumps(secret))
    source.chmod(0o600)
    request = {"operation": "prepare", "namespace": "marty-test", "current": str(current),
               "candidate": str(candidate), "observed": str(source), "output": str(tmp_path / "patch.json"),
               "activationId": "0123456789abcdef0123456789abcdef"}
    return request, secret, before, after, replacements


def native_application_publication(native_tools, tmp_path, request):
    return subprocess.run(
        [str(native_tools[0]), "operator", "kubernetes-application-publication"],
        input=json.dumps(request), text=True, capture_output=True, timeout=20,
        cwd=tmp_path, env={"PATH": str(native_tools[1].parent), "TEST_ROOT": str(tmp_path)},
    )


def test_native_application_patch_and_observation_keep_payloads_private(
    native_tools, tmp_path, application_publication,
):
    request, secret, before, after, replacements = application_publication
    result = native_application_publication(native_tools, tmp_path, request)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"ready": True, "secret": "marty-secrets", "count": 11}
    assert "PRIVATE_" not in result.stdout + result.stderr
    patch_path = Path(request["output"])
    assert patch_path.stat().st_mode & 0o7777 == 0o600
    patch = json.loads(patch_path.read_text())
    assert patch[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": secret["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "41"},
    ]
    assert len(patch) == 14
    applied = json.loads(json.dumps(secret))
    for name, key in replacements.items():
        applied["data"][key] = base64.b64encode(after[name]).decode()
    applied["metadata"]["resourceVersion"] = "42"
    applied["metadata"]["annotations"]["marty.elevenid.com/application-activation"] = request["activationId"]
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(applied))
    result_path.chmod(0o600)
    verify = {key: value for key, value in request.items() if key != "output"}
    verify.update(operation="verify", result=str(result_path))
    result = native_application_publication(native_tools, tmp_path, verify)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "candidate"
    assert "PRIVATE_" not in result.stdout + result.stderr
    for path, expected in ((Path(request["current"]), before), (Path(request["candidate"]), after)):
        assert {file.name: file.read_bytes() for file in path.iterdir()} == expected
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.mark.parametrize("drift", ["uid", "version", "preserved-key", "marker"])
def test_native_application_outcome_refuses_conflicting_or_foreign_writers(
    native_tools, tmp_path, application_publication, drift,
):
    request, secret, _, after, replacements = application_publication
    observed = json.loads(json.dumps(secret))
    for name, key in replacements.items():
        observed["data"][key] = base64.b64encode(after[name]).decode()
    observed["metadata"]["resourceVersion"] = "42"
    observed["metadata"]["annotations"]["marty.elevenid.com/application-activation"] = request["activationId"]
    if drift == "uid":
        observed["metadata"]["uid"] = "2949fcec-a21a-41d1-a774-e833c93c1f57"
    elif drift == "version":
        observed["metadata"]["resourceVersion"] = "41"
    elif drift == "preserved-key":
        observed["data"]["TOKEN_HMAC_KEY"] = base64.b64encode(b"PRIVATE_FOREIGN_WRITER_CANARY").decode()
    else:
        observed["metadata"]["annotations"]["marty.elevenid.com/application-activation"] = "a" * 32
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(observed))
    result_path.chmod(0o600)
    verify = {key: value for key, value in request.items() if key != "output"}
    verify.update(operation="verify", result=str(result_path))
    result = native_application_publication(native_tools, tmp_path, verify)
    assert result.returncode != 0
    assert "PRIVATE_" not in result.stdout + result.stderr
    assert not (tmp_path / "native-manifest.json").exists()


def test_native_application_patch_refuses_incomplete_generation_before_output(
    native_tools, tmp_path, application_publication,
):
    request, _, _, _, _ = application_publication
    (Path(request["candidate"]) / "keycloak_signing_kms_token").unlink()
    result = native_application_publication(native_tools, tmp_path, request)
    assert result.returncode != 0
    assert "PRIVATE_" not in result.stdout + result.stderr
    assert not Path(request["output"]).exists()
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.fixture
def renewal_publication(tmp_path):
    if os.name != "posix":
        pytest.skip("Private Renewal activation uses POSIX operator custody")
    sys.path.insert(0, str(ROOT / "scripts"))
    import bootstrap_kubernetes_openbao as bootstrap

    tmp_path.chmod(0o700)
    current, candidate = tmp_path / "current", tmp_path / "candidate"
    current.mkdir(mode=0o700)
    candidate.mkdir(mode=0o700)
    changed = (set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES) - {"workload_identity_ca_cert"}
    names = changed | set(bootstrap.TOKEN_FILES.values()) | {"workload_identity_ca_cert", "openbao_tls_ca_cert"}
    before, after = {}, {}
    for name in names:
        before[name] = ("PRIVATE_CURRENT_CANARY_" + name).encode()
        after[name] = ("PRIVATE_CANDIDATE_CANARY_" + name).encode() if name in changed else before[name]
        if name.endswith("cert"):
            before[name] = b"-----BEGIN CERTIFICATE-----\r\n" + before[name] + b"\r\n-----END CERTIFICATE-----\r\n"
            after[name] = b"-----BEGIN CERTIFICATE-----\r\n" + after[name] + b"\r\n-----END CERTIFICATE-----\r\n"
        for directory, payload in ((current, before[name]), (candidate, after[name])):
            (directory / name).write_bytes(payload)
            (directory / name).chmod(0o600)
    catalog = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())

    def build(name):
        entry = next(entry for entry in catalog["secrets"] if entry["name"] == name)
        fields = {key: field["env"].lower() for key, field in entry["fields"].items()}
        selected = {key: file for key, file in fields.items() if file in changed}
        secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": name, "namespace": "marty-test", "uid": "existing-secret-uid",
                               "resourceVersion": "41", "annotations": {"example.test/preserve": "original"}},
                  "data": {key: base64.b64encode(before[file].replace(b"\r", b"").rstrip(b"\n")).decode()
                           for key, file in fields.items()}}
        secret["data"]["unrelated"] = base64.b64encode(b"PRIVATE_PRESERVED_CANARY").decode()
        observed = tmp_path / "before.json"
        observed.write_text(json.dumps(secret))
        observed.chmod(0o600)
        request = {"operation": "prepare", "namespace": "marty-test", "secret": name,
                   "current": str(current), "candidate": str(candidate), "observed": str(observed),
                   "output": str(tmp_path / "patch.json"), "activationId": "0123456789abcdef0123456789abcdef"}
        return request, secret, before, after, selected

    return build


def native_renewal_publication(native_tools, tmp_path, request):
    return subprocess.run(
        [str(native_tools[0]), "operator", "kubernetes-renewal-publication"],
        input=json.dumps(request), text=True, capture_output=True, timeout=20,
        cwd=tmp_path, env={"PATH": str(native_tools[1].parent), "TEST_ROOT": str(tmp_path)},
    )


@pytest.mark.parametrize("secret_name", ["keycloak-kms", "signing-keys-integration-secret-server-tls"])
def test_native_renewal_publication_has_private_per_secret_patches_and_exact_readback(
    native_tools, tmp_path, renewal_publication, secret_name,
):
    request, secret, before, after, selected = renewal_publication(secret_name)
    result = native_renewal_publication(native_tools, tmp_path, request)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"ready": True, "secret": secret_name, "count": len(selected)}
    assert "PRIVATE_" not in result.stdout + result.stderr
    output = Path(request["output"])
    assert output.stat().st_mode & 0o7777 == 0o600
    patch = json.loads(output.read_text())
    assert patch[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": secret["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "41"},
    ]
    assert len(patch) == len(selected) + 3
    applied = json.loads(json.dumps(secret))
    for key, file in selected.items():
        published = base64.b64encode(after[file].replace(b"\r", b"").rstrip(b"\n")).decode()
        assert {"op": "replace", "path": f"/data/{key}", "value": published} in patch
        applied["data"][key] = published
    applied["metadata"]["resourceVersion"] = "42"
    applied["metadata"]["annotations"]["marty.elevenid.com/renewal-activation"] = request["activationId"]
    verify = {key: value for key, value in request.items() if key != "output"}
    result_path = tmp_path / "result.json"
    verify.update(operation="verify", result=str(result_path))
    for observation, state in ((applied, "candidate"), (secret, "unchanged")):
        result_path.write_text(json.dumps(observation))
        result_path.chmod(0o600)
        result = native_renewal_publication(native_tools, tmp_path, verify)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"ready": True, "secret": secret_name,
                                            "count": len(selected), "state": state}
        assert "PRIVATE_" not in result.stdout + result.stderr
    for path, expected in ((Path(request["current"]), before), (Path(request["candidate"]), after)):
        assert {file.name: file.read_bytes() for file in path.iterdir()} == expected
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.mark.parametrize("fault", ["foreign-owner", "changed-live-ca", "unrelated-generation"])
def test_native_renewal_publication_refuses_other_owners_trust_and_generation_changes(
    native_tools, tmp_path, renewal_publication, fault,
):
    request, secret, _, _, _ = renewal_publication("keycloak-kms")
    if fault == "foreign-owner":
        secret["metadata"]["ownerReferences"] = [{"kind": "Certificate", "uid": "foreign-owner"}]
    elif fault == "changed-live-ca":
        secret["data"]["openbao_tls_ca_cert"] = base64.b64encode(b"PRIVATE_WRONG_CA_CANARY").decode()
    else:
        (Path(request["candidate"]) / "openbao_tls_ca_cert").write_bytes(b"PRIVATE_CHANGED_CA_CANARY")
    Path(request["observed"]).write_text(json.dumps(secret))
    result = native_renewal_publication(native_tools, tmp_path, request)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "PRIVATE_" not in result.stderr
    assert not Path(request["output"]).exists()
    assert not (tmp_path / "native-manifest.json").exists()


@pytest.fixture
def harness(tmp_path, native_tools):
    if os.name == "nt":
        git = shutil.which("git")
        assert git, "Git Bash is required for the shell contract"
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash and Path(bash).is_file()
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    shutil.copy2(native_tools[1], empty_path / native_tools[1].name)
    operator_root = tmp_path / "operator"
    operator_scripts = operator_root / "scripts"
    operator_scripts.mkdir(parents=True)
    catalog_double = operator_scripts / "marty-deploy.sh"
    catalog_double.write_bytes(
        b'#!/bin/sh\n'
        b'if [ "$1" = kubernetes-secrets ]; then exec "$TEST_NATIVE_BIN" --repo-root "$TEST_SOURCE_ROOT" "$@"; fi\n'
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
        "TEST_NATIVE_BIN": native_tools[0].as_posix(),
        "TEST_SOURCE_ROOT": ROOT.as_posix(),
        "NAMESPACE": "synthetic-owned-namespace",
        "K8S_STACK_NAME": "kubernetes-production",
        "REGISTRY_AUTH_TOKEN": "synthetic-registry-token",
        "REGISTRY_USERNAME": "synthetic-registry-user",
        "REGISTRY_HOST": "registry.example.invalid",
        "IMAGE_PULL_SECRET_NAME": "synthetic-pull-secret",
        "FLOW_WEBHOOK_SECRET": "synthetic-flow-webhook-at-least-thirty-two-bytes",
        "SIGNING_KEYS_WORKLOAD_SERVER_CERT": "synthetic-signing-keys-server-certificate",
        "OPENBAO_TLS_CA_CERT": "synthetic-openbao-ca-certificate",
        "SIGNING_KEYS_TLS_KMS_TOKEN": "synthetic-signing-keys-tls-kms-token",
        "PYTHONPATH": str(ROOT / "packages"),
        "TEST_REQUIRED_SECRET_ENVS": "\n".join(
            entry["env"] for entry in token_catalog().values()
            if "kubernetes-production" in entry.get("required_for", [])
            and "env" in entry
        ),
    }
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
    for entry in token_catalog().values():
        if "kubernetes-production" in entry.get("required_for", []) and "env" in entry:
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

    def run(changes=None, *, operation="setup", file_bytes=None, next_file_value=None,
            timeout=20):
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
        script = prelude + extracted_functions() + "\n" + suffix + "\n"
        command = [bash, "--noprofile", "--norc", "-s"]
        process = subprocess.Popen(
            command,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_path,
            env=selected,
            start_new_session=os.name == "posix",
        )
        try:
            stdout, stderr = process.communicate(script, timeout=timeout)
        except BaseException:
            # The shell owns a native publisher, wrappers and client children.
            # Stop that test-owned group on timeout or interruption before the
            # API fixture is torn down, and preserve the original exception.
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            raise
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        calls = [
            path.read_bytes().decode().rstrip("\0").split("\0")
            for path in tmp_path.glob("call-*")
        ]
        manifest = tmp_path / "native-manifest.json"
        if manifest.exists():
            # Retain the pre-migration field assertions against actual native output.
            for line in manifest.read_text().splitlines():
                item = json.loads(line)
                calls.append(["create", "secret", "generic", item["metadata"]["name"],
                              *[f"--from-literal={key}={value}" for key, value in item["stringData"].items()]])
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
            == 35
    )
    created_names = {
        call[3]
        for call in calls
        if call[:3] == ["create", "secret", "generic"]
    }
    assert {
        "keycloak-kms",
        "org-workload-tls", "org-tls-kms",
        "es-workload-tls", "es-tls-kms",
        "rp-workload-tls", "rp-tls-kms",
        "ct-workload-tls", "ct-tls-kms",
        "notification-workload-tls", "notification-tls-kms",
    } <= created_names
    signing_tls = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "signing-keys-integration-secret-server-tls"]
    )
    assert any(arg.startswith("--from-literal=tls.crt=") for arg in signing_tls)
    assert not any(arg.startswith("--from-literal=tls.key=") for arg in signing_tls)
    kms_tls = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "signing-keys-tls-kms"]
    )
    assert any(arg.startswith("--from-literal=ca.crt=") for arg in kms_tls)
    assert any(arg.startswith("--from-literal=token=") for arg in kms_tls)
    pp_tls = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "presentation-policy-workload-tls"]
    )
    assert not any(arg.startswith("--from-literal=tls.key=") for arg in pp_tls)
    pp_kms = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "pp-tls-kms"]
    )
    assert any(arg.startswith("--from-literal=ca.crt=") for arg in pp_kms)
    assert any(arg.startswith("--from-literal=token=") for arg in pp_kms)
    auth_tls = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "auth-workload-tls"]
    )
    assert not any(arg.startswith("--from-literal=tls.key=") for arg in auth_tls)
    auth_kms = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "auth-tls-kms"]
    )
    assert any(arg.startswith("--from-literal=ca.crt=") for arg in auth_kms)
    assert any(arg.startswith("--from-literal=token=") for arg in auth_kms)
    verification_tls = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "verification-workload-tls"]
    )
    assert not any(arg.startswith("--from-literal=tls.key=") for arg in verification_tls)
    verification_kms = next(
        call for call in calls
        if call[:4] == ["create", "secret", "generic", "verification-tls-kms"]
    )
    assert any(arg.startswith("--from-literal=ca.crt=") for arg in verification_kms)
    assert any(arg.startswith("--from-literal=token=") for arg in verification_kms)
    for workload, signer in (
        ("flow-workload-tls", "flow-client-tls-kms"),
        ("flow-server-workload-tls", "flow-server-tls-kms"),
        ("deployment-profile-workload-tls", "deployment-profile-tls-kms"),
        ("compliance-profile-workload-tls", "compliance-profile-tls-kms"),
    ):
        tls_secret = next(
            call for call in calls
            if call[:4] == ["create", "secret", "generic", workload]
        )
        assert not any(arg.startswith("--from-literal=tls.key=") for arg in tls_secret)
        kms_secret = next(
            call for call in calls
            if call[:4] == ["create", "secret", "generic", signer]
        )
        assert any(arg.startswith("--from-literal=ca.crt=") for arg in kms_secret)
        assert any(arg.startswith("--from-literal=token=") for arg in kms_secret)


def test_native_publishes_notification_certificates_and_scoped_token_once(harness, tmp_path):
    inputs = {
        "TOKEN_HMAC_KEY": TOKEN,
        "NOTIFICATION_WORKLOAD_SERVER_CERT": "PUBLIC_NOTIFICATION_CERTIFICATE_CANARY",
        "MARTY_WORKLOAD_IDENTITY_CA_CERT": "PUBLIC_WORKLOAD_CA_CANARY",
        "OPENBAO_TLS_CA_CERT": "PUBLIC_OPENBAO_CA_CANARY",
        "NOTIFICATION_TLS_KMS_TOKEN": "PRIVATE_NOTIFICATION_TLS_TOKEN_CANARY",
    }
    result, _ = harness(inputs)
    assert result.returncode == 0, result.stderr
    manifests = [json.loads(line) for line in (tmp_path / "native-manifest.json").read_text().splitlines()]
    expected = {
        "notification-workload-tls": {
            "tls.crt": inputs["NOTIFICATION_WORKLOAD_SERVER_CERT"],
            "ca.crt": inputs["MARTY_WORKLOAD_IDENTITY_CA_CERT"],
        },
        "notification-tls-kms": {
            "token": inputs["NOTIFICATION_TLS_KMS_TOKEN"],
            "ca.crt": inputs["OPENBAO_TLS_CA_CERT"],
        },
    }
    for name, fields in expected.items():
        selected = [item for item in manifests if item["metadata"]["name"] == name]
        assert len(selected) == 1
        assert selected[0] == {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": name, "namespace": "synthetic-owned-namespace"},
            "stringData": fields,
        }
    assert "PRIVATE_NOTIFICATION_TLS_TOKEN_CANARY" not in result.stdout + result.stderr


@pytest.mark.parametrize("name", ["NOTIFICATION_WORKLOAD_SERVER_CERT", "NOTIFICATION_TLS_KMS_TOKEN"])
def test_missing_notification_input_prevents_all_native_secret_publication(harness, tmp_path, name):
    result, _ = harness({"TOKEN_HMAC_KEY": TOKEN, name: ""})
    assert result.returncode != 0
    assert name + " must be set to a non-placeholder value" in result.stderr
    assert not (tmp_path / "native-manifest.json").exists()


def test_notification_apply_failure_retains_prefix_and_stops_before_later_secrets(harness, tmp_path):
    result, _ = harness({"TOKEN_HMAC_KEY": TOKEN, "TEST_APPLY_FAIL_NAME": "notification-tls-kms"})
    assert result.returncode != 0
    assert "secret apply failed" in result.stderr
    assert "synthetic-sensitive-diagnostic" not in result.stdout + result.stderr
    attempted = [json.loads(line)["metadata"]["name"]
                 for line in (tmp_path / "native-manifest.json").read_text().splitlines()]
    inventory = json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())
    names = [entry["name"] for entry in inventory["secrets"] if "optional_env" not in entry]
    stop = names.index("notification-tls-kms") + 1
    assert "notification-workload-tls" in attempted[:-1]
    assert attempted == names[:stop]
    assert stop < len(names), "failure must exercise a remaining destination"


@pytest.mark.parametrize("source", ["environment", "file"])
@pytest.mark.parametrize("suffix", ["\n\n", "\r\n\n"])
def test_published_secret_matches_legacy_trailing_newline_normalization(harness, source, suffix):
    value = TOKEN + suffix
    expected = TOKEN + ("\r" if source == "environment" and "\r" in suffix else "")
    if source == "file":
        result, calls = harness(file_bytes=value.encode())
    else:
        result, calls = harness({"TOKEN_HMAC_KEY": value})
    assert result.returncode == 0, result.stderr
    secret = next(call for call in calls if call[:4] == ["create", "secret", "generic", "marty-secrets"])
    assert f"--from-literal=TOKEN_HMAC_KEY={expected}" in secret
    assert TOKEN not in result.stdout + result.stderr


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
    assert not (tmp_path / "token-file-reads").exists()
    assert (tmp_path / "synthetic-token.txt").read_text().strip() == placeholder
    assert placeholder not in result.stdout + result.stderr
    assert TOKEN not in result.stdout + result.stderr


def test_second_valid_file_read_cannot_replace_validated_captured_key(
    harness, tmp_path
):
    later = "synthetic-different-key-after-first-read"
    result, calls = harness(file_bytes=(TOKEN + "\n").encode(), next_file_value=later)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "token-file-reads").exists()
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


def test_native_apply_failure_is_propagated_without_credential_diagnostics(harness):
    result, _ = harness({"TOKEN_HMAC_KEY": TOKEN, "TEST_APPLY_FAIL": "1"})
    assert result.returncode != 0
    assert "secret apply failed" in result.stderr
    assert TOKEN not in result.stdout + result.stderr
    assert "synthetic-sensitive-diagnostic" not in result.stdout + result.stderr


@pytest.mark.parametrize("payload", [b"x" * (1024 * 1024 + 1), b"synthetic\0token", b"\xff\xfe"], ids=["oversize", "nul", "non-utf8"])
def test_native_file_content_boundary_fails_before_secret_write(harness, payload):
    result, calls = harness(file_bytes=payload)
    assert result.returncode != 0
    assert not applications(calls)
    assert "TOKEN_HMAC_KEY_FILE" in result.stderr


def test_native_apply_stops_at_first_failure(harness):
    result, calls = harness({"TOKEN_HMAC_KEY": TOKEN, "TEST_APPLY_FAIL": "1"})
    assert result.returncode != 0
    assert len([call for call in calls if call[:3] == ["create", "secret", "generic"]]) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group ownership")
def test_harness_timeout_stops_native_client_descendants(harness, tmp_path):
    import fcntl
    import time

    # The actual shell -> native publisher -> wrapper chain starts this owned
    # client. A lock held by the client proves it has exited after the deadline.
    client = tmp_path / "hanging-kubectl"
    client.write_text(
        f"#!{sys.executable}\n"
        "import fcntl, os, time\n"
        "from pathlib import Path\n"
        "root = Path(os.environ['TEST_ROOT'])\n"
        "with (root / 'client.lock').open('w') as lock:\n"
        "    fcntl.flock(lock, fcntl.LOCK_EX)\n"
        "    (root / 'client-ready').write_text('ready')\n"
        "    time.sleep(30)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    client.chmod(0o700)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        harness({"TOKEN_HMAC_KEY": TOKEN, "TEST_REAL_KUBECTL": str(client),
                 "TEST_API_SERVER": "http://127.0.0.1:1",
                 "TEST_KUBECONFIG": str(tmp_path / "unused-kubeconfig")}, timeout=5)
    assert (tmp_path / "client-ready").read_text() == "ready"
    with (tmp_path / "client.lock").open() as lock:
        # SIGKILL delivery to the descendant is asynchronous even after its
        # parent has exited. Require release within the original total budget;
        # a surviving client still fails instead of extending or retrying it.
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                assert time.monotonic() - started < 15, "timed-out descendants were not stopped promptly"
                time.sleep(0.01)
    assert time.monotonic() - started < 15, "timed-out descendants were not stopped promptly"
    assert len((tmp_path / "native-manifest.json").read_text().splitlines()) == 1


def test_real_kubectl_applies_synthetic_secret_schema_against_owned_api(harness, tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from urllib.parse import urlsplit

    binary = shutil.which("kubectl")
    if not binary:
        pytest.skip("Optional real kubectl client qualification requires kubectl on PATH")
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/api":
                self.reply(200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]})
            elif path == "/apis":
                self.reply(200, {"kind": "APIGroupList", "apiVersion": "v1", "groups": []})
            elif path == "/api/v1":
                self.reply(200, {"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "v1", "resources": [{"name": "secrets", "singularName": "secret", "namespaced": True, "kind": "Secret", "verbs": ["get", "create", "patch"]}]})
            else:
                self.reply(404, {"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "NotFound", "code": 404})

        def do_POST(self):
            assert urlsplit(self.path).path == "/api/v1/namespaces/synthetic-owned-namespace/secrets"
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(value)
            self.reply(201, value)

    config = tmp_path / "empty-kubeconfig"
    config.write_text("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # This integration launches 35 real clients sequentially. Give their
        # startup/API work a bounded aggregate budget while each request
        # retains the wrapper's three-second timeout.
        result, _ = harness({"TOKEN_HMAC_KEY": TOKEN, "TEST_REAL_KUBECTL": binary,
                             "TEST_API_SERVER": f"http://127.0.0.1:{server.server_port}",
                             "TEST_KUBECONFIG": str(config)}, timeout=120)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert result.returncode == 0, result.stderr
    assert len(received) == 35
    expected = [json.loads(line) for line in (tmp_path / "native-manifest.json").read_text().splitlines()]
    for actual, manifest in zip(received, expected, strict=True):
        assert actual["metadata"]["name"] == manifest["metadata"]["name"]
        assert actual["type"] == "Opaque"
        assert actual["stringData"] == manifest["stringData"]
    keycloak = next(item for item in received if item["metadata"]["name"] == "keycloak-kms")
    assert keycloak["stringData"]["master-cookie.token"] == "synthetic-required-value-at-least-thirty-two-bytes"
    assert TOKEN not in result.stdout + result.stderr


@pytest.mark.skipif(os.name != "posix", reason="native adoption requires Linux private custody")
@pytest.mark.parametrize("fault", ["cluster", "namespace", "operator", "owner", "partial-identity"])
def test_native_adoption_refuses_mismatched_pair_before_mutating_authority(native_tools, tmp_path, fault):
    from tests.native_operator_https import https_json_server
    binary = native_tools[0]
    identity = subprocess.run([str(binary), "--build-identity"], check=True, capture_output=True).stdout.decode().strip()
    private_root = tmp_path / "private-adoption"
    private_root.mkdir(mode=0o700)
    current, application, renewal, output = [private_root / name for name in ("current", "application", "renewal", "proof")]
    for directory in (current, application, renewal, output):
        directory.mkdir(mode=0o700)
    binding = {"namespace": "marty-test", "namespaceUid": "11111111-2222-3333-4444-555555555555",
        "openbaoClusterId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "workloadProject": "marty-selfhost-disposable-k8s-012345abcdef"}
    def private_file(path, value):
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(0o600)
    specs = json.loads((ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())["tokens"]
    for spec in specs:
        private_file(current / spec["file"], ("synthetic-retained-" + spec["file"]).encode())
    for name in ("application-role-id", "application-secret-id"):
        private_file(application / name, ("synthetic-existing-" + name).encode())
    private_file(application / "application-binding.json", binding)
    for name in ("renewal-role-id", "renewal-secret-id"):
        private_file(renewal / name, ("synthetic-existing-" + name).encode())
    private_file(renewal / "renewal-leaf-policies.json", [f"synthetic-scoped-{index:02}" for index in range(21)])
    bound = private_root / "binding.json"
    private_file(bound, {"schema": "marty.kubernetes-renewal-binding/v1", "binding": binding,
                         "producerNonce": "012345abcdef"})
    context = {"binding": dict(binding), "bootstrap_id": "22222222-3333-4444-5555-666666666666",
        "adoption_id": "a" * 32, "operator_identity": identity, "candidate": str(current),
        "application_identity": str(application), "renewal_identity": str(renewal), "renewal_binding": str(bound)}
    if fault == "namespace":
        context["binding"]["namespace"] = "foreign-namespace"
    elif fault == "operator":
        context["operator_identity"] = "foreign-source:foreign-release"
    elif fault == "owner":
        current.chmod(0o755)
    elif fault == "partial-identity":
        (application / "application-secret-id").unlink()
    calls, errors = [], []
    def dispatch(method, path, body, token):
        calls.append((method, path))
        assert (method, path, body, token) == ("GET", "sys/health", None, None)
        return 200, {"initialized": True, "sealed": False, "standby": False,
                     "cluster_id": "00000000-1111-2222-3333-444444444444"}
    with https_json_server(tmp_path, dispatch, errors) as server:
        server.ca.chmod(0o600)
        private_file(current / "openbao_tls_ca_cert", server.ca.read_bytes())
        result = subprocess.run([str(binary), "operator", "kubernetes-renewal-adoption-verify", server.endpoint,
            str(server.ca), str(output)], input=json.dumps(context).encode(), capture_output=True, timeout=30)
    assert result.returncode != 0 and result.stdout == b""
    assert not (output / "verified.json").exists()
    assert calls == ([("GET", "sys/health")] if fault == "cluster" else [])
    assert all(method == "GET" for method, _ in calls)
