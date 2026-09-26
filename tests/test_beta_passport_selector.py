"""The beta passport selector is opt-in and rejects raw-key or partial KMS modes."""

import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = runpy.run_path(
    str(ROOT / "scripts/validate_beta_passport_configuration.py")
)
PROFILE = "docker-compose.profile.passport-native-beta.yml"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
TOKEN = "synthetic-internal-passport-token-00000001"


def model(enabled=True):
    services = {
        name: {"environment": {}, "secrets": []}
        for name in ("gateway", "flow", "issuance-native")
    }
    for service, flag in (
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ):
        services[service]["environment"][flag] = str(enabled).lower()
    result = {"services": services, "secrets": {}}
    if not enabled:
        return result
    for service in services.values():
        service["environment"].update(
            {
                "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
                "PASSPORT_TENANT_API_KEYS": "",
                "PASSPORT_TENANT_API_KEYS_FILE": "",
                "GRPC_SERVICE_TOKEN": TOKEN,
            }
        )
    services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
        "http://issuance-native:8005"
    )
    services["issuance-native"]["environment"].update(
        {
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
            "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
            "PASSPORT_KMS_CALLBACKS_ENABLED": "true",
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED": "false",
            "ICAO_DOCUMENT_SIGNER_URL": "",
            "PERSONALIZATION_BUREAU_URL": VALIDATOR["PRIVATE_BUREAU_URL"],
            "PERSONALIZATION_BUREAU_API_KEY": TOKEN,
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
        }
    )
    services["passport-beta-bureau"] = {
        "image": IMAGE,
        "environment": {
            "SERVICE_NAME": "passport_beta_bureau",
            "ENVIRONMENT": "beta",
            "PASSPORT_BETA_BUREAU_ENABLED": "true",
            "GRPC_SERVICE_TOKEN": TOKEN,
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
            "SIGNING_KEYS_INTERNAL_URL": VALIDATOR["PRIVATE_SIGNING_URL"],
            "PASSPORT_BUREAU_CALLBACK_URL": VALIDATOR["PRIVATE_CALLBACK_URL"],
        },
        "networks": {"marty-network": None},
    }
    return result


def validate(candidate, enabled=True):
    VALIDATOR["validate_model"](
        candidate,
        passport_enabled=enabled,
        files=[PROFILE] if enabled else ["base.yml"],
    )


def test_opt_in_kms_only_and_bureau_is_absent_when_disabled():
    validate(model())
    validate(model(False), False)
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        VALIDATOR["validate_model"](model(), passport_enabled=False, files=[PROFILE])


def test_rendered_compose_environment_list_is_supported():
    candidate = model()
    for service in candidate["services"].values():
        service["environment"] = [
            f"{key}={value}" for key, value in service["environment"].items()
        ]
    validate(candidate)


@pytest.mark.parametrize(
    "mutation",
    (
        "owner",
        "target",
        "internal",
        "signer_mode",
        "artifact_mode",
        "callback_mode",
        "self_signed",
        "remote_signer",
        "bureau_target",
        "tenant_key",
        "tenant_key_file",
        "artifact_key",
        "artifact_key_file",
        "callback_key",
        "callback_key_file",
        "missing_bureau",
        "token_mismatch",
        "signing_key_mismatch",
        "signing_route",
        "callback_route",
        "image",
        "exposed_port",
        "network",
        "legacy_mount",
        "bureau_key_file",
        "local_build",
        "entrypoint_override",
    ),
)
def test_partial_or_unsafe_selection_fails_closed(mutation):
    candidate = model()
    services = candidate["services"]
    native = services["issuance-native"]["environment"]
    bureau = services["passport-beta-bureau"]
    if mutation == "owner":
        services["gateway"]["environment"]["PASSPORT_NATIVE_GATEWAY_ENABLED"] = "false"
    elif mutation == "target":
        services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
            "http://issuance:8005"
        )
    elif mutation == "internal":
        services["flow"]["environment"]["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] = (
            "false"
        )
    elif mutation in ("signer_mode", "artifact_mode", "callback_mode"):
        name = {
            "signer_mode": "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "artifact_mode": "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "callback_mode": "PASSPORT_KMS_CALLBACKS_ENABLED",
        }[mutation]
        native[name] = "false"
    elif mutation == "self_signed":
        native["PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"] = "true"
    elif mutation == "remote_signer":
        native["ICAO_DOCUMENT_SIGNER_URL"] = "https://signer.example.test"
    elif mutation == "bureau_target":
        native["PERSONALIZATION_BUREAU_URL"] = "https://bureau.example.test"
    elif mutation == "tenant_key":
        services["gateway"]["environment"]["PASSPORT_TENANT_API_KEYS"] = (
            "synthetic-private-value"
        )
    elif mutation == "tenant_key_file":
        services["flow"]["environment"]["PASSPORT_TENANT_API_KEYS_FILE"] = (
            "/tmp/keyring"
        )
    elif mutation == "artifact_key":
        native["PHYSICAL_DOCUMENT_ARTIFACT_KEY"] = "synthetic-private-value"
    elif mutation == "artifact_key_file":
        native["PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE"] = "/tmp/artifact"
    elif mutation == "callback_key":
        native["PERSONALIZATION_BUREAU_WEBHOOK_SECRET"] = "synthetic-private-value"
    elif mutation == "callback_key_file":
        native["PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE"] = "/tmp/callback"
    elif mutation == "missing_bureau":
        del services["passport-beta-bureau"]
    elif mutation == "token_mismatch":
        native["PERSONALIZATION_BUREAU_API_KEY"] = "synthetic-private-value"
    elif mutation == "signing_key_mismatch":
        native["SIGNING_KEYS_INTERNAL_API_KEY"] = "synthetic-other-credential"
    elif mutation == "signing_route":
        bureau["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
            "https://public.example.test"
        )
    elif mutation == "callback_route":
        bureau["environment"]["PASSPORT_BUREAU_CALLBACK_URL"] = (
            "https://public.example.test"
        )
    elif mutation == "image":
        bureau["image"] = "services:latest"
    elif mutation == "exposed_port":
        bureau["ports"] = ["8020:8020"]
    elif mutation == "network":
        bureau["networks"] = {"default": None}
    elif mutation == "legacy_mount":
        candidate["secrets"]["passport_tenant_api_keys"] = {"file": "/tmp/keyring"}
    elif mutation == "bureau_key_file":
        native["PERSONALIZATION_BUREAU_API_KEY_FILE"] = "/tmp/bureau"
    elif mutation == "local_build":
        bureau["build"] = "."
    elif mutation == "entrypoint_override":
        bureau["entrypoint"] = ["sh", "-c", "true"]
    with pytest.raises(VALIDATOR["PassportConfigurationError"]) as error:
        validate(candidate)
    assert "synthetic-private-value" not in str(error.value)


def test_compose_call_is_read_only_and_closed():
    candidate = model()
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(candidate).encode())

    VALIDATOR["validate_compose"](
        project="elevenid-beta",
        env_files=["synthetic.env"],
        files=[PROFILE],
        passport_enabled=True,
        runner=run,
    )
    command, kwargs = calls[0]
    assert command[-3:] == ["config", "--format", "json"]
    assert kwargs["stdin"] is not None and kwargs["stderr"] is not None


@pytest.mark.parametrize("failure", ("exit", "json", "oversize", "timeout"))
def test_compose_failures_do_not_expose_rendered_credential_values(failure):
    def run(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(["synthetic-private-value"], 30)
        output = (
            b"x" * (VALIDATOR["MAX_MODEL_BYTES"] + 1)
            if failure == "oversize"
            else b"synthetic-private-value"
        )
        return SimpleNamespace(returncode=1 if failure == "exit" else 0, stdout=output)

    with pytest.raises(VALIDATOR["PassportConfigurationError"]) as error:
        VALIDATOR["validate_compose"](
            project="elevenid-beta",
            env_files=["synthetic.env"],
            files=[PROFILE],
            passport_enabled=True,
            runner=run,
        )
    assert str(error.value) == "Beta passport Compose validation failed"


def test_runner_validates_twice_before_mutation():
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    assert "[switch]$EnablePassportNative" in source
    assert (
        "$passportProfiles = @(Get-BetaPassportProfiles -Enabled ([bool]$EnablePassportNative))"
        in source
    )
    assert "passport_configuration_validated = $false" in source
    assert '$script:SelectedApplicationServices += "passport-beta-bureau"' in source
    assert (
        "retire it explicitly before deploying without the passport profile" in source
    )
    marker = "Assert-BetaPassportConfiguration -RepoRoot $script:RepoRoot"
    assert source.count(marker) == 2
    assert source.index(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments @("pull",'
    )
    assert source.rindex(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments (@("stop")'
    )


def test_selected_bureau_has_a_packaged_rust_entrypoint():
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "services/entrypoint.sh").read_text(encoding="utf-8")
    assert (
        "COPY --from=rust-service-builder /build/rust/target/release/marty-passport-beta-bureau /usr/local/bin/marty-passport-beta-bureau"
        in dockerfile
    )
    assert 'if [ "$MODULE_NAME" = "passport_beta_bureau" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-passport-beta-bureau" in entrypoint


def test_passport_transit_keys_are_verified_non_exportable_at_bootstrap():
    source = (ROOT / "docker/openbao-init.sh").read_text(encoding="utf-8")
    for key, kind in (
        ("passport-artifact-marty-aes256", "aes256-gcm96"),
        ("passport-bureau-callback-marty-hmac", "hmac"),
    ):
        assert f"transit/keys/{key}" in source
        assert f"type={kind} exportable=false" in source
        assert f"-field=type transit/keys/{key}" in source
        assert f"-field=exportable transit/keys/{key}" in source


def synthetic_beta_compose_env(tmp_path):
    required = set()
    for file in ROOT.glob("docker-compose*.yml"):
        required.update(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", file.read_text()))
    values = {name: "synthetic-value" for name in required}
    values["GRPC_SERVICE_TOKEN"] = TOKEN
    values["MARTY_SERVICES_IMAGE"] = IMAGE
    env_file = tmp_path / "synthetic-beta.env"
    env_file.write_text(
        "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n",
        encoding="utf-8",
    )
    passthrough = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
    )
    environment = {name: os.environ[name] for name in passthrough if name in os.environ}
    return env_file, environment


def test_actual_beta_compose_merge_preserves_default_off_and_kms_selection(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is not installed")
    base = [
        str(ROOT / name)
        for name in (
            "docker-compose.base.yml",
            "docker-compose.beta.yml",
            "docker-compose.profile.dev.yml",
        )
    ]
    env_file, environment = synthetic_beta_compose_env(tmp_path)

    def render(files):
        command = ["docker", "compose", "--env-file", str(env_file)]
        for file in files:
            command.extend(["-f", file])
        command.extend(["config", "--format", "json"])
        return json.loads(
            subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                env=environment,
                check=True,
                timeout=30,
            ).stdout
        )

    disabled = render(base)
    enabled = render([*base, str(ROOT / PROFILE)])
    assert "passport-beta-bureau" not in disabled["services"]
    assert "passport-beta-bureau" in enabled["services"]
    for name, flag in (
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ):
        before = VALIDATOR["environment"](disabled["services"][name])
        after = VALIDATOR["environment"](enabled["services"][name])
        assert before.get(flag, "false") != "true"
        assert after[flag] == "true"
        assert after["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] == "true"
    native = VALIDATOR["environment"](enabled["services"]["issuance-native"])
    assert native["PASSPORT_KMS_ARTIFACTS_ENABLED"] == "true"
    assert native["PASSPORT_KMS_CALLBACKS_ENABLED"] == "true"
    assert native["PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED"] == "true"
    assert not set(VALIDATOR["PASSPORT_RAW_KEY_NAMES"]).intersection(
        name for name, value in native.items() if value
    )
    validate(enabled)


def test_actual_interpolated_beta_compose_passes_selector(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is not installed")
    files = [
        str(ROOT / name)
        for name in (
            "docker-compose.base.yml",
            "docker-compose.beta.yml",
            "docker-compose.profile.dev.yml",
            PROFILE,
        )
    ]
    env_file, environment = synthetic_beta_compose_env(tmp_path)

    def run(command, **kwargs):
        kwargs["stderr"] = subprocess.PIPE
        result = subprocess.run(command, env=environment, cwd=ROOT, **kwargs)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result

    VALIDATOR["validate_compose"](
        project="elevenid-beta",
        env_files=[str(env_file)],
        files=files,
        passport_enabled=True,
        runner=run,
    )
