"""The beta passport selector is opt-in and rejects partial or unsafe bindings."""

import json
from pathlib import Path
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


def model(tmp_path, enabled=True):
    services = {
        name: {"environment": {}, "secrets": []}
        for name in ("gateway", "flow", "issuance-native")
    }
    names = {
        "gateway": "PASSPORT_NATIVE_GATEWAY_ENABLED",
        "flow": "PASSPORT_NATIVE_FLOW_ENABLED",
        "issuance-native": "PASSPORT_NATIVE_HTTP_ENABLED",
    }
    for service, name in names.items():
        services[service]["environment"][name] = str(enabled).lower()
    result = {"services": services, "secrets": {}}
    if not enabled:
        return result
    services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
        "http://issuance-native:8005"
    )
    native = services["issuance-native"]["environment"]
    native["PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"] = "false"
    native["ICAO_DOCUMENT_SIGNER_URL"] = "https://signer.example.test"
    native["PERSONALIZATION_BUREAU_URL"] = "https://bureau.example.test"
    for secret, owners in VALIDATOR["SECRET_MOUNTS"].items():
        path = tmp_path / secret
        path.write_text("synthetic-private-value", encoding="utf-8")
        result["secrets"][secret] = {"file": str(path)}
        for owner in owners:
            services[owner]["secrets"].append(
                {"source": secret, "target": "/run/secrets/" + secret}
            )
            name = VALIDATOR["ENV_NAMES"][secret]
            services[owner]["environment"][name] = ""
            services[owner]["environment"][name + "_FILE"] = "/run/secrets/" + secret
    return result


def validate(candidate, enabled=True):
    VALIDATOR["validate_model"](
        candidate,
        passport_enabled=enabled,
        files=[PROFILE] if enabled else ["base.yml"],
    )


def test_opt_in_and_valid_file_bindings(tmp_path):
    validate(model(tmp_path))
    validate(model(tmp_path, False), False)
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        VALIDATOR["validate_model"](
            model(tmp_path), passport_enabled=False, files=[PROFILE]
        )


def test_rendered_compose_environment_list_is_supported(tmp_path):
    candidate = model(tmp_path)
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
        "self_signed",
        "url",
        "url_query",
        "url_malformed",
        "missing",
        "path_malformed",
        "empty",
        "mount",
        "inline",
        "file",
    ),
)
def test_partial_or_unsafe_selection_fails_closed(tmp_path, mutation):
    candidate = model(tmp_path)
    services = candidate["services"]
    if mutation == "owner":
        services["gateway"]["environment"]["PASSPORT_NATIVE_GATEWAY_ENABLED"] = "false"
    elif mutation == "target":
        services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
            "http://issuance:8005"
        )
    elif mutation == "self_signed":
        services["issuance-native"]["environment"][
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"
        ] = "true"
    elif mutation == "url":
        services["issuance-native"]["environment"]["ICAO_DOCUMENT_SIGNER_URL"] = (
            "http://signer.example.test"
        )
    elif mutation == "url_query":
        services["issuance-native"]["environment"]["ICAO_DOCUMENT_SIGNER_URL"] = (
            "https://signer.example.test/?api_key=synthetic-private-value"
        )
    elif mutation == "url_malformed":
        services["issuance-native"]["environment"]["ICAO_DOCUMENT_SIGNER_URL"] = (
            "https://[synthetic-private-value"
        )
    elif mutation == "missing":
        Path(candidate["secrets"]["passport_tenant_api_keys"]["file"]).unlink()
    elif mutation == "path_malformed":
        candidate["secrets"]["passport_tenant_api_keys"]["file"] = (
            "synthetic-private-value\x00"
        )
    elif mutation == "empty":
        Path(candidate["secrets"]["passport_tenant_api_keys"]["file"]).write_text("")
    elif mutation == "mount":
        services["flow"]["secrets"].clear()
    elif mutation == "inline":
        services["gateway"]["environment"]["PASSPORT_TENANT_API_KEYS"] = (
            "synthetic-private-value"
        )
    else:
        services["gateway"]["environment"]["PASSPORT_TENANT_API_KEYS_FILE"] = (
            "/tmp/keyring"
        )
    with pytest.raises(VALIDATOR["PassportConfigurationError"]) as error:
        validate(candidate)
    assert "synthetic-private-value" not in str(error.value)


def test_compose_call_is_read_only_and_closed(tmp_path):
    candidate = model(tmp_path)
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
    marker = "Assert-BetaPassportConfiguration -RepoRoot $script:RepoRoot"
    assert source.count(marker) == 2
    assert source.index(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments @("pull",'
    )
    assert source.rindex(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments (@("stop")'
    )


def test_actual_beta_compose_merge_preserves_default_off_and_selected_mounts():
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

    def render(files):
        command = ["docker", "compose"]
        for file in files:
            command.extend(["-f", file])
        command.extend(["config", "--no-interpolate", "--format", "json"])
        return json.loads(
            subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                check=True,
                timeout=30,
            ).stdout
        )

    disabled = render(base)
    enabled = render([*base, str(ROOT / PROFILE)])
    for name, flag in (
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ):
        before = VALIDATOR["environment"](disabled["services"][name])
        after = VALIDATOR["environment"](enabled["services"][name])
        assert before.get(flag, "false") != "true"
        assert after[flag] == "true"
    for secret, owners in VALIDATOR["SECRET_MOUNTS"].items():
        for owner in owners:
            mounts = enabled["services"][owner]["secrets"]
            assert {"source": secret, "target": "/run/secrets/" + secret} in mounts
