"""Execute only pure selectors/mocked validation, never the deployment runner."""

from copy import deepcopy
import json
from pathlib import Path
import runpy
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_beta_didcomm_configuration.py"


@pytest.fixture
def validator():
    return runpy.run_path(str(VALIDATOR))


def model(enabled):
    services = {
        name: {"environment": {"UNRELATED_SECRET": "synthetic-private-value"}}
        for name in ("issuance", "issuance-native", "gateway")
    }
    services["issuance"]["environment"].update(
        DIDCOMM_DELIVERY_OWNER="native",
        ISSUANCE_NATIVE_SERVICE_URL="http://issuance-native:8005",
    )
    services["issuance"]["depends_on"] = {
        "issuance-native": {"condition": "service_healthy", "required": True}
    }
    services["issuance"]["healthcheck"] = {
        "test": ["CMD", "curl", "--fail", "http://localhost:8005/ready"]
    }
    if enabled:
        native = services["issuance-native"]
        native["environment"].update(
            DIDCOMM_ENCRYPTION_POLICY_FILE="/run/secrets/didcomm-authcrypt/didcomm-encryption-policy.json",
            DIDCOMM_KMS_ADDR="http://openbao:8200",
            DIDCOMM_KMS_TOKEN_FILE="/run/secrets/didcomm-kms/openbao-token",
        )
        native["volumes"] = [
            {
                "type": "bind",
                "source": f"/synthetic-owned-policy/{name}",
                "target": f"/run/secrets/didcomm-authcrypt/{name}",
                "read_only": True,
                "bind": {"create_host_path": False},
            }
            for name in ("didcomm-encryption-policy.json",)
        ]
        native["volumes"].append(
            {
                "type": "volume",
                "source": "didcomm_issuance_token",
                "target": "/run/secrets/didcomm-kms",
                "read_only": True,
            }
        )
        native["depends_on"] = {
            "openbao-init": {"condition": "service_completed_successfully"}
        }
        image = "synthetic.invalid/openbao-didcomm@sha256:" + "a" * 64
        services["openbao"] = {
            "image": image,
            "command": ["server", "-dev", "-config", "/bao/config/didcomm-plugin.hcl"],
            "volumes": [
                {
                    "type": "bind",
                    "source": "/synthetic/docker/openbao-didcomm-dev.hcl",
                    "target": "/bao/config/didcomm-plugin.hcl",
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
            ],
        }
        services["openbao-init"] = {
            "image": image,
            "environment": {
                "DIDCOMM_KMS_PLUGIN_REQUIRED": "true",
                "DIDCOMM_ISSUANCE_TOKEN_FILE": "/run/didcomm-token/openbao-token",
            },
            "volumes": [
                {
                    "type": "volume",
                    "source": "didcomm_issuance_token",
                    "target": "/run/didcomm-token",
                }
            ],
        }
    return {
        "services": services,
        "volumes": {"didcomm_issuance_token": {}} if enabled else {},
    }


@pytest.mark.parametrize(
    ("setting", "value"),
    (
        ("DIDCOMM_DELIVERY_OWNER", None),
        ("DIDCOMM_DELIVERY_OWNER", "legacy"),
        ("ISSUANCE_NATIVE_SERVICE_URL", None),
        ("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance:8005"),
    ),
)
def test_validator_requires_exact_native_delivery_selection(validator, setting, value):
    candidate = model(False)
    if value is None:
        candidate["services"]["issuance"]["environment"].pop(setting)
    else:
        candidate["services"]["issuance"]["environment"][setting] = value
    with pytest.raises(validator["DidcommConfigurationError"]):
        validator["validate_model"](candidate, authcrypt_enabled=False)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing-dependency",
        "weak-condition",
        "optional-dependency",
        "legacy-health",
    ),
)
def test_validator_requires_native_dependency_and_retained_readiness(
    validator, mutation
):
    candidate = model(False)
    if mutation == "missing-dependency":
        candidate["services"]["issuance"]["depends_on"].clear()
    elif mutation == "weak-condition":
        candidate["services"]["issuance"]["depends_on"]["issuance-native"][
            "condition"
        ] = "service_started"
    elif mutation == "optional-dependency":
        candidate["services"]["issuance"]["depends_on"]["issuance-native"][
            "required"
        ] = False
    else:
        candidate["services"]["issuance"]["healthcheck"]["test"][-1] = (
            "http://localhost:8005/health"
        )
    with pytest.raises(validator["DidcommConfigurationError"]):
        validator["validate_model"](candidate, authcrypt_enabled=False)


def https_model(enabled):
    candidate = model(enabled)
    native = candidate['services']['issuance-native']
    native['environment'].update(
        DIDCOMM_KMS_ADDR='https://openbao:8200',
        DIDCOMM_KMS_CA_CERT_FILE='/bao/public-ca/ca.crt',
        DIDCOMM_KMS_TOKEN_FILE='/bao/didcomm-issuance-token/token',
    )
    native['volumes'] = [mount for mount in native.get('volumes', [])
                         if mount['target'] != '/run/secrets/didcomm-kms'] + [
        {'type': 'volume', 'source': source, 'target': target, 'read_only': True}
        for source, target in (
            ('openbao_public_ca', '/bao/public-ca'),
            ('openbao_didcomm_issuance_token', '/bao/didcomm-issuance-token'),
        )
    ]
    return candidate


@pytest.mark.parametrize('mutation', ['http', 'missing_ca', 'writable_token', 'legacy_custody'])
def test_compose_gate_requires_current_tls_custody(validator, mutation):
    candidate = https_model(False)
    native = candidate['services']['issuance-native']
    if mutation == 'http':
        native['environment']['DIDCOMM_KMS_ADDR'] = 'http://openbao:8200'
    elif mutation == 'missing_ca':
        native['volumes'] = native['volumes'][1:]
    elif mutation == 'writable_token':
        native['volumes'][-1]['read_only'] = False
    else:
        candidate['services']['issuance']['environment']['DIDCOMM_KMS_TOKEN_FILE'] = '/foreign/token'
    with pytest.raises(validator['DidcommConfigurationError']):
        validator['validate_compose'](
            project='elevenid-beta', env_files=['controlled.env'], files=['controlled.yml'],
            authcrypt_enabled=False,
            runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(candidate).encode()),
        )


@pytest.mark.parametrize("enabled", (False, True))
def test_validator_captures_actual_model_with_closed_output(validator, enabled, capsys):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(https_model(enabled)).encode())

    validator["validate_compose"](
        project="elevenid-beta",
        env_files=["synthetic.env"],
        files=["base.yml", "generated-official-images.yml"],
        authcrypt_enabled=enabled,
        runner=run,
    )
    command, kwargs = calls[0]
    assert command == [
        "docker",
        "compose",
        "--project-name",
        "elevenid-beta",
        "--env-file",
        "synthetic.env",
        "--file",
        "base.yml",
        "--file",
        "generated-official-images.yml",
        "config",
        "--format",
        "json",
    ]
    assert kwargs["timeout"] == 30 and kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["stdout"] == subprocess.PIPE
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "case",
    (
        "legacy-only",
        "legacy-policy",
        "disabled",
        "missing",
        "source",
        "writable",
        "auto-create",
        "gateway",
        "wrong-token-path",
        "writable-token-volume",
        "wrong-token-volume",
        "token-mounted-into-gateway",
        "external-token-volume",
        "missing-init-dependency",
        "missing-mint",
        "stock-openbao",
        "malformed",
    ),
)
def test_invalid_native_kms_custody_fails_closed_without_secret_values(validator, case):
    candidate = model(True)
    enabled = True
    if case == "legacy-only":
        candidate["services"]["issuance-native"]["environment"].pop(
            "DIDCOMM_ENCRYPTION_POLICY_FILE"
        )
    elif case == "legacy-policy":
        candidate["services"]["issuance"]["environment"][
            "DIDCOMM_ENCRYPTION_POLICY_FILE"
        ] = "synthetic-private-value"
    elif case == "disabled":
        enabled = False
    elif case == "missing":
        candidate = model(False)
    elif case == "source":
        candidate["services"]["issuance-native"]["volumes"][0]["source"] = (
            "synthetic-private-value"
        )
    elif case == "writable":
        candidate["services"]["issuance-native"]["volumes"][0]["read_only"] = False
    elif case == "auto-create":
        candidate["services"]["issuance-native"]["volumes"][0]["bind"][
            "create_host_path"
        ] = True
    elif case == "gateway":
        candidate["services"]["gateway"]["volumes"] = deepcopy(
            candidate["services"]["issuance-native"]["volumes"]
        )
    elif case == "wrong-token-path":
        candidate["services"]["issuance-native"]["environment"][
            "DIDCOMM_KMS_TOKEN_FILE"
        ] = "synthetic-private-value"
    elif case == "writable-token-volume":
        candidate["services"]["issuance-native"]["volumes"][1]["read_only"] = False
    elif case == "wrong-token-volume":
        candidate["services"]["issuance-native"]["volumes"][1]["source"] = (
            "synthetic-private-value"
        )
    elif case == "token-mounted-into-gateway":
        candidate["services"]["gateway"]["volumes"] = [
            deepcopy(candidate["services"]["issuance-native"]["volumes"][1])
        ]
    elif case == "external-token-volume":
        candidate["volumes"]["didcomm_issuance_token"] = {"external": True}
    elif case == "missing-init-dependency":
        candidate["services"]["issuance-native"]["depends_on"].clear()
    elif case == "missing-mint":
        candidate["services"]["openbao-init"]["environment"].pop(
            "DIDCOMM_ISSUANCE_TOKEN_FILE"
        )
    elif case == "stock-openbao":
        candidate["services"]["openbao"]["image"] = "quay.io/openbao/openbao:2"
    else:
        candidate = {"services": "synthetic-private-value"}
    with pytest.raises(validator["DidcommConfigurationError"]) as error:
        validator["validate_model"](candidate, authcrypt_enabled=enabled)
    assert "synthetic-private-value" not in str(error.value)


@pytest.mark.parametrize("case", ("exit", "json", "oversize", "timeout"))
def test_compose_failures_are_bounded_and_closed(validator, case):
    def run(*args, **kwargs):
        if case == "timeout":
            raise subprocess.TimeoutExpired(["synthetic-private-value"], 30)
        return SimpleNamespace(
            returncode=1 if case == "exit" else 0,
            stdout=b"x" * (validator["MAX_MODEL_BYTES"] + 1)
            if case == "oversize"
            else b"synthetic-private-value",
        )

    with pytest.raises(validator["DidcommConfigurationError"]) as error:
        validator["validate_compose"](
            project="elevenid-beta",
            env_files=["synthetic.env"],
            files=["synthetic.yml"],
            authcrypt_enabled=False,
            runner=run,
        )
    assert str(error.value) == "DIDComm Compose validation failed"


@pytest.mark.parametrize("source", ("/", "C:\\", "\\\\server\\share\\"))
def test_policy_sources_cannot_be_filesystem_roots(validator, source):
    candidate = model(True)
    candidate["services"]["issuance-native"]["volumes"][0]["source"] = source
    with pytest.raises(validator["DidcommConfigurationError"]):
        validator["validate_model"](candidate, authcrypt_enabled=True)


def test_runner_selects_and_revalidates_before_mutations():
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    assert "[switch]$EnableDidcommAuthcrypt" in source
    assert (
        "$didcommProfiles = @(Get-BetaDidcommProfiles -Enabled ([bool]$EnableDidcommAuthcrypt))"
        in source
    )
    assert "$script:ComposeFiles += (Join-Path $script:RepoRoot $profile)" in source
    marker = "Assert-BetaDidcommConfiguration -RepoRoot $script:RepoRoot"
    assert source.count(marker) >= 2
    first = source.index(marker, source.index("$script:ComposeFiles += $releaseComposeFile"))
    second = source.rindex(marker)
    assert first < second
    assert second > source.index('Write-Step "Reverify coordinated source after image builds"')
    assert source.index("$script:ComposeFiles += $releaseComposeFile") < first
    assert source.index("$env:MARTY_DOCS_IMAGE =") < first
    assert first < source.index('Invoke-Checked -FilePath docker -Arguments @("pull",')
    assert first < source.index('Write-Step "Capture preflight backup')
    assert source.index("$script:ComposeFiles += $verificationImageOverride") < second
    assert second < source.index(
        'Invoke-Checked -FilePath docker -Arguments (@("stop")'
    )
    assert "didcomm-native-conformance" not in source


def test_actual_powershell_selector_and_validation_are_fail_closed(tmp_path):
    executable = shutil.which("pwsh") or shutil.which("powershell")
    assert executable, "PowerShell is required for beta selector qualification"
    harness = tmp_path / "selector.ps1"
    harness.write_text(
        r"""
param([string]$Helper, [string]$Runner)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. $Helper
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Runner,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Invalid runner syntax' }
$script:captured=@()
function python { $script:captured=@($args); $global:LASTEXITCODE=$script:status }
$reports=@()
foreach ($enabled in @($false,$true)) {
    $EnableDidcommAuthcrypt=$enabled
    $didcommProfiles=@(Get-BetaDidcommProfiles -Enabled $enabled)
    $plan=@{}
    $expected=@{didcomm_authcrypt_enabled='[bool]$EnableDidcommAuthcrypt'; didcomm_profiles='$didcommProfiles'; didcomm_configuration_validated='$false'}
    foreach ($table in $ast.FindAll({param($n) $n -is [Management.Automation.Language.HashtableAst]},$true)) {
        foreach ($pair in $table.KeyValuePairs) {
            $key=$pair.Item1.Extent.Text
            if ($expected.ContainsKey($key)) {
                $expression=$pair.Item2.Extent.Text
                if ($expression -cne $expected[$key] -or $plan.ContainsKey($key)) { throw 'Ambiguous PlanOnly field' }
                $plan[$key]=$expression
            }
        }
    }
    if ($plan.Count -ne 3) { throw 'Missing PlanOnly fields' }
    $planExpression='[ordered]@{' + (($plan.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ';') + '}'
    $plan=Invoke-Expression $planExpression
    $script:status=0
    Assert-BetaDidcommConfiguration -RepoRoot 'synthetic-root' -EnvFiles @('synthetic.env') -ComposeFiles @('base.yml','generated-official-images.yml') -AuthcryptEnabled $enabled
    $successArgs=$script:captured
    $script:status=1
    $caught=$false
    try { Assert-BetaDidcommConfiguration -RepoRoot 'synthetic-root' -EnvFiles @('synthetic.env') -ComposeFiles @('base.yml') -AuthcryptEnabled $enabled } catch { $caught=$true }
    $reports+=@{enabled=$enabled; profiles=$didcommProfiles; argv=$successArgs; rejected=$caught; plan=$plan}
}
ConvertTo-Json -InputObject @($reports) -Depth 8 -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            "-Helper",
            str(ROOT / "scripts/beta-didcomm-configuration.ps1"),
            "-Runner",
            str(ROOT / "scripts/deploy-local-beta-release.ps1"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    reports = json.loads(result.stdout)
    assert reports[0]["profiles"] == []
    assert reports[1]["profiles"] == [
        "docker-compose.profile.issuance-native-authcrypt.yml",
    ]
    for report in reports:
        assert report["rejected"] is True
        assert ("--authcrypt-enabled" in report["argv"]) == report["enabled"]
        assert (
            report["argv"][-1 if not report["enabled"] else -2]
            == "generated-official-images.yml"
        )
        assert "conformance" not in str(report)
        assert report["plan"] == {
            "didcomm_authcrypt_enabled": report["enabled"],
            "didcomm_profiles": report["profiles"],
            "didcomm_configuration_validated": False,
        }
