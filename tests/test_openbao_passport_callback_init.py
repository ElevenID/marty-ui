"""Execute the shared production shell mode against an isolated command port."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("sh") or (
    "C:/Program Files/Git/usr/bin/sh.exe"
    if Path("C:/Program Files/Git/usr/bin/sh.exe").is_file() else None
)
pytestmark = pytest.mark.skipif(SHELL is None, reason="POSIX shell required")

BAO = r'''#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
case "$1" in
status) printf '{"initialized":%s,"sealed":%s}' "${INITIALIZED:-true}" "${SEALED:-false}" ;;
read) case "$*" in *-field=type*) echo hmac ;; *) echo "${EXPORTABLE:-false}" ;; esac ;;
write) exit 0 ;;
policy) cat > "$POLICY"; test "${FAIL_POLICY:-0}" = 0 ;;
token) case "$2" in
  lookup) printf '{"data":{"policies":%s,"entity_id":"%s"}}' "${POLICIES:-[\"passport-callback-hmac-service\"]}" "${ENTITY:-}" ;;
  create) printf 'synthetic-new-callback-token' ;;
  revoke) printf '%s' "$4" > "$REVOKED" ;;
esac ;;
*) exit 90 ;;
esac
'''


def execute(tmp_path, *, existing=None, fail_command=None, **settings):
    commands = tmp_path / "bin"
    commands.mkdir()
    (commands / "bao").write_text(BAO, encoding="utf-8", newline="\n")
    (commands / "bao").chmod(0o755)
    if fail_command:
        path = commands / fail_command
        path.write_text("#!/bin/sh\nexit 19\n", encoding="utf-8", newline="\n")
        path.chmod(0o755)
    token = tmp_path / "callback.token"
    if existing is not None:
        token.write_text(existing, encoding="utf-8")
    operator = tmp_path / "operator.token"
    operator.write_text("synthetic-operator-token", encoding="utf-8")
    (tmp_path / "public-ca.crt").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    command_path = commands.as_posix()
    if os.name == "nt":
        command_path = "/" + command_path[0].lower() + command_path[2:]
        test_path = command_path + ":/usr/bin:/bin"
    else:
        test_path = command_path + os.pathsep + os.environ["PATH"]
    environment = dict(os.environ, PATH=test_path,
                       BAO_ADDR="https://local-test.invalid:8200",
                       BAO_CACERT=(tmp_path / "public-ca.crt").as_posix(),
                       BAO_PASSPORT_CALLBACK_OPERATOR_TOKEN_FILE=operator.as_posix(),
                       BAO_PASSPORT_CALLBACK_TOKEN_FILE=token.as_posix(),
                       CALLS=(tmp_path / "calls").as_posix(), POLICY=(tmp_path / "policy").as_posix(),
                       REVOKED=(tmp_path / "revoked").as_posix(), **settings)
    result = subprocess.run([SHELL, str(ROOT / "docker/openbao-init.sh"),
                             "--passport-callback-only"], env=environment,
                            capture_output=True, text=True, timeout=15)
    assert (tmp_path / "calls").exists(), result.stderr
    calls = (tmp_path / "calls").read_text(encoding="utf-8")
    assert "synthetic-" not in result.stdout + result.stderr
    assert "operator init" not in calls
    assert "secrets enable" not in calls
    return result, token, calls


def test_scoped_mode_publishes_exact_workload_token_and_policy(tmp_path):
    result, token, calls = execute(tmp_path)
    assert result.returncode == 0, result.stderr
    assert token.read_text() == "synthetic-new-callback-token"
    assert "-policy=passport-callback-hmac-service -no-default-policy -orphan" in calls
    assert (tmp_path / "policy").read_text() == (
        'path "transit/hmac/passport-bureau-callback-marty-hmac" {\n'
        '  capabilities = ["create", "update"]\n}\n'
    )
    assert "token revoke" not in calls


def test_existing_exact_token_is_reused_without_mint_or_revoke(tmp_path):
    result, token, calls = execute(tmp_path, existing="synthetic-old-token")
    assert result.returncode == 0, result.stderr
    assert token.read_text() == "synthetic-old-token"
    assert "token create" not in calls and "token revoke" not in calls


@pytest.mark.parametrize("settings", [
    {"POLICIES": '["passport-callback-hmac-service","default"]'},
    {"ENTITY": "entity-bound-token"},
])
def test_existing_excess_authority_is_rejected_before_mutation(tmp_path, settings):
    result, token, calls = execute(tmp_path, existing="synthetic-old-token", **settings)
    assert result.returncode != 0
    assert token.read_text() == "synthetic-old-token"
    assert "policy write" not in calls and "token create" not in calls
    assert "token revoke" not in calls


@pytest.mark.parametrize("settings", [
    {"SEALED": "true"}, {"INITIALIZED": "false"}, {"EXPORTABLE": "true"},
])
def test_unready_or_exportable_target_cannot_mint(tmp_path, settings):
    result, token, calls = execute(tmp_path, **settings)
    assert result.returncode != 0 and not token.exists()
    assert "token create" not in calls


@pytest.mark.parametrize("fail_command", ["mktemp", "chmod", "mv"])
def test_failed_atomic_publication_revokes_only_new_orphan(tmp_path, fail_command):
    result, token, calls = execute(tmp_path, fail_command=fail_command)
    assert result.returncode != 0 and not token.exists()
    assert "token revoke" in calls
    assert (tmp_path / "revoked").read_text() == "synthetic-new-callback-token"
    assert not list(tmp_path.glob("callback.token.*"))


def test_reused_token_survives_policy_failure(tmp_path):
    result, token, calls = execute(tmp_path, existing="synthetic-old-token", FAIL_POLICY="1")
    assert result.returncode != 0 and token.read_text() == "synthetic-old-token"
    assert "token revoke" not in calls and "token create" not in calls


@pytest.mark.parametrize("settings", [{"BAO_SKIP_VERIFY": "true"}, {"VAULT_SKIP_VERIFY": "true"}])
def test_scoped_mode_rejects_tls_bypass_before_any_bao_command(tmp_path, settings):
    with pytest.raises(AssertionError, match="verified TLS"):
        execute(tmp_path, **settings)
    assert not (tmp_path / "calls").exists()


def test_full_bootstrap_and_beta_deploy_share_existing_script_mode():
    init = (ROOT / "docker/openbao-init.sh").read_text(encoding="utf-8")
    bootstrap = (ROOT / "docker/openbao-selfhost-init.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(encoding="utf-8")
    assert init.count("ensure_passport_callback\n") == 2
    assert "policy=passport-callback-hmac-service" not in bootstrap
    assert '/bin/sh /scripts/openbao-init.sh' in bootstrap
    assert "'openbao-init', '/scripts/openbao-init.sh', '--passport-callback-only'" in deploy
    start = deploy.index('$callbackServices = @("passport-callback-signer"')
    assert deploy.index("Assert-BetaCallbackSignerNetwork -AttachOpenBao", start) < deploy.index(
        "Wait-ForServiceHealth $callbackServices", start)
    assert "try { Restore-BetaCallbackNetworkAttachment }" in deploy
    application = deploy[deploy.index('Write-Step "Recreate application containers'):]
    assert application.index("if ($EnablePassportNative -and -not $EnablePassportPhysicalProvider)") < application.index("--passport-callback-only")


@pytest.mark.parametrize("scenario", ["added", "baseline", "foreign-project", "changed-identity"])
def test_real_powershell_network_helpers_restore_only_owned_edge(tmp_path, scenario):
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        pytest.skip("PowerShell required for deployment helper execution")
    control = tmp_path / "network.ps1"
    control.write_text(r'''
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:DEPLOY_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Production PowerShell syntax error' }
foreach ($name in @('Assert-BetaCallbackSignerNetwork', 'Restore-BetaCallbackNetworkAttachment')) {
    $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Invoke-Expression $function.Extent.Text
}
$script:BetaProject = 'elevenid-beta'
$script:BetaCallbackNetworkAttachment = $null
$script:connected = $env:SCENARIO -eq 'baseline'
$script:changed = $false
$script:operations = @()
$script:controlIds = @{ openbao = ('a' * 64); 'passport-beta-bureau' = ('b' * 64); 'passport-callback-signer' = ('c' * 64) }
function Get-ComposeContainerId { param($Service) return $Service }
function Invoke-Checked { param($FilePath, $Arguments)
    $script:operations += $Arguments[1]
    if ($Arguments[1] -eq 'connect') { $script:connected = $true }
    if ($Arguments[1] -eq 'disconnect') { $script:connected = $false }
}
function docker {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'network') {
        $members = @{ ('b' * 64) = @{}; ('c' * 64) = @{} }
        if ($script:connected) { $members[('a' * 64)] = @{} }
        $project = if ($env:SCENARIO -eq 'foreign-project') { 'foreign' } else { 'elevenid-beta' }
        $networkId = if ($script:changed) { 'e' * 64 } else { 'd' * 64 }
        return ConvertTo-Json -Depth 6 -Compress @(@{
            Id = $networkId; Name = 'elevenid-beta-passport-callback-signing'; Internal = $true
            Labels = @{ 'com.docker.compose.project' = $project; 'com.docker.compose.network' = 'passport-callback-signing' }
            Containers = $members
        })
    }
    switch ($args[3]) {
        '{{.Id}}' { return $script:controlIds[$args[1]] }
        '{{.State.Running}}' { return 'true' }
        '{{json .NetworkSettings.Networks}}' { return '{"elevenid-beta-passport-callback-signing":{"Aliases":["openbao"]}}' }
        default { throw 'Unexpected actual helper Docker operation' }
    }
}
if ($env:SCENARIO -eq 'foreign-project') {
    try { Assert-BetaCallbackSignerNetwork -AttachOpenBao; throw 'Expected rejection' }
    catch { if ($_.Exception.Message -notmatch 'Isolated beta callback network is unavailable') { throw } }
    if ($script:operations.Count) { throw 'Foreign network mutated' }
} else {
    Assert-BetaCallbackSignerNetwork -AttachOpenBao
    if ($env:SCENARIO -eq 'changed-identity') {
        $script:changed = $true
        try { Restore-BetaCallbackNetworkAttachment; throw 'Expected changed identity rejection' }
        catch { if ($_.Exception.Message -notmatch 'Callback network identity changed') { throw } }
        if ($script:operations -contains 'disconnect') { throw 'Changed network was disconnected' }
    } else {
        Restore-BetaCallbackNetworkAttachment
        if ($env:SCENARIO -eq 'baseline' -and (-not $script:connected -or $script:operations.Count)) { throw 'Baseline edge changed' }
        if ($env:SCENARIO -eq 'added' -and ($script:connected -or ($script:operations -join ',') -ne 'connect,disconnect')) { throw 'Owned edge not restored' }
    }
}
''', encoding="utf-8")
    result = subprocess.run([powershell, "-NoProfile", "-File", str(control)],
                            env=dict(os.environ, SCENARIO=scenario,
                                     DEPLOY_SCRIPT=str(ROOT / "scripts/deploy-local-beta-release.ps1")),
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
