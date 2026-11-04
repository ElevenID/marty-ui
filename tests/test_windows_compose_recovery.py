"""Execute the Windows wrapper against a harmless Docker command recorder."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh")
pytestmark = pytest.mark.skipif(not POWERSHELL, reason="PowerShell required")


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


NATIVE_DOCKER = None


@pytest.fixture(scope="session", autouse=True)
def native_docker_recorder(tmp_path_factory):
    global NATIVE_DOCKER
    if os.name != "nt" or not POWERSHELL:
        return
    NATIVE_DOCKER = tmp_path_factory.mktemp("native-docker") / "docker-read.exe"
    source = r"""
using System;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
public static class DockerRecorder {
 public static int Main(string[] args) {
  Func<string,string> env = key => Environment.GetEnvironmentVariable("MARTY_TEST_DOCKER_" + key);
  File.AppendAllText(env("LOG"), new JavaScriptSerializer().Serialize(args) + "\n");
  if(args[0] == "context") { Console.WriteLine(env("CONTEXT")); return 0; }
  if(args[0] == "info") { Console.WriteLine("linux"); return 0; }
  if(args[0] == "inspect") {
   if(env("MISSING") == "1" && args.Last().Contains("unseal") &&
      (!File.Exists(env("STARTED")) || env("PERMANENT") == "1")) {
    Console.Error.WriteLine("PRIVATE_INSPECT_SENTINEL"); return 1;
   }
   Console.WriteLine("running|healthy"); return 0;
  }
  if(args.Contains("config") && env("FAILURE") == "1") {
   Console.Error.WriteLine("PRIVATE_CONFIG_SENTINEL"); return 1;
  }
  if(args.Contains("--services")) {
   Console.WriteLine("openbao");
   Console.WriteLine(env("LEGACY") == "1" ? "openbao-bootstrap" : "openbao-unseal");
  }
  return 0;
 }
}
"""
    code = "Add-Type -TypeDefinition @'\n" + source + "\n'@ -OutputAssembly " + quote(NATIVE_DOCKER) + (
        " -OutputType ConsoleApplication -ReferencedAssemblies System.Web.Extensions,System.Core"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(code.encode("utf-16le")).decode()],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr

def invoke(tmp_path, *, check=True, omit=False, config_failure=False, missing=False,
           context="desktop-linux", retained=False, malformed=False, permanent=False, legacy_bao=False):
    stack = tmp_path / "stack with spaces"
    stack.mkdir()
    files = [stack / name for name in ("base.yml", "private-overlay.yml", "bao.yml", "production.env")]
    for path in files:
        path.touch()
    log = tmp_path / "commands.jsonl"
    settings = {
        "StackDirectory": str(stack), "ProductionComposeFile": [str(p) for p in files[:2]],
        "ProductionEnvFile": str(files[3]), "OpenbaoComposeFile": str(files[2]),
        "ProductionProject": "isolated-product", "OpenbaoProject": "isolated-bao",
        "ExpectedDockerContext": "desktop-linux",
    }
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps({"schema": "marty.windows-recovery/v1", "parameters": settings}))
    if malformed:
        settings["CheckOnly"] = False
        config.write_text(json.dumps({"schema": "marty.windows-recovery/v1", "parameters": settings}))
    args = "-RecoveryConfigurationFile " + quote(config) if retained else (
        "-StackDirectory " + quote(stack) + " -ProductionEnvFile " + quote(files[3])
        + " -OpenbaoComposeFile " + quote(files[2])
        + " -ProductionProject isolated-product -OpenbaoProject isolated-bao"
        + " -ExpectedDockerContext desktop-linux"
        + ("" if omit else " -ProductionComposeFile @(" + ",".join(quote(p) for p in files[:2]) + ")")
    )
    script = r"""
$env:COMPOSE_PROFILES = ''
$global:waited = $false
function global:Start-Sleep { $global:waited = $true }
function global:Get-Date {
    param([string]$Format)
    $date = [DateTime]::Now
    if ($global:waited) { $date = $date.AddHours(1) }
    if ($Format) { return $date.ToString($Format) }
    return $date
}
function global:Get-Command {
    param($Name, $CommandType, $ErrorAction)
    return [pscustomobject]@{Source=NATIVE_DOCKER_PATH}
}
function global:docker {
    ConvertTo-Json -InputObject @($args) -Compress | Add-Content -LiteralPath LOG_PATH
    $global:LASTEXITCODE = 0
    if ($args -contains 'up') { Set-Content -LiteralPath STARTED_PATH -Value 'started' }
}
& SCRIPT_PATH ARGUMENTS CHECK_ONLY
"""
    if os.name != "nt":
        pytest.skip("native Windows stderr regression")
    started = tmp_path / "started"
    for key, value in {
        "LOG_PATH": quote(log), "NATIVE_DOCKER_PATH": quote(NATIVE_DOCKER), "STARTED_PATH": quote(started),
        "SCRIPT_PATH": quote(ROOT / "scripts/recover-marty-after-reboot.ps1"),
        "ARGUMENTS": args, "CHECK_ONLY": "-CheckOnly" if check else "",
    }.items():
        script = script.replace(key, value)
    environment = {**os.environ, "MARTY_TEST_DOCKER_LOG": str(log), "MARTY_TEST_DOCKER_STARTED": str(started),
                   "MARTY_TEST_DOCKER_CONTEXT": context, "MARTY_TEST_DOCKER_FAILURE": str(int(config_failure)),
                   "MARTY_TEST_DOCKER_MISSING": str(int(missing)), "MARTY_TEST_DOCKER_PERMANENT": str(int(permanent)),
                   "MARTY_TEST_DOCKER_LEGACY": str(int(legacy_bao))}
    result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(script.encode("utf-16le")).decode()],
                            capture_output=True, encoding="utf-8", errors="replace", timeout=30, env=environment)
    transcript = tmp_path / "marty-selfhost-prod/marty-recovery.log"
    if transcript.exists():
        contents = transcript.read_text(encoding="utf-8-sig", errors="replace")
        assert "PRIVATE_CONFIG_SENTINEL" not in contents
        assert "PRIVATE_INSPECT_SENTINEL" not in contents
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8-sig").splitlines()] if log.exists() else []
    return result, calls, files


@pytest.mark.parametrize("retained", [False, True])
def test_preflight_retains_order_and_never_mutates(tmp_path, retained):
    result, calls, files = invoke(tmp_path, retained=retained)
    assert result.returncode == 0, result.stderr
    assert not any("up" in call for call in calls)
    product = next(call for call in calls if "config" in call and "isolated-product" in call)
    assert product[product.index("-f"):] == ["-f", str(files[0]), "-f", str(files[1]), "config", "--quiet"]
    assert not any("beta" in str(call) for call in calls)


@pytest.mark.parametrize("options", [{"omit": True}, {"config_failure": True},
                                        {"context": "wrong-engine"}, {"retained": True, "malformed": True}])
def test_refusals_precede_mutation_and_do_not_echo_native_diagnostics(tmp_path, options):
    result, calls, _ = invoke(tmp_path, **options)
    assert result.returncode != 0
    assert not any("up" in call for call in calls)
    assert "PRIVATE_CONFIG_SENTINEL" not in result.stdout + result.stderr


def test_recovery_checks_entire_model_even_when_sampled_containers_are_healthy(tmp_path):
    result, calls, files = invoke(tmp_path, check=False, missing=True)
    assert result.returncode == 0, result.stderr
    assert "PRIVATE_INSPECT_SENTINEL" not in result.stdout + result.stderr
    mutations = [call for call in calls if "up" in call]
    assert len(mutations) == 2  # missing unseal helper, then all default product roles
    product = next(call for call in mutations if "isolated-product" in call)
    assert product[product.index("-f"):] == ["-f", str(files[0]), "-f", str(files[1]), "up", "-d", "--no-build", "--wait"]
    assert not any("--force-recreate" in call or "beta" in str(call) for call in calls)


def test_permanently_failed_unseal_helper_blocks_product_recovery(tmp_path):
    result, calls, _ = invoke(tmp_path, check=False, missing=True, permanent=True)
    assert result.returncode != 0
    assert not any("up" in call and "isolated-product" in call for call in calls)


def test_native_file_entrypoint_validates_configuration_before_docker(tmp_path):
    configuration = tmp_path / "bad.json"
    configuration.write_text('{}')
    result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-File",
                             str(ROOT / "scripts/recover-marty-after-reboot.ps1"),
                             "-RecoveryConfigurationFile", str(configuration), "-CheckOnly"],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "Invalid retained recovery configuration" in result.stderr
    assert "Split-Path" not in result.stderr


def test_legacy_openbao_model_is_refused_before_any_mutation(tmp_path):
    result, calls, _ = invoke(tmp_path, legacy_bao=True)
    assert result.returncode != 0
    assert "persistent unseal service" in result.stderr
    assert not any("up" in call for call in calls)


@pytest.mark.parametrize("preflight_exit", [0, 1])
def test_installer_retains_exact_configuration_without_registering_on_failure(tmp_path, preflight_exit):
    if os.name != "nt":
        pytest.skip("Windows scheduled-task API recorder")
    installer = tmp_path / "install.ps1"
    shutil.copyfile(ROOT / "scripts/install-marty-boot-recovery.ps1", installer)
    child_log = tmp_path / "preflight.json"
    registered = tmp_path / "registered.json"
    configuration = tmp_path / "operator's retained configuration.json"
    configuration.write_text("{}")
    (tmp_path / "recover-marty-after-reboot.ps1").write_text(
        "param([string]$RecoveryConfigurationFile, [switch]$CheckOnly)\n"
        + "@{configuration=$RecoveryConfigurationFile; check=[bool]$CheckOnly} | ConvertTo-Json | Set-Content "
        + quote(child_log) + f"\nexit {preflight_exit}\n"
    )
    code = r"""
$global:record = @{}
function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory)
    $global:record.action = $Argument; return @{} }
function New-ScheduledTaskTrigger { param([switch]$AtLogOn, $User)
    $global:record.logon = [bool]$AtLogOn; return [pscustomobject]@{Delay=''} }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel)
    $global:record.principal = @($UserId, $LogonType, $RunLevel); return @{} }
function New-ScheduledTaskSettingsSet { return @{} }
function Register-ScheduledTask { $global:record | ConvertTo-Json | Set-Content REGISTERED; return @{} }
& INSTALLER -RecoveryConfigurationFile CONFIGURATION
"""
    for key, value in {"REGISTERED": quote(registered), "INSTALLER": quote(installer),
                       "CONFIGURATION": quote(configuration)}.items():
        code = code.replace(key, value)
    result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(code.encode("utf-16le")).decode()],
                            capture_output=True, text=True, timeout=30)
    child = json.loads(child_log.read_text(encoding="utf-8-sig"))
    assert child == {"configuration": str(configuration), "check": True}
    if preflight_exit:
        assert result.returncode != 0 and not registered.exists()
    else:
        assert result.returncode == 0, result.stderr
        record = json.loads(registered.read_text(encoding="utf-8-sig"))
        assert record["logon"] is True
        assert record["principal"][1:] == ["Interactive", "Limited"]
        assert '-RecoveryConfigurationFile "' + str(configuration) + '"' in record["action"]
        assert "-CheckOnly" not in record["action"]
