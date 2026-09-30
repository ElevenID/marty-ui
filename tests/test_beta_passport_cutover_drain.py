"""Behavior checks for the beta-only passport drain preflight."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/deploy-local-beta-release.ps1"
CONTRACT = ROOT / "contracts/passport-beta-cutover-drain-behavior.json"
LOCK = ROOT / "scripts/beta-deployment-lock.ps1"
RESTORE = ROOT / "scripts/restore-local-beta-release.ps1"


def _function_source() -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^function Assert-NoInFlightPassportJobs \{.*?^\}", source)
    assert match, "beta passport drain function is missing"
    return match.group()


def _query_source(name: str) -> str:
    match = re.search(rf"(?ms)^\s*\${name} = @'\n(.*?)\n'@", _function_source())
    assert match, f"{name} SQL is missing"
    return match.group(1)


def test_drain_preflight_counts_artifacts_and_flows_before_backup():
    source = SCRIPT.read_text(encoding="utf-8")
    function = _function_source()
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["artifact_policy"]["legacy_or_unknown"].startswith("block")
    assert "exclusive beta deployment/restore mutation lock" in contract["writer_fence"]
    assert "secure_artifact_ciphertext::jsonb" in function
    assert "marty.passport-artifact-manifest/v1" in function
    assert "jsonb_array_elements" in function
    assert "LEFT JOIN flow_service.flow_definitions" in function
    assert "definition.id IS NULL" in function
    assert "flow_definition_reference' = '__verification__'" in function
    assert "instance.expires_at < clock_timestamp()" in function
    assert "instance.step_history::jsonb = '[]'::jsonb" in function
    assert (
        "jsonb_typeof(instance.context::jsonb->'auth_request') = 'string'" in function
    )
    assert "physical_document_issuance" in function
    assert "definition.extension::jsonb->>'extends_flow_type'" in function
    assert "physical_document_job" in function
    assert source.index("Assert-NoInFlightPassportJobs\n") < source.index(
        'Write-Step "Capture quiesced maintenance snapshot"'
    )


def test_beta_mutations_hold_one_lock_and_recheck_live_writers() -> None:
    deploy = SCRIPT.read_text(encoding="utf-8")
    restore = RESTORE.read_text(encoding="utf-8")
    for source in (deploy, restore):
        assert 'Enter-BetaDeploymentLock' in source
        assert 'Exit-BetaDeploymentLock -Lock $betaDeploymentLock' in source
    assert deploy.index('Enter-BetaDeploymentLock') < deploy.index(
        '$preDeployContainers = Get-ServiceRecords')
    assert deploy.index('Start-BetaMutation\n') < deploy.index(
        'docker -Arguments (@("stop")')
    assert deploy.index('Complete-BetaMutation\n') < deploy.index(
        'Exit-BetaDeploymentLock -Lock $betaDeploymentLock')
    assert 'Start-BetaMutation -ResumePending' in restore
    assert 'Complete-BetaMutation' in restore
    assert restore.index('Missing beta recovery input:') < restore.index(
        'Start-BetaMutation -ResumePending')
    assert restore.index('Beta backup checksum mismatch:') < restore.index(
        'Start-BetaMutation -ResumePending')
    assert restore.index('Start-BetaMutation -ResumePending') < restore.index(
        'Invoke-Checked docker (Get-ComposeArgs (@("stop")')
    assert deploy.index('$runningWriters = @(Get-ServiceRecords') < deploy.index(
        'Assert-NoInFlightPassportJobs\n')
    assert deploy.index('Assert-NoInFlightPassportJobs\n') < deploy.index(
        'Write-Step "Capture quiesced maintenance snapshot"')
    assert deploy.index('try {\n    Start-BetaMutation') < deploy.index(
        'docker -Arguments (@("stop")')
    assert 'Assert-MaintenanceContainersRestored $maintenanceContainers' in deploy
    assert deploy.index('Assert-MaintenanceContainersRestored $maintenanceContainers') < deploy.index(
        'Complete-BetaMutation\n            Write-Warning')
    assert deploy.index('$liveMutationStarted = $true') < deploy.index(
        '"openbao-init")')


@pytest.mark.parametrize(
    ("running", "verified"),
    [("alpha,beta", True), ("alpha", False), ("alpha,beta,gamma", False),
     ("alpha,gamma", False)],
)
def test_maintenance_recovery_requires_exact_container_set(
    tmp_path: Path, running: str, verified: bool,
) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^function Assert-MaintenanceContainersRestored\(.*?^\}", source
    )
    assert match
    ids = ",".join(f"'{item}'" for item in running.split(","))
    harness = tmp_path / "recovery.ps1"
    harness.write_text(
        match.group() + "\n"
        "$script:SelectedApplicationServices = @('issuance-native')\n"
        "$script:InfrastructureWriterServices = @('keycloak')\n"
        f"function Get-ServiceRecords {{ @({ids}) | ForEach-Object {{ "
        "[pscustomobject]@{ container_id = $_; running = $true } } }\n"
        "try { Assert-MaintenanceContainersRestored @('alpha', 'beta') } "
        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=8, check=False,
    )
    assert (result.returncode == 0) is verified, result.stdout + result.stderr
    if not verified:
        assert "did not restore the exact running container set" in result.stderr


def test_beta_deployment_lock_excludes_concurrent_processes(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    helper = str(LOCK).replace("'", "''")
    release_signal = tmp_path / "release-signal"
    signal_path = str(release_signal).replace("'", "''")
    holder = tmp_path / "holder.ps1"
    holder.write_text(
        f". '{helper}'\n$lock = Enter-BetaDeploymentLock\n"
        "try { Write-Output 'LOCK_HELD'; [Console]::Out.Flush(); "
        f"while (-not (Test-Path -LiteralPath '{signal_path}')) {{ "
        "Start-Sleep -Milliseconds 100 } } finally { "
        "Exit-BetaDeploymentLock -Lock $lock }\n",
        encoding="utf-8",
    )
    contender = tmp_path / "contender.ps1"
    contender.write_text(
        f". '{helper}'\n$lock = Enter-BetaDeploymentLock\n"
        "try { Write-Output 'LOCK_ACQUIRED' } finally { "
        "Exit-BetaDeploymentLock -Lock $lock }\n",
        encoding="utf-8",
    )
    first = subprocess.Popen(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(holder)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert first.stdout is not None
        assert first.stdout.readline().strip() == "LOCK_HELD"
        blocked = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-File", str(contender)],
            capture_output=True, text=True, timeout=8, check=False,
        )
        assert blocked.returncode != 0
        assert "Another elevenid-beta deployment or restore is active" in (
            blocked.stdout + blocked.stderr)
    finally:
        release_signal.write_text("release", encoding="utf-8")
        output, error = first.communicate(timeout=10)
        assert first.returncode == 0, output + error
    acquired = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(contender)],
        capture_output=True, text=True, timeout=8, check=False,
    )
    assert acquired.returncode == 0, acquired.stdout + acquired.stderr
    assert "LOCK_ACQUIRED" in acquired.stdout


def test_pending_beta_mutation_blocks_new_deploy_until_restore(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    helper = str(LOCK).replace("'", "''")
    marker = str(tmp_path / "pending").replace("'", "''")
    common = f". '{helper}'\nfunction Get-BetaMutationMarkerPath {{ '{marker}' }}\n"

    def invoke(body: str) -> subprocess.CompletedProcess[str]:
        path = tmp_path / "marker-harness.ps1"
        path.write_text(common + body, encoding="utf-8")
        return subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-File", str(path)],
            capture_output=True, text=True, timeout=8, check=False,
        )

    started = invoke("$lock = Enter-BetaDeploymentLock\n"
                     "try { Start-BetaMutation } finally { "
                     "Exit-BetaDeploymentLock -Lock $lock }\n")
    assert started.returncode == 0, started.stdout + started.stderr
    assert (tmp_path / "pending").is_file()
    blocked = invoke("$lock = Enter-BetaDeploymentLock\n"
                     "try { throw 'unexpected' } finally { "
                     "Exit-BetaDeploymentLock -Lock $lock }\n")
    assert blocked.returncode != 0
    assert "prior elevenid-beta mutation is pending" in blocked.stderr
    restored = invoke("$lock = Enter-BetaDeploymentLock -AllowPending\n"
                      "try { Start-BetaMutation -ResumePending; "
                      "Complete-BetaMutation } finally { "
                      "Exit-BetaDeploymentLock -Lock $lock }\n")
    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert not (tmp_path / "pending").exists()
    available = invoke("$lock = Enter-BetaDeploymentLock\n"
                       "try { Write-Output 'READY' } finally { "
                       "Exit-BetaDeploymentLock -Lock $lock }\n")
    assert available.returncode == 0, available.stdout + available.stderr
    assert "READY" in available.stdout


@pytest.mark.parametrize(
    ("scenario", "expected_message"),
    [
        ("clean", ""),
        ("missing_job_table", ""),
        ("pending_job", "In-flight passport jobs must drain"),
        ("legacy_artifact", "Legacy or unknown passport artifacts block"),
        ("artifact_query_failure", "Could not verify stored passport artifact format"),
        ("active_flow", "Active physical-document Flows must drain"),
        ("missing_flow_tables", "Could not verify beta physical-document Flow storage"),
        ("flow_query_failure", "Could not count active physical-document Flows"),
    ],
)
def test_drain_preflight_executes_count_only_queries(
    tmp_path, scenario, expected_message
):
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    harness = r"""
$script:ComposeProject = "beta-test"
function Get-ComposeContainerId { "disposable-postgres" }
function docker {
    $query = [string]$args[-1]
    $global:LASTEXITCODE = 0
    if ($query.Contains("to_regclass('issuance_service.physical_document_jobs')")) {
        if ($env:DRAIN_SCENARIO -eq "missing_job_table") { "f" } else { "t" }
    } elseif ($query.Contains("WHERE status NOT IN ('ACTIVE', 'FAILED', 'CANCELLED')")) {
        if ($env:DRAIN_SCENARIO -eq "pending_job") { "1" } else { "0" }
    } elseif ($query.Contains("marty.passport-artifact-manifest/v1")) {
        if ($env:DRAIN_SCENARIO -eq "artifact_query_failure") {
            $global:LASTEXITCODE = 1
            "error"
        } elseif ($env:DRAIN_SCENARIO -eq "legacy_artifact") { "1" } else { "0" }
    } elseif ($query.Contains("to_regclass('flow_service.flow_instances')")) {
        if ($env:DRAIN_SCENARIO -eq "missing_flow_tables") { "f" } else { "t" }
    } elseif ($query.Contains("physical_document_issuance")) {
        if ($env:DRAIN_SCENARIO -eq "flow_query_failure") {
            $global:LASTEXITCODE = 1
            "error"
        } elseif ($env:DRAIN_SCENARIO -eq "active_flow") { "1" } else { "0" }
    } else {
        throw "Unexpected query in drain preflight"
    }
}
try {
    Assert-NoInFlightPassportJobs
    Write-Output "DRAIN_OK"
} catch {
    Write-Output $_.Exception.Message
    exit 1
}
"""
    path = tmp_path / "drain-preflight.ps1"
    path.write_text(_function_source() + "\n" + harness, encoding="utf-8")
    environment = dict(os.environ, DRAIN_SCENARIO=scenario)
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if expected_message:
        assert result.returncode != 0, result.stdout + result.stderr
        assert expected_message in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "DRAIN_OK" in result.stdout


@pytest.mark.skipif(
    not os.getenv("BETA_DRAIN_TEST_POSTGRES"),
    reason="requires a disposable PostgreSQL 15 container",
)
def test_drain_sql_against_disposable_postgres():
    container = os.environ["BETA_DRAIN_TEST_POSTGRES"]

    def query(sql: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                container,
                "psql",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-At",
                "-v",
                "ON_ERROR_STOP=1",
            ],
            input=sql,
            capture_output=True,
            text=True,
            check=False,
        )

    artifact_sql = _query_source("legacyArtifactSql")
    flow_sql = _query_source("activeFlowsSql")
    setup = """
BEGIN;
CREATE SCHEMA issuance_service;
CREATE SCHEMA flow_service;
CREATE TABLE issuance_service.physical_document_jobs (
    status text NOT NULL, secure_artifact_ciphertext text NOT NULL
);
CREATE TABLE flow_service.flow_definitions (id text, flow_type text, extension json);
CREATE TABLE flow_service.flow_instances (
    flow_definition_id text, status text, context json,
    current_step_id text, application_flow_key_hash text,
    subject_type text DEFAULT 'applicant', state_history json DEFAULT '[]',
    step_history json DEFAULT '[]',
    expires_at timestamptz
);
"""
    verification_context = (
        '{"flow_definition_reference":"__verification__",'
        '"flow_type":"verification",'
        '"protocol_flow_type":"oid4vp_presentation",'
        '"auth_request":"request","oid4vp_profile":"standard","request_uri":"local"}'
    )
    modern_history = '[{"event":"verification_started","actor":"verification_api"}]'

    def verification_row(
        *,
        context=verification_context,
        subject_type="holder",
        history=modern_history,
        step_history="[]",
        expiry="now()-interval '1 day'",
    ):
        return (
            "INSERT INTO flow_service.flow_instances "
            "(flow_definition_id,status,context,subject_type,state_history,step_history,expires_at) "
            f"VALUES ('missing','awaiting_wallet','{context}','{subject_type}',"
            f"'{history}','{step_history}',{expiry});"
        )

    fixtures = [
        (
            "INSERT INTO issuance_service.physical_document_jobs VALUES ('ACTIVE', 'gAAAAlegacy');",
            artifact_sql,
            1,
        ),
        (
            'INSERT INTO issuance_service.physical_document_jobs VALUES (\'ACTIVE\', \'{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:abc"]}\');',
            artifact_sql,
            0,
        ),
        (
            'INSERT INTO issuance_service.physical_document_jobs VALUES (\'ACTIVE\', \'{"schema":"marty.passport-artifact-manifest/v1","chunks":[]}\');',
            artifact_sql,
            1,
        ),
        (
            'INSERT INTO issuance_service.physical_document_jobs VALUES (\'ACTIVE\', \'{"schema":"ignored","schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:abc"]}\');',
            artifact_sql,
            1,
        ),
        (
            "INSERT INTO flow_service.flow_definitions (id, flow_type) VALUES ('physical', 'physical_document_issuance'); INSERT INTO flow_service.flow_instances (flow_definition_id,status,context) VALUES ('physical', 'in_progress', '{}');",
            flow_sql,
            1,
        ),
        (
            "INSERT INTO flow_service.flow_definitions (id, flow_type) VALUES ('physical', 'physical_document_issuance'); INSERT INTO flow_service.flow_instances (flow_definition_id,status,context) VALUES ('physical', 'completed', '{}');",
            flow_sql,
            0,
        ),
        (
            "INSERT INTO flow_service.flow_definitions VALUES ('custom', 'custom', '{\"extends_flow_type\":\"physical_document_issuance\"}'); INSERT INTO flow_service.flow_instances (flow_definition_id,status,context) VALUES ('custom', 'in_progress', '{}');",
            flow_sql,
            1,
        ),
        (
            "INSERT INTO flow_service.flow_instances (flow_definition_id,status,context) VALUES ('missing', 'in_progress', '{}');",
            flow_sql,
            1,
        ),
        (
            "INSERT INTO flow_service.flow_definitions (id, flow_type) VALUES ('custom', 'custom'); INSERT INTO flow_service.flow_instances (flow_definition_id,status,context) VALUES ('custom', 'created', '{\"physical_document_job\":{}}');",
            flow_sql,
            1,
        ),
        (verification_row(), flow_sql, 0),
        (verification_row(subject_type="applicant", history="[]"), flow_sql, 0),
        (verification_row(expiry="now()+interval '1 day'"), flow_sql, 1),
        (
            verification_row(
                context=verification_context.replace(
                    '"auth_request":"request"', '"auth_request":{}'
                )
            ),
            flow_sql,
            1,
        ),
        (
            verification_row(
                context=verification_context.replace(
                    '"oid4vp_profile":"standard"', '"oid4vp_profile":null'
                )
            ),
            flow_sql,
            1,
        ),
        (
            verification_row(
                context=verification_context.replace(
                    '"request_uri":"local"', '"request_uri":""'
                )
            ),
            flow_sql,
            1,
        ),
        (verification_row(step_history='["entered"]'), flow_sql, 1),
        (
            verification_row(
                context=verification_context.replace(
                    '"request_uri"', '"physical_document_job":{},"request_uri"'
                )
            ),
            flow_sql,
            1,
        ),
        (
            verification_row(
                context=verification_context.replace(
                    '"protocol_flow_type":"oid4vp_presentation"',
                    '"protocol_flow_type":"physical_document_issuance"',
                )
            ),
            flow_sql,
            1,
        ),
    ]
    for fixture, selected_sql, expected in fixtures:
        result = query(setup + fixture + "\n" + selected_sql + ";\nROLLBACK;")
        assert result.returncode == 0, result.stderr
        assert str(expected) in result.stdout.splitlines(), result.stdout

    malformed = query(
        setup
        + "INSERT INTO issuance_service.physical_document_jobs VALUES ('ACTIVE', '{invalid');\n"
        + artifact_sql
        + ";\nROLLBACK;"
    )
    assert malformed.returncode != 0
