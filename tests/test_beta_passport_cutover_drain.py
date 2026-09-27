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
    assert "secure_artifact_ciphertext::jsonb" in function
    assert "marty.passport-artifact-manifest/v1" in function
    assert "jsonb_array_elements" in function
    assert "LEFT JOIN flow_service.flow_definitions" in function
    assert "definition.id IS NULL" in function
    assert "flow_definition_reference' = '__verification__'" in function
    assert "instance.expires_at < clock_timestamp()" in function
    assert "physical_document_issuance" in function
    assert "definition.extension::jsonb->>'extends_flow_type'" in function
    assert "physical_document_job" in function
    assert source.index("Assert-NoInFlightPassportJobs\n") < source.index(
        'Write-Step "Capture quiesced maintenance snapshot"'
    )


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
    expires_at timestamptz
);
"""
    verification_context = (
        '{"flow_definition_reference":"__verification__",'
        '"flow_type":"verification",'
        '"protocol_flow_type":"oid4vp_presentation",'
        '"auth_request":{},"oid4vp_profile":"standard","request_uri":"local"}'
    )
    modern_history = '[{"event":"verification_started","actor":"verification_api"}]'

    def verification_row(
        *,
        context=verification_context,
        subject_type="holder",
        history=modern_history,
        expiry="now()-interval '1 day'",
    ):
        return (
            "INSERT INTO flow_service.flow_instances "
            "(flow_definition_id,status,context,subject_type,state_history,expires_at) "
            f"VALUES ('missing','awaiting_wallet','{context}','{subject_type}',"
            f"'{history}',{expiry});"
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
