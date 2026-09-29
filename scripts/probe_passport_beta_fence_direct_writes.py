#!/usr/bin/env python3
"""Rollback-only direct write probes for a protected beta fence receipt.

The caller must supply a protected target plan and attest the returned result.
This module has no live CLI.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import uuid
from typing import Any, Callable


DOCKER_ID = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[0-9]+\Z")
OBSERVED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
ERRORS = {
    "physical_document_jobs": "beta passport job writes are fenced",
    "physical_flow_definitions":
        "beta physical-document Flow definition writes are fenced",
    "physical_flow_instances": "beta physical-document Flow writes are fenced",
}


class FenceProbeError(ValueError):
    pass


def candidate_sql(token: str) -> dict[str, str]:
    """Use rows that satisfy the reviewed pre-fence beta table constraints."""
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise FenceProbeError("Direct write probe token is invalid")
    job = f"fence-probe-{token}"
    flow = f"fence-probe-{token[:24]}"
    manifest = '{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:probe"]}'
    return {
        "physical_document_jobs": f"""
            INSERT INTO issuance_service.physical_document_jobs
                (id, organization_id, flow_execution_id, application_id,
                 application_template_id, credential_template_id,
                 delivery_destination_profile_id, document_type, country_code,
                 secure_artifact_ciphertext, secure_artifact_reference,
                 status, created_at, updated_at)
            VALUES ('{job}', 'fence-probe', '{flow}', '{job}',
                'fence-probe', 'fence-probe', 'fence-probe', 'P', 'USA',
                '{manifest}', 'physical-artifact://fence-probe',
                'DRAFT', clock_timestamp(), clock_timestamp())
        """,
        "physical_flow_definitions": f"""
            INSERT INTO flow_service.flow_definitions
                (id, organization_id, name, status, flow_type, steps,
                 transitions, default_timeout_seconds, max_retries,
                 enable_resume, version, created_at, updated_at,
                 deployment_profile_ids, approval_strategy, hooks)
            VALUES ('{flow}', 'fence-probe', 'Fence probe', 'active',
                'physical_document_issuance', '[]', '[]', 3600, 0,
                true, 1, clock_timestamp(), clock_timestamp(),
                '[]', 'automatic', '{{}}')
        """,
        "physical_flow_instances": f"""
            INSERT INTO flow_service.flow_instances
                (id, flow_definition_id, organization_id, status, context,
                 step_history, subject_type, created_at, updated_at,
                 state_history)
            VALUES ('{flow}', 'fence-probe-definition', 'fence-probe',
                'in_progress', '{{"physical_document_job":"{job}"}}',
                '[]', 'applicant', clock_timestamp(), clock_timestamp(), '[]')
        """,
    }


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=30,
                          check=False)


def _stdout(
    args: list[str], runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
) -> str:
    result = runner(args)
    if result.returncode != 0 or not result.stdout.strip():
        raise FenceProbeError("Direct write probe target inspection failed")
    return result.stdout.strip()


def probe_direct_writes(
    postgres_container_id: str,
    *,
    expected_docker_context: str,
    expected_daemon_id: str,
    expected_system_identifier: str,
    expected_database_oid: str,
    expected_fence_epoch: int,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run,
) -> dict[str, Any]:
    """Probe as the live writer role; all candidates roll back on success."""
    if (DOCKER_ID.fullmatch(postgres_container_id) is None
            or not expected_docker_context or not expected_daemon_id
            or DECIMAL.fullmatch(expected_system_identifier) is None
            or DECIMAL.fullmatch(expected_database_oid) is None
            or type(expected_fence_epoch) is not int or expected_fence_epoch <= 0):
        raise FenceProbeError("Direct write probe target identity is invalid")

    def assert_target() -> None:
        context = _stdout(["docker", "context", "show"], runner)
        daemon = _stdout(["docker", "info", "--format", "{{.ID}}"], runner)
        container = _stdout([
            "docker", "inspect", postgres_container_id, "--format", "{{.Id}}",
        ], runner)
        state = _stdout([
            "docker", "exec", postgres_container_id, "psql", "-X", "-qAt",
            "-U", "postgres", "-d", "marty", "-v", "ON_ERROR_STOP=1",
            "-c", "SELECT (SELECT system_identifier::text FROM pg_control_system())"
                  " || '|' || (SELECT oid::text FROM pg_database WHERE datname=current_database())"
                  " || '|' || (SELECT epoch::text FROM passport_cutover.state WHERE singleton)"
                  " || '|' || (SELECT phase FROM passport_cutover.state WHERE singleton)",
        ], runner)
        if (context != expected_docker_context or daemon != expected_daemon_id
                or container != postgres_container_id
                or state != f"{expected_system_identifier}|{expected_database_oid}|"
                            f"{expected_fence_epoch}|fully_fenced"):
            raise FenceProbeError("Direct write probe beta target or fence changed")

    assert_target()
    role = runner([
        "docker", "exec", postgres_container_id, "psql", "-X", "-qAt",
        "-U", "marty", "-d", "marty", "-v", "ON_ERROR_STOP=1",
        "-c", "SELECT session_user || '|' || current_user",
    ])
    if role.returncode != 0 or role.stdout.strip() != "marty|marty":
        raise FenceProbeError("Direct write probe is not using the beta Python writer role")
    rejections: dict[str, dict[str, Any]] = {}
    nonce = uuid.uuid4().hex
    for surface, statement in candidate_sql(nonce).items():
        # If the guard is absent, the INSERT succeeds but the transaction is
        # explicitly rolled back. A fence rejection exits before ROLLBACK; the
        # disconnected psql session then rolls the aborted transaction back.
        query = "BEGIN; SET LOCAL statement_timeout='5s'; " + statement + "; ROLLBACK;"
        result = runner([
            "docker", "exec", postgres_container_id, "psql", "-X", "-qAt",
            "-U", "marty", "-d", "marty", "-v", "ON_ERROR_STOP=1",
            "-v", "VERBOSITY=verbose", "-c", query,
        ])
        expected = ERRORS[surface]
        if result.returncode == 0 or re.search(
            rf"ERROR:\s+55000:\s+{re.escape(expected)}(?:\r?\n|\Z)",
            result.stderr,
        ) is None:
            raise FenceProbeError(f"Direct beta fence rejection is absent: {surface}")
        rejections[surface] = {
            "valid_without_fence": True, "sqlstate": "55000", "message": expected,
        }
    assert_target()
    observation = _stdout([
        "docker", "exec", postgres_container_id, "psql", "-X", "-qAt",
        "-U", "postgres", "-d", "marty", "-v", "ON_ERROR_STOP=1",
        "-c", "SELECT txid_current()::text || '|' || "
              "to_char(clock_timestamp() AT TIME ZONE 'UTC', "
              "'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')",
    ], runner).split("|", 1)
    if (len(observation) != 2 or DECIMAL.fullmatch(observation[0]) is None
            or OBSERVED_AT.fullmatch(observation[1]) is None):
        raise FenceProbeError("Direct write probe database watermark is invalid")
    receipt = {
        "schema": "marty.passport-beta-fence-direct-probe/v1",
        "method": "postgresql_transaction_rollback",
        "docker_context": expected_docker_context,
        "docker_daemon_id": expected_daemon_id,
        "postgres_container_id": postgres_container_id,
        "database_uid": f"postgresql:{expected_system_identifier}:{expected_database_oid}",
        "fence_epoch": expected_fence_epoch,
        "observation_watermark": int(observation[0]),
        "observed_at_utc": observation[1],
        "session_user": "marty", "current_user": "marty",
        "probe_nonce": nonce,
        "rejections": rejections,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return receipt
