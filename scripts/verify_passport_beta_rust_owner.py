#!/usr/bin/env python3
"""Read-only, source-bound proof of the committed beta Rust passport owner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Callable

try:
    from .check_passport_beta_fence_authority import file_sha256
    from .prepare_passport_beta_aggregate_compose import (
        ROOT, TRANSITION_SQL_FILES, verify_render_plan,
    )
    from .probe_passport_beta_host import HostProbeError, beta_psql, run
except ImportError:
    from check_passport_beta_fence_authority import file_sha256
    from prepare_passport_beta_aggregate_compose import (
        ROOT, TRANSITION_SQL_FILES, verify_render_plan,
    )
    from probe_passport_beta_host import HostProbeError, beta_psql, run


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def verify(plan: dict[str, Any],
           runner: Callable[[list[str]], str] = run,
           render_verifier: Callable[[dict[str, Any]], dict[str, Any]] = verify_render_plan,
) -> dict[str, Any]:
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and plan.get("beta_origin") == "https://beta.elevenidllc.com"
            and re.fullmatch(r"[0-9a-f]{40}", str(plan.get("source_commit"))) is not None
            and re.fullmatch(r"[0-9a-f]{64}",
                             str(plan.get("cutover_report_file_sha256"))) is not None
            and type(plan.get("cutover_report_run_id")) is int
            and plan["cutover_report_run_id"] > 0
            and render_verifier(plan).get("verified") is True,
            "Rust owner signed aggregate plan is invalid")
    for field, filename in TRANSITION_SQL_FILES.items():
        require(re.fullmatch(r"[0-9a-f]{64}", str(plan.get(field))) is not None
                and plan[field] == file_sha256(ROOT / "scripts/sql" / filename),
                f"Rust owner protected SQL changed: {filename}")
    container = str(plan.get("postgres_container_id"))
    system_id = str(plan.get("postgres_system_identifier"))
    database_oid = str(plan.get("database_oid"))
    epoch = str(plan.get("fence_epoch"))
    source = plan["source_commit"]
    digest = str(plan.get("migration_set_sha256"))
    require(re.fullmatch(r"[0-9a-f]{64}", container) is not None
            and all(re.fullmatch(r"[0-9]+", value) is not None
                    for value in (system_id, database_oid, epoch))
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "Rust owner beta database target is invalid")
    query = (
        "SELECT (SELECT system_identifier::text FROM pg_control_system()) || '|' || "
        "(SELECT oid::text FROM pg_database WHERE datname=current_database()) || '|' || "
        "(SELECT phase || '|' || epoch::text || '|' || transition_txid::text "
        "FROM passport_cutover.state WHERE singleton=true) || '|' || "
        "(SELECT fence_epoch::text || '|' || source_commit || '|' || "
        "migration_set_sha256 FROM passport_cutover.native_migration_receipt "
        "WHERE singleton=true) || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty') || '|' || "
        "(SELECT rolcanlogin::text FROM pg_roles WHERE rolname='marty_beta_migrator')"
    )
    marker = beta_psql(query, runner, container)
    pieces = marker.split("|")
    require(len(pieces) == 10
            and pieces[:4] == [system_id, database_oid, "rust_owner", epoch]
            and re.fullmatch(r"[0-9]+", pieces[4]) is not None
            and int(pieces[4]) > int(epoch)
            and pieces[5:] == [epoch, source, digest, "true", "false"],
            "Rust owner database marker differs from signed beta release")
    transition_txid = pieces[4]
    sql = (
        "SET marty.passport_beta_verified_project = 'elevenid-beta';\n"
        f"SET marty.passport_beta_expected_system_identifier = '{system_id}';\n"
        f"SET marty.passport_beta_expected_database_oid = '{database_oid}';\n"
        f"SET marty.passport_beta_expected_fence_epoch = '{epoch}';\n"
        f"SET marty.passport_beta_expected_transition_txid = '{transition_txid}';\n"
        + (ROOT / "scripts/sql/passport-beta-rust-owner-verify.sql").read_text(
            encoding="utf-8")
    )
    raw = runner(["docker", "exec", container, "psql", "-X", "-U", "postgres",
                  "-d", "marty", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", sql])
    try:
        observed = json.loads(raw)
    except ValueError as exc:
        raise HostProbeError("Rust owner verifier returned ambiguous evidence") from exc
    require(isinstance(observed, dict)
            and observed.get("schema") == "marty.passport-beta-rust-owner-verification/v1"
            and observed.get("phase") == "rust_owner"
            and str(observed.get("fence_epoch")) == epoch
            and str(observed.get("transition_txid")) == transition_txid
            and isinstance(observed.get("transitioned_at"), str)
            and isinstance(observed.get("functions_md5"), dict),
            "Rust owner verifier differs from committed marker")
    return {
        "schema": "marty.passport-beta-rust-owner-proof/v1",
        "verified": True,
        "source_commit": source,
        "postgres_container_id": container,
        "postgres_system_identifier": system_id,
        "database_oid": database_oid,
        "fence_epoch": epoch,
        "transition_txid": transition_txid,
        "transitioned_at": observed["transitioned_at"],
        "functions_md5": observed["functions_md5"],
        "transition_sql_sha256": plan["transition_sql_sha256"],
        "rust_owner_verify_sql_sha256": plan["rust_owner_verify_sql_sha256"],
        "cutover_report_file_sha256": plan["cutover_report_file_sha256"],
        "cutover_report_run_id": plan["cutover_report_run_id"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        require(isinstance(plan, dict), "Rust owner plan is invalid")
        result = verify(plan)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Protected Rust owner proof is unavailable: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
