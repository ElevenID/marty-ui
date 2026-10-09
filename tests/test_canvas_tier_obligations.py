"""Bounded discovery and source-input checks for Canvas's existing tier split."""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci.check_canvas_tier_obligations import (
    listed_test_names,
    validate,
    validate_fast_owner_execution,
    validate_package_migration,
    validate_selection,
)

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = json.loads(
    (ROOT / "contracts/canvas-worker-tier-obligations.json").read_text(encoding="utf-8")
)
MIGRATION = json.loads(
    (ROOT / "contracts/canvas-worker-package-migration.json").read_text(
        encoding="utf-8"
    )
)
RUNNER = ROOT / "scripts/ci/run-published-canvas-contracts.sh"


@pytest.mark.parametrize(
    "ignore_file",
    [
        ".dockerignore",
        "services/Dockerfile.dockerignore",
        "rust/services/Dockerfile.ci.dockerignore",
    ],
)
def test_ci_inventory_is_not_copied_into_service_images(ignore_file: str) -> None:
    lines = (ROOT / ignore_file).read_text(encoding="utf-8").splitlines()
    assert "contracts/canvas-worker-tier-obligations.json" in lines
    assert "contracts/canvas-worker-package-migration.json" in lines


def test_ci_inventory_has_no_rust_runtime_consumer() -> None:
    # A new runtime consumer requires revisiting the CI-only image exclusions.
    for directory in (ROOT / "rust/services", ROOT / "rust/crates"):
        for source in directory.rglob("*.rs"):
            assert "canvas-worker-tier-obligations.json" not in source.read_text(
                encoding="utf-8"
            ), source.relative_to(ROOT)
            assert "canvas-worker-package-migration.json" not in source.read_text(
                encoding="utf-8"
            ), source.relative_to(ROOT)


def test_worker_package_migration_accounts_for_all_original_case_ids() -> None:
    names = set(MIGRATION["case_ids"])
    assert len(names) == 147
    assert discovered() <= names
    validate_package_migration(MIGRATION, names)


def test_worker_package_migration_rejects_same_count_substitution() -> None:
    names = set(MIGRATION["case_ids"])
    names.remove("worker_repository_root_is_independent_of_cargo_package_depth")
    names.add("worker_same_count_substitute")
    assert len(names) == 147
    with pytest.raises(ValueError, match="missing a compiled case"):
        validate_package_migration(MIGRATION, names)


def discovered() -> set[str]:
    return {
        entry["test"] for entry in INVENTORY["historical"] + INVENTORY["preflights"]
    }


def test_exact_current_inventory_is_source_and_fixture_backed() -> None:
    validate(INVENTORY, discovered())
    assert len(INVENTORY["historical"]) == 33
    assert len(INVENTORY["preflights"]) == 4
    assert (
        "worker_oauth_revocation_counters_reference_matches_published_cycle"
        in discovered()
    )
    assert (
        "worker_oauth_revocation_selection_reference_matches_published_repository"
        in discovered()
    )


def test_compiled_list_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="Duplicate compiled"):
        listed_test_names(
            "worker_timeout_reference_matches_published_process: test\n" * 2
        )


@pytest.mark.parametrize(
    "change", ["missing-historical", "extra-historical", "missing-preflight"]
)
def test_compiled_list_drift_fails_closed(change: str) -> None:
    names = discovered()
    if change == "missing-historical":
        names.remove(INVENTORY["historical"][0]["test"])
    elif change == "extra-historical":
        names.add("worker_new_reference_matches_published_process")
    else:
        names.remove(INVENTORY["preflights"][0]["test"])
    with pytest.raises(ValueError, match="mismatch|missing"):
        validate(INVENTORY, names)


@pytest.mark.parametrize(
    "change", ["duplicate", "assertion", "corpus", "mode", "routine", "input"]
)
def test_inventory_drift_fails_closed(change: str) -> None:
    inventory = deepcopy(INVENTORY)
    if change == "duplicate":
        inventory["historical"][1]["test"] = inventory["historical"][0]["test"]
    elif change == "assertion":
        inventory["historical"][0]["assertion"] = ""
    elif change == "corpus":
        inventory["historical"][0]["test"] = (
            "worker_unknown_reference_matches_published_process"
        )
    elif change == "mode":
        inventory["preflights"][0]["mode"] = "unknown"
    elif change == "routine":
        inventory["preflights"][0]["routine"] = (
            "executed as a routine same-run preflight"
        )
    else:
        inventory["preflights"][0]["inputs"][0] = "contracts/missing-native-input.json"
    with pytest.raises(ValueError):
        validate(inventory, discovered())


def test_guard_is_additive_after_discovery_before_skip_selection() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    discovery = runner.index('worker_tests=$("$worker_executable" --list)')
    guard = runner.index("check_canvas_tier_obligations.py")
    skips = runner.index("preflight_skips=()")
    assert discovery < guard < skips


@pytest.mark.parametrize(
    "mode,qualification",
    [("full", "0"), ("full-after-preflights", "0"), ("full-after-preflights", "1")],
)
def test_exact_selected_set_for_each_tier(mode: str, qualification: str) -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    deadline = "worker_deadline_matches_frozen_published_process"
    original = discovered() | {serial, deadline, "unrelated_native_worker_test"}
    omitted = {serial, deadline}
    historical_serial = {
        "worker_mixed_roster_reference_matches_published_process",
        "worker_oauth_revocation_lease_reference_matches_published_process",
    }
    selected_serial = historical_serial if mode == "full" or qualification == "1" else set()
    omitted |= selected_serial
    if mode == "full-after-preflights":
        omitted |= {entry["test"] for entry in INVENTORY["preflights"]}
        if qualification == "0":
            omitted |= {entry["test"] for entry in INVENTORY["historical"]}
    validate_selection(
        INVENTORY,
        original,
        original - omitted,
        mode,
        qualification,
        serial,
        deadline,
        *sorted(selected_serial),
    )
    if mode == "full-after-preflights" and qualification == "0":
        assert len(omitted - {serial, deadline}) == 37
    if mode == "full-after-preflights" and qualification == "1":
        assert len(omitted - {serial, deadline}) == 6


def test_historical_serial_owner_must_be_registered_for_full_qualification() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    deadline = "worker_deadline_matches_frozen_published_process"
    historical = "worker_mixed_roster_reference_matches_published_process"
    original = discovered() | {serial, deadline}
    omitted = {serial, deadline, historical}
    omitted |= {entry["test"] for entry in INVENTORY["preflights"]}
    with pytest.raises(ValueError, match="selection drift"):
        validate_selection(
            INVENTORY,
            original,
            original - omitted,
            "full-after-preflights",
            "1",
            serial,
            deadline,
        )


def test_deadline_serial_owner_cannot_be_omitted_from_selection_guard() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    deadline = "worker_deadline_matches_frozen_published_process"
    original = discovered() | {serial, deadline}
    with pytest.raises(ValueError, match="selection drift"):
        validate_selection(INVENTORY, original, original - {serial, deadline}, "full", "0", serial)


def test_same_count_wrong_selected_case_fails_closed() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    extra = "unrelated_native_worker_test"
    original = discovered() | {serial, extra}
    omitted = {serial, extra}
    omitted |= {entry["test"] for entry in INVENTORY["preflights"]}
    omitted |= {entry["test"] for entry in INVENTORY["historical"][1:]}
    assert len(omitted - {serial}) == 37
    with pytest.raises(ValueError, match="selection drift"):
        validate_selection(
            INVENTORY,
            original,
            original - omitted,
            "full-after-preflights",
            "0",
            serial,
        )


def test_unregistered_selected_case_fails_closed() -> None:
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    original = discovered() | {serial}
    with pytest.raises(ValueError, match="unregistered"):
        validate_selection(
            INVENTORY, original, original | {"new_unknown"}, "full", "0", serial
        )


FAST_ROWS = {
    "contracts": [
        "canvas_sync_worker::retry_handoff_tests::terminal_validation_errors_reach_actual_worker_dead_letter_port",
        "canvas_sync_worker_postgres::validation_policy_tests::all_published_repository_validation_decisions_have_one_fast_owner",
    ],
    "canvas": ["worker_validation_repository_matches_frozen_errors"],
}


def fast_rows(lane: str) -> str:
    return "".join(f"test {owner} ... ok\n" for owner in FAST_ROWS[lane])


@pytest.mark.parametrize(
    "lane,owner", [(lane, owner) for lane, owners in FAST_ROWS.items() for owner in owners]
)
def test_exact_fast_owner_success_row_is_required(lane: str, owner: str) -> None:
    assert owner in fast_rows(lane)
    validate_fast_owner_execution(INVENTORY, lane, fast_rows(lane))


@pytest.mark.parametrize(
    "lane,owner", [(lane, owner) for lane, owners in FAST_ROWS.items() for owner in owners]
)
@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "ignored", "failed", "substituted"]
)
def test_fast_owner_execution_rows_fail_closed(
    lane: str, owner: str, mutation: str
) -> None:
    row = f"test {owner} ... ok\n"
    changed_row = {
        "missing": "",
        "duplicate": row * 2,
        "ignored": f"test {owner} ... ignored\n",
        "failed": f"test {owner} ... FAILED\n",
        "substituted": f"test other::{owner} ... ok\n",
    }[mutation]
    changed = fast_rows(lane).replace(row, changed_row)
    with pytest.raises(ValueError, match="did not execute exactly once"):
        validate_fast_owner_execution(INVENTORY, lane, changed)


@pytest.mark.parametrize("lane", ["canvas", "contracts"])
def test_fast_owner_manifest_identity_cannot_change(lane: str) -> None:
    inventory = deepcopy(INVENTORY)
    inventory["native_validation"]["full_only"][0]["fast_owners"][0] = "new_owner"
    with pytest.raises(ValueError, match="fast-owner identity"):
        validate_fast_owner_execution(
            inventory, lane, fast_rows(lane)
        )


@pytest.mark.parametrize("field", ["policy_test", "repository_database_test", "repository_database_cases"])
def test_validation_split_manifest_cannot_drift(field: str) -> None:
    inventory = deepcopy(INVENTORY)
    inventory["native_validation"][field] = []
    with pytest.raises(ValueError, match="policy or database owner"):
        validate_fast_owner_execution(inventory, "contracts", fast_rows("contracts"))


def test_contracts_fast_owner_cli_reads_actual_log(tmp_path: Path) -> None:
    log = tmp_path / "rust-workspace.log"
    command = [
        sys.executable,
        str(ROOT / "scripts/ci/check_canvas_tier_obligations.py"),
        "--require-execution",
        "contracts",
        str(log),
    ]
    missing = subprocess.run(command, capture_output=True, text=True, check=False)
    assert missing.returncode != 0
    log.write_text(fast_rows("contracts"), encoding="utf-8")
    passed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert passed.returncode == 0, passed.stderr
    log.write_text(
        fast_rows("contracts").replace(
            f"test {FAST_ROWS['contracts'][1]} ... ok\n",
            f"test {FAST_ROWS['contracts'][1]} ... ignored\n",
        ),
        encoding="utf-8",
    )
    ignored = subprocess.run(command, capture_output=True, text=True, check=False)
    assert ignored.returncode != 0


def test_fast_owner_guards_run_before_lane_success() -> None:
    runner = RUNNER.read_text(encoding="utf-8")
    assert runner.rindex('--require-execution canvas "$worker_log"') > runner.index(
        "(( composition_status == 0 && flow_status == 0 && worker_status == 0 && selfhost_status == 0 ))"
    )
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert workflow.index(
        "Require terminal validation worker fast-owner execution"
    ) > workflow.index("Run safe Rust contract groups concurrently")
    assert (
        'python3 scripts/ci/check_canvas_tier_obligations.py --require-execution contracts "$RUNNER_TEMP/rust-workspace.log"'
        in workflow
    )
