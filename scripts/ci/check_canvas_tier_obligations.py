#!/usr/bin/env python3
"""Validate the bounded Canvas tier inventory against the compiled worker list.

This is a discovery/ownership guard, not a claim that every listed case ran.
The existing runner still owns every invocation, skip and run-bound proof.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "contracts/canvas-worker-tier-obligations.json"
MIGRATION = ROOT / "contracts/canvas-worker-package-migration.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def listed_test_names(output: str) -> set[str]:
    names = [
        line.removesuffix(": test")
        for line in output.splitlines()
        if line.endswith(": test")
    ]
    require(len(names) == len(set(names)), "Duplicate compiled Canvas test names")
    return set(names)


def validate_package_migration(migration: dict, listed: set[str], root: Path = ROOT) -> None:
    """Keep all moved case identities; new future cases need not rewrite history."""
    require(
        migration.get("schema") == "marty.canvas-worker-package-migration/v1",
        "Unknown Canvas package migration schema",
    )
    require(
        migration.get("from")
        == {
            "package": "marty-canvas-acceptance",
            "target": "canvas_published_worker_contract",
            "source": "rust/crates/canvas-acceptance/tests/canvas_published_worker_contract.rs",
        }
        and migration.get("to")
        == {
            "package": "marty-canvas-worker-acceptance",
            "target": "canvas_published_worker_contract",
            "source": "rust/crates/canvas-worker-acceptance/tests/canvas_published_worker_contract.rs",
        },
        "Canvas package migration owner drift",
    )
    require(
        migration.get("required_lane") == "test-rust-services/canvas"
        and (root / migration["to"]["source"]).is_file()
        and (root / migration.get("shared_fixture_source", "")).is_file(),
        "Canvas package migration source or lane drift",
    )
    case_ids = migration.get("case_ids")
    require(
        isinstance(case_ids, list)
        and len(case_ids) == 147
        and all(isinstance(name, str) and name for name in case_ids)
        and case_ids == sorted(set(case_ids)),
        "Canvas package migration identity list drift",
    )
    require(
        set(case_ids) <= listed,
        "Canvas package migration missing a compiled case",
    )
    require(
        migration.get("ignored_capture_only_case_ids")
        == [
            "capture_worker_body_timeout_published_process",
            "capture_worker_lease_expiry_published_process",
        ]
        and set(migration["ignored_capture_only_case_ids"]) <= set(case_ids),
        "Canvas package migration capture-only identity drift",
    )


def validate(inventory: dict, listed: set[str], root: Path = ROOT) -> None:
    require(
        inventory.get("schema") == "marty.canvas-worker-tier-obligations/v1",
        "Unknown Canvas tier inventory schema",
    )
    require(
        inventory.get("package") == "marty-canvas-worker-acceptance",
        "Wrong Canvas owner package",
    )
    require(
        inventory.get("target") == "canvas_published_worker_contract",
        "Wrong Canvas owner target",
    )
    source = root / inventory["test_source"]
    require(source.is_file(), "Canvas test source missing")
    text = source.read_text(encoding="utf-8")
    for name in inventory["shared_inputs"]:
        require((root / name).is_file(), f"Canvas shared input missing: {name}")
    require(
        len(inventory["shared_inputs"]) == len(set(inventory["shared_inputs"])),
        "Duplicate Canvas shared input",
    )

    historical = inventory["historical"]
    preflights = inventory["preflights"]
    names = [entry["test"] for entry in historical + preflights]
    require(
        len(historical) == 33 and len(preflights) == 4,
        "Canvas tier inventory count changed",
    )
    require(len(names) == len(set(names)), "Duplicate Canvas obligation")
    actual_historical = {
        name for name in listed if "reference_matches_published" in name
    }
    expected_historical = {entry["test"] for entry in historical}
    require(
        expected_historical == actual_historical,
        "Historical Canvas discovery/inventory mismatch",
    )
    require(
        {entry["test"] for entry in preflights} <= listed,
        "Canvas preflight missing from compiled target",
    )

    producers = json.loads(
        (root / "contracts/canvas-worker-oracle-producers.json").read_text(
            encoding="utf-8"
        )
    )
    direct = set(producers["direct_runner_corpora"])
    shared = {
        name for cases in producers["shared_runner_corpora"].values() for name in cases
    }
    for entry in historical:
        name = entry["test"]
        require(
            name.startswith("worker_") and "::" not in name,
            f"Unexpected historical test ID: {name}",
        )
        require(f"fn {name}(" in text, f"Historical source owner missing: {name}")
        require(
            entry.get("assertion", "").strip(), f"Historical assertion missing: {name}"
        )
        kind = (
            name.removeprefix("worker_")
            .split("_reference_matches_published", 1)[0]
            .replace("_", "-")
        )
        corpus = f"canvas-worker-{kind}-oracle.json"
        scenario = f"canvas-worker-{kind}-scenarios.json"
        require(
            corpus in direct | shared, f"Historical producer owner missing: {corpus}"
        )
        require(
            (root / "contracts" / corpus).is_file(),
            f"Historical corpus missing: {corpus}",
        )
        require(
            (root / "contracts" / scenario).is_file(),
            f"Historical scenario missing: {scenario}",
        )
    modes = {entry["mode"] for entry in preflights}
    require(
        modes
        == {
            "mixed-roster-preflight",
            "body-timeout-preflight",
            "timeout-preflight",
            "lease-expiry-preflight",
        },
        "Canvas preflight mode drift",
    )
    routine_modes = {
        entry["mode"]
        for entry in preflights
        if entry["routine"].startswith("executed as a routine")
    }
    require(
        routine_modes == {"timeout-preflight", "lease-expiry-preflight"},
        "Canvas routine preflight classification drift",
    )
    excluded_modes = {
        entry["mode"]
        for entry in preflights
        if entry["routine"].startswith("tier-excluded")
    }
    require(
        excluded_modes == {"mixed-roster-preflight", "body-timeout-preflight"},
        "Canvas routine native tier-exclusion classification drift",
    )
    for entry in preflights:
        name = entry["test"]
        require(f"fn {name}(" in text, f"Native sentinel owner missing: {name}")
        require(entry.get("assertion", "").strip(), f"Native assertion missing: {name}")
        require(len(entry["inputs"]) >= 2, f"Native inputs missing: {name}")
        for path in entry["inputs"]:
            require((root / path).is_file(), f"Native input missing: {path}")
    for disposition in ("historical_disposition", "preflight_disposition"):
        for field in ("layer", "tier", "oracle_role", "cheapest_proving_layer"):
            require(
                inventory[disposition].get(field, "").strip(),
                f"Canvas {disposition}.{field} missing",
            )


def validate_selection(
    inventory: dict,
    original: set[str],
    selected: set[str],
    mode: str,
    qualification: str,
    *serial_tests: str,
) -> None:
    require(
        len(serial_tests) >= 1 and len(serial_tests) == len(set(serial_tests)),
        "Canvas serial worker owner list invalid",
    )
    require(set(serial_tests) <= original, "Canvas serial worker owner missing")
    require(
        selected <= original,
        "Canvas selected worker list contains an unregistered case",
    )
    omitted = original - selected
    expected = set(serial_tests)
    if mode == "full-after-preflights":
        require(qualification in {"0", "1"}, "Unknown Canvas qualification flag")
        expected.update(entry["test"] for entry in inventory["preflights"])
        if qualification == "0":
            expected.update(entry["test"] for entry in inventory["historical"])
    else:
        require(mode == "full", "Unknown Canvas worker selection mode")
    require(
        omitted == expected,
        f"Canvas worker selection drift: missing={sorted(expected - omitted)}, "
        f"unexpected={sorted(omitted - expected)}",
    )


def validate_fast_owner_execution(inventory: dict, lane: str, log: str) -> None:
    """Require real successful harness rows for each lane's declared owners."""
    owners = {
        "contracts": [
            "canvas_sync_worker::retry_handoff_tests::terminal_validation_errors_reach_actual_worker_dead_letter_port",
            "canvas_sync_worker_postgres::validation_policy_tests::all_published_repository_validation_decisions_have_one_fast_owner",
        ],
        "canvas": ["worker_validation_repository_matches_frozen_errors"],
    }
    require(lane in owners, "Unknown Canvas fast-owner execution lane")
    native = inventory.get("native_validation", {})
    require(
        native.get("test") == "worker_validation_matches_frozen_published_process"
        and native.get("historical_test")
        == "worker_validation_reference_matches_published_process",
        "Wrong native validation test owner",
    )
    require(
        native.get("policy_test") == owners["contracts"][1]
        and native.get("repository_database_test") == owners["canvas"][0]
        and native.get("repository_database_cases")
        == [
            "binding_platform_mismatch",
            "platform_archived",
            "stale_configuration",
            "application_removed_after_target_read",
            "candidate_removed_after_target_read",
        ],
        "Wrong native validation policy or database owner",
    )
    full_only = native.get("full_only", [])
    require(
        len(full_only) == 10
        and len({entry.get("case") for entry in full_only}) == 10
        and all(
            entry.get("fast_owners")
            == [
                "all_published_repository_validation_decisions_have_one_fast_owner",
                "terminal_validation_errors_reach_actual_worker_dead_letter_port",
            ]
            for entry in full_only
        ),
        "Wrong native validation fast-owner identity",
    )
    rows = [
        match
        for line in log.splitlines()
        if (match := re.fullmatch(r"test (\S+) \.\.\. (\S+)", line.strip()))
        and match.group(1) in owners[lane]
    ]
    for owner in owners[lane]:
        matches = [row for row in rows if row.group(1) == owner]
        require(
            len(matches) == 1 and matches[0].group(2) == "ok",
            f"Canvas {lane} fast owner did not execute exactly once and pass: {owner}",
        )


def main() -> int:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    migration = json.loads(MIGRATION.read_text(encoding="utf-8"))
    if len(sys.argv) == 4 and sys.argv[1] == "--require-execution":
        lane = sys.argv[2]
        path = Path(sys.argv[3])
        require(path.is_file(), "Missing Canvas fast-owner execution log")
        validate_fast_owner_execution(inventory, lane, path.read_text(encoding="utf-8"))
        print(f"Canvas {lane} fast owners executed exactly once and passed")
    elif len(sys.argv) == 1:
        listed = listed_test_names(sys.stdin.read())
        validate(inventory, listed)
        validate_package_migration(migration, listed)
        print(
            "Canvas tier inventory: 33 historical references and 4 native cases discovered; "
            "147 package-migrated cases retained"
        )
    else:
        require(
            len(sys.argv) >= 5 and sys.argv[1] == "--selected",
            "Invalid Canvas selection guard invocation",
        )
        original_output, separator, selected_output = sys.stdin.buffer.read().partition(
            b"\0"
        )
        require(bool(separator), "Missing Canvas selected-list separator")
        original = listed_test_names(original_output.decode("utf-8"))
        selected = listed_test_names(selected_output.decode("utf-8"))
        validate(inventory, original)
        validate_package_migration(migration, original)
        validate_selection(inventory, original, selected, *sys.argv[2:])
        print("Canvas tier inventory: exact compiled worker selection confirmed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
