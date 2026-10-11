#!/usr/bin/env python3
"""Validate the bounded Canvas tier inventory against the compiled worker list.

This is a discovery/ownership guard, not a claim that every listed case ran.
The existing runner still owns every invocation, skip and run-bound proof.
"""

from __future__ import annotations

import hashlib
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
        and len(case_ids) == 133
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
    native_replays = inventory["native_replays"]
    native_oauth = inventory["native_oauth_replays"]
    names = [
        entry["test"]
        for entry in historical + preflights + native_replays + native_oauth
    ]
    names.append(inventory["native_validation"]["test"])
    require(
        len(historical) == 19
        and len(preflights) == 4
        and len(native_replays) == 3
        and len(native_oauth) == 10,
        "Canvas tier inventory count changed",
    )
    require(len(names) == len(set(names)), "Duplicate Canvas obligation")
    require(
        inventory["native_validation"]["test"] in listed
        and 'assert_worker_https("validation")' in text,
        "Native validation process owner missing",
    )
    actual_historical = {
        name for name in listed if "reference_matches_published" in name
    }
    expected_historical = {entry["test"] for entry in historical}
    require(
        expected_historical == actual_historical,
        "Historical Canvas discovery/inventory mismatch",
    )
    expected_native = {
        "rest": ("worker_rest_matches_frozen_published_process", 4),
        "facts": ("worker_facts_match_frozen_published_process", 4),
        "retry": ("worker_retry_matches_frozen_published_process", 5),
    }
    require(
        {entry["scenario"] for entry in native_replays} == set(expected_native),
        "Native replay scenario inventory drift",
    )
    for entry in native_replays:
        scenario = entry["scenario"]
        name, stages = expected_native[scenario]
        inputs = [
            f"contracts/canvas-worker-{scenario}-oracle.json",
            f"contracts/canvas-worker-{scenario}-scenarios.json",
        ]
        if scenario == "rest":
            inputs.append("contracts/canvas-worker-rest-current-inputs.json")
        require(
            entry["test"] == name
            and entry["stages"] == stages
            and entry["inputs"] == inputs
            and entry.get("assertion", "").strip()
            and name in listed
            and f"fn {name}(" in text
            and all((root / path).is_file() for path in inputs),
            f"Native {scenario} replay obligation drift",
        )
        pinned = entry.get("sha256")
        require(
            isinstance(pinned, dict) and set(pinned) == {"oracle", "scenarios"},
            f"Native {scenario} frozen pins missing",
        )
        for kind, path in zip(("oracle", "scenarios"), inputs[:2]):
            source = (root / path).read_text(encoding="utf-8")
            digest = hashlib.sha256(
                source.replace("\r\n", "\n").replace("\r", "\n").encode()
            ).hexdigest()
            require(
                pinned[kind] == digest,
                f"Native {scenario} frozen {kind} input drift",
            )
        scenarios = json.loads((root / inputs[1]).read_text(encoding="utf-8"))
        oracle = json.loads((root / inputs[0]).read_text(encoding="utf-8"))
        require(
            [stage["name"] for stage in scenarios["stages"]]
            == [observation["name"] for observation in oracle["observations"]]
            and len(scenarios["stages"]) == stages,
            f"Native {scenario} frozen stage inventory drift",
        )
    expected_oauth = {
        "oauth-revocation": ("worker_oauth_revocation_matches_frozen_published_process", 7),
        "oauth-revocation-fence": ("worker_oauth_revocation_fence_matches_frozen_published_process", 2),
        "oauth-revocation-patch": ("worker_oauth_revocation_patch_matches_frozen_published_process", 1),
        "oauth-revocation-retry-after": ("worker_oauth_revocation_retry_after_matches_frozen_published_process", 8),
        "oauth-revocation-backoff": ("worker_oauth_revocation_backoff_matches_frozen_published_process", 5),
        "oauth-revocation-queue": ("worker_oauth_revocation_queue_matches_frozen_published_process", 2),
        "oauth-revocation-lease": ("worker_oauth_revocation_lease_matches_frozen_published_process", 4),
        "oauth-revocation-counters": ("worker_oauth_revocation_counters_matches_frozen_published_cycle", 4),
        "oauth-revocation-secrets": ("worker_oauth_revocation_secrets_matches_frozen_published_process", 6),
        "oauth-revocation-selection": ("worker_oauth_revocation_selection_repository_matches_published", 1),
    }
    require(
        {entry["scenario"] for entry in native_oauth} == set(expected_oauth),
        "Native OAuth corpus owner inventory drift",
    )
    parent = (root / "scripts/test_canvas_worker_oauth_revocation_https.py").read_text(
        encoding="utf-8"
    )
    native_source = (
        root / "rust/services/issuance/tests/support/canvas_worker_oauth_revocation_replay.rs"
    ).read_text(encoding="utf-8")
    require(
        "assert_native_oauth_revocation_matrix" in text
        and "assert_capped_repository_selection" in text
        and "assert_capped_repository_selection" in native_source,
        "Native OAuth process or repository owner missing",
    )
    for entry in native_oauth:
        scenario = entry["scenario"]
        name, cases = expected_oauth[scenario]
        require(
            entry["test"] == name
            and entry["cases"] == cases
            and name in listed
            and f"fn {name}(" in text,
            f"Native {scenario} test owner drift",
        )
        if scenario != "oauth-revocation-selection":
            require(
                f'assert_native_oauth_revocation_matrix("{scenario}")' in text
                and f'"{scenario}"' in parent
                and 'for case in matrix["cases"]' in parent,
                f"Native {scenario} HTTPS dispatch missing",
            )
        else:
            require(
                "assert_capped_repository_selection(&pool).await" in text,
                "Native OAuth repository selection dispatch missing",
            )
        scenarios_path = root / f"contracts/canvas-worker-{scenario}-scenarios.json"
        oracle_path = root / f"contracts/canvas-worker-{scenario}-oracle.json"
        require(
            scenarios_path.is_file() and oracle_path.is_file(),
            f"Native {scenario} frozen input missing",
        )
        pinned = entry.get("sha256")
        require(
            isinstance(pinned, dict) and set(pinned) == {"scenarios", "oracle"},
            f"Native {scenario} frozen pins missing",
        )
        for kind, path in (("scenarios", scenarios_path), ("oracle", oracle_path)):
            source = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(
                source.replace("\r\n", "\n").replace("\r", "\n").encode()
            ).hexdigest()
            require(pinned[kind] == digest, f"Native {scenario} frozen {kind} drift")
        matrix = json.loads(scenarios_path.read_text(encoding="utf-8"))
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
        case_names = [case["name"] for case in matrix["cases"]]
        require(
            len(case_names) == cases
            and len(set(case_names)) == cases
            and set(case_names) == set(oracle),
            f"Native {scenario} frozen case inventory drift",
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
    require(
        producers.get("schema") == "marty.canvas-worker-oracle-producers/v3",
        "Wrong Canvas corpus ownership inventory schema",
    )
    direct = set(producers["direct_runner_corpora"])
    shared = {
        name for cases in producers["shared_runner_corpora"].values() for name in cases
    }
    frozen = producers.get("frozen_native_corpora", [])
    expected_frozen = {
        f"canvas-worker-{entry['scenario']}-oracle.json"
        for entry in native_oauth
    } | {
        "canvas-worker-logging-oracle.json",
        "canvas-worker-facts-oracle.json",
        "canvas-worker-retry-oracle.json",
        "canvas-worker-validation-oracle.json",
    }
    require(
        isinstance(frozen, list)
        and len(frozen) == len(set(frozen)) == len(expected_frozen)
        and set(frozen) == expected_frozen,
        "Frozen native corpus ownership drift",
    )
    logging_owner = (
        root / "rust/services/issuance/src/bin/canvas_sync_worker.rs"
    ).read_text(encoding="utf-8")
    logging_process = (
        root / "rust/services/issuance/tests/support/canvas_worker_logging_contract.rs"
    ).read_text(encoding="utf-8")
    require(
        "fn deployed_log_level_matches_frozen_published_thresholds()"
        in logging_owner
        and 'include_str!(\n            "../../../../../contracts/canvas-worker-logging-oracle.json"'
        in logging_owner
        and "fn invalid_log_level_process_failure_does_not_echo_operator_value()"
        in logging_process,
        "Frozen logging corpus native owner drift",
    )
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
        and "historical_test" not in native,
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
            "Canvas tier inventory: 19 historical references, 3 native REST-family replays, 10 native OAuth corpus owners, one native validation owner, and 4 native preflights discovered; "
            "133 package-migrated cases retained"
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
