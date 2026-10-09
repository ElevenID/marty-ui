"""Exercise the real CI shell with local command doubles, never Docker/network."""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/run-published-canvas-contracts.sh"
MIGRATED_CASES = json.loads(
    (ROOT / "contracts/canvas-worker-package-migration.json").read_text(
        encoding="utf-8"
    )
)["case_ids"]
TARGET = "worker_mixed_roster_matches_frozen_published_process"
TIMEOUT_TARGET = "worker_timeout_matches_frozen_published_process"
BODY_TIMEOUT_TARGET = "worker_body_timeout_matches_frozen_published_process"
LEASE_EXPIRY_TARGET = "worker_lease_expiry_matches_frozen_published_process"
DEADLINE_TARGET = "worker_deadline_matches_frozen_published_process"
MIXED_ROSTER_REFERENCE = "worker_mixed_roster_reference_matches_published_process"
OAUTH_LEASE_REFERENCE = "worker_oauth_revocation_lease_reference_matches_published_process"
HISTORICAL_SERIAL = (MIXED_ROSTER_REFERENCE, OAUTH_LEASE_REFERENCE)
PREFLIGHTS = [
    ("mixed-roster-preflight", TARGET),
    ("timeout-preflight", TIMEOUT_TARGET),
    ("body-timeout-preflight", BODY_TIMEOUT_TARGET),
    ("lease-expiry-preflight", LEASE_EXPIRY_TARGET),
]
FAST_MODE_SKIPS = [
    TARGET,
    BODY_TIMEOUT_TARGET,
    TIMEOUT_TARGET,
    LEASE_EXPIRY_TARGET,
    "reference_matches_published",
]
SCHEMA_ENV = "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST"
SELFHOST_CASES = (
    "selfhost_public_image_loader_isolated",
    "selfhost_public_image_loader_child",
    "selfhost_packaged_runtime::tests::child_stage_diagnostic_accepts_only_closed_values",
    "selfhost_packaged_runtime::tests::database_authentication_failure_never_qualifies_as_healthy",
    "selfhost_packaged_runtime::tests::process_control_child",
    "selfhost_packaged_runtime::tests::host_timeout_and_abrupt_exit_preserve_inputs_until_verified_recovery",
    "selfhost_packaged_runtime::tests::cleanup_failure_retains_scratch_and_original_failure",
    "selfhost_packaged_runtime::tests::held_pending_operation_withholds_recovery_and_retains_scratch",
    "selfhost_runtime_sidecar::recovery_tests::pending_operation_record_is_exclusive_validated_and_explicitly_completed",
    "selfhost_runtime_sidecar::recovery_tests::exact_parent_native_recovery_refuses_foreign_identity_and_mounts",
)
FLOW_CASES = (
    "didcomm_flow_grpc_provider_preserves_keyed_admission",
    "flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http",
    "flow_rendered_provider_child",
    "flow_actual_main_boots_rendered_base_and_preserves_public_admission",
    "flow_rendered_settings_select_native_rpc_and_preserve_legacy_http",
    "didcomm_http_admission_recovers_real_keyed_reservation",
    "didcomm_admission_recovery::flow_consumer::public_startup::loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn",
    "didcomm_admission_recovery::flow_consumer::public_startup::owned_output_child",
    "didcomm_admission_recovery::flow_consumer::public_startup::owned_process_output_and_early_exit_cleanup_are_verified",
)
# These seven cases occupied one contiguous block in the original 170-case
# mandatory roster. The other two Flow IDs were discovered but not separately
# listed by the old grep gate; the new executable checks all nine exactly.
FLOW_HISTORICAL_ROSTER = (
    "didcomm_http_admission_recovers_real_keyed_reservation",
    "didcomm_flow_grpc_provider_preserves_keyed_admission",
    "flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http",
    "flow_rendered_settings_select_native_rpc_and_preserve_legacy_http",
    "flow_actual_main_boots_rendered_base_and_preserves_public_admission",
    "didcomm_admission_recovery::flow_consumer::public_startup::owned_process_output_and_early_exit_cleanup_are_verified",
    "didcomm_admission_recovery::flow_consumer::public_startup::loader_capture_preserves_values_and_removes_file_alias_before_direct_spawn",
)
PINS = [
    "postgres@sha256:" + "a" * 64,
    "registry.invalid/issuance@sha256:" + "b" * 64,
]
MANDATORY_REGISTRATION_COUNT = 165
MANDATORY_REGISTRATION_SHA256 = (
    "8161a364b2f639c8eb3b0603487a4931ed639307ff0f5132711dcc8f7d2a792f"
)
RENDERED_CONFIG = (
    "rendered_base_process::"
    "rendered_base_renewal_config_crosses_encryption_and_private_address_policy"
)
CURRENT_REGISTRATION_COUNT = 166
CURRENT_REGISTRATION_SHA256 = (
    "74d9216c5c22c8f6446c79b397a2e6024b7f78741b19476e8555f6823a60d9d9"
)
PRIVATE_IP_PG = "didcomm_renewal_private_ip_refusal_preserves_published_rows"
NEW_REGISTRATION_COUNT = 167
NEW_REGISTRATION_SHA256 = (
    "38a2ba7d161448622df763cb926fb0e67bfb5e648c000f36d2bb590e1170c3a1"
)
K8S_RENDERED_CONFIG = (
    "resolved_kubernetes_runtime::"
    "resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy"
)
PRE_ROSTER_REGISTRATION_COUNT = 168
PRE_ROSTER_REGISTRATION_SHA256 = (
    "aea60fcdeff981e4df06b6aa58341e6f6b5bcff481954a47657dee8e0f853025"
)
ROSTER_EXPIRY_TESTS = (
    "worker_roster_metadata_expired_before_write_preserves_current_fields_and_fences",
    "worker_roster_metadata_expired_during_lock_preserves_current_fields_and_fences",
)
RENDERER_BOUNDS = "rendered_base_process::renderer_bounds_proof_is_image_free"
LATEST_REGISTRATION_COUNT = 171
LATEST_REGISTRATION_SHA256 = (
    "56e6384a8bb480f2d9ca66cd59f5060a41e98581127cbf269671700ccfbe0d90"
)
PRE_RENDERER_REGISTRATION_COUNT = 170
PRE_RENDERER_REGISTRATION_SHA256 = (
    "db3ce3bed72fb3fcafe86edf5ad913fbafc9810ffa5d6ce55f8ea68c6db7ebbd"
)


def required_registrations():
    # The existing CI-workflow suite pins the mandatory inventory. Here derive
    # it to exercise every current check without copying another long roster.
    names = re.findall(r"grep -Fx '([^']+): test'", SCRIPT.read_text(encoding="utf-8"))
    assert names and all(target in names for _, target in PREFLIGHTS)
    flow_block = SCRIPT.read_text(encoding="utf-8").split(
        "expected_flow_tests=$(printf '%s\\n' ", 1
    )[1].split(")\n[[", 1)[0]
    flow_exact = re.findall(r"'([^']+): test'", flow_block)
    assert set(flow_exact) == set(FLOW_CASES) and len(flow_exact) == 9
    assert set(FLOW_HISTORICAL_ROSTER) <= set(flow_exact)
    anchor = "didcomm_unkeyed_grpc_initiation_composes_real_delivery"
    assert names.count(anchor) == 1
    names[names.index(anchor):names.index(anchor)] = FLOW_HISTORICAL_ROSTER
    # Keep each mandatory registration's full-mode place without copying it.
    return [name for index, name in enumerate(names) if name not in names[index + 1 :]]


def test_mandatory_full_mode_registration_roster_is_unchanged() -> None:
    names = required_registrations()
    assert len(names) == LATEST_REGISTRATION_COUNT
    assert len(names) == len(set(names))
    assert hashlib.sha256("\n".join(names).encode()).hexdigest() == (
        LATEST_REGISTRATION_SHA256
    )
    assert names.count(RENDERER_BOUNDS) == 1
    names = [name for name in names if name != RENDERER_BOUNDS]
    assert len(names) == PRE_RENDERER_REGISTRATION_COUNT
    assert hashlib.sha256("\n".join(names).encode()).hexdigest() == (
        PRE_RENDERER_REGISTRATION_SHA256
    )
    assert all(names.count(name) == 1 for name in ROSTER_EXPIRY_TESTS)
    before_roster = [name for name in names if name not in ROSTER_EXPIRY_TESTS]
    assert len(before_roster) == PRE_ROSTER_REGISTRATION_COUNT
    assert hashlib.sha256("\n".join(before_roster).encode()).hexdigest() == (
        PRE_ROSTER_REGISTRATION_SHA256
    )
    assert before_roster.count(K8S_RENDERED_CONFIG) == 1
    before_k8s = [name for name in before_roster if name != K8S_RENDERED_CONFIG]
    assert len(before_k8s) == NEW_REGISTRATION_COUNT
    assert hashlib.sha256("\n".join(before_k8s).encode()).hexdigest() == (
        NEW_REGISTRATION_SHA256
    )
    assert names.count(PRIVATE_IP_PG) == 1
    prior = [name for name in before_k8s if name != PRIVATE_IP_PG]
    assert len(prior) == CURRENT_REGISTRATION_COUNT
    assert hashlib.sha256("\n".join(prior).encode()).hexdigest() == (
        CURRENT_REGISTRATION_SHA256
    )
    assert names.count(RENDERED_CONFIG) == 1
    historical = [name for name in prior if name != RENDERED_CONFIG]
    assert len(historical) == MANDATORY_REGISTRATION_COUNT
    assert hashlib.sha256("\n".join(historical).encode()).hexdigest() == (
        MANDATORY_REGISTRATION_SHA256
    )


def test_full_mode_keeps_sensitive_probes_serial_and_other_targets_concurrent() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    preflight = (
        '"$worker_executable" "$preflight_target" --exact --nocapture --test-threads=1'
    )
    serial = '"$worker_executable" "$serial_test" --exact --nocapture --test-threads=1'
    worker_full = '"$worker_executable" --skip "$serial_test" --skip "$deadline_serial_test" "${historical_serial_skips[@]}" "${preflight_skips[@]}" --nocapture --test-threads=4'
    json_serial = '"$composition_executable" "$serial_composition_test" --exact --nocapture --test-threads=1'
    composition_full = '"$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4'
    assert (
        sum(
            line.strip() == 'timed canvas_serial "$mode" ' + preflight
            for line in script.splitlines()
        )
        == 1
    )
    assert (
        sum(
            line.strip() == "timed canvas_serial sql_logging " + serial
            for line in script.splitlines()
        )
        == 1
    )
    deadline_serial = '"$worker_executable" "$deadline_serial_test" --exact --nocapture --test-threads=1'
    assert script.count("timed canvas_serial worker_deadline " + deadline_serial) == 2
    assert script.rindex("timed canvas_serial worker_deadline " + deadline_serial) < script.index(composition_full)
    assert script.count("run_historical_serial_tests") == 3  # definition and both full paths
    assert 'historical_serial_tests=("$mixed_roster_serial_test" "$oauth_lease_serial_test")' in script
    for case, phase in (
        ("mixed_roster_serial_test", "mixed_roster_reference"),
        ("oauth_lease_serial_test", "oauth_lease_reference"),
    ):
        assert (
            f'timed canvas_serial {phase} "$worker_executable" "${case}" --exact --nocapture --test-threads=1'
            in script
        )
    assert (
        sum(
            line.strip() == "timed canvas_serial json_consumer " + json_serial
            for line in script.splitlines()
        )
        == 1
    )
    assert (
        "[[ $((all_tests - parallel_tests)) == $((3 + ${#historical_serial_tests[@]} + expected_skipped_worker_tests + expected_skipped_config_tests + expected_skipped_timeout_tests)) ]]"
        in script
    )
    assert script.count(composition_full + ' >"$composition_log" 2>&1 &') == 1
    assert (
        script.count(
            'MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" '
            'MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" '
            + worker_full
            + ' >"$worker_log" 2>&1 &'
        )
        == 1
    )
    assert 'tail --pid="$pid"' in script
    assert script.count(': > "$composition_log"') == 1
    assert script.count(': > "$worker_log"') == 1
    assert script.count(': > "$selfhost_log"') == 1
    assert script.index("trap cleanup_target_logs EXIT") < script.index(
        ': > "$composition_log"'
    )
    assert script.index(': > "$composition_log"') < script.index(composition_full)
    assert script.index(': > "$worker_log"') < script.index(worker_full)
    assert (
        'relay_target_timing "$composition_pid" "$composition_log" "$composition_end" &'
        in script
    )
    assert 'relay_target_timing "$worker_pid" "$worker_log" "$worker_end" &' in script
    assert (
        'relay_target_timing "$selfhost_pid" "$selfhost_log" "$selfhost_end" &'
        in script
    )
    assert script.index(composition_full) < script.index(worker_full)
    assert script.index(json_serial) < script.index(composition_full)
    assert script.index(worker_full) < script.index('wait "$composition_pid"')
    assert script.count("if (( expected_skipped_config_tests == 0 )); then") == 1
    assert (
        script.count(
            "grep -Fo 'RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1' \"$composition_log\""
        )
        == 2
    )
    assert (
        script.count(
            "grep -Fo 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1' \"$composition_log\""
        )
        == 2
    )
    assert (
        script.count(
            "grep -Fo 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1' \"$composition_log\""
        )
        == 2
    )
    assert (
        script.count(
            "grep -Fo 'DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1' \"$composition_log\""
        )
        == 1
    )
    assert script.rstrip().endswith(
        'python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" '
        '--require-execution canvas "$worker_log"'
    )
    assert sorted(set(re.findall(r"--test-threads=(\d+)", script))) == ["1", "4"]


RENEWAL_GATES = [
    (
        PRIVATE_IP_PG,
        "didcomm_composed_delivery::run_renewal_private_ip_refusal",
    ),
    (
        "renewal_postgres_binding_and_same_successor_recovery_are_fenced",
        "renewal_binding_postgres::run",
    ),
    (
        "didcomm_renewal_http_composes_real_delivery_and_renewal_links",
        "didcomm_composed_delivery::run_renewal_http",
    ),
    (
        "renewal_fresh_packaged_main_delivers_both_encryption_modes",
        "renewal_fresh_main::run",
    ),
    (
        "renewal_packaged_main_recovers_historical_keyed_offer",
        "renewal_main_replay::run",
    ),
    (
        "didcomm_renewal_gateway_selects_native_with_required_owner_read",
        "didcomm_composed_delivery::run_renewal_gateway",
    ),
    (
        "didcomm_renewal_canvas_preserves_real_association_and_delivery_phases",
        "didcomm_composed_delivery::run_renewal_canvas",
    ),
]


def assert_renewal_registration(script, source, name, owner):
    check = f"printf '%s\\n' \"$all_test_names\" | grep -Fx '{name}: test'"
    assert script.splitlines().count(check) == 1
    function = re.search(
        rf"#\[tokio::test\]\s*async fn {name}\(\) \{{(.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert function is not None
    body = function.group(1)
    assert 'std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST")' in body
    assert "canvas_published_database::PublishedDatabase::start()" in body
    assert f"{owner}(&owned.url).await;" in body
    assert "owned.close_verified().unwrap();" in body
    if name == PRIVATE_IP_PG:
        marker = 'println!("\\nDIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1");'
        assert body.count(marker) == 1
        assert body.index("owned.close_verified().unwrap();") < body.index(marker)


def test_renewal_private_ip_pg_owner_keeps_real_adapter_and_fence_assertions() -> None:
    support = (
        ROOT / "rust/crates/canvas-acceptance/tests/support/didcomm_renewal_composed.rs"
    ).read_text(encoding="utf-8")
    graph = (
        ROOT
        / "rust/crates/canvas-acceptance/tests/support/didcomm_composed_delivery.rs"
    ).read_text(encoding="utf-8")
    required = (
        "PostgresCredentialRepository::new(",
        "PostgresCredentialLifecycle::new(",
        "NativeInitiationDidcommDelivery::new(",
        "DidcommEndpointValidator::new(false)",
        "fresh_initiation::services(",
        "CredentialRenewalService::new(",
        "NativeDidcommError::EndpointNotPublic",
        "InitiationDidcommTransportClaimOutcome::Absent",
        "snapshot(pool, &id).await",
        "builder.calls.load(Ordering::SeqCst), 0",
        "transport.attempts.load(Ordering::SeqCst), 0",
    )
    for token in required:
        assert token in support
    assert "pub(super) async fn run_renewal_private_ip_refusal" in graph
    assert "renewal::run_private_ip_refusal(&pool).await;" in graph


@pytest.mark.parametrize("name,owner", RENEWAL_GATES)
def test_renewal_gates_require_real_owned_database_and_cleanup(name, owner):
    source = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    assert_renewal_registration(SCRIPT.read_text(encoding="utf-8"), source, name, owner)


@pytest.mark.parametrize("name,owner", RENEWAL_GATES)
@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "ignored", "owner", "cleanup"]
)
def test_renewal_gate_registration_rejects_weakened_qualification(
    name, owner, mutation
):
    script = SCRIPT.read_text(encoding="utf-8")
    source = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    line = next(line for line in script.splitlines() if f"'{name}: test'" in line)
    if mutation == "missing":
        script = script.replace(line, "")
    elif mutation == "duplicate":
        script += "\n" + line + "\n"
    elif mutation == "ignored":
        source = source.replace(f"async fn {name}()", f"#[ignore]\nasync fn {name}()")
    elif mutation == "owner":
        source = source.replace(f"{owner}(&owned.url).await;", "")
    else:
        source = source.replace("owned.close_verified().unwrap();", "")
    with pytest.raises(AssertionError):
        assert_renewal_registration(script, source, name, owner)


@pytest.fixture
def shell_case(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash and Path(bash).is_file(), (
        "Executable Bash is mandatory for CI shell contracts"
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    doubles = {
        "python3": f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
        "docker": r"""#!/usr/bin/env bash
set -euo pipefail
record=docker
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
if [[ $# == 3 && "$1" == image && "$2" == inspect ]]; then exit 1; fi
[[ $# == 2 && "$1" == pull ]] || exit 90
[[ "$TEST_FAILURE" != docker ]] || exit 13
""",
        "jq": r"""#!/usr/bin/env bash
set -euo pipefail
printf 'jq|%s\n' "$1" >> "$TEST_LOG"
if [[ "$1" == -er ]]; then
  [[ "$#" == 3 && "$3" == ../contracts/canvas-worker-consumer-range-oracle.json ]] || exit 90
  [[ "$TEST_FAILURE" != images ]] || exit 17
  printf '%s\n' "$TEST_POSTGRES_IMAGE" "$TEST_PYTHON_IMAGE"
elif [[ "$#" == 6 && "$1" == -r && "$2" == --arg && "$3" == target ]]; then
  [[ "$6" == "$RUNNER_TEMP/rust-test-artifacts.json" ]] || exit 90
  [[ "$5" == *'.target.name == $target'* && "$5" == *'.profile.test == false'* && "$5" == *'#marty-issuance-service@'* ]] || exit 90
  [[ "$4" == marty-canvas-sync-worker || "$4" == marty-issuance-service ]] || exit 90
  if [[ "${TEST_REAL_WORKER_JQ:-0}" == 1 ]]; then
    exec /usr/bin/jq "$@"
  fi
  [[ "$TEST_FAILURE" != artifacts ]] || exit 18
  if [[ "$4" == marty-issuance-service ]]; then
    if [[ "$TEST_FAILURE" == missing-issuance-binary ]]; then
      printf '%s\n' "$RUNNER_TEMP/does-not-exist"
    elif [[ "$TEST_FAILURE" == duplicate-issuance-binaries ]]; then
      printf '%s\n%s\n' "$TEST_ISSUANCE_BINARY" "$RUNNER_TEMP/other-worker-binary"
    else
      printf '%s\n' "$TEST_ISSUANCE_BINARY"
    fi
  elif [[ "$TEST_FAILURE" == missing-worker-binary ]]; then
    printf '%s\n' "$RUNNER_TEMP/does-not-exist"
  elif [[ "$TEST_FAILURE" == duplicate-worker-binaries ]]; then
    printf '%s\n%s\n' "$TEST_WORKER_BINARY" "$RUNNER_TEMP/other-worker-binary"
  else
    printf '%s\n' "$TEST_WORKER_BINARY"
  fi
else
  [[ "$#" == 9 && "$1" == -r && "$2" == --arg && "$3" == target && "$5" == --arg && "$6" == package && "$9" == "$RUNNER_TEMP/rust-test-artifacts.json" ]] || exit 90
  [[ "$8" == *'"#" + $package + "@"'* ]] || exit 90
  [[ "$4" == canvas_published_schema_contract || "$4" == canvas_published_worker_contract || "$4" == flow_published_schema_contract || "$4" == selfhost_public_image_contract ]] || exit 90
  if [[ "$4" == canvas_published_worker_contract ]]; then
    [[ "$7" == marty-canvas-worker-acceptance ]] || exit 90
  elif [[ "$4" == flow_published_schema_contract ]]; then
    [[ "$7" == marty-flow-acceptance ]] || exit 90
  elif [[ "$4" == selfhost_public_image_contract ]]; then
    [[ "$7" == marty-selfhost-acceptance ]] || exit 90
  else
    [[ "$7" == marty-canvas-acceptance ]] || exit 90
  fi
  [[ "$TEST_FAILURE" != artifacts ]] || exit 18
  if [[ "$TEST_FAILURE" == missing-executable ]]; then
    printf './does-not-exist\n'
  elif [[ "$TEST_FAILURE" == duplicate-executables ]]; then
    printf './contract\n./different-contract\n'
  elif [[ "$4" == canvas_published_worker_contract ]]; then
    printf './worker-contract\n'
  elif [[ "$4" == flow_published_schema_contract ]]; then
    printf './flow-contract\n'
  elif [[ "$4" == selfhost_public_image_contract ]]; then
    printf './selfhost-contract\n'
  else
    printf './contract\n'
  fi
fi
""",
        "grep": r"""#!/usr/bin/env bash
set -euo pipefail
record=grep
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
exec /usr/bin/grep "$@"
""",
    }
    for name, source in doubles.items():
        path = fake_bin / name
        path.write_text(source, encoding="utf-8", newline="\n")
        path.chmod(0o755)
    contract = tmp_path / "contract"
    contract.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
name="${0##*/}"
[[ "$MARTY_CANVAS_WORKER_TEST_BINARY" == "$TEST_WORKER_BINARY" ]] || exit 91
if [[ "${TEST_WORKER_ONLY_MODE:-0}" != 1 ]]; then
  [[ "$MARTY_ISSUANCE_TEST_BINARY" == "$TEST_ISSUANCE_BINARY" ]] || exit 91
fi
record="child|$name|${MARTY_CANVAS_PUBLISHED_SCHEMA_TEST:-absent}"
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
if [[ "$#" == 1 && "$1" == --list ]]; then
  [[ "$TEST_FAILURE" != list ]] || exit 19
  while IFS= read -r registration; do printf '%s\n' "$registration"; done < "registrations-$name"
elif [[ "$#" -ge 3 && "$1" == --list && "$2" == --skip ]]; then
  while IFS= read -r registration; do
    keep=1
    for (( index=3; index<=$#; index+=2 )); do
      argument="${!index}"
      [[ "$registration" == *"$argument"* ]] && keep=0
    done
    (( keep == 0 )) || printf '%s\n' "$registration"
  done < "registrations-$name"
else
  [[ "$TEST_FAILURE" != execute ]] || exit 23
  if [[ "$name" == worker-contract && "$*" == *--test-threads=4* ]]; then
    printf 'retry-tier|%s\n' "${MARTY_CANVAS_WORKER_RETRY_AFTER_TIER:-absent}" >> "$TEST_LOG"
    printf 'validation-tier|%s\n' "${MARTY_CANVAS_WORKER_VALIDATION_TIER:-absent}" >> "$TEST_LOG"
  fi
  if [[ "$TEST_FAILURE" == json-serial && "$name" == contract &&
    "$1" == json_consumer_diagnostic_matches_published_boundaries ]]; then
    exit 26
  fi
  if [[ "$*" == *--test-threads=4* || ( "$name" == flow-contract && "$*" == *--test-threads=1* ) ]]; then
    printf 'full target %s\n' "$name"
    printf 'MARTY_CI_PHASE_V1 {"phase":"scenario","name":"%s","duration_ms":1,"status":"ok"}\n' "$name"
    [[ "$TEST_FAILURE" != "$name-full" ]] || exit 24
    if [[ "$name" == worker-contract ]]; then
      case "$TEST_FAST_OWNER_ROW" in
        ok) printf 'test worker_validation_repository_matches_frozen_errors ... ok\n' ;;
        missing) ;;
        duplicate) printf 'test worker_validation_repository_matches_frozen_errors ... ok\ntest worker_validation_repository_matches_frozen_errors ... ok\n' ;;
        ignored) printf 'test worker_validation_repository_matches_frozen_errors ... ignored\n' ;;
        failed) printf 'test worker_validation_repository_matches_frozen_errors ... FAILED\n' ;;
        substituted) printf 'test wrong_worker_validation_repository_matches_frozen_errors ... ok\n' ;;
      esac
    elif [[ "$name" == contract ]]; then
      if [[ "$*" != *"--skip timeout_consumer_matches_published_socket_behavior"* ]]; then
        case "$TEST_TIMEOUT_MARKER" in
          ok) printf 'PUBLISHED_TIMEOUT_CONSUMER_COMPLETE_V1\n' ;;
          missing) ;;
          duplicate) printf 'PUBLISHED_TIMEOUT_CONSUMER_COMPLETE_V1\nPUBLISHED_TIMEOUT_CONSUMER_COMPLETE_V1\n' ;;
        esac
      fi
      if [[ "$*" != *"--skip rendered_base_process::renderer_bounds_proof_is_image_free"* ]]; then
        case "$TEST_RENDERER_BOUNDS_MARKER" in
          ok) printf 'RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1\n' ;;
          prefixed) printf 'test %s ... RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1\nok\n' 'renderer-bounds' ;;
          missing) ;;
          duplicate) printf 'RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1\n' ;;
        esac
      fi
      if [[ "$*" != *"--skip rendered_base_process::rendered_base_renewal_config_crosses_encryption_and_private_address_policy"* ]]; then
      case "$TEST_RENDERED_CONFIG_MARKER" in
        ok) printf 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1\n' ;;
        prefixed) printf 'test %s ... RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1\nok\n' 'rendered-base-config' ;;
        missing) ;;
        duplicate) printf 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1\n' ;;
      esac
      fi
      case "${TEST_PRIVATE_IP_PG_MARKER:-ok}" in
        ok) printf 'DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1\n' ;;
        prefixed) printf 'test %s ... DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1\nok\n' 'private-ip-pg' ;;
        missing) ;;
        duplicate) printf 'DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1\n' ;;
      esac
      if [[ "$*" != *"--skip resolved_kubernetes_runtime::resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy"* ]]; then
      case "${TEST_K8S_CONFIG_MARKER:-ok}" in
        ok) printf 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1\n' ;;
        prefixed) printf 'test %s ... RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1\nok\n' 'k8s-config' ;;
        missing) ;;
        duplicate) printf 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1\n' ;;
      esac
      fi
    fi
    if [[ "$TEST_FAILURE" == barrier || "$TEST_FAILURE" == signal ]]; then
      touch "started-$name"
      for (( attempt=0; attempt<200; attempt++ )); do
        [[ -f started-contract && -f started-worker-contract && -f started-flow-contract && -f started-selfhost-contract ]] && break
        sleep 0.05
      done
      [[ -f started-contract && -f started-worker-contract && -f started-flow-contract && -f started-selfhost-contract ]] || exit 25
      if [[ "$TEST_FAILURE" == signal ]]; then
        trap 'printf "stopped|%s\n" "$name" >> "$TEST_LOG"; exit 143' TERM
        touch "armed-$name"
        if [[ "$name" == contract ]]; then
          for (( attempt=0; attempt<200; attempt++ )); do
            [[ -f armed-contract && -f armed-worker-contract && -f armed-flow-contract && -f armed-selfhost-contract ]] && break
            sleep 0.05
          done
          [[ -f armed-contract && -f armed-worker-contract && -f armed-flow-contract && -f armed-selfhost-contract ]] || exit 25
          kill -TERM "$TEST_PARENT_PID"
        fi
        while :; do sleep 0.05; done
      fi
    fi
  fi
fi
""",
        encoding="utf-8",
        newline="\n",
    )
    contract.chmod(0o755)
    worker_contract = tmp_path / "worker-contract"
    worker_contract.write_bytes(
        contract.read_bytes() + b"\n# distinct worker executable\n"
    )
    worker_contract.chmod(0o755)
    selfhost_contract = tmp_path / "selfhost-contract"
    selfhost_contract.write_bytes(
        contract.read_bytes() + b"\n# distinct selfhost executable\n"
    )
    selfhost_contract.chmod(0o755)
    flow_contract = tmp_path / "flow-contract"
    flow_contract.write_bytes(contract.read_bytes() + b"\n# distinct Flow executable\n")
    flow_contract.chmod(0o755)
    worker_binary = tmp_path / "worker-binary"
    worker_binary.write_bytes(worker_contract.read_bytes())
    worker_binary.chmod(0o755)
    other_worker_binary = tmp_path / "other-worker-binary"
    other_worker_binary.write_bytes(worker_contract.read_bytes())
    other_worker_binary.chmod(0o755)
    issuance_binary = tmp_path / "issuance-binary"
    issuance_binary.write_bytes(worker_contract.read_bytes())
    issuance_binary.chmod(0o755)

    def run(
        arguments=(),
        *,
        failure="",
        registrations=None,
        duplicate_across_targets=False,
        worker_artifacts=None,
        pins=PINS,
        run_id="12345",
        qualification=False,
        fast_owner_row="ok",
        config_marker="ok",
        renderer_marker="ok",
        timeout_marker="ok",
        private_ip_pg_marker="ok",
        k8s_config_marker="ok",
    ):
        lines = (
            registrations
            if registrations is not None
            else [
                f"{name}: test"
                for name in sorted(
                    set(required_registrations())
                    | set(MIGRATED_CASES)
                    | set(SELFHOST_CASES)
                    | set(FLOW_CASES)
                )
            ]
        )
        composition = [
            line
            for line in lines
            if line.startswith(
                (
                    "heartbeat_readiness_",
                    "json_consumer_diagnostic_",
                    "timeout_consumer_",
                    RENDERER_BOUNDS,
                    RENDERED_CONFIG,
                    PRIVATE_IP_PG,
                    K8S_RENDERED_CONFIG,
                )
            )
        ]
        selfhost = [
            line for line in lines if line.partition(": test")[0] in SELFHOST_CASES
        ]
        flow = [line for line in lines if line.partition(": test")[0] in FLOW_CASES]
        composition = [line for line in composition if line not in selfhost]
        worker = [
            line for line in lines if line not in composition and line not in selfhost and line not in flow
        ]
        if duplicate_across_targets:
            composition.append(f"{TARGET}: test")
        for name, subset in (
            ("contract", composition),
            ("flow-contract", flow),
            ("worker-contract", worker),
            ("selfhost-contract", selfhost),
        ):
            (tmp_path / f"registrations-{name}").write_text(
                "\n".join(subset) + "\n", encoding="utf-8"
            )
        log = tmp_path / "calls"
        log.write_text("", encoding="utf-8")
        if worker_artifacts is not None:
            bash_root = subprocess.run(
                [bash, "--noprofile", "--norc", "-c", "pwd"],
                cwd=tmp_path,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (tmp_path / "rust-test-artifacts.json").write_text(
                "\n".join(
                    json.dumps(artifact)
                    .replace("__WORKER_BINARY__", f"{bash_root}/worker-binary")
                    .replace(
                        "__OTHER_WORKER_BINARY__", f"{bash_root}/other-worker-binary"
                    )
                    .replace("__ISSUANCE_BINARY__", f"{bash_root}/issuance-binary")
                    for artifact in [
                        *worker_artifacts,
                        {
                            "reason": "compiler-artifact",
                            "package_id": "path+file:///checkout/rust/services/issuance#marty-issuance-service@0.1.0",
                            "target": {
                                "name": "marty-issuance-service",
                                "kind": ["bin"],
                            },
                            "profile": {"test": False},
                            "executable": "__ISSUANCE_BINARY__",
                        },
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
        environment = dict(os.environ)
        environment.update(
            {
                "TEST_FAILURE": failure,
                "TEST_FAST_OWNER_ROW": fast_owner_row,
                "TEST_RENDERED_CONFIG_MARKER": config_marker,
                "TEST_RENDERER_BOUNDS_MARKER": renderer_marker,
                "TEST_TIMEOUT_MARKER": timeout_marker,
                "TEST_PRIVATE_IP_PG_MARKER": private_ip_pg_marker,
                "TEST_K8S_CONFIG_MARKER": k8s_config_marker,
                "TEST_POSTGRES_IMAGE": pins[0],
                "TEST_PYTHON_IMAGE": pins[1],
                "TEST_REAL_WORKER_JQ": "1" if worker_artifacts is not None else "0",
                "TEST_WORKER_ONLY_MODE": "1"
                if arguments and arguments[0].startswith("worker-")
                else "0",
                "CONTRACT_SOURCE": SCRIPT.as_posix(),
                "GITHUB_RUN_ID": run_id,
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_JOB": "test-rust-services",
                "GITHUB_SHA": "a" * 40,
                "MARTY_CANVAS_FULL_QUALIFICATION": "1" if qualification else "0",
                SCHEMA_ENV: "0",
            }
        )
        # Fake binaries shadow commands even if the shell uses `command docker`.
        wrapper = """export PATH="$PWD/fake-bin:/usr/bin:/bin"
export TEST_LOG="$PWD/calls" RUNNER_TEMP="$PWD"
export TEST_PARENT_PID="$BASHPID"
export TEST_WORKER_BINARY="$PWD/worker-binary"
export TEST_ISSUANCE_BINARY="$PWD/issuance-binary"
source "$CONTRACT_SOURCE" "$@"
"""
        result = subprocess.run(
            [bash, "--noprofile", "--norc", "-c", wrapper, "synthetic-ci", *arguments],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        calls = [
            line.split("|") for line in log.read_text(encoding="utf-8").splitlines()
        ]
        return result, calls

    return run


@pytest.mark.parametrize(
    "arguments,qualification,expected",
    [
        ([], False, "full"),
        (["full"], False, "full"),
        (["full"], True, "full"),
        (["full-after-preflights"], False, "routine"),
        (["full-after-preflights"], True, "full"),
    ],
)
def test_nested_tiers_select_worker_and_historical_timeout_owners(
    shell_case, tmp_path, arguments, qualification, expected
):
    if arguments == ["full-after-preflights"]:
        evidence = tmp_path / "canvas-published-preflights.sha256"
        evidence.write_text(
            hashlib.sha256((tmp_path / "worker-contract").read_bytes()).hexdigest()
            + f"\n12345\n1\ntest-rust-services\n{int(qualification)}\n",
            newline="\n",
        )
    result, calls = shell_case(arguments, qualification=qualification)
    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call[0] == "retry-tier"] == [
        ["retry-tier", expected]
    ]
    assert [call for call in calls if call[0] == "validation-tier"] == [
        ["validation-tier", expected]
    ]
    composition = next(
        call
        for call in calls
        if call[:2] == ["child", "contract"] and "--test-threads=4" in call
    )
    assert ("timeout_consumer_matches_published_socket_behavior" in composition) == (
        arguments == ["full-after-preflights"] and not qualification
    )
    flow = [
        call
        for call in calls
        if call[:2] == ["child", "flow-contract"] and "--test-threads=4" in call
    ]
    assert len(flow) == 1
    assert '"phase":"canvas_target","name":"flow"' in result.stdout


def test_flow_target_failure_fails_complete_canvas_gate(shell_case):
    result, calls = shell_case(["full"], failure="flow-contract-full")
    assert result.returncode != 0
    assert any(call[:2] == ["child", "flow-contract"] for call in calls)
    assert '"phase":"canvas_target","name":"flow"' in result.stdout
    assert '"status":"failed"' in result.stdout


@pytest.mark.parametrize("timeout_marker", ["missing", "duplicate"])
def test_full_timeout_reference_requires_one_verified_completion(
    shell_case, timeout_marker
):
    result, _ = shell_case(["full"], qualification=True, timeout_marker=timeout_marker)
    assert result.returncode != 0
    assert "Published HTTPX timeout reference did not match" in result.stderr


def test_caller_cannot_override_native_retry_tier(shell_case, monkeypatch):
    monkeypatch.setenv("MARTY_CANVAS_WORKER_RETRY_AFTER_TIER", "routine")
    result, calls = shell_case(["full"], qualification=True)
    assert result.returncode == 2
    assert "tier is owned by this runner" in result.stderr
    assert not any(call[0] in {"docker", "child"} for call in calls)


@pytest.mark.parametrize("qualification", [False, True])
def test_caller_cannot_override_native_validation_tier(
    shell_case, monkeypatch, qualification
):
    monkeypatch.setenv("MARTY_CANVAS_WORKER_VALIDATION_TIER", "routine")
    result, calls = shell_case(["full"], qualification=qualification)
    assert result.returncode == 2
    assert "tier is owned by this runner" in result.stderr
    assert not any(call[0] in {"docker", "child"} for call in calls)


@pytest.mark.parametrize(
    "row", ["missing", "duplicate", "ignored", "failed", "substituted"]
)
@pytest.mark.parametrize("mode", ["full", "worker-full"])
def test_canvas_fast_owner_must_actually_pass_once(shell_case, row, mode):
    result, calls = shell_case([mode], fast_owner_row=row)
    assert result.returncode != 0
    assert any(call[0] == "child" and call[1] == "worker-contract" for call in calls)
    assert "fast owner did not execute exactly once and pass" in result.stderr


@pytest.mark.parametrize("marker", ["missing", "duplicate"])
def test_rendered_config_marker_must_complete_exactly_once(shell_case, marker):
    result, calls = shell_case(["full"], config_marker=marker)
    assert result.returncode != 0
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )
    assert (
        "configuration proof did not execute and complete exactly once" in result.stderr
    )


def test_rendered_config_marker_accepts_interleaved_harness_output(shell_case):
    result, calls = shell_case(["full"], config_marker="prefixed")
    assert result.returncode == 0, result.stderr
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )


@pytest.mark.parametrize("marker", ["missing", "duplicate"])
def test_renderer_bounds_marker_must_complete_exactly_once(shell_case, marker):
    result, calls = shell_case(["full"], renderer_marker=marker)
    assert result.returncode != 0
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )
    assert "Renderer bounds proof did not execute and complete exactly once" in result.stderr


def test_renderer_bounds_marker_accepts_interleaved_harness_output(shell_case):
    result, calls = shell_case(["full"], renderer_marker="prefixed")
    assert result.returncode == 0, result.stderr
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )


def _config_evidence(tmp_path, *, qualification=False):
    record = {
        "schema": 1,
        "composition_sha256": hashlib.sha256(
            (tmp_path / "contract").read_bytes()
        ).hexdigest(),
        "run": {
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "test-rust-services",
            "GITHUB_SHA": "a" * 40,
        },
        "qualification": "1" if qualification else "0",
        "cases": [RENDERER_BOUNDS, RENDERED_CONFIG, K8S_RENDERED_CONFIG],
    }
    (tmp_path / "canvas-config-proofs.json").write_text(
        json.dumps(record) + "\n", encoding="ascii"
    )
    return record


@pytest.mark.parametrize("qualification", [False, True])
@pytest.mark.parametrize("mode", ["full", "full-after-preflights"])
def test_same_run_composition_proof_skips_only_three_completed_cases(
    shell_case, tmp_path, qualification, mode
):
    _config_evidence(tmp_path, qualification=qualification)
    if mode == "full-after-preflights":
        (tmp_path / "canvas-published-preflights.sha256").write_text(
            hashlib.sha256((tmp_path / "worker-contract").read_bytes()).hexdigest()
            + f"\n12345\n1\ntest-rust-services\n{int(qualification)}\n",
            encoding="ascii",
            newline="\n",
        )
    result, calls = shell_case([mode], qualification=qualification)
    assert result.returncode == 0, result.stderr
    composition = [
        call
        for call in calls
        if call[:2] == ["child", "contract"] and "--test-threads=4" in call
    ]
    assert len(composition) == 1
    assert composition[0].count(RENDERER_BOUNDS) == 1
    assert composition[0].count(RENDERED_CONFIG) == 1
    assert composition[0].count(K8S_RENDERED_CONFIG) == 1
    assert composition[0].count("--skip") == (
        5 if mode == "full-after-preflights" and not qualification else 4
    )  # serial, three image-free cases, and routine-only historical HTTPX proof
    assert PRIVATE_IP_PG not in composition[0]


@pytest.mark.parametrize(
    "mutation", ["missing", "hash", "run", "tier", "source", "cases", "malformed"]
)
def test_untrusted_composition_proof_falls_back_to_full_execution(
    shell_case, tmp_path, mutation
):
    if mutation != "missing":
        record = _config_evidence(tmp_path)
        if mutation == "hash":
            record["composition_sha256"] = "0" * 64
        elif mutation == "run":
            record["run"]["GITHUB_RUN_ATTEMPT"] = "other"
        elif mutation == "tier":
            record["qualification"] = "1"
        elif mutation == "source":
            record["run"]["GITHUB_SHA"] = "b" * 40
        elif mutation == "cases":
            record["cases"] = [RENDERED_CONFIG]
        (tmp_path / "canvas-config-proofs.json").write_text(
            "not-json" if mutation == "malformed" else json.dumps(record),
            encoding="ascii",
        )
    result, calls = shell_case(["full"])
    assert result.returncode == 0, result.stderr
    composition = [
        call
        for call in calls
        if call[:2] == ["child", "contract"] and "--test-threads=4" in call
    ]
    assert len(composition) == 1
    assert RENDERER_BOUNDS not in composition[0]
    assert RENDERED_CONFIG not in composition[0]
    assert K8S_RENDERED_CONFIG not in composition[0]


@pytest.mark.parametrize("marker", ["missing", "duplicate"])
def test_renewal_private_ip_pg_marker_must_complete_exactly_once(shell_case, marker):
    result, calls = shell_case(["full"], private_ip_pg_marker=marker)
    assert result.returncode != 0
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )
    assert (
        "Published-SQL renewal private-IP refusal proof did not execute"
        in result.stderr
    )


def test_renewal_private_ip_pg_marker_accepts_interleaved_harness_output(shell_case):
    result, calls = shell_case(["full"], private_ip_pg_marker="prefixed")
    assert result.returncode == 0, result.stderr
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )


@pytest.mark.parametrize("marker", ["missing", "duplicate"])
def test_k8s_renewal_config_marker_must_complete_exactly_once(shell_case, marker):
    result, calls = shell_case(["full"], k8s_config_marker=marker)
    assert result.returncode != 0
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )
    assert (
        "Resolved Kubernetes renewal 2x2 configuration proof did not execute"
        in result.stderr
    )


def test_k8s_renewal_config_marker_accepts_interleaved_harness_output(shell_case):
    result, calls = shell_case(["full"], k8s_config_marker="prefixed")
    assert result.returncode == 0, result.stderr
    assert any(
        call[:2] == ["child", "contract"] and "--test-threads=4" in call
        for call in calls
    )


def test_k8s_renewal_config_owner_is_opt_in_and_completes_after_four_cases() -> None:
    target = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    source = (
        ROOT
        / "rust/crates/canvas-acceptance/tests/support/resolved_kubernetes_runtime.rs"
    ).read_text(encoding="utf-8")
    assert (
        '#[path = "support/resolved_kubernetes_runtime.rs"]\nmod resolved_kubernetes_runtime;'
        in target
    )
    owner = "fn resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy() {"
    assert source.count(owner) == 1
    body = source.split(owner, 1)[1]
    assert "#[test]\n" + owner in source
    assert 'if !cfg!(target_os = "linux")' in body
    assert 'std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST")' in body
    assert "let prepared = Prepared::prepare()" in body
    assert body.count("resolve(&spec, &prepared)") == 1
    assert "(false, false), (true, false), (false, true), (true, true)" in body
    assert body.index("assert_eq!(seen.len(), 4);") < body.index(
        'println!("\\nRESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1");'
    )


def test_worker_preflight_does_not_claim_rendered_config_completion(shell_case):
    result, calls = shell_case(["timeout-preflight"], config_marker="missing")
    assert result.returncode == 0, result.stderr
    assert not any("--test-threads=4" in call for call in calls)


def test_opt_in_worker_full_keeps_exact_worker_owner_without_composition(shell_case):
    result, calls = shell_case(["worker-full"])
    assert result.returncode == 0, result.stderr
    children = [call for call in calls if call[0] == "child"]
    assert all(call[1] == "worker-contract" for call in children)
    assert children[0] == ["child", "worker-contract", "1", "--list"]
    assert any("--test-threads=1" in call for call in children)
    assert any("--test-threads=4" in call for call in children)
    for target in HISTORICAL_SERIAL:
        assert sum(call[3:] == [target, "--exact", "--nocapture", "--test-threads=1"] for call in children) == 1
    parallel = next(call for call in children if "--test-threads=4" in call)
    assert all(["--skip", target] == parallel[i : i + 2] for target in HISTORICAL_SERIAL for i in [parallel.index(target) - 1])
    assert [call for call in calls if call[0] == "docker"] == [
        ["docker", "image", "inspect", PINS[0]],
        ["docker", "image", "inspect", "mirror.gcr.io/library/" + PINS[0]],
        ["docker", "pull", "mirror.gcr.io/library/" + PINS[0]],
        ["docker", "pull", PINS[1]],
    ]
    assert (
        "Canvas tier inventory: exact compiled worker selection confirmed"
        in result.stdout
    )


@pytest.mark.parametrize("name,target", PREFLIGHTS)
def test_opt_in_worker_preflight_needs_only_its_owned_target(
    shell_case, name: str, target: str
):
    result, calls = shell_case([f"worker-{name}"])
    assert result.returncode == 0, result.stderr
    children = [call for call in calls if call[0] == "child"]
    assert children == [
        ["child", "worker-contract", "1", "--list"],
        [
            "child",
            "worker-contract",
            "1",
            target,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
    ]
    assert not any(
        call[1:3] == ["-r", "--arg"] and "canvas_published_schema_contract" in call
        for call in calls
    )


def test_opt_in_worker_reuse_requires_exact_run_bound_proof_before_image_pull(
    shell_case, tmp_path
):
    evidence = tmp_path / "canvas-published-preflights.sha256"
    result, calls = shell_case(["worker-full-after-preflights"])
    assert result.returncode != 0
    assert not any(call[0] == "docker" for call in calls)
    evidence.write_text(
        hashlib.sha256((tmp_path / "worker-contract").read_bytes()).hexdigest()
        + "\n12345\n1\ntest-rust-services\n0\n",
        newline="\n",
    )
    result, calls = shell_case(["worker-full-after-preflights"])
    assert result.returncode == 0, result.stderr
    worker_full = next(
        call
        for call in calls
        if call[:2] == ["child", "worker-contract"] and "--test-threads=4" in call
    )
    assert [
        worker_full[index + 1]
        for index, item in enumerate(worker_full[:-1])
        if item == "--skip"
    ] == [
        "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings",
        DEADLINE_TARGET,
        *FAST_MODE_SKIPS,
    ]
    assert not any(call[:2] == ["child", "contract"] for call in calls)
    mismatched, mismatched_calls = shell_case(
        ["worker-full-after-preflights"], run_id="other-run"
    )
    assert mismatched.returncode != 0
    assert not any(call[0] == "docker" for call in mismatched_calls)


def test_opt_in_worker_failure_propagates_and_removes_owned_log(shell_case, tmp_path):
    result, calls = shell_case(["worker-full"], failure="worker-contract-full")
    assert result.returncode != 0
    assert any("--test-threads=4" in call for call in calls)
    assert not list(tmp_path.glob("canvas-worker-only.*"))


def test_opt_in_worker_missing_case_fails_before_image_pull(shell_case):
    cases = [
        f"{name}: test"
        for name in sorted(set(required_registrations()) | set(MIGRATED_CASES))
        if name != TIMEOUT_TARGET
    ]
    result, calls = shell_case(["worker-full"], registrations=cases)
    assert result.returncode != 0
    assert not any(call[0] == "docker" for call in calls)


def test_opt_in_worker_same_count_substitution_fails_before_image_pull(shell_case):
    names = sorted(set(required_registrations()) | set(MIGRATED_CASES))
    cases = [
        f"{('substituted_worker_timeout' if name == TIMEOUT_TARGET else name)}: test"
        for name in names
    ]
    result, calls = shell_case(["worker-full"], registrations=cases)
    assert result.returncode != 0
    assert not any(call[0] == "docker" for call in calls)


@pytest.mark.parametrize("substitution", [False, True])
def test_selfhost_case_inventory_fails_closed_before_image_pull(
    shell_case, substitution
):
    names = sorted(
        set(required_registrations()) | set(MIGRATED_CASES) | set(SELFHOST_CASES)
    )
    removed = "selfhost_packaged_runtime::tests::cleanup_failure_retains_scratch_and_original_failure"
    cases = [f"{name}: test" for name in names if name != removed]
    if substitution:
        cases.append("substituted_selfhost_cleanup_case: test")
    result, calls = shell_case(registrations=cases)
    assert result.returncode != 0
    assert not any(call[0] == "docker" for call in calls)
    assert not any("--test-threads=4" in call for call in calls)


@pytest.mark.parametrize("arguments", [[], ["full"]])
def test_default_and_explicit_full_keep_all_registrations_and_run_every_test(
    shell_case, arguments
):
    result, calls = shell_case(arguments)
    assert result.returncode == 0, result.stderr
    checks = [call[2] for call in calls if call[:2] == ["grep", "-Fx"]]
    serial = "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings"
    json_serial = "json_consumer_diagnostic_matches_published_boundaries"
    assert checks == [
        f"{name}: test"
        for name in required_registrations()
        if name not in FLOW_HISTORICAL_ROSTER
    ] + [
        f"{serial}: test",
        f"{DEADLINE_TARGET}: test",
        f"{json_serial}: test",
        *(f"{target}: test" for target in HISTORICAL_SERIAL),
    ]
    children = [call for call in calls if call[0] == "child"]
    assert children[:11] == [
        ["child", "contract", "1", "--list"],
        ["child", "worker-contract", "1", "--list"],
        ["child", "selfhost-contract", "1", "--list"],
        ["child", "flow-contract", "1", "--list"],
        ["child", "contract", "1", "--list", "--skip", json_serial],
        ["child", "worker-contract", "1", "--list", "--skip", serial, "--skip", DEADLINE_TARGET, *[item for target in HISTORICAL_SERIAL for item in ("--skip", target)]],
        [
            "child",
            "worker-contract",
            "1",
            serial,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
        [
            "child",
            "worker-contract",
            "1",
            DEADLINE_TARGET,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
        *[
            ["child", "worker-contract", "1", target, "--exact", "--nocapture", "--test-threads=1"]
            for target in HISTORICAL_SERIAL
        ],
        [
            "child",
            "contract",
            "1",
            json_serial,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
    ]
    assert sorted(children[11:]) == sorted(
        [
            [
                "child",
                "contract",
                "1",
                "--skip",
                json_serial,
                "--nocapture",
                "--test-threads=4",
            ],
            [
                "child",
                "worker-contract",
                "1",
                "--skip",
                serial,
                "--skip",
                DEADLINE_TARGET,
                *[item for target in HISTORICAL_SERIAL for item in ("--skip", target)],
                "--nocapture",
                "--test-threads=4",
            ],
            [
                "child",
                "selfhost-contract",
                "1",
                "--nocapture",
                "--test-threads=4",
            ],
            [
                "child",
                "flow-contract",
                "1",
                "--nocapture",
                "--test-threads=4",
            ],
        ]
    )
    assert [call for call in calls if call[0] == "docker"] == [
        ["docker", "image", "inspect", PINS[0]],
        ["docker", "image", "inspect", "mirror.gcr.io/library/" + PINS[0]],
        ["docker", "pull", "mirror.gcr.io/library/" + PINS[0]],
        ["docker", "pull", PINS[1]],
    ]


def test_proven_preflights_are_skipped_only_in_explicit_reuse_mode(
    shell_case, tmp_path
):
    evidence = tmp_path / "canvas-published-preflights.sha256"
    evidence.write_text(
        hashlib.sha256((tmp_path / "worker-contract").read_bytes()).hexdigest()
        + "\n12345\n1\ntest-rust-services\n0\n",
        newline="\n",
    )
    result, calls = shell_case(["full-after-preflights"])
    assert result.returncode == 0, result.stderr
    children = [call for call in calls if call[0] == "child"]
    skipped = FAST_MODE_SKIPS
    assert [
        "child",
        "worker-contract",
        "1",
        "--skip",
        "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings",
        "--skip",
        DEADLINE_TARGET,
        *[item for target in skipped for item in ("--skip", target)],
        "--nocapture",
        "--test-threads=4",
    ] in children
    assert not any(
        call[3:5] == [target, "--exact"] for call in children for target in skipped
    )

    mismatched, mismatched_calls = shell_case(
        ["full-after-preflights"], qualification=True
    )
    assert mismatched.returncode != 0
    assert not any(call[0] == "docker" for call in mismatched_calls)
    evidence.write_text(evidence.read_text().replace("\n0\n", "\n1\n"), newline="\n")
    result, calls = shell_case(["full-after-preflights"], qualification=True)
    assert result.returncode == 0, result.stderr
    worker_full = next(
        call
        for call in calls
        if call[:2] == ["child", "worker-contract"] and "--test-threads=4" in call
    )
    assert [
        worker_full[index + 1]
        for index, item in enumerate(worker_full[:-1])
        if item == "--skip"
    ] == [
        "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings",
        DEADLINE_TARGET,
        *HISTORICAL_SERIAL,
        TARGET,
        BODY_TIMEOUT_TARGET,
        TIMEOUT_TARGET,
        LEASE_EXPIRY_TARGET,
    ]
    assert "reference_matches_published" not in worker_full

    result, calls = shell_case([])
    assert result.returncode == 0, result.stderr
    assert any(
        call[:2] == ["child", "worker-contract"]
        and "--test-threads=4" in call
        and call.count("--skip") == 4
        for call in calls
    )

    result, calls = shell_case(["full-after-preflights"], run_id="other-run")
    assert result.returncode != 0
    assert not any("--test-threads=4" in call for call in calls)
    assert not any(call[0] == "docker" for call in calls)


def test_full_targets_reach_the_barrier_concurrently(shell_case, tmp_path):
    result, calls = shell_case(failure="barrier")
    assert result.returncode == 0, result.stderr
    full = [call for call in calls if "--test-threads=4" in call]
    assert {call[1] for call in full} == {
        "contract",
        "worker-contract",
        "flow-contract",
        "selfhost-contract",
    }
    assert "Canvas composition target exit: 0" in result.stdout
    assert "Canvas worker target exit: 0" in result.stdout
    assert "Flow target exit: 0" in result.stdout
    assert "Selfhost target exit: 0" in result.stdout
    assert "full target contract" in result.stdout
    assert "full target worker-contract" in result.stdout
    assert "full target flow-contract" in result.stdout
    assert "full target selfhost-contract" in result.stdout
    assert not list(tmp_path.glob("canvas-targets.*"))


def test_failed_serial_json_probe_stops_before_parallel_targets(shell_case):
    result, calls = shell_case(failure="json-serial")
    assert result.returncode != 0
    assert any(
        call[1:5]
        == [
            "contract",
            "1",
            "json_consumer_diagnostic_matches_published_boundaries",
            "--exact",
        ]
        for call in calls
        if call[0] == "child"
    )
    assert not any("--test-threads=4" in call for call in calls)


def test_signal_reports_both_target_logs_before_cleanup(shell_case, tmp_path):
    result, calls = shell_case(failure="signal")
    assert result.returncode == 143
    assert {call[1] for call in calls if "--test-threads=4" in call} == {
        "contract",
        "worker-contract",
        "flow-contract",
        "selfhost-contract",
    }
    assert "Canvas composition target exit:" in result.stdout
    assert "Canvas worker target exit:" in result.stdout
    assert "Flow target exit:" in result.stdout
    assert "Selfhost target exit:" in result.stdout
    assert "full target contract" in result.stdout
    assert "full target worker-contract" in result.stdout
    assert "full target flow-contract" in result.stdout
    assert "full target selfhost-contract" in result.stdout
    assert {call[1] for call in calls if call[0] == "stopped"} == {
        "contract",
        "worker-contract",
        "flow-contract",
        "selfhost-contract",
    }
    assert not list(tmp_path.glob("canvas-targets.*"))


def test_fast_targets_relay_each_marker_before_final_raw_logs(shell_case):
    result, _ = shell_case()
    assert result.returncode == 0, result.stderr
    assert "tail: cannot open" not in result.stderr
    assert "Optional Canvas target timing unavailable" not in result.stderr
    live = result.stdout.split("Canvas composition target exit:", 1)[0]
    assert live.count('"name":"contract"') == 1
    assert live.count('"name":"worker-contract"') == 1
    assert live.count('"name":"flow-contract"') == 1
    assert live.count('"name":"selfhost-contract"') == 1
    assert (
        result.stdout.count('MARTY_CI_PHASE_V1 {"phase":"scenario","name":"contract"')
        == 2
    )
    assert (
        result.stdout.count(
            'MARTY_CI_PHASE_V1 {"phase":"scenario","name":"worker-contract"'
        )
        == 2
    )
    assert (
        result.stdout.count(
            '[raw-log] MARTY_CI_PHASE_V1 {"phase":"scenario","name":"contract"'
        )
        == 1
    )
    assert (
        result.stdout.count(
            '[raw-log] MARTY_CI_PHASE_V1 {"phase":"scenario","name":"worker-contract"'
        )
        == 1
    )
    assert (
        result.stdout.count(
            '[raw-log] MARTY_CI_PHASE_V1 {"phase":"scenario","name":"selfhost-contract"'
        )
        == 1
    )
    assert (
        result.stdout.count(
            '[raw-log] MARTY_CI_PHASE_V1 {"phase":"scenario","name":"flow-contract"'
        )
        == 1
    )


def test_explicit_database_close_cannot_emit_second_cleanup_timing():
    source = (
        ROOT / "rust/services/issuance/tests/support/canvas_published_database.rs"
    ).read_text(encoding="utf-8")
    cleanup = source.split("    fn cleanup(&mut self) -> Result<(), String> {", 1)[1]
    cleanup = cleanup.split("    pub fn close(mut self)", 1)[0]
    assert cleanup.index("if self.probe.is_none() && self.postgres.is_none()") < (
        cleanup.index('PhaseTimer::start("cleanup", "published_database_removal")')
    )
    assert "self.probe = None;" in cleanup
    assert "self.postgres = None;" in cleanup
    assert "self.cleanup()" in source.split("impl Drop for PublishedDatabase {", 1)[1]


@pytest.mark.parametrize("failed", ["contract", "worker-contract", "flow-contract", "selfhost-contract"])
def test_full_target_failure_is_not_masked_by_other_target(
    shell_case, tmp_path, failed
):
    result, calls = shell_case(failure=f"{failed}-full")
    assert result.returncode != 0
    full = [call for call in calls if "--test-threads=4" in call]
    assert {call[1] for call in full} == {
        "contract",
        "worker-contract",
        "flow-contract",
        "selfhost-contract",
    }
    assert "Canvas composition target exit:" in result.stdout
    assert "Canvas worker target exit:" in result.stdout
    assert "Flow target exit:" in result.stdout
    assert "Selfhost target exit:" in result.stdout
    assert "full target contract" in result.stdout
    assert "full target worker-contract" in result.stdout
    assert "full target flow-contract" in result.stdout
    assert "full target selfhost-contract" in result.stdout
    assert not list(tmp_path.glob("canvas-targets.*"))


@pytest.mark.parametrize("evidence", ["missing", "wrong", "malformed"])
def test_reuse_mode_fails_closed_without_matching_evidence(
    shell_case, tmp_path, evidence
):
    path = tmp_path / "canvas-published-preflights.sha256"
    if evidence == "wrong":
        path.write_text("0" * 64 + "\n12345\n1\ntest-rust-services\n0\n")
    elif evidence == "malformed":
        path.write_text("not-a-digest\n")
    result, calls = shell_case(["full-after-preflights"])
    assert result.returncode != 0
    assert not any("--test-threads=4" in call for call in calls)
    assert not any(call[0] == "docker" for call in calls)


def test_reuse_mode_rejects_composition_executable_digest(shell_case, tmp_path):
    (tmp_path / "canvas-published-preflights.sha256").write_text(
        hashlib.sha256((tmp_path / "contract").read_bytes()).hexdigest()
        + "\n12345\n1\ntest-rust-services\n0\n",
        newline="\n",
    )
    result, calls = shell_case(["full-after-preflights"])
    assert result.returncode != 0
    assert not any(call[0] == "docker" for call in calls)


def test_duplicate_name_across_targets_fails_before_docker(shell_case):
    result, calls = shell_case(duplicate_across_targets=True)
    assert result.returncode != 0
    assert "Duplicate Canvas test names" in result.stderr
    assert not any(call[0] == "docker" for call in calls)
    assert not any("--test-threads=4" in call for call in calls)


def test_real_jq_selects_only_the_owned_non_test_worker_binary(shell_case):
    if os.name == "nt":
        pytest.skip("real jq is exercised in Linux CI; Windows Git Bash has no jq")

    def artifact(package, kind, test, executable):
        return {
            "reason": "compiler-artifact",
            "package_id": f"path+file:///checkout/rust/services/issuance#{package}@0.1.0",
            "target": {"name": "marty-canvas-sync-worker", "kind": kind},
            "profile": {"test": test},
            "executable": executable,
        }

    real = artifact("marty-issuance-service", ["bin"], False, "__WORKER_BINARY__")
    decoys = [
        artifact("marty-issuance-service", ["bin"], True, "__OTHER_WORKER_BINARY__"),
        artifact(
            "marty-issuance-service-copy", ["bin"], False, "__OTHER_WORKER_BINARY__"
        ),
        artifact("marty-issuance-service", ["test"], False, "__OTHER_WORKER_BINARY__"),
    ]
    result, calls = shell_case(["timeout-preflight"], worker_artifacts=[*decoys, real])
    assert result.returncode == 0, result.stderr
    assert any(call[:2] == ["child", "worker-contract"] for call in calls)

    result, calls = shell_case(["timeout-preflight"], worker_artifacts=decoys)
    assert result.returncode != 0
    assert "Expected one real marty-canvas-sync-worker binary artifact" in result.stderr
    assert not any(call[0] == "docker" for call in calls)

    duplicate = artifact(
        "marty-issuance-service", ["bin"], False, "__OTHER_WORKER_BINARY__"
    )
    result, calls = shell_case(
        ["timeout-preflight"], worker_artifacts=[*decoys, real, duplicate]
    )
    assert result.returncode != 0
    assert "Expected one real marty-canvas-sync-worker binary artifact" in result.stderr
    assert not any(call[0] == "docker" for call in calls)


def test_full_mode_rejects_a_skip_that_would_drop_another_test(shell_case):
    registrations = [
        f"{name}: test"
        for name in sorted(
            set(required_registrations()) | set(MIGRATED_CASES) | set(SELFHOST_CASES)
        )
    ]
    registrations.append(
        "worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings_extra: test"
    )
    result, calls = shell_case(registrations=registrations)
    assert result.returncode != 0
    assert not any("--test-threads=4" in call for call in calls)


@pytest.mark.parametrize("mode,target", PREFLIGHTS)
def test_preflight_requires_only_exact_target_and_forces_configured_serial_execution(
    shell_case, mode, target
):
    result, calls = shell_case(
        [mode],
        registrations=[
            f"{RENDERED_CONFIG}: test",
            f"{RENDERER_BOUNDS}: test",
            f"{target}: test",
        ],
    )
    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call[:2] == ["grep", "-Fx"]] == [
        ["grep", "-Fx", f"{RENDERED_CONFIG}: test"],
        ["grep", "-Fx", f"{RENDERER_BOUNDS}: test"],
        ["grep", "-Fx", f"{target}: test"],
    ]
    assert [call for call in calls if call[0] == "child"] == [
        ["child", "contract", "1", "--list"],
        ["child", "worker-contract", "1", "--list"],
        [
            "child",
            "worker-contract",
            "1",
            target,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
    ]


def test_preflight_rejects_missing_compiled_config_owner(shell_case):
    result, calls = shell_case(
        ["timeout-preflight"], registrations=[f"{TIMEOUT_TARGET}: test"]
    )
    assert result.returncode != 0
    assert [call for call in calls if call[0] == "child"] == [
        ["child", "contract", "1", "--list"],
        ["child", "worker-contract", "1", "--list"],
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        [""],
        ["unknown"],
        ["--help"],
        [TARGET],
        [TIMEOUT_TARGET],
        [BODY_TIMEOUT_TARGET],
        [LEASE_EXPIRY_TARGET],
        ["full", "extra"],
        ["mixed-roster-preflight", "extra"],
        ["timeout-preflight", "extra"],
        ["timeout-preflight", ""],
        ["timeout-preflight; docker ps"],
        ["body-timeout-preflight", "extra"],
        ["body-timeout-preflight", ""],
        ["body-timeout-preflight; docker ps"],
        ["lease-expiry-preflight", "extra"],
        ["lease-expiry-preflight", ""],
        ["lease-expiry-preflight; docker ps"],
        ["lease-expiry-preflight "],
        ["lease-expiry"],
    ],
)
def test_invalid_mode_or_extra_argument_fails_before_any_external_work(
    shell_case, arguments
):
    result, calls = shell_case(arguments)
    assert result.returncode == 2
    assert calls == []


@pytest.mark.parametrize("mode,target", PREFLIGHTS)
@pytest.mark.parametrize(
    "shape", ["missing", "bare", "prefix", "suffix", "other-preflight"]
)
def test_preflight_rejects_missing_or_inexact_registration_without_running_it(
    shell_case, mode, target, shape
):
    registration = {
        "missing": "",
        "bare": target,
        "prefix": f"prefix::{target}: test",
        "suffix": f"{target}_suffix: test",
        "other-preflight": f"{TIMEOUT_TARGET if target == TARGET else TARGET}: test",
    }[shape]
    result, calls = shell_case(
        [mode], registrations=[f"{RENDERED_CONFIG}: test", registration]
    )
    assert result.returncode != 0
    assert [call for call in calls if call[0] == "child"] == [
        ["child", "contract", "1", "--list"],
        ["child", "worker-contract", "1", "--list"],
    ]


@pytest.mark.parametrize(
    "failure",
    [
        "images",
        "docker",
        "artifacts",
        "missing-executable",
        "duplicate-executables",
        "missing-worker-binary",
        "duplicate-worker-binaries",
        "missing-issuance-binary",
        "duplicate-issuance-binaries",
        "list",
        "execute",
    ],
)
@pytest.mark.parametrize("mode,target", PREFLIGHTS)
def test_preflight_propagates_preparation_listing_and_test_failures(
    shell_case, mode, target, failure
):
    result, calls = shell_case([mode], failure=failure)
    assert result.returncode != 0
    children = [call for call in calls if call[0] == "child"]
    expected = []
    if failure in ("list", "execute", "docker"):
        expected.append(["child", "contract", "1", "--list"])
        if failure != "list":
            expected.append(["child", "worker-contract", "1", "--list"])
    if failure == "execute":
        expected.append(
            [
                "child",
                "worker-contract",
                "1",
                target,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
        )
        assert result.returncode == 23
    assert children == expected


@pytest.mark.parametrize(
    "missing",
    [
        "heartbeat_readiness_matches_published_python",
        TARGET,
        TIMEOUT_TARGET,
        BODY_TIMEOUT_TARGET,
        LEASE_EXPIRY_TARGET,
        "worker_lease_expiry_native_child",
        "worker_body_timeout_reference_matches_published_process",
        "worker_lease_expiry_reference_matches_published_process",
        "worker_body_timeout_native_child",
        "worker_provider_recovery_first_native_child",
        "operations_gateway_candidate_preserves_review_lifecycle",
        RENDERED_CONFIG,
    ],
)
def test_full_mode_still_fails_on_missing_mandatory_registration(shell_case, missing):
    names = required_registrations()
    assert missing in names
    result, calls = shell_case(
        registrations=[
            f"{name}: test"
            for name in sorted(set(names) | set(MIGRATED_CASES) | set(SELFHOST_CASES))
            if name != missing
        ]
    )
    assert result.returncode != 0
    assert all(call[3:] == ["--list"] for call in calls if call[0] == "child")


def test_workflow_runs_worker_preflights_before_public_image_and_keeps_full_gate():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    names = [step.get("name") for step in steps]
    rendered = names.index("Prepare required rendered base executable acceptance")
    preflight = names.index("Preflight published worker parity in two isolated groups")
    image = names.index("Build public selfhost image")
    loader = names.index("Prepare public selfhost image loader acceptance")
    passport = names.index("Verify default passport test-mode boundary")
    prepare = names.index("Prepare database contract executables")
    databases = names.index("Create isolated Rust contract databases")
    full = names.index("Run isolated database contract suites concurrently")
    assert names.count("Preflight published worker parity in two isolated groups") == 1
    assert rendered + 1 == preflight < image < loader < passport < full
    assert prepare < databases < full
    assert steps[preflight]["working-directory"] == "rust"
    assert steps[preflight]["shell"] == "bash"
    assert (
        steps[preflight]["run"]
        == "python3 ../scripts/ci/run-db-contract-groups.py preflights"
    )
    assert steps[preflight]["if"] == "matrix.lane == 'canvas'"
    assert steps[full]["run"] == (
        "set -euo pipefail\n"
        'if [[ "${{ matrix.lane }}" == worker ]]; then\n'
        "  python3 ../scripts/ci/run-db-contract-groups.py worker-preflights\n"
        "  python3 ../scripts/ci/run-db-contract-groups.py worker-canvas\n"
        'elif [[ "${{ matrix.lane }}" == flow ]]; then\n'
        "  bash ../scripts/ci/run-flow-acceptance-contracts.sh\n"
        "else\n"
        "  python3 ../scripts/ci/run-db-contract-groups.py "
        "${{ matrix.lane == 'canvas' && 'canvas' || 'rust-db' }}\n"
        "fi\n"
    )
    assert steps[image]["if"] == "matrix.lane == 'canvas'"
    assert "if" not in steps[full]
    for index in (preflight, full):
        assert not steps[index].get("continue-on-error", False)
    images = workflow["jobs"]["test-rust-service-images"]["steps"]
    gate_index = next(
        index
        for index, step in enumerate(images)
        if step.get("name") == "Verify captured worker rollback launch configuration"
    )
    gate = images[gate_index]
    assert gate["run"] == "python3 scripts/test_beta_worker_launch_compose.py"
    assert "if" not in gate and not gate.get("continue-on-error", False)
    builds = [
        index
        for index, step in enumerate(images)
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert builds and gate_index < min(builds)


def test_database_group_owner_still_invokes_default_full_mode(tmp_path, monkeypatch):
    module = runpy.run_path(str(ROOT / "scripts/ci/run-db-contract-groups.py"))
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    observed = {}

    def groups(commands, directory):
        observed.update(commands)
        for name in commands:
            (directory / f"{name}.log").write_text(
                "synthetic result\n", encoding="utf-8"
            )
        return dict.fromkeys(commands, 0)

    namespace = module["main"].__globals__
    monkeypatch.setitem(namespace, "run_groups", groups)
    monkeypatch.setitem(
        namespace,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=lambda **kwargs: nullcontext(str(tmp_path))),
    )
    assert module["main"]() == 0
    assert observed["published-canvas"] == ["bash", str(SCRIPT)]
    assert "rust-db" in observed


@pytest.mark.parametrize("qualification", [False, True])
def test_preflight_group_owner_runs_exact_modes(tmp_path, monkeypatch, qualification):
    module = runpy.run_path(str(ROOT / "scripts/ci/run-db-contract-groups.py"))
    executable = tmp_path / "canvas-contract"
    executable.write_bytes(b"synthetic compiled Canvas contract")
    (tmp_path / "rust-test-artifacts.json").write_text(
        json.dumps(
            {
                "reason": "compiler-artifact",
                "package_id": "path+file:///checkout/rust/crates/canvas-worker-acceptance#marty-canvas-worker-acceptance@0.1.0",
                "target": {"name": "canvas_published_worker_contract"},
                "executable": str(executable),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_RUN_ID", "synthetic-run")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_JOB", "test-rust-services")
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", "1" if qualification else "0")
    observed = {}

    def groups(commands, directory):
        observed.update(commands)
        for name in commands:
            (directory / f"{name}.log").write_text(
                "synthetic result\n", encoding="utf-8"
            )
        return dict.fromkeys(commands, 0)

    namespace = module["main"].__globals__
    monkeypatch.setitem(namespace, "run_groups", groups)
    monkeypatch.setitem(
        namespace,
        "tempfile",
        SimpleNamespace(
            TemporaryDirectory=lambda **kwargs: nullcontext(str(tmp_path)),
            NamedTemporaryFile=tempfile.NamedTemporaryFile,
        ),
    )
    assert module["main"]("preflights") == 0
    assert (tmp_path / "canvas-published-preflights.sha256").read_text(
        encoding="ascii"
    ) == (
        hashlib.sha256(executable.read_bytes()).hexdigest()
        + f"\nsynthetic-run\n1\ntest-rust-services\n{int(qualification)}\n"
    )
    assert list(observed) == (
        [name for name, _ in PREFLIGHTS]
        if qualification
        else ["timeout-preflight", "lease-expiry-preflight"]
    )
    assert all(
        command == ["bash", str(SCRIPT), name] for name, command in observed.items()
    )


def test_preflight_digest_selects_worker_owner_not_stale_packages(
    tmp_path, monkeypatch
):
    module = runpy.run_path(str(ROOT / "scripts/ci/run-db-contract-groups.py"))
    acceptance = tmp_path / "acceptance-worker-contract"
    acceptance.write_bytes(b"current acceptance worker contract")
    stale = tmp_path / "issuance-worker-contract"
    stale.write_bytes(b"stale issuance worker contract")
    old_acceptance = tmp_path / "old-acceptance-worker-contract"
    old_acceptance.write_bytes(b"stale composition-package worker contract")

    def artifact(owner, executable):
        return {
            "reason": "compiler-artifact",
            "package_id": f"path+file:///checkout/rust/#{owner}@0.1.0",
            "target": {"name": "canvas_published_worker_contract"},
            "executable": str(executable),
        }

    artifacts = tmp_path / "rust-test-artifacts.json"
    artifacts.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in (
                artifact("marty-issuance-service", stale),
                artifact("marty-canvas-acceptance", old_acceptance),
                artifact("marty-canvas-worker-acceptance", acceptance),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert module["_canvas_executable"]() == acceptance
    artifacts.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in (
                artifact("marty-issuance-service", stale),
                artifact("marty-canvas-acceptance", old_acceptance),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exactly one Canvas worker contract"):
        module["_canvas_executable"]()
