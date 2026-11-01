#!/usr/bin/env bash
# Permission-sensitive component fixtures. These exercise retained state and
# synthetic native receipts; they do not qualify a Docker daemon, CA or host.
set -euo pipefail
[[ $# == 1 && -f "$1" && ! -L "$1" ]]
[[ "$(uname -s)" == Linux && "$(id -u)" != 0 && "$(id -g)" != 0 ]]
[[ -x /usr/bin/setpriv && -d "${RUNNER_TEMP:?RUNNER_TEMP is required}" ]]
installer_artifacts="$1"
installer_source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$installer_source_root"
umask 077
installer_gate_dir="$(mktemp -d "$RUNNER_TEMP/installer-recovery-fixtures.XXXXXXXX")"
printf 'Installer recovery component fixture logs: %s\n' "$installer_gate_dir"

# Select only the default library test executable recorded by this CI build.
# Do not rediscover stale target hashes or use the unsigned development build.
installer_test_binary="$(python3 - "$installer_artifacts" "$installer_source_root" <<'PY'
import json
from pathlib import Path
import stat
import sys

source = Path(sys.argv[2])
manifest = source / "rust/crates/deployment-catalog/Cargo.toml"
paths, completions = set(), []
with Path(sys.argv[1]).open(encoding="utf-8") as records:
    for line in records:
        row = json.loads(line)
        if row.get("reason") == "build-finished":
            completions.append(row.get("success") is True)
        if (row.get("reason") != "compiler-artifact"
                or row.get("manifest_path") != str(manifest)
                or row.get("target", {}).get("name") != "marty_deployment_catalog"
                or row.get("target", {}).get("kind") != ["lib"]
                or row.get("profile", {}).get("test") is not True
                or row.get("executable") is None):
            continue
        if "installer-development" in row.get("features", []):
            raise SystemExit("Recovery fixtures require the default production feature boundary")
        paths.add(row["executable"])
if not completions or not all(completions) or len(paths) != 1:
    raise SystemExit("Expected one library test executable from a successful recorded build")
binary = Path(paths.pop())
if (not binary.is_absolute() or binary.is_symlink()
        or binary.resolve() != binary
        or not binary.is_relative_to(source / "rust/target")
        or not stat.S_ISREG(binary.stat().st_mode)
        or not binary.stat().st_mode & stat.S_IXUSR
        or any(character in str(binary) for character in "\n\r\0")):
    raise SystemExit("Recorded installer fixture executable is not a regular local build")
print(binary)
PY
)"

# Match the production process boundary before any fixture can produce a pass.
/usr/bin/setpriv --no-new-privs python3 - <<'PY'
import os
from pathlib import Path

uids, gids = os.getresuid(), os.getresgid()
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
if (len(set(uids)) != 1 or 0 in uids or len(set(gids)) != 1 or 0 in gids
        or status.get("NoNewPrivs", "").strip() != "1"
        or any(status.get(key, "").strip() != "0000000000000000" for key in ("CapEff", "CapPrm", "CapAmb"))):
    raise SystemExit("Recovery fixtures require an ordinary UID/GID with no-new-privileges and no capabilities")
PY

installer_cases=(
  installer_acme_host::boundary_tests::complete_pending_boundary_reopens_and_rejects_rebound_inputs_proofs_and_native_jobs
  installer_acme_host::boundary_tests::complete_prepared_staging_candidate_can_roll_over_after_expiry_and_resume_its_permit
  installer_acme_host::boundary_tests::initial_replacement_never_crosses_application_or_lifecycle_ownership
  installer_acme_host::boundary_tests::recurring_setup_retains_provenance_without_reapplying_original_storage_observations
  installer_acme_host::boundary_tests::initial_terminal_cases::consecutive_initial_terminal_orders_count_only_the_immediate_initial_chain
  installer_acme_host::boundary_tests::initial_terminal_cases::failed_replacement_after_expired_initial_candidate_has_distinct_initial_retry_authority
  installer_acme_host::boundary_tests::initial_terminal_cases::initial_terminal_proof_rejects_wrong_host_binding_and_later_ownership
  installer_acme_host::boundary_tests::initial_terminal_cases::initial_terminal_retry_retains_long_cooldown_and_reuses_unstarted_permit
  installer_acme_host::boundary_tests::initial_terminal_cases::initial_terminal_retry_waits_for_actual_withdrawal_and_never_retrofits_legacy_failure
  installer_acme_host::boundary_tests::initial_terminal_cases::unknown_initial_order_outcome_cannot_create_terminal_retry_authority
  installer_rootless_storage_canary::completed_tests::completed_acceptance_chain_preserves_exact_authenticated_scope_after_grant_expiry
  installer_rootless_storage_canary::completed_tests::acceptance_preparation_refuses_controller_proof_and_hosting_substitution
  installer_rootless_storage_canary::completed_tests::completed_candidate_chain_and_preparation_reopen_without_creation_capability
  installer_rootless_storage_canary::completed_tests::candidate_preparation_refuses_changed_canary_inventory_operator_and_storage
)
installer_log="$installer_gate_dir/fixtures.log"
set +e
/usr/bin/setpriv --no-new-privs "$installer_test_binary" "${installer_cases[@]}" \
  --ignored --exact --test-threads=1 --color never 2>&1 | tee "$installer_log"
installer_status=("${PIPESTATUS[@]}")
set -e
[[ "${installer_status[0]}" == 0 && "${installer_status[1]}" == 0 ]] || exit 1

# Libtest exits zero for unknown filters. Every named case must actually pass,
# and the one summary must account for the entire nonignored execution set.
python3 - "$installer_log" "${installer_cases[@]}" <<'PY'
import re
from pathlib import Path
import sys

lines, cases = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(), sys.argv[2:]
if len(cases) != len(set(cases)) or any(lines.count(f"test {case} ... ok") != 1 for case in cases):
    raise SystemExit("A required installer recovery fixture did not pass exactly once")
outcomes = [line for line in lines if re.fullmatch(r"test \S+ \.\.\. (?:ok|FAILED|ignored.*)", line)]
summaries = [line for line in lines if line.startswith("test result: ")]
pattern = (rf"test result: ok\. {len(cases)} passed; 0 failed; 0 ignored; 0 measured; "
           r"\d+ filtered out; finished in .+")
if len(outcomes) != len(cases) or len(summaries) != 1 or not re.fullmatch(pattern, summaries[0]):
    raise SystemExit("Installer recovery fixture selection was empty, incomplete or unexpected")
PY
