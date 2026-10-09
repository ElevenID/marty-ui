#!/usr/bin/env bash
set -euo pipefail
run_timed() {
  local name="$1"
  shift
  local started ended status=0
  started=$(python3 -c 'import time; print(time.monotonic_ns())')
  "$@" || status=$?
  ended=$(python3 -c 'import time; print(time.monotonic_ns())')
  printf 'MARTY_CI_PHASE_V1 {"phase":"contract","name":"%s","duration_ms":%s,"status":"%s"}\n' \
    "$name" "$(((ended - started) / 1000000))" "$([[ $status == 0 ]] && echo ok || echo failed)"
  return "$status"
}
resolve_contract_executable() {
  local target="$1"
  local artifacts="${RUNNER_TEMP:-}/rust-test-artifacts.json"
  if [[ -n "${RUNNER_TEMP:-}" && -f "$artifacts" ]]; then
    # Later focused Cargo runs can leave a second binary hash in deps. Use
    # the exact workspace test artifact selected before those runs instead.
    jq -r --arg target "$target" '
      select(.reason == "compiler-artifact")
      | select(.target.name == $target)
      | select(.executable != null)
      | .executable
    ' "$artifacts" | tail -n 1
  else
    find target/debug/deps -maxdepth 1 -type f -name "$target-*" -perm -u+x
  fi
}
export MARTY_TEST_POSTGRES_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export MARTY_TEST_REDIS_URL=redis://127.0.0.1:6379/0
export MARTY_TEST_REVOCATION_MIGRATION_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export MARTY_TEST_REVOCATION_MIGRATION_DATABASE_NAME=marty_db_contracts_test
export CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export PRESENTATION_POLICY_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export ISSUANCE_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export MARTY_ISSUANCE_POSTGRES_CONTRACT_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export ORGANIZATION_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export TEST_POSTGRES_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_db_contracts_test
export MARTY_RETENTION_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_retention_contract_test
export MARTY_PASSPORT_POSTGRES_TEST_URL=postgresql://postgres:postgres@127.0.0.1:5432/marty_passport_contract_test
set -euo pipefail
mapfile -t contracts < <(resolve_contract_executable contracts)
if (( ${#contracts[@]} != 1 )); then
  printf 'Expected one contracts executable, found %s.\n' "${#contracts[@]}" >&2
  exit 1
fi
run_timed general_contracts "${contracts[0]}" --ignored --test-threads=1
mapfile -t registry_contracts < <(resolve_contract_executable registry_storage_contract)
if (( ${#registry_contracts[@]} != 1 )); then
  printf 'Expected one signing registry contract executable, found %s.\n' "${#registry_contracts[@]}" >&2
  exit 1
fi
run_timed signing_registry "${registry_contracts[0]}" --ignored --test-threads=1
mapfile -t document_contracts < <(resolve_contract_executable document_storage_contract)
if (( ${#document_contracts[@]} != 1 )); then
  printf 'Expected one signing document contract executable, found %s.\n' "${#document_contracts[@]}" >&2
  exit 1
fi
run_timed signing_document "${document_contracts[0]}" --ignored --test-threads=1
mapfile -t issuer_profile_contracts < <(resolve_contract_executable issuer_profile_storage_contract)
if (( ${#issuer_profile_contracts[@]} != 1 )); then
  printf 'Expected one issuer profile contract executable, found %s.\n' "${#issuer_profile_contracts[@]}" >&2
  exit 1
fi
run_timed issuer_profile "${issuer_profile_contracts[0]}" --ignored --test-threads=1
test -x target/debug/credential-template-postgres-contract
test -x target/debug/presentation-policy-postgres-contract
run_timed credential_template target/debug/credential-template-postgres-contract --test-threads=1
run_timed presentation_policy target/debug/presentation-policy-postgres-contract --test-threads=1
mapfile -t issuance_oid4vci_migration_contracts < <(resolve_contract_executable oid4vci_migration_postgres_contract)
if (( ${#issuance_oid4vci_migration_contracts[@]} != 1 )); then
  printf 'Expected one Issuance OID4VCI migration PostgreSQL contract executable, found %s.\n' "${#issuance_oid4vci_migration_contracts[@]}" >&2
  exit 1
fi
run_timed issuance_oid4vci_migration "${issuance_oid4vci_migration_contracts[0]}" --test-threads=1
mapfile -t issuance_transaction_contracts < <(resolve_contract_executable issuance_transaction_postgres_contract)
if (( ${#issuance_transaction_contracts[@]} != 1 )); then
  printf 'Expected one Issuance transaction PostgreSQL contract executable, found %s.\n' "${#issuance_transaction_contracts[@]}" >&2
  exit 1
fi
run_timed issuance_transaction "${issuance_transaction_contracts[0]}" --test-threads=1
mapfile -t issuance_credential_contracts < <(resolve_contract_executable credential_postgres_contract)
if (( ${#issuance_credential_contracts[@]} != 1 )); then
  printf 'Expected one Issuance credential PostgreSQL contract executable, found %s.\n' "${#issuance_credential_contracts[@]}" >&2
  exit 1
fi
run_timed issuance_credential "${issuance_credential_contracts[0]}" --test-threads=1
mapfile -t retention_contracts < <(resolve_contract_executable retention_postgres_contract)
if (( ${#retention_contracts[@]} != 1 )); then
  printf 'Expected one Issuance retention PostgreSQL contract executable, found %s.\n' "${#retention_contracts[@]}" >&2
  exit 1
fi
run_timed retention "${retention_contracts[0]}" --test-threads=1

mapfile -t passport_contracts < <(resolve_contract_executable passport_postgres_contract)
if (( ${#passport_contracts[@]} != 1 )); then
  printf 'Expected one Issuance passport PostgreSQL contract executable, found %s.\n' "${#passport_contracts[@]}" >&2
  exit 1
fi
run_timed passport "${passport_contracts[0]}" --test-threads=1
mapfile -t application_template_contracts < <(resolve_contract_executable application_template_postgres_contract)
if (( ${#application_template_contracts[@]} != 1 )); then
  printf 'Expected one Application Template PostgreSQL contract executable, found %s.\n' "${#application_template_contracts[@]}" >&2
  exit 1
fi
run_timed application_template "${application_template_contracts[0]}" --test-threads=1
mapfile -t internal_application_contracts < <(resolve_contract_executable internal_application_postgres_contract)
if (( ${#internal_application_contracts[@]} != 1 )); then
  printf 'Expected one internal Application PostgreSQL contract executable, found %s.\n' "${#internal_application_contracts[@]}" >&2
  exit 1
fi
run_timed internal_application "${internal_application_contracts[0]}" --test-threads=1
mapfile -t canvas_issuance_contracts < <(
  find target/debug/deps -maxdepth 1 -type f -perm -u+x \
    \( -name 'canvas_*_postgres_contract-*' -o -name 'proof_nonce_postgres_contract-*' \) \
    | sort
)
if (( ${#canvas_issuance_contracts[@]} != 11 )); then
  printf 'Expected eleven issuance PostgreSQL contract executables (ten Canvas plus proof nonce), found %s.\n' "${#canvas_issuance_contracts[@]}" >&2
  exit 1
fi
for contract in "${canvas_issuance_contracts[@]}"; do
  contract_name=$(basename "$contract")
  run_timed "${contract_name%-*}" "$contract" --test-threads=1
done
test -x target/debug/credential-template-migration-contract
run_timed credential_template_migration target/debug/credential-template-migration-contract --test-threads=1
test -x target/debug/trust-profile-migration-contract
run_timed trust_profile_migration target/debug/trust-profile-migration-contract --test-threads=1
test -x target/debug/organization-migration-contract
test -x target/debug/organization-application-postgres-contract
test -x target/debug/organization-repository-postgres-contract
run_timed organization_migration target/debug/organization-migration-contract --test-threads=1
run_timed organization_application target/debug/organization-application-postgres-contract --test-threads=1
run_timed organization_repository target/debug/organization-repository-postgres-contract --test-threads=1
