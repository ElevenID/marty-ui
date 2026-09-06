#!/usr/bin/env bash
set -euo pipefail
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
set -euo pipefail
mapfile -t contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'contracts-*' -perm -u+x)
if (( ${#contracts[@]} != 1 )); then
  printf 'Expected one contracts executable, found %s.\n' "${#contracts[@]}" >&2
  exit 1
fi
"${contracts[0]}" --ignored --test-threads=1
mapfile -t registry_contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'registry_storage_contract-*' -perm -u+x)
if (( ${#registry_contracts[@]} != 1 )); then
  printf 'Expected one signing registry contract executable, found %s.\n' "${#registry_contracts[@]}" >&2
  exit 1
fi
"${registry_contracts[0]}" --ignored --test-threads=1
mapfile -t document_contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'document_storage_contract-*' -perm -u+x)
if (( ${#document_contracts[@]} != 1 )); then
  printf 'Expected one signing document contract executable, found %s.\n' "${#document_contracts[@]}" >&2
  exit 1
fi
"${document_contracts[0]}" --ignored --test-threads=1
mapfile -t issuer_profile_contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'issuer_profile_storage_contract-*' -perm -u+x)
if (( ${#issuer_profile_contracts[@]} != 1 )); then
  printf 'Expected one issuer profile contract executable, found %s.\n' "${#issuer_profile_contracts[@]}" >&2
  exit 1
fi
"${issuer_profile_contracts[0]}" --ignored --test-threads=1
test -x target/debug/credential-template-postgres-contract
test -x target/debug/presentation-policy-postgres-contract
target/debug/credential-template-postgres-contract --test-threads=1
target/debug/presentation-policy-postgres-contract --test-threads=1
mapfile -t issuance_transaction_contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'issuance_transaction_postgres_contract-*' -perm -u+x)
if (( ${#issuance_transaction_contracts[@]} != 1 )); then
  printf 'Expected one Issuance transaction PostgreSQL contract executable, found %s.\n' "${#issuance_transaction_contracts[@]}" >&2
  exit 1
fi
"${issuance_transaction_contracts[0]}" --test-threads=1
mapfile -t issuance_credential_contracts < <(find target/debug/deps -maxdepth 1 -type f -name 'credential_postgres_contract-*' -perm -u+x)
if (( ${#issuance_credential_contracts[@]} != 1 )); then
  printf 'Expected one Issuance credential PostgreSQL contract executable, found %s.\n' "${#issuance_credential_contracts[@]}" >&2
  exit 1
fi
"${issuance_credential_contracts[0]}" --test-threads=1
mapfile -t canvas_issuance_contracts < <(
  find target/debug/deps -maxdepth 1 -type f -perm -u+x \
    \( -name 'canvas_*_postgres_contract-*' -o -name 'proof_nonce_postgres_contract-*' \) \
    | sort
)
if (( ${#canvas_issuance_contracts[@]} != 10 )); then
  printf 'Expected ten issuance PostgreSQL contract executables (nine Canvas plus proof nonce), found %s.\n' "${#canvas_issuance_contracts[@]}" >&2
  exit 1
fi
for contract in "${canvas_issuance_contracts[@]}"; do
  "$contract" --test-threads=1
done
test -x target/debug/credential-template-migration-contract
target/debug/credential-template-migration-contract --test-threads=1
test -x target/debug/trust-profile-migration-contract
target/debug/trust-profile-migration-contract --test-threads=1
test -x target/debug/organization-migration-contract
test -x target/debug/organization-application-postgres-contract
test -x target/debug/organization-repository-postgres-contract
target/debug/organization-migration-contract --test-threads=1
target/debug/organization-application-postgres-contract --test-threads=1
target/debug/organization-repository-postgres-contract --test-threads=1
