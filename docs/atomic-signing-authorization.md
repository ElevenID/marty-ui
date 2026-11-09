# Atomic signing authorization

## Scope

This is the W05 prerequisite-workflow foundation: the issuance service carries
its admitted authority to the final `authorized` to `signing` transition. It
closes the interval in which an asynchronous proof, issuer, or readiness check
could complete against one transaction while the repository claimed a changed
transaction under the same ID.

It does not implement the complete prerequisite workflow. Canonical verified
prerequisite evidence, binding to a prerequisite policy revision, and a durable
single-use proof continuation remain separate planned work. The existing
asynchronous lifecycle readiness check is still a prerequisite to the signing
claim; it does not atomically bind a changing external policy to that claim.

## Authorization carried to the claim

`CredentialSigningAuthorization` borrows the original transaction, the linked
OID4VCI authorization session when one exists, and the request's bearer token.
The transaction is captured before credential selection and issuer enrichment.
Its diagnostic representation redacts those contents.

A grant represented by both a transaction and an authorization session now
retains both. This prevents the service from losing the session's client,
configuration, DPoP, tenant, grant association, or token-expiry evidence after
initial grant resolution.

The service still resolves issuer context again immediately before readiness
and signing. That selected issuer is kept separate from the original database
snapshot. A valid refresh can therefore select the current signing service,
issuer DID, or algorithm without confusing enrichment with an unauthorized
change to the stored admission state.

## PostgreSQL transition

`PostgresCredentialRepository::claim_for_signing` performs the following in one
SQL transaction:

1. Lock the admitted transaction using its ID and organization. Check the
   bearer digest and transaction/grant expiry, then parse the current row.
2. When a linked session was admitted, lock that exact session and compare its
   complete admitted representation. Require the same organization, logical
   grant, client, DPoP binding, and access-token expiration as the transaction.
3. For an authorized transaction, require equality with the original admitted
   transaction. This includes the dataset, applicant/application/subject,
   template, configuration and format policy, validity, wallet settings,
   nonce, issuer settings, and transaction expiry.
4. Execute the guarded update using a fresh database wall clock after all lock
   waits. The predicate rechecks the bearer and transaction expiry, linked
   session liveness, and absence of another live grant using the token digest.
   The update claims the reserved credential ID and selected credential/issuer
   fields while changing `authorized` to `signing`.
5. Commit before returning the claimed transaction to the service.

A concurrent `signing` or `issued` row can trigger recovery only when its signing
target matches. Only status, nonce, and reserved-credential bookkeeping are
excluded from that target comparison. This recovery branch runs the same fresh
live-authority predicate after acquiring the locks. The service also compares
the target again when rereading a concurrently completed credential.

The predicate checks the live-grant set visible to the final SQL statement. It
does not create a new global token-uniqueness constraint or change the isolation
level. Tokens continue to be minted and bound by the existing issuance flows.

## Compatibility

The accepted legacy fallback is unchanged: a transaction with a null client ID
may be linked to a session only when its transaction ID is the existing
deterministic ID derived from that exact session. A null client on an unrelated
transaction is rejected, as is any incorrect non-null client. Explicit matching
client IDs continue to work for the ordinary issuer-state linkage.

Existing proof verification, nonce consumption, fresh issuer resolution,
readiness, status allocation, signing, and finalization order is retained. A
failed readiness or final authorization check cannot reach the credential
builder. Rejected claims do not consume the transaction's signing reservation.

This change does not replace the existing replay path for a request initially
admitted as already issued. It hardens the claim and concurrent recovery paths
for a request admitted for new issuance.

## Verification

The following commands were run from `rust/` with Rust 1.97.1 and the project's
exact private-fork dependencies:

```sh
cargo test --locked -p marty-issuance-service \
  --test credential_admission_behavior \
  --test credential_signing_behavior \
  --test credential_postgres_contract --no-run

cargo test --locked -p marty-issuance-service \
  --test credential_admission_behavior \
  --test credential_signing_behavior
```

All three test executables compiled, including a final locked build. The locked behavioral execution passed the
admission oracle test and all 12 signing behavior tests. The new behavior cases
cover changed authority/datasets and expired transactions, readiness denial,
valid fresh issuer resolution, and rejection of mismatched concurrent recovery.
The mutation/denial cases assert that no credential builder or downstream
signing side effect was reached.

The real PostgreSQL contract target adds coverage for transaction and session
mutations, live token ambiguity across authorized/signing/issued grants,
deterministic legacy client compatibility, concurrent row mutation under a
lock, and transaction/grant expiration while waiting for the session lock. The
expiry scenarios cover normal claiming and both concurrent recovery statuses.

**Database execution is pending the existing CI database gate.** The local
container could not start a supported PostgreSQL instance. Compiling these
cases is not evidence that their SQL or concurrency assertions have executed.
The test target returns early when `ISSUANCE_POSTGRES_TEST_URL` is absent; do
not report such a run as PostgreSQL validation.

The existing `scripts/ci/run-rust-db-contracts.sh` runner supplies
`ISSUANCE_POSTGRES_TEST_URL` and invokes the complete
`credential_postgres_contract` executable with `--test-threads=1`. The database
name must end in `_test`; the fixtures recreate the test schema. The required
execution on a provisioned disposable test database is:

```sh
ISSUANCE_POSTGRES_TEST_URL='<disposable PostgreSQL URL ending in _test>' \
  cargo test --locked -p marty-issuance-service \
  --test credential_postgres_contract -- --test-threads=1
```

The independently reviewed source and the real database result must be recorded
against the final PR commit before this foundation is treated as merge-ready.
