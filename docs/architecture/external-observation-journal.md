# External observation PostgreSQL journal candidate

Status: implemented candidate, not wired to a public route or startup migration.
This follows the provider-neutral admission kernel in PR #1959. The connector
still has no core database access; only core owns this implementation.

## Transaction boundary

`PostgresObservationJournal::submit` accepts an authenticated producer identity
and a typed observation, not a caller-built admission plan. It opens a
SERIALIZABLE PostgreSQL transaction, requires a canonical authority adapter to
lock current key/grant/binding/application state, reads receipts and the binding
head, and invokes the admission kernel. Missing rows and unavailable reads are
not interchangeable.

A new observation stages one core-assigned UUID receipt, one sequence-head
compare-and-swap and one admission audit row. Source-wide observation IDs and
per-binding sequences have unique constraints. Composite foreign keys prevent a
head from pointing at a different source, organization, binding or sequence.
Deferred constraints prevent committed receipts without a head or audit event.
The audit row joins provenance from the receipt and contains no raw claims.

The complete decision is recomputed from locked authority after staging. A
changed authority fence or denial rolls back all staged rows. A fresh database
clock is read after waits/writes: transaction-start timestamps are not used for
expiry. Exact retries reauthorize and return the original receipt without
another event or sequence change. No receipt is acknowledged before COMMIT.

Serialization/deadlock/unique/CAS conflicts are retryable conflicts. There is no
automatic write retry. A transport error during COMMIT is conservatively
`CommitUnknown`; callers must reconcile the SAME observation ID, not invent a
new event. Errors expose a fixed class, never SQL, keys, claims or database URLs.

Authorization is linearized at the final locked decision. Network delivery or
COMMIT acknowledgment may occur later. This is not a promise that wall-clock
expiry cannot pass while a COMMIT response is in transit.

## Mandatory authority adapter; no shadow authorization database

`PostgresObservationAuthority` now implements the canonical adapter as a core
module. It locks the canonical `organization_service.api_keys` row, then the
producer grant, grant-membership rows, evidence binding and application row in
one PostgreSQL transaction. The organization and issuance schemas share the
same `marty` database in the supported Compose topology, so API-key revocation
and journal admission serialize on the same key row. The organization revoke
path uses `api_key_by_id_for_update_in_transaction`.

Grant and binding records are candidate core-owned tables in the journal schema.
Grant/binding revision triggers invalidate old fences; membership changes bump
the grant revision. The adapter carries API-key, grant, binding and application
expiry into the admission decision. Application expiry is checked by the
admission kernel against the database clock after lock waits, not frozen as an
early boolean snapshot. Required lock order is key -> grant -> membership ->
binding -> application. Admin grant/binding handlers must preserve that order.

This is not yet wired to a public Gateway route or production startup migration.
No admin grant/binding management endpoints or least-privilege DB role grants
are installed. A stale replica, unlocked RPC, cached key scopes or disconnected
authorization copy still does not satisfy the contract.

The journal tests retain a synthetic adapter for isolated transaction-failure
cases and now also exercise `PostgresObservationAuthority` against disposable
canonical-shaped `organization_service.api_keys`, grant, binding and application
tables. They verify the exact scope, tenant and lifecycle decisions and that a
concurrent API-key revocation waits for the admission row lock. These tables are
created only in the loopback fixture; they are not production migrations or a
replacement for the canonical organization/application owners.

## Test isolation

The existing admission workflow adds one bounded PostgreSQL job. The focused
harness compiles the exact checked-in Rust modules, using registry dependencies
from production Cargo declarations and the production lock. Resolved dependency
versions and checksums must already be in that lock before compilation. It does
not pull private core forks or alter production dependency versions.

The PostgreSQL fixture requires the explicit `synthetic-local-only` marker. It
uses a fixed loopback host, fixed disposable database name and synthetic fixture
password; it accepts no arbitrary DATABASE_URL or cloud endpoint. Missing
fixture access fails the tests rather than silently skipping them. Test schemas
are reset only inside that disposable database. No AWS instance is provisioned.

Run serially through the harness (PostgreSQL fixture must already be running):

```sh
EXTERNAL_OBSERVATION_CONTRACT_TEST=synthetic-local-only \
  python3 scripts/run_external_observation_journal_contract.py \
  --artifacts /tmp/external-observation-journal-evidence
```

## Still required before activation

- Organization-admin grant/binding management APIs, audited approval/revocation,
  production startup migration registration and least-privilege database roles.
- Gateway route wiring that passes only authenticated API-key identity into the
  core ingress, exact `evidence:submit` scope enforcement and OpenAPI contract.
  Original-byte decoding and transactional journal composition are implemented,
  but no public endpoint is mounted.
- Reviewed production migration, least-privilege database roles, retention and
  operational recovery for the receipt journal.
- Explicit policy admission for producer-attested observations; receipts never
  grant VERIFIED status, approval, signing or issuance on their own.
- Real Gateway key/tenant/revocation/audit/idempotency qualification, then the
  isolated OB3 flow and network-denial checks before switching Canvas workers.

The existing Canvas worker, React UI, core policy transitions, startup migration
list, rootless Docker, OpenBao and live deployments are unchanged.
