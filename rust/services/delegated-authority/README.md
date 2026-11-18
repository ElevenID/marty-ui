# Marty Delegated Authority service

This crate implements the managed DelegationGrant v1 lifecycle and persistence
application layer. It is not yet a hosted or production-qualified authorization
service. The optional delegated-authority capability must remain undiscoverable
until its remaining runtime integrations are qualified.

Commerce, checkout, payments, inventory, merchant adapters and order execution
remain outside ElevenID. A grant describes authority; it does not execute a
domain operation.

## Implemented behavior

- The application service creates pending grants from a trusted organization
  context, configured managed issuer and submitted terms. IDs, status, revision,
  timestamps and digests are service-owned.
- Approval requires the authenticated principal's complete type and identifier
  to equal the grantor, plus a configured `ConsentEvidenceVerifier`. The verifier
  receives the full immutable grant, approval, purpose and trusted time, and
  returns an authenticated freshness deadline. Unknown profiles, unavailable
  evidence and withdrawn authority must fail closed.
- The lifecycle supports approval, suspension, reinstatement, revocation and
  explicit expiration. Reinstatement and active resolution reverify consent and
  current grantor authority. An injected service clock rechecks both grant and
  evidence deadlines after asynchronous verification. Resolution rereads the
  authoritative snapshot to detect intervening revocation or revision changes.
- Authority, identity, terms, digest, creation time and existing approval are
  immutable. Both repositories validate initial states, stored snapshots and
  transitions under their atomic write boundary. Revisions are bounded by the
  protocol's maximum JSON-safe integer, `9007199254740991`.
- In-memory and PostgreSQL repositories scope operations to the organization and
  use revision-checked updates. A failed or racing update leaves no grant change
  or journal event. Each successful initial insertion or transition commits one
  lifecycle event with the same revision.
- External-authority snapshots can be structurally validated, but the managed
  service and repositories refuse to own or transition them. A qualified
  external authority/status resolver is still required.

Grantor, subject, delegate and issuer are separate roles even when their
identifiers are equal. Matching identifiers do not merge their authority.
Subdelegation is unsupported in v1. Scope sets are explicit, unique, bounded
absolute URI identifiers, with no wildcard matching.

`resolve()` returns an active managed candidate with current evidence; it is
not a permit for a requested operation. Final-use evaluation must still verify
the authenticated actor, key/session binding, exact scope, domain constraints,
policy, current revision and replay protections. Revocation after a successful
read is possible, so a previously resolved candidate cannot be reused as a
status cache or bearer authorization.

## Protocol and strict decoding

The contract is based on
[`marty-protocol` Delegated Authority v1](https://github.com/ElevenID/marty-protocol/blob/a9ce6a1d912f22a5627faebb482c44b9104d840d/protocol/delegated-authority/SPECIFICATION.md)
and its schema/reference validation at the pinned commit. Historical snapshot
validation is independent of the current clock; activation and expiration time
rules are checked on transitions, and current validity is checked on use.

The terms digest is SHA-256 over RFC 8785 canonical JSON of exactly:

```text
{profile, id, organization_id, authority, terms}
```

That v1 projection is number-free. Object keys use UTF-16 ordering, arrays retain
their order, strings retain their contents, and numbers in the projection are
rejected. Tests pin the upstream managed-grant digest vector and include UTF-16
ordering/escaping checks.

Use `decode_grant_snapshot(&bytes)` on untrusted snapshot bytes before any
ordinary JSON decoding or JSONB storage. It rejects duplicate fields, unknown
fields, malformed Unicode, floating-point values, explicit nulls, documents over
65,536 bytes, nesting over 24 levels and documents over 8,192 JSON nodes. It
checks the digest over the original string values before deserializing a DTO.
Typed programmatic writes enforce the same serialized byte limit.

This adapter deliberately supports the string spellings emitted by its Rust
DTOs: lowercase hyphenated UUIDs and UTC `Z` timestamps with canonical fractional
precision, years 0001–9999 and no leap seconds. Alternate valid protocol UUID or
time spellings are rejected rather than silently normalized. Broader wire
interoperability requires preserving those lexical values in the domain model;
this milestone does not claim that qualification. URI references are identifiers
only; validation never dereferences them or trusts their origin.

## PostgreSQL startup and journal

`PgDelegationGrantRepository::migrate()` applies bundled SQL under a
transaction-scoped advisory lock, stores SHA-256 migration checksums and refuses
changed migration content. Repeated startup is idempotent.
`readiness()` checks the expected migration versions/checksums, tables and enabled
lifecycle guards. It establishes persistence readiness only.

Migration `0002_atomic_lifecycle_journal.sql` adds document/column consistency
constraints, the protocol revision bound, guarded lifecycle updates and an
atomic append-only journal. PostgreSQL stores its query timestamps at microsecond
precision; the JSON snapshot and journal preserve the exact RFC3339 instant.
Transition ordering is checked at nanosecond precision. Read paths validate the
snapshot's digest and ensure its identity, organization, status, revision, digest
and timestamps agree with the indexed columns.

Run migrations with a dedicated migration owner. Runtime database credentials
must have only the required schema usage, grant SELECT/INSERT/UPDATE, journal
and migration-checksum SELECT, and EXECUTE on the pure `grant_instant(TEXT)`
helper. They must have no table ownership, DDL, trigger management or journal
write privileges. The journal trigger runs with its migration owner's authority
and a fixed search path. Runtime code must not call `migrate()` using restricted
request-serving credentials. Database roles are deployment configuration; this
crate does not create a production role or grant broad privileges.

The new journal requires an empty initial grant table. If the earlier draft
migration was applied and records were created, migration 0002 refuses to invent
a history. Reconcile those records against their authoritative evidence/audit
source before adopting this repository; do not delete production records to
make startup pass.

Journal events contain organization/grant IDs, revision, old/new status, digest
and exact occurrence time. They exclude principal identifiers, consent evidence
references and full grant documents. This is a lifecycle journal. Authenticated
operator attribution, request correlation, retention and external audit delivery
remain runtime work. Errors from parsing and persistence avoid echoing submitted
documents, evidence or database connection information.

## Validation

From the repository's `rust` workspace:

```bash
cargo fmt --all -- --check
cargo test --locked -p marty-delegated-authority
cargo clippy --locked -p marty-delegated-authority --all-targets -- -D warnings
```

The PostgreSQL contract test runs when
`DELEGATED_AUTHORITY_TEST_DATABASE_URL` names a dedicated disposable test database.
A configured but unavailable database fails the test; an unset variable skips
that database-specific test. The existing workspace contracts CI lane supplies a
fresh database and sets this variable, so CI executes the live PostgreSQL path.
The test database owner must be able to create schemas and test roles.

Tests cover the pinned protocol digest, strict parsing, typed-identity rejection,
withdrawn consent/authority, expiration during verification, evidence freshness,
clock regression, concurrent revocation, tenant isolation, immutable-term
substitution with a recomputed digest, competing updates, atomic journal rollback,
terminal states, migration/readiness and timestamp precision.

## Remaining runtime qualification

- A production consent-evidence verifier integrated with an authenticated trusted
  approval surface and current grantor-authority evidence.
- External authority and fresh status resolution with configured trusted sources.
- Authenticated delegate proof and key/session establishment verification.
- Delegation-aware Cedar evaluation, domain-constraint evidence, signed receipts
  and final-use replay/revision enforcement.
- HTTP/gRPC hosting, public Gateway contracts, organization action authorization,
  attributed security audit delivery and capability discovery.
- Deployment wiring and end-to-end qualification across the relevant services.

No allow-all consent verifier is provided for production. Test doubles exist only
under `cfg(test)`. There is no public Gateway route, discovery advertisement or
production deployment in this milestone.
