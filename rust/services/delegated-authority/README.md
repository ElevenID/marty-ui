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
  Activation and reinstatement carry a guard bound to the exact grant revision
  and complete approval into persistence. The repository rechecks it under its
  lock and against a fresh database clock after writes, immediately before
  commit. Expiration rolls back the grant update and lifecycle journal together.
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

## Configured trusted consent records

`ConfiguredConsentEvidenceVerifier` is a concrete verifier for authenticated
server-record adapters. Configure each allowed approval profile with an exact
numeric three-part version and SHA-256 artifact digest. The pin describes the
reviewed adapter contract; the verifier compares configured metadata and does
not measure a running executable or authenticate arbitrary signed JSON.
Unknown profiles, mismatched pins and malformed configuration fail closed.

Consent and representation authority come from separate provider ports. Each
must bind the organization, grant ID, terms digest, complete grantor/subject/issuer
principals, and both evidence references. The digest also commits the delegate,
key/session binding, scopes, validity and constraints. Identical grantor/subject
identifiers never bypass the authority check. Both lookups share a five-second
timeout and return sanitized failures.

The verifier keeps these clocks distinct:

| Timestamp | Meaning |
| --- | --- |
| `confirmed_at` | Original explicit confirmation from the trusted surface; immutable. |
| `GrantApproval.approved_at` | Admission of that confirmation into the managed grant. |
| `asserted_at` | Independent authority check by the configured authority producer. |
| `observed_at` | Current read of confirmation withdrawal or authority status. |

Confirmation must occur between grant creation and approval admission. Initial
activation also applies the configured maximum confirmation age. Reinstatement
and resolution preserve the original confirmation while requiring fresh
withdrawal observations and representation authority. Each age limit is an
explicit configuration value between 1 and 3,600 seconds. Returned validity is
bounded by the earliest relevant grant, evidence, observation and authority
assertion deadline. A database read never renews an old authority assertion.

`PgConsentEvidenceProvider` resolves these records from the authoritative
PostgreSQL database, with statement-start observation timestamps. It never
fetches an evidence-reference URI. Migration 0003 adds:

- Immutable consent confirmations and terminal withdrawal records.
- Immutable representation-authority source bindings.
- Append-only authority assertions with increasing revisions and assertion times.
- Terminal authority revocation; a revoked source cannot be refreshed.
- Database binding, timing, immutability and truncation guards.

`PgTrustedConsentWriter::record_consent` is called only after a trusted surface
has authenticated the real grantor and obtained explicit confirmation of the
exact displayed terms. `record_authority` and `refresh_authority` are called only
after the independent authority producer has rechecked representation authority.
`withdraw_consent` and `revoke_authority` record terminal withdrawal/revocation.
These methods take typed internal inputs, not public request DTOs. Record types
do not derive `Deserialize`; possessing an identifier or digest proves nothing.
The module does not provide a public evidence-ingestion route or turn login into
consent. No generic approval JWS format is invented or borrowed from decision
receipts.

Use distinct credentials for the two producers even though the writer type
supports both sets of methods:

| Component | Evidence-table access |
| --- | --- |
| Lifecycle verifier | SELECT on all four evidence tables. |
| Trusted confirmation producer | SELECT/INSERT on confirmations and withdrawals. |
| Independent authority producer | SELECT/INSERT on authority sources and assertions. |
| Migration owner | Schema/object ownership and migration administration. |

Each role needs schema USAGE; the confirmation producer also needs EXECUTE on
the pure `grant_instant(TEXT)` check helper. Neither producer needs UPDATE, DELETE,
TRUNCATE, trigger management or object ownership. Do not give the confirmation
surface authority-assertion INSERT privileges. Existing grant persistence and
journal privileges are described below. Roles are provisioned by deployment,
not automatically created in production by this crate.

Duplicate or stale producer operations fail without changing earlier records.
After an uncertain transport result, reconcile the original evidence reference
and expected revision; do not silently generate a new confirmation or retry a
mutation with a replacement intent.

Evidence reads and grant activation are bounded freshness observations, not one
distributed transaction spanning every source. A source can be withdrawn after a
successful observation. Final-use resolution and operation authorization must
still recheck current evidence and status; no instantaneous global-revocation or
bearer-permit guarantee is implied.

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
The visitor also rejects the private numeric-map representation used when
workspace feature unification enables `serde_json/arbitrary_precision`; floats
and oversized integers cannot become ordinary objects. Regression coverage
includes both ordinary and unified JSON feature modes. Typed programmatic writes
enforce the same serialized byte limit.

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
terminal states, migration/readiness and timestamp precision. They also cover
complete evidence/pin substitutions, confirmation versus authority freshness,
provider timeout, trusted-record activation and withdrawal, explicit authority
renewal, independent producer permissions, activation lock delays, post-write
expiry rollback and rejection when an application clock is frozen.

## Remaining runtime qualification

- Connect the configured verifier and typed producer APIs to an authenticated
  trusted approval surface and the current grantor-authority source. This still
  requires own-session confirmation, fresh challenges and organization action
  authorization; database records alone do not establish those guarantees.
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


## Delegated operation evaluation boundary

The crate now exposes `DelegationUseAuthorizer` as a fail-closed orchestration
boundary for one exact delegated operation. It composes three required adapters:

1. `DelegateProofVerifier` authenticates the delegate's original cryptographic
   proof and exact key/session binding. Key grants must verify the configured
   key thumbprint; session grants must verify the established session and its
   establishment evidence. The proof must bind the organization, grant,
   challenge/nonce, audience and operation digest, and enforce proof freshness
   and replay status. A login, caller boolean or actor ID is not proof.
2. `ExternalConstraintVerifier` verifies external-profile constraints against
   the exact grant, document reference/digest, evaluator identity and operation.
   It must use a configured trusted source, never fetch a caller-selected URI.
   Exact-operation constraints are checked directly against the frozen profile
   and digest in the grant.
3. `DelegationCedarEvaluator` evaluates the exact principal, action, resource
   and operation context against the organization's active Cedar policy. There
   is no default or allow-all evaluator. Only an explicit Permit with a valid
   policy identity, revision, digest, observation time and deadline is accepted;
   Forbid, Abstain, malformed metadata, timeout and provider errors all fail
   closed.

The authorizer first resolves the active grant and its trusted consent deadline,
checks the expected revision and exact delegate/action/audience/resource scope,
then verifies proof, constraints and Cedar. It resolves the grant again after
those asynchronous operations and rejects a concurrent suspension, revocation,
revision change or expired evidence. The returned `DelegationUseEvaluation`
is deliberately not serializable and is not a bearer permit. It records the
grant and policy revision/digest plus the shortest verified deadline. The
consuming operation must still atomically enforce final-use revision and replay
reservation at its own commit boundary. Do not cache or reuse this result to
authorize another operation.

The MMF Cedar execution adapter is implemented; its active-policy/entity-source
port must be implemented by the consuming domain integration (for example, the
separate Commerce Gateway) or its organization-owned policy provider. ElevenID
does not own commerce action/resource policy or domain execution. This is not a
claim that the production proof verifier, external constraint source, active
Cedar policy source, signed receipt writer or final-use reservation are deployed. The next work is
to implement those adapters against the established Marty identity, policy and
transaction services, then qualify them end to end. Commerce execution remains
in the separate consuming project.


## OID4VP delegate proof verification

The crate includes `MartyOid4vpDelegateProofVerifier`, which reuses the pinned
Marty Core `VerificationEngine::verify_authenticated_vp_proof_at` and Marty
Verification's RFC 7638 JWK thumbprint implementation. It does not implement a
second JOSE parser, JWT signature verifier, or thumbprint algorithm.

The verifier accepts the compact JWT VP produced through the existing OID4VP
Flow. Its challenge ID resolves to authoritative Flow-owned challenge state;
the nonce and verifier audience are loaded from that state and never accepted
from caller-supplied proof metadata. The verifier requires the exact grant ID,
organization, revision, audience, nonce, holder principal, short proof lifetime,
and signer key binding. Key-bound grants compare the RFC 7638 thumbprint.
Session-bound grants compare the exact session and establishment evidence
references plus the key thumbprint established by that session.

The challenge lookup is read-only. Evaluation is not a permit and must not
consume the challenge prematurely. The external operation's final-use
transaction must atomically recheck the grant revision, reserve the challenge
once, enforce its idempotency/replay key, and commit its signed authorization
receipt with the domain operation. The challenge ID is carried in the
non-serializable evaluation object for that boundary. The Flow owner remains
responsible for standard OID4VP request construction, request signing,
nonce/session persistence, direct_post handling and its existing finalizer.

The challenge store is an explicit integration port, not a new parallel
challenge database. Its production implementation must read the exact saved
Flow session and use the existing Flow nonce lifecycle. The final-use
reservation/receipt transaction and the Flow adapter remain follow-up
integration gates. A mock or in-memory challenge store is test-only and cannot
qualify production replay protection.
