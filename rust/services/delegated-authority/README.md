# Marty Delegated Authority service

This crate implements the managed DelegationGrant v1 lifecycle, persistence and
delegated operation evaluation layer, including Marty OID4VP proof and MMF Cedar
adapters. The internal retained-use composition additionally provides original
command claims, an explicitly assembled authenticated internal router, a concrete
Flow transaction owner, selected machine-policy/credential verification, durable
machine audit and managed receipt-signing adapters. An optional organization
approval producer is hosted behind the authenticated Gateway; delegated-use
authorization is not production-qualified.
The optional delegated-authority capability must remain undiscoverable until its
remaining runtime integrations are qualified.

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

## P03 lifecycle commands and original-result recovery

`DelegationCommandService::execute` implements the lifecycle subset of the
[versioned command contract](https://github.com/ElevenID/marty-protocol/blob/6126da7619e057be2ff58dd38a5d50f49891d1b3/protocol/delegated-authority/COMMANDS.md):
`CREATE_GRANT`, `APPROVE_GRANT`, `SUSPEND_GRANT`, `REINSTATE_GRANT`,
`REVOKE_GRANT`, and `RECOVER_RESULT`. `START_USE` and `FINALIZE_USE` explicitly
return `UnsupportedCommand`; they are not composed through this lifecycle
service or its human executable. The separate internal
[`DelegationUseCommandService`](USE_COMMANDS.md) implements the bounded KEY use
composition selected by the separate default-off
[`marty-delegated-use` host](../delegated-use/README.md). No public Gateway route
is installed.

The [internal use HTTP router](USE_HTTP.md) selects either
[mandatory mutual TLS](USE_MTLS.md) with exact leaf certificate identity mapping
or a separately trusted forwarding workload. It carries the original bounded
authentication observation into source rechecks and COMMIT guards. The explicit
serving executable selects mandatory mutual TLS only. Full-machine
use additionally requires the [audited machine gate](MACHINE_AUTH.md): migration
0007 retains exact immutable audit bytes and rejects machine receipts without a
matching retained record. The selected [nested JWT-VC adapter](MACHINE_CREDENTIALS.md)
performs real issuer and holder cryptography while leaving authoritative
Trust Profile, issuer/key/status ownership explicitly configured. The concrete
[Organization registry](../organization/MACHINE_REGISTRY.md),
[machine policy source](MACHINE_POLICY_SOURCE.md) and
[credential source](../../crates/machine-credential-source/README.md) now implement
those internal owner paths. Migration 0008 requires retained source/evaluation
evidence for selected machine authorization. Migration 0009 adds fixed row-lock
helpers so the use writer needs no UPDATE authority over grants or immutable
claims/admissions. The executable assembles these adapters with fourteen
restricted database connections; public routing remains separate.

The [machine-use access owner](../organization/MACHINE_USE_ACCESS.md) now supplies
current full-machine/deployment access for commands and Flow ingress. The
[delegated-use policy source](DELEGATION_POLICY_SOURCE.md) selects an actual
Organization-owned exact-operation Cedar revision with retained observations.
[Protected Flow ingress](../flow/DELEGATED_USE_INGRESS.md) retains the original
signed request and immutable proof bytes under independent current rights.

The service accepts original request bytes. It reuses the bounded JSON reader
before normal deserialization, rejects duplicate/unknown fields, explicit nulls,
floats and unsafe revisions, and calculates the command digest over the complete
validated intent. Command canonicalization supports the protocol's safe integer
revision and preserves lexical identifiers; it does not change the number-free
grant terms digest. This Rust adapter continues to reject noncanonical UUID/time
spellings instead of silently normalizing them before equality checks. The
public tests use freshly authored synthetic equality inputs. The exact upstream
corpus is an explicitly ignored external-checkout gate documented under
`tests/fixtures/commands/README.md`; protocol data is not redistributed here.

Tenant and complete typed actor come from `DelegationCommandCaller`, a separate
internal context with no `Deserialize` implementation. Its constructor validates
shape only. It does not authenticate a caller, and the principal/runtime binding
consistency validator does not establish authentication either. A qualified
Gateway/runtime adapter must authenticate them independently before invoking
this service. The optional [separate command host](COMMAND_HOST.md) composes the
human-session lifecycle subset behind the Gateway; it is default off and does
not advertise a delegated-use capability.

Every new mutation requires `DelegationCommandAuthorizer`. It receives the exact
intent and current grant resource; access is checked before disclosing a grant
revision/digest conflict. It returns a trusted observation and deadline, bounded
to 30 seconds. Read-only preparation has a five-second time budget. The sealed
preparation retains the authorization bound and its latest trusted clock sample.
Repositories check those under their write boundary and reobserve source
mutation permission after identity/grant lock waits for the exact sealed intent
and prior grant. The new observation cannot renew the original deadline.
PostgreSQL samples fresh database time after lock waits and after all
grant/journal/result writes. An
expired observation or regressed clock rolls the entire mutation back. These
are bounded observations of the configured authorization owner, not a global
revocation transaction with that owner. Deployment must qualify the source's
freshness and revocation guarantees.

Approval additionally requires a configured `DelegationConfirmationSource`,
which resolves an immutable confirmation identifier from its trusted producer.
A UUID alone never supplies `ApprovalEvidence`. The existing approval lifecycle
still requires the authenticated actor to equal the complete typed grantor, and
`ConsentEvidenceVerifier` checks consent and independent current representation
authority. The optional command host uses the independently current Organization
permission authorizer and immutable confirmation/source adapter. It contains no
consent or authority producer write credential.

The existing lifecycle APIs and command path share the same sealed preparation,
consent verification and transition validation. PostgreSQL migration 0004 adds
an immutable `command_results` table. One transaction serializes the exact
`(organization, actor type, actor ID, command ID)` identity, checks any original
result/digest, applies the revision-checked lifecycle mutation and its existing
journal trigger, inserts the original command result, and rechecks freshness.
A concurrent identical command recovers the original result; changed intent
conflicts. Memory storage models the same write boundary under one lock but is
not durable production persistence. Existing repository implementations that do
not implement command persistence retain their old APIs and fail command calls
closed through the new trait defaults.

Recovery always obtains fresh current read authorization for the original tenant,
typed actor and grant resource. This applies to explicit `RECOVER_RESULT` and
mutation retries. It preserves the original grant ID, revision, terms, approval
and timestamps, even after later revocation or expiry. An expired mutation
permission does not prevent a separately authorized historical read; lost current
read access does. The historical snapshot never asserts fresh authority. No
new grant, approval, receipt or expiry is manufactured during recovery.

This slice performs only read-only preparation before its local transaction and
stores completed outcomes. It has no independently committed external work or
pending final-use job. A missing result can overlap an uncommitted preparation;
it is not proof that no request is running or permission to repeat a business
operation. An ambiguous commit is reconciled using the same original command
identity and digest. The service never retries external work and does not impose
an application cancellation deadline on COMMIT. The separate
[`START_USE`/`FINALIZE_USE` composition](USE_COMMANDS.md) adds durable
pending/unresolved state, retained nonce admission, proof submission ownership
and atomic challenge/result persistence. It requires explicit source and signer
selection and does not change this lifecycle service's admission boundary.

Migration 0004 grants no privileges automatically. The request-serving role needs
only SELECT/INSERT on `command_results`, in addition to its existing grant/journal
privileges. Confirmation and representation-authority producers need no access
to this table. Its insertion guard binds the committed result to the current
snapshot and exact lifecycle event once; historical reads retain that old
snapshot independently of later transitions. UPDATE, DELETE and TRUNCATE are
rejected. Records are retained indefinitely in this milestone. A future retention
implementation must preserve command reuse tombstones and reconciliation rules;
removing a response must never permit identity reuse. The table contains actor
and grant data and requires the same restricted handling as authoritative grants.

Rifare still owns business idempotency, budgets, reservations, financial records
and execution. The command result records a Marty lifecycle change only.

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
changed migration content. Repeated startup is idempotent. For an existing grant table it also obtains an
ACCESS EXCLUSIVE table lock with a five-second lock timeout before checking or
applying migrations. A legacy writer that ignores the advisory lock must finish
before migration 0002 checks emptiness; its committed row causes that upgrade to
refuse without deleting the row or inventing history. Operators must still
quiesce and drain writers before migration.
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
cargo test --locked -p marty-flow --lib delegation_
cargo test --locked -p marty-flow --test delegation_context_boundary
cargo clippy --locked -p marty-delegated-authority -p marty-flow --all-targets -- -D warnings
```

The delegated-authority PostgreSQL contract tests run when
`DELEGATED_AUTHORITY_TEST_DATABASE_URL` names a dedicated disposable test database.
A configured but unavailable database fails the test; an unset variable skips
the database-specific cases. The existing workspace contracts CI lane supplies a
fresh database and sets this variable, so CI executes the live PostgreSQL paths.
The test database owner must be able to create schemas, test roles and disposable
test databases. The command migration race test uses its own temporary database;
it never resets the shared test schema.

The Flow start contract uses `FLOW_POSTGRES_TEST_URL`, pointing to the dedicated
local `marty_atomic_test` database. It takes the existing shared schema-test
advisory lock and resets its Flow and deployment-profile fixture schemas. CI
provides this database as well. The delegated-authority tests serialize their
table-wide guard fixtures within the test process; competing lifecycle updates
inside each case remain concurrent.

Tests cover the pinned protocol digest, strict parsing, typed-identity rejection,
withdrawn consent/authority, expiration during verification, evidence freshness,
clock regression, concurrent revocation, tenant isolation, immutable-term
substitution with a recomputed digest, competing updates, atomic journal rollback,
terminal states, migration/readiness and timestamp precision. They also cover
complete evidence/pin substitutions, confirmation versus authority freshness,
provider timeout, trusted-record activation and withdrawal, explicit authority
renewal, independent producer permissions, activation lock delays, post-write
expiry rollback and rejection when an application clock is frozen.

## Trusted Flow challenge admission

`DelegationChallengeIssuer` admits an exact operation into the existing Flow
challenge lifecycle. Its caller must already authenticate the organization and
complete typed delegate and authorize challenge creation. The request supplies
the grant/revision and operation action, audience, resource, profile and digest;
the issuer generates the opaque challenge ID and verifies the current active
grant, consent, typed delegate and exact scope. Exact-operation grants must also
match their frozen operation profile and digest. Admission creates an identity
challenge; it does not evaluate external constraints or Cedar and cannot permit
an operation.

Key-bound grants use the immutable grant key and require no session provider.
Session-bound grants require a configured `DelegationSessionBindingSource` that
independently authenticates current establishment evidence. Its result must bind
the exact organization, grant, terms digest, typed delegate, session reference,
establishment reference and verified signing-key thumbprint. The provider must
resolve the grant's references through its own trusted source, never fetch a
caller-selected URI. Its deadline must bound both status-observation freshness
and session/key lifetime. Establishment evidence must remain bound to the key it
authenticated; the source cannot retarget an existing evidence reference to a
replacement key. A bound-key change requires a new grant identifier and fresh
approval in v1. No production default source is provided.

Admission rechecks the grant and consent after session resolution. Each awaited
stage checks clock ordering and deadlines; the complete admission has a
five-second budget. The configured challenge lifetime is between 30 and 600
seconds, shortened by grant, consent and session-evidence validity. The returned
`DelegationChallengeAdmission` is move-only, nonserializable and has no public
constructor or mutable binding accessor. Its debug representation omits the
actor, operation and evidence references. Revalidation reads current evidence,
rejects changed grant revisions or session keys, and can only shorten the
original deadline.

Flow's `FlowDelegatedVerificationStarter` accepts this sealed admission and
trusted definition/verifier settings. It loads the existing persisted,
version-pinned active OID4VP definition, validates its references, and reuses
defined verification start, frozen requests, nonce generation and request-URI
construction. It preserves the real definition ID and authenticated delegate
attribution. No wallet request is returned until persistence succeeds. Provider
preparation is bounded separately from the database commit, and errors retain
the original challenge ID for reconciliation. An uncertain commit outcome must
be reconciled against that ID rather than retried with a replacement challenge.

Before persistence, Flow revalidates grant/consent/session evidence and caps the
request expiry again. Its existing start transaction locks and compares the
configured definition snapshot and checks fresh database time after lock
acquisition and after writes. Expiry or changed definition rolls back the start.
These guards protect challenge creation; they do not lock external consent or
session owners until commit or claim instantaneous distributed revocation.

The exact operation is stored in `_marty_delegation_oid4vp_v1`. The independently
configured OID4VP verifier client ID is frozen in
`_marty_delegation_verifier_client_id_v1`. The operation audience identifies the
relying domain; the proof's JWT audience identifies the OID4VP verifier. They
need not be equal. The signed nonce and private Flow binding connect the proof
to the exact operation.

Generic Flow start/upsert paths cannot install or remove these private bindings.
The existing compare-and-swap path preserves their definition, delegate, nonce,
verifier and frozen request while allowing request retrieval, cancellation and
expiry. It cannot attach a successful result or complete a delegated challenge.
The ordinary verification finalizer also rejects delegated challenges until the
delegated final-use transaction is composed. Public context input and output
boundaries continue to protect both reserved keys.

The admission and Flow APIs are internal composition boundaries, not new public
routes. Their tests cover cross-tenant and typed-actor substitution, evidence
binding and freshness, concurrent revocation/withdrawal, session-key rotation,
bounded provider work and deadlines that cannot be extended. Database tests
also exercise trusted start, immutable bindings and rollback at expiry.

## Delegated operation evaluation boundary

The crate now exposes `DelegationUseAuthorizer` as a fail-closed orchestration
boundary for one exact delegated operation. It composes three required adapters:

1. `DelegateProofVerifier` authenticates the delegate's original cryptographic
   proof and exact key/session binding. Key grants must verify the configured
   key thumbprint; session grants must verify the established session and its
   establishment evidence. The proof must bind the organization, grant,
   challenge/nonce, audience and operation digest, and check proof freshness and
   observed live challenge state. Atomic replay enforcement remains a final-use
   obligation. A login, caller boolean or actor ID is not proof.
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
then verifies proof, constraints and Cedar. Each asynchronous stage checks for
clock regression and expired evidence before starting the next one. One
five-second budget covers the complete evaluation, including both lifecycle
reads. A timed-out provider or a result arriving after the budget expires cannot
return a successful evaluation.

The authorizer resolves the grant again after proof, constraint and policy work
and rejects a concurrent suspension, revocation or revision change. It accepts
only a Cedar observation made for the current evaluation, with at most a
30-second validity horizon. The returned `DelegationUseEvaluation` is deliberately
not serializable and is not a bearer permit. It retains the exact typed actor,
action, audience, resource, operation profile/digest, constraint-evidence digest,
grant and policy revision/digest, and the shortest verified deadline. Final use
must still revalidate current grant/evidence and reserve the challenge through
its owning service. The consuming domain must enforce replay and operation
idempotency with its own commit and coordinate those boundaries; a remote grant
read is not atomic with a domain write. Do not cache or reuse this result to
authorize another operation.

The MMF Cedar execution adapter now has a concrete Organization-owned
[exact-operation policy source](DELEGATION_POLICY_SOURCE.md). Its fixed schema
binds the complete typed actor, tenant, grant and requested operation; it supplies
no business roles or domain resource attributes. A consumer domain integration
must independently own and qualify external context, entity graphs and domain
permissions when selected. ElevenID does not own commerce execution. These
adapters still require authenticated runtime composition and end-to-end
qualification; they are not deployed authorization endpoints.

## OID4VP delegate proof verification

The crate includes `MartyOid4vpDelegateProofVerifier`, which reuses the pinned
Marty Core `VerificationEngine::verify_authenticated_vp_proof_at` and Marty
Verification's RFC 7638 JWK thumbprint implementation. It does not implement a
second JOSE parser, JWT signature verifier, or thumbprint algorithm.

The verifier accepts the compact JWT VP produced through the existing OID4VP
Flow. Its challenge ID resolves to authoritative Flow-owned challenge state;
the nonce and verifier audience are loaded from that state and never accepted
from caller-supplied proof metadata. `DelegationFlowContextV1` binds that challenge
to the exact tenant, grant/revision, typed actor, action, audience, resource and
operation profile/digest. Reusing the signed nonce for another in-scope operation
fails. The context rejects unknown fields, nil identifiers, out-of-range revisions
and partial session bindings.

The verifier also requires a well-formed presentation, matching holder/issuer,
matching subject when present, a short proof lifetime, no future `nbf`, and the
signer key binding. Key-bound grants compare the RFC 7638 thumbprint, encoded as
the MIP `sha256:` lowercase hexadecimal digest. Session-bound grants compare the
exact session and establishment evidence references plus the key thumbprint
established by that session.

The challenge lookup is read-only. Evaluation is not a permit and must not
consume the challenge prematurely. Final use still needs current grant/evidence
checks, one-time challenge consumption, replay reservation and signed receipts.
The challenge ID is carried in the nonserializable evaluation object for that
integration. Atomicity can cover records participating in the same database
transaction; it cannot be claimed for an external domain's side effects. The
consuming domain must enforce its operation idempotency and coordinated commit
contract. Two independently issued challenges for the same operation are not
the same as a nonce replay. Flow retains standard OID4VP request construction,
request signing and nonce/session persistence; its ordinary finalizer is guarded
against completing a delegated challenge without the required integration.

The challenge store is an explicit integration port, not a new parallel
challenge database. The Flow service now provides
`FlowDelegationOid4vpChallengeStore`, which resolves the opaque challenge ID to
the existing tenant-scoped Flow instance, requires an active OID4VP definition
and unfinished, unexpired session, validates its frozen request, and reads the
typed binding and verifier pin from private Flow context. Public start and
advance requests reject reserved keys at every nesting level; public results
remove them recursively. It reuses the Flow request/session lifecycle and request
URI scheme. The retained-use owner adds immutable nonce correlation and replay
retention without replacing Flow as the challenge owner. The trusted starter
described above populates the snapshot from an authenticated admission.
Production session evidence, authenticated proof ingress and public runtime
composition remain separate qualification gates. A mock or in-memory challenge
store is test-only and cannot qualify production replay protection.

Regression tests use public-only signed Ed25519 JWT VP vectors with the actual
pinned Marty verifier. They cover valid key/session proofs, wrong keys, changed
signatures, nonce/audience/identity mismatches, malformed presentation claims,
expired and not-yet-valid proofs, operation substitution and incomplete session
bindings. Flow tests exercise frozen-request/state checks and the public input
and output boundary. Authorization tests use the actual MMF Cedar engine and
cover policy denial, typed principals, freshness, timeout and intervening state
changes.

## Signed delegated decision receipts

The crate now defines the Delegated Decision Receipt v1 payload and compact JWS
envelope from the pinned MIP schema. A receipt is built only from a completed,
nonserializable DelegationUseEvaluation, carrying PERMIT or DENY; the operation, typed actor/subject,
grant revision/digest, approval and authority evidence references, OID4VP nonce
and proof evidence, active status observation, policy identity and all evidence
deadlines are copied from verified service state. External-profile evaluations
also retain the configured evaluator, immutable profile/document digest,
authenticated evidence reference, decision and freshness window.

DelegatedDecisionReceiptIssuer resolves a tenant-scoped key for the configured
receipt issuer and exact urn:marty:delegated-decision:jws-v1 purpose, then signs
the exact compact-JWS signing input using that same resolved key identity. Only
ES256 and EdDSA with raw 64-byte JOSE signatures are accepted. The signing
adapter is an explicit port to the existing managed signing/KMS service; this
crate does not create/export keys or implement another JOSE cryptographic stack.
The protected header uses typ=mip-delegated-decision+jws, and the payload uses
the protocol's urn:marty:delegated-decision-receipt:v1 profile.

Receipt expiry is bounded by the evaluation, proof, current grant/consent status,
external constraint evidence and configured receipt lifetime. The payload is
evidence of one evaluation, not a bearer permit. It does not consume the Flow
nonce, reserve merchant idempotency, or atomically commit a purchase. Those
remain separate final-use and consuming-domain obligations. The
[`HttpManagedDelegatedReceiptSigner`](RECEIPT_SIGNING.md) now provides an explicit
managed-custody adapter with exact public-key pins, a dedicated signing-grant
origin and independent verification of the returned signature. Live provider
and credential qualification, executable selection and independent protocol
consumer verification remain required before runtime qualification.

## Internal retained-use and selected machine composition

[`DelegationUseCommandService`](USE_COMMANDS.md) and
`PgDelegationUseRepository` retain the original command identity before external
preparation or signing, then atomically persist challenge admission or a signed
final decision. Completed denial is retained just like permit. An unresolved
claim never triggers automatic preparation, evaluation or signing again.
Historical recovery preserves the exact result and requires current read
authorization.

The concrete `FlowDelegatedUseOwner` operates through the supplied PostgreSQL
connection, checks its immutable storage identity and retains nonce, proof and
consumption state. Its immutable proof-submission API now has an explicitly
assembled [authenticated ingress](../flow/DELEGATED_USE_INGRESS.md); submitted
bytes become verified evidence only after the configured
cryptographic verifier runs. All current state comparisons and deadlines are
rechecked at the local commit boundary. The resulting response has
`semantics: EVIDENCE_ONLY` and asserts no business side effect.

[`MartyMachineOid4vpProofVerifier`](MACHINE_AUTH.md) supplies a selected
`DelegateProofVerifier` composition using actual Core OID4VP verification,
strict full-machine/MAP consistency and every selected credential, attestation
and machine-authorization requirement. `MmfMachineAuthorizationVerifier` runs
the selected machine policy through MMF Cedar; separate delegated/domain policy
evaluation remains required. The SERVICE_ACCOUNT enrollment inventory does not
satisfy the full MachineIdentity source contract; the separate concrete registry
owns that state. `AuditedMachineOid4vpProofVerifier` durably retains the exact
aggregate audit before returning authenticated proof. Its referenced source
records remain independently retained by their actual owners.

These are internal composition APIs. The human administration executable and
Gateway continue rejecting use commands; no default machine source, signer or
use host is installed. See the
[application checkpoint](../../../docs/delegated-use-runtime-candidate.md) for
the measured verification and remaining deployment work.

### Protected original receipt recovery

The separately assembled `delegated_use_receipt_router` exposes
`POST /internal/v1/organizations/{organization_id}/delegated-use/receipts/recover`.
It uses the same configured workload authenticator as retained-use commands.
Its request is the existing strictly decoded `RECOVER_RESULT` document, containing
`profile`, `command`, `original_command_id`, and `expected_command_digest`.
The path accepts no query parameters, receipt-reference lookup, listing or new
command form. The ordinary command router and its P03 response are unchanged.

`DelegationUseCommandService::recover_receipt_before` requires the authenticated
context's original observation and expiry. Current `RECOVER_RESULT` access is
checked before and after fetching the artifact; the second check cannot extend
the original authentication or first access deadline. Both lookups use bounded,
read-only PostgreSQL transactions. The reader binds tenant, full typed actor,
original command and digest, retained admission and result, receipt reference,
SHA-256 digest, and decoded compact-JWS payload. It preserves the signed timestamp
precision while checking the corresponding PostgreSQL timestamp representation.
No new database permission, migration, signer call, evaluation or mutation is
required.

Only a completed `FINAL_USE` original returns a receipt. The sealed,
Serialize-only response contains `original_response` with `recovered: true`,
`receipt_ref`, `receipt_digest`, the exact stored `compact_jws`, and
`semantics: EVIDENCE_ONLY`. Debug output redacts its identifiers and artifact.
Every HTTP response carries `Cache-Control: no-store`, `Pragma: no-cache`, and
`X-Content-Type-Options: nosniff`.

An original PERMIT or DENY can still be recovered after its grant, proof or
receipt expires or the grant is revoked, provided the actor retains current
identity and recovery access. Recovery neither renews that evidence nor changes
the decision. A consumer must independently verify the receipt against its pinned
key and expected context, then apply the appropriate fresh-use or historical
policy and its own operation idempotency and business commit rules.

## Optional organization approval producer

The `marty-delegation-approval` binary hosts an explicitly enabled approval
candidate for a narrow relationship: an authenticated human grantor represents
the configured organization, and the delegate is bound by `KEY`. The subject is
exactly `urn:marty:organization:<tenant UUID>` and the grantor is exactly
`urn:marty:user:<canonical user UUID>`. The configured issuer must be an
`ORGANIZATION`. This path does not establish delegated `SESSION` evidence or
authenticate the delegate's key; those remain separate use-time requirements.

The Gateway validates a live, non-impersonated Auth session, its actual expiry,
the exact active tenant, the configured browser Origin and current organization
permission. It forwards a short-lived observation through a mandatory service
token hop. Only the SHA-256 reference of the validated session cookie is
forwarded/stored, never the cookie. `AuthenticatedApprovalSession` has no
deserializer; calling its constructor only checks shape and does not authenticate.
Public JSON cannot supply actor, session, source state or an authority-success flag.

The service returns a server-issued review ID with the exact immutable grant
reference, terms, issuer, fixed review expiry and maximum consent lifetime.
Only an explicit `CONFIRM` for that review/digest can produce consent. Review and
confirmation bind the authenticated human and original session. Consent and its
confirmation index commit in one PostgreSQL transaction. Concurrent identical
confirmation requests recover the same original record; different terms, grant,
review or session cannot reuse that identity. Each review can be confirmed once.
Neither a review nor a confirmation activates the grant.

Current representation authority comes from `PostgresOrganizationStore`, using
the authoritative database, an active organization and membership, and the exact
`delegation-grant:approve` permission. Owner status and role names do not replace
that permission. The authority producer independently checks that source and
appends an assertion plus source/member provenance using its own database role.
Assertions live for at most 15 seconds, bounded from before the source read;
slow reads, source failures, clock regression and expired observations deny.
The trusted worker refreshes due assertions only after another source check.
Revocation is terminal for an evidence reference. The read-only
`OrganizationRepresentationAuthorityProvider` separately rechecks Organization
on every verification and reads current durable revocation state. It never
renews authority or confirmation timestamps as a side effect of resolution.
This is bounded current-source validation, not an atomic lock across Organization
administration and a delegated operation.

Consent expires at the earlier of the grant deadline and the configured
confirmation lifetime (at most 300 seconds); the returned `valid_until` is that
actual bound. Historical retry does not renew it. Confirm/recovery and withdrawal
require current `delegation-grant:view`; a new confirmation additionally requires
the independently checked approval permission. An identical committed
confirmation can therefore be recovered after the approval permission is removed.
Withdrawal is available to the original human using a fresh live session and
current read access, even without current representation authority. It records
one immutable withdrawal event. Historical confirmation recovery after withdrawal
still returns the original historical result, not current authority.

`PgApprovalConfirmationSource` composes with the existing P03
`DelegationConfirmationSource`. It requires the same typed human, exact grant
and digest, original authenticated session reference, unwithdrawn consent and
fresh immutable deadline. A command runtime must populate session provenance
from its authenticated context, never command JSON. The existing configured
consent verifier still performs the independent current-authority check before
an activation can commit. The approval host exposes no lifecycle command or
final-use route and does not automatically approve on confirmation.

Migration `0005_organization_approval.sql` is additive. Migrations 0001–0004 are
unchanged. Deploy four distinct restricted credentials: evidence reader, consent
producer, authority producer and Organization source reader. Use a separate
migration owner. Startup applies no DDL/grants and requires schema/readiness
qualification. Readiness checks reachable roles (including `SET ROLE`), column
ACLs and grant options, source-write crossover, object ownership, enabled guard
bindings and the evidence installation identity. It is not a measurement of the
running executable or complete network/credential attestation. Operators must
qualify deployment isolation, exact profile/version/artifact metadata, primary
database routing, clocks, security audit delivery and the public Gateway/Auth
composition before enabling the candidate. The existing deployment preflight
remains part of that qualification.

Run owned migrations explicitly with `marty-delegation-approval migrate` and
`DELEGATION_MIGRATION_DATABASE_URL` (or its `_FILE` form). The optional host
requires `MARTY_DELEGATION_APPROVAL_ENABLED=true`, a mandatory `GRPC_SERVICE_TOKEN`,
and the `DELEGATION_APPROVAL_*` configuration in `approval_host_config.rs`.
`verify-owned-schema` is read-only. No capability discovery claim follows merely
from enabling these approval administration routes.

## Remaining runtime qualification

- Qualify the optional KEY organization approval and human command paths across
  live Gateway, Auth, Organization and independently provisioned credentials.
  Additional represented-subject/issuer relationships and session-bound signing
  keys require their own reviewed authority and establishment sources.
- Qualify the selected machine gate's independent full MachineIdentity/MAP
  source, credential issuer/status providers, required attestation and current
  machine-policy/schema/entity source. Preserve the SERVICE_ACCOUNT inventory
  distinction and fail closed for missing configured requirements.
- Configure external-authority/status and external-constraint sources where
  selected, plus the consuming domain's active Cedar policy and typed entities.
  Verify freshness and revocation behavior across those independent owners.
- Qualify deployment of the implemented default-off use executable with its
  mutual-TLS boundary, current use-access/policy owners, protected request/proof
  ingress, same-database Flow owner, restricted use writer and independent source
  credentials. Qualify production certificate issuance/revocation and pin
  rotation. The human command executable and Gateway lifecycle surface must
  continue rejecting use commands.
- Qualify deployed machine-audit and referenced-source retention. Establish
  attributed audit delivery and a separate reconciliation design for retained
  pending command and request-signing claims without retrying external work.
- Qualify live managed receipt custody and its separate mint/verify authority,
  exact issuer/key pins, rotation and unavailable/replay behavior. The implemented
  disposable OpenBao/Redis gate qualifies its actual router/kernel composition;
  deployed outer HTTPS, production credentials and AWS/IAM remain separate.
- Qualify public Gateway contracts, independent receipt consumers and deployment
  behavior before capability discovery changes. Rifare must retain its own
  operation idempotency and business commit contract; the local evidence/nonce
  transaction does not make an external business side effect atomic.

No allow-all consent verifier is provided for production. Test doubles exist only
under `cfg(test)`. There is no public delegated-use route, discovery
advertisement or production deployment qualification in this milestone.
