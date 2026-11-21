# Retained delegated-use runtime candidate

This follow-on to `0404d1100f34f1423c80c432c0cd63df60908f48` adds an internal
composition for retained `START_USE` and `FINALIZE_USE` commands, the concrete
Flow transaction owner, selected full-machine authentication, and managed
decision-receipt signing. It closes implementation gaps between the existing
proof, grant, policy and persistence components. It does not install a
delegated-use executable or public route.

The human `marty-delegation-commands` executable and its Gateway surface still
reject use commands. There is no default caller authorizer, machine evidence
source or selected receipt signer. Public MIP remains 0.5.0; support levels and
capability discovery remain unchanged. The Protocol source stays pinned at
`6126da7619e057be2ff58dd38a5d50f49891d1b3`.

## Implemented composition

| Component | Implemented responsibility | Boundary that remains explicit |
| --- | --- | --- |
| `DelegationUseCommandService` | Strict P03 use intent, durable original command claims, current caller authorization, sealed START admission, final PERMIT/DENY evaluation and original-result recovery | Internal KEY-grant API; no automatic host or caller authentication |
| `PgDelegationUseRepository` | Shared lifecycle/use command identity, immutable admission/receipt/result records and deferred deadline checks | Requires separately provisioned privileges and the same PostgreSQL database as its Flow owner |
| `FlowDelegatedUseOwner` | Actual Flow challenge preparation, immutable proof submission, frozen definition/proof checks, retained nonce admission and final consumption on the supplied connection | Proof ingress must authenticate the caller; storing proof bytes does not verify them |
| `MartyMachineOid4vpProofVerifier` | Concrete Core OID4VP verification plus selected full-machine MAP, key/runtime and required evidence checks | Full-machine, credential and attestation providers must be independently qualified |
| `MmfMachineAuthorizationVerifier` | Actual MMF Cedar evaluation of the selected `MACHINE_AUTHORIZATION` policy and typed context | Requires a current trusted policy/schema/entity source; delegated/domain authorization still runs separately |
| `HttpManagedDelegatedReceiptSigner` | Pinned managed issuer/key, separate signing-grant origin, remote signing and independent verification of the returned signature | Explicit deployment selection, key provisioning and live provider qualification remain required |

The component contracts are documented in
[retained use commands](../rust/services/delegated-authority/USE_COMMANDS.md),
[selected machine authentication](../rust/services/delegated-authority/MACHINE_AUTH.md),
[managed receipt signing](../rust/services/delegated-authority/RECEIPT_SIGNING.md)
and the [Flow delegated-use owner](../rust/services/flow/DELEGATED_USE.md).

## Original intent and retained outcomes

The service commits an immutable command claim before preparing a Flow request
or signing a receipt. Its identity includes the organization, complete typed
actor and command UUID; its digest covers the original P03 intent. Lifecycle
and use commands share that namespace, so one command identity cannot be reused
for a different intent or operation kind.

| Retained state | Result of repeating the original command |
| --- | --- |
| No claim or result | Admission may proceed after current authorization |
| Claim without a completed result | `PreparationPending`; external preparation, evaluation and signing are not repeated |
| Completed result with the same intent | Original immutable response with `recovered=true`, after current read authorization |
| Same identity with changed intent | Conflict |

Pending claims survive preparation failures, process exits, ambiguous signing
and final transaction rollback. This candidate has no lease takeover,
automatic retry, claim deletion or reconciliation override. Recovery of an
original result preserves its historical timestamps, decision and evidence; it
does not refresh authority or create another challenge.

### START_USE

The service resolves the exact active grant revision and terms, checks the
requested operation and obtains an opaque `DelegationChallengeAdmission`.
After the command claim is retained, the configured Flow owner prepares its
nonce and wallet request. A command cannot supply the verifier identity,
nonce, private Flow context or a successful verification flag.

The Flow challenge, retained nonce correlation and original `CHALLENGE` result
commit in one local transaction. The concrete Flow owner checks the immutable
storage identity on the supplied `PgConnection`; it cannot report a write from
a different database as part of that transaction. The current Flow definition
is locked and compared with the prepared snapshot. The retained nonce remains
reserved after expiry or consumption, independently of ordinary verification
nonce cleanup.

### Proof submission and FINALIZE_USE

An authenticated future ingress may call `record_proof_submission` to retain
bounded proof bytes against the original tenant, actor and challenge. Repeating
the same bytes returns the retained submission identity. The public projection
contains identifiers, digest and submission time; raw proof bytes stay in the
restricted Flow source table. That storage step establishes no authentication
or authority.

`FINALIZE_USE` names the original challenge and immutable submission ID. The
service reserves one finalization identity per challenge before evaluating or
signing. The configured proof verifier, current grant/consent owner, operation
constraints and active Cedar policy must produce a completed evaluation.

A completed Cedar FORBID or ABSTAIN produces a signed DENY and consumes the
original challenge. A later policy change cannot turn that original finalization
into PERMIT. Invalid proof, unavailable evidence, expiry and signing failure
remain unresolved errors; they do not fabricate a signed decision.

The final transaction locks the retained command, current grant and admission,
then the original Flow instance and immutable proof. It compares the exact
prepared state, rechecks current permission and grant/consent without extending
the earlier deadline, consumes Flow state and persists the exact compact JWS,
receipt digest and original `FINAL_USE` result. Later failures roll those writes
back together; the original command claim remains. Fresh database-clock checks
and deferred guards reject expiry after later lock or commit-time waits.

Request retrieval can update permitted progress metadata while preserving the
original challenge and frozen request. If it changes the complete Flow snapshot
after finalization has already been prepared, the conservative finalizer returns
a conflict and retains the unresolved command. Coordinating that path remains
an explicit host obligation; the candidate does not retry signing automatically.

## Selected machine authentication

`MartyMachineOid4vpProofVerifier` implements the existing `DelegateProofVerifier`
port. Its cryptographic step always uses the concrete Core-backed
`MartyOid4vpDelegateProofVerifier`. The existing public-only VP vectors exercise
actual verification; enrollment proofs cannot satisfy this path.

This selection requires a real current `MACHINE_IDENTITY`, a managed runtime,
an assigned deployment, current active registered public key and a MAP selecting
`MACHINE_KEY` with `OID4VP_VERIFIABLE_PRESENTATION`. The authentication audience
is the Flow verifier client ID; the relying operation audience remains a
separately bound value.

The current Organization inventory remains `SERVICE_ACCOUNT`. Its ACTIVE and
`KEY_CONTROL_VERIFIED` enrollment state does not manufacture a full
MachineIdentity. No automatic conversion or fallback directory source is
provided. A deployment must independently source the full machine record,
current key/runtime state and actual MAP assignment.

Every selected credential type must be authenticated under the configured Trust
Profile and associated with a currently registered machine credential. Required
attestation must bind the selected format, verifier Trust Profile, machine key,
runtime and challenge. A selected machine authorization policy must produce an
error-free permit under its exact current policy identity, revision and digest.
Missing or unqualified providers fail closed. Positive results are trusted
in-process evidence records; HTTP callers cannot supply success booleans.

All provider results bind the entire derived machine, key, runtime, MAP, grant,
challenge and operation scope. Source observations are bounded to 30 seconds,
the full read-only gate has a five-second timeout, and later observations cannot
extend the original deadline. The trusted clock is reread after awaited work.
These are bounded observations across owners, not a distributed atomic
revocation transaction.

The returned generic proof reference commits a bounded canonical machine audit
record containing the original Core proof, MAP document/digest and every
selected provider observation. `verify_machine` exposes the exact audit bytes
through its opaque result. Hashing those bytes does not store them: durable
retention of this record and its referenced evidence is a required host
integration, and is not supplied by the generic proof conversion.

## Managed receipt custody

The managed signer uses a configured HTTPS Signing Keys origin and an exact
tenant, typed issuer, verification method, provider key reference, algorithm and
public-key pin. It resolves the current profile again after receipt preparation
and verifies returned ES256 or Ed25519 signatures over the exact signing input.
The production constructor holds no local private key.

The dedicated `DelegatedDecision` signing-grant origin binds the receipt ID,
tenant, route, issuer, key, purpose, algorithm and exact input digest. Existing
gateway, issuance and Flow origins cannot sign for that purpose. Signing Keys
consumes the one-use grant before its provider call. Receipt-purpose profiles
and key bindings require explicit configuration and cannot reuse another
registered purpose. The default origin set and public purpose catalog do not
acquire receipt authority.

`MARTY_DELEGATED_RECEIPT_SIGNING_ENABLED` only selects the new verifier origin;
it does not create a receipt key, provider policy, use host or capability.
The adapter has separate read and signing credentials, but the read credential
is the existing broader internal Signing Keys credential. A narrower resolver
role, where needed, remains deployment work.

## Persistence and operator boundaries

Delegated Authority migration 0006 adds the shared command identity and retained
use ledger. Flow migration 0005 adds its storage identity, immutable challenge
and proof records, consumption evidence and guards. Earlier migration bytes are
preserved. Follow the
[read-only upgrade and rollback procedure](delegated-authority-upgrade.md);
readiness never repairs missing historical evidence.

Existing lifecycle writers additionally require the narrowly scoped shared
command-identity access. They do not receive the use ledger, proof, receipt,
consent or authority producer's privileges. A use writer needs its own reviewed
role composition across the relevant local schemas. Preserving separate
producers and source readers remains necessary even when Flow and the ledger
participate in the same database transaction.

Disabling a future host stops new admissions while preserving original claims,
nonce reservations, proofs, decisions and receipts. Rollback does not erase an
ambiguous command or free its identity for reuse.

## Evidence meaning and Rifare

The result and Flow completion carry `semantics: EVIDENCE_ONLY`. They record the
Marty identity and authority decision for one exact request. A valid receipt
does not assert that a merchant accepted an order, a payment occurred, a budget
was reserved or a provider completed work.

Rifare continues to own logical agents, models and prompts, orchestration,
domain/resource permissions, budgets, business idempotency, reservations,
provider execution and business outcomes. It must consume qualified public
Gateway contracts; this candidate does not permit importing private Marty Core
code or reading Marty storage. A local atomic receipt/nonce commit does not
make an external business side effect atomic.

## Measured local validation

The following are separate verification views and overlap; do not add them into
one aggregate. Rust checks use the locked dependency graph offline. Hosted
Actions, live managed signing providers and a production deployment are outside
this evidence.

| Check | Result |
| --- | --- |
| Principal binding, enrollment and pinned Protocol corpus | 56 passed, zero ignored; includes 10 new MAP tests and four compile-fail contracts |
| Selected machine gate and real MMF Cedar | 13 passed, zero ignored; actual Core VP crypto, full evidence scope, requirements, clocks, timeout and aggregate audit provenance |
| Opaque machine-proof contract | One service compile-fail doctest passed |
| Retained use command ledger | 15 focused tests passed, including all 14 explicit PostgreSQL cases |
| OID4VP verifier-ID compatibility and retained ledger | 24 focused tests passed after preserving opaque verifier client IDs; includes the 15 ledger tests |
| Read-only upgrade preflight | 101 live PostgreSQL tests passed |
| Receipt signing adapter | Six tests passed with actual ES256/Ed25519 signatures and negative returned-key/origin/response cases |
| Signing-grant library | 32 passed; three existing live provider fixtures remain ignored |
| Signing Keys library | 274 passed; 22 existing live/external fixtures remain ignored |
| Signing Keys executable | Targeted binary compilation passed |
| Full delegated-authority regression | 184 passed, zero failures or ignores, with all PostgreSQL cases enabled and serialized; one separately configured external command-corpus case was explicitly filtered |
| External command corpus | The filtered case separately passed against the clean pinned Protocol checkout |
| Concrete Flow transaction/proof integration | 10 passed, zero ignored; includes six new explicit PostgreSQL cases with actual Core/ES256 proof, signed PERMIT/DENY, post-sign rollback, source isolation, retrieval progress and deferred expiry |
| Broader Flow library | 92 passed; 13 fixture cases ignored in the normal run, including the six delegated-use cases and public-retention case executed explicitly |
| Existing Flow PostgreSQL regressions | Five passed across retained-data handling, physical-start/finalization/callback atomicity, issuance-prerequisite freshness and public HTTP retry/quota/cancel races; one separate fenced-role case remains ignored |
| Combined six-package all-targets compilation | Passed for Gateway, Flow, Delegated Authority, principal binding, signing grant and Signing Keys |
| Formatting and whitespace | Scoped Rust formatting and CRLF-aware diff checks passed |

The full service aggregate preceded the final verifier-client-ID correction;
the subsequent 24-test run covers that correction and the ledger/OID4VP paths.
The external command corpus was then run separately with its explicit source
configuration instead of being counted as an unexecuted aggregate case.
The focused Flow group overlaps the normal library suite in four tests. Its six
delegated-use cases and the separately selected public-retention case cover
seven of the normal run's thirteen fixture-gated ignores. External TLS/OpenBao
and separately provisioned fenced-role qualification remain outside these runs.

The public VP fixtures contain no private keys. Signature adapter tests generate
ephemeral keys in memory. Credential and attestation test providers exercise
the gate's contract; they do not qualify external issuers or attesters. The
receipt HTTP fixture models Signing Keys responses and replay denial; it does
not replace live OpenBao/AWS/Redis receipt-origin qualification.

## Remaining runtime milestones

1. Qualify the independently authenticated full-machine/MAP source, credential
   issuer/status sources, required attestation and active machine/domain policy
   sources. Connection/grant aggregation and broader authority/session profiles
   retain their separate contracts.
2. Compose an explicit executable and authenticated ingress for command callers,
   wallet request retrieval and immutable proof submission. Provision the bounded
   use writer and independent source credentials, and retain machine audit
   records before returning qualified results. The human administration host
   must continue rejecting use commands.
3. Exercise real managed receipt custody with distinct mint/verify permissions,
   exact issuer/key pins, rotation and unavailable/replay behavior. Local
   cryptographic tests do not qualify live provider operation.
4. Qualify retained recovery, source freshness and the selected public
   request/response and independent consumer verification contracts across the
   deployed services. Pending command reconciliation needs its own reviewed
   design before any automatic retry or takeover is introduced.
5. Promote public support/discovery only after those gates pass, then integrate
   Rifare through those public features with its own operation commit and
   idempotency rules. This checkpoint changes no Rifare execution behavior.
