# Flow verification and replay receipts

## Scope

This W05 increment gives Flow's existing terminal verification transaction a
bounded, recoverable receipt. It continues the managed SD-JWT prerequisite work
on top of the protocol corrections in PR 1851, preserving its Core and MMF
dependency pins. The new contract records a Flow persistence fact:

> This original Flow request and wallet submission produced this terminal
> result, and Flow committed that result, its nonce consumption and any callback
> together.

The wire contract is `marty.flow-verification-receipt/v1`. It is separate from
the native query and managed-owner records described in
[SD-JWT prerequisite evidence](sd-jwt-prerequisite-evidence.md).

A receipt does not establish that an earlier policy decision was still valid
at database commit, authenticate a plaintext owner response, become
`AuthenticatedOid4vpEvidenceV1`, authorize a credential offer, or grant an
issuance continuation. Those remaining W05 boundaries stay explicit.

## Clock ownership

| Value | Owner and meaning |
| --- | --- |
| `policy_evaluated_at_epoch_micros` | The actual evaluation timestamp returned by Policy in its existing protobuf field 12, retained without substituting Flow's clock. |
| `nonce_consumed_at_epoch_micros` | PostgreSQL's `clock_timestamp()` returned by the nonce insertion inside the transaction. This is not the exact instant that PostgreSQL completed COMMIT. |
| Receipt availability | The sealed in-process result is returned only after `transaction.commit().await` succeeds. |
| `nonce_retention_expires_at_epoch_micros` | The nonce row's cleanup deadline, not an authorization lease for the result or receipt. |

Timestamps use integer microseconds, preserving PostgreSQL precision. Policy
time must be positive and no later than nonce consumption; consumption must
precede the nonce retention deadline. Unsupported sub-microsecond Policy
timestamps are rejected rather than rounded into a different observation.
Future Policy observations fail closed at finalization.

Flow now carries Policy's existing `evaluation_timestamp` through its internal
provider result, stored terminal result, HTTP projection, gRPC result timestamp
and MIP `evaluated_at` field. Existing Flow completion timestamps retain their
compatibility meaning; neither is relabeled as the database commit timestamp.
Legacy stored results without a Policy timestamp retain their previous
projection fallback.

## Exact bindings and privacy

The strict receipt projection contains:

- The tenant, Flow instance and existing `FrozenPolicyIdentity`.
- A domain-separated digest of the complete **original** expected Flow record,
  including its private frozen request and context. This binds the exact query,
  nonce, verifier, owner snapshot, policy, initiating principal and original
  record used by finalization's comparison. The working result context is not
  substituted for that original record.
- The exact existing submission digest and consumed nonce-table key.
- A domain-separated digest of the complete terminal result before adding the
  receipt.
- A separate digest of the minimized callback basis before receipt and decision
  digest fields are added.
- The three timestamps above and a digest of the complete receipt body.

The receipt contains no raw presentation, disclosure, nonce, subject, claim
value, private key or private context. Its hashes use the existing canonical
digest owner. Flow-specific domains distinguish this stored-request binding
from the still-separate canonical `FrozenOid4vpRequestV1` contract.

Wire deserialization and digest validation establish correspondence only. They
cannot construct `CommittedVerificationFinalization`. That type has private
fields, no deserializer and a repository-owned constructor used after commit.
The in-memory repository models atomicity under one lock; it does not claim
durability across process restarts.

## Preparation, transaction and recovery

When Policy supplies a valid timestamp, Flow prepares receipt correspondence
alongside the terminal candidate. The managed prerequisite profile requires
that owner timestamp. Older providers that omit it retain the legacy path
outside the managed profile. SIOP finalization is unchanged.

Preparation contains no completed receipt. Its private binding also covers the
candidate result, callback envelope, nonce and retention deadline, so mutations
after preparation are rejected before persistence.

Both PostgreSQL finalization paths lock the instance before nonce work. This
common order prevents a mixed legacy/receipt lock inversion. The receipt path
compares the complete locked row with the original expected record. The legacy
path retains its existing status, context and update-time predicates.

Within one READ COMMITTED transaction, Flow:

1. Locks the tenant-scoped instance and checks the original request state.
2. Inserts the nonce consumption and obtains its database timestamp.
3. Constructs the receipt and adds it to the terminal result and callback.
4. Applies the existing conditional update, including a fresh live-expiry check
   after any row-lock wait, and inserts the callback outbox row.
5. Commits, then returns the sealed committed instance and receipt.

A conflicting nonce, changed original state, expired session, invalid clock or
callback insertion failure cannot publish a new receipt. Transaction rollback
also removes nonce and terminal-result changes. The legacy repository APIs
reject preattached receipts in either a result or callback, so caller JSON
cannot enter the normal callback signer through that path.

Generic start and advance inputs reserve the `verification_receipt` field.
General instance saves, starts, application reservations and conditional writes
also reject receipt-bearing context or results, including internally consistent
receipt JSON. Only the private finalization path may write the owner-produced
receipt; terminal readback and recovery require no generic write exception.

The HTTP response is projected from the committed instance. Permitted identical
retries and later readback return the original persisted receipt, without
refreshing its clocks or request/result binding. A conflicting submission gets
no new receipt. If a commit response is lost, recovery reads stored state; it
does not invent a second consumption event.

The receipt remains in the terminal result when expired nonce rows are cleaned
up. Historical receipt validation therefore does not require its retention
deadline to remain in the future. Normal Flow-record retention still applies.
A terminal denial can also have a receipt, bound to that denial. Retryable
authentication rejection and uncommitted preparation have no receipt.

## Callback and deployment compatibility

The shared callback producer adds an optional `verification_receipt` before
calculating the callback decision digest. The existing evidence digest keeps
its credential-result meaning. Existing callback HMAC authentication covers the
complete receipt-bearing payload.

Auth's independent typed consumer preserves that optional field, validates its
session, policy and callback correspondence, and checks its tenant against the
configured owner scope before acquiring or recovering a login claim. Auth does
not possess the private full-result basis and does not claim to verify that
result hash independently.

Absent receipts are omitted during serialization. Queued legacy canonical
payloads and HMAC vectors remain unchanged. Deploy compatible Auth callback
handling before Flow begins sending receipt-bearing callbacks. The receipt
lives in existing result/outbox JSON; this increment adds no migration, new
external endpoint, key store, dependency version or protobuf field.

## Validation boundaries

Focused regressions exercise distinct owner/consumption clocks; no precommit
receipt; privacy; callback/result identity; digest-consistent substitution;
preparation mutation; expired and changed requests; one-winner races; denial
receipts; historical recovery; and legacy callback compatibility. Compile-fail
checks guard against JSON construction or canonical promotion.

The existing registered Flow PostgreSQL contract also covers real row locks,
the mixed legacy/receipt race, database consumption-time correspondence,
callback-insertion rollback and persisted readback. Its SQL assertions require
the existing isolated `FLOW_POSTGRES_TEST_URL` environment. Compilation or an
early return without that database is not an executed database pass.

Exact test receipts, both independent source-audit dispositions and hosted CI
status are recorded in the publishing PR. The next canonical producer still
must preserve the [authenticated owner acquisitions](authenticated-managed-owner-channels.md)
and explicitly compose
Policy observation, native validity and this durable replay outcome. The
canonical validator's current single-time semantics are not relaxed here.
An Issuance-owned, expiring, single-use continuation remains subsequent work.
