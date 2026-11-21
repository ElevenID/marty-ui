# Flow owner for retained delegated use

`FlowDelegatedUseOwner` supplies the concrete Flow ports used by the internal
`DelegationUseCommandService`. It builds on the existing sealed
`DelegationChallengeAdmission`, defined verification start and
`FlowDelegationOid4vpChallengeStore`. It introduces no new Flow type, public
endpoint, caller-authentication shortcut or business execution hook.

## Ownership and transaction composition

Flow owns the actual OID4VP instance, private operation binding, frozen request,
verifier client ID, nonce, proof submission and consumption. Delegated Authority
owns the original use command, grant/consent evaluation, retained admission,
decision receipt and immutable result. Its admission is a correlation with the
Flow record; it cannot replace that source with caller-supplied fields.

Construct the adapter with a separately configured `PostgresFlowRepository`,
trusted provider registry and `DelegatedVerificationStartConfiguration`. It
loads a stable UUID from `flow_service.delegated_use_storage_identity`. Every
prepared start or finalization checks that UUID through the `PgConnection`
supplied by the use transaction and performs all authoritative writes through
that connection. It never opens a separate write transaction for those ports.
Both owner schemas must therefore live in the same PostgreSQL database.

Lock order is the use command advisory lock, immutable command claim, current
grant, retained admission, Flow definition, Flow instance and proof submission,
followed by receipt/result insertion. The definition and original Flow state
are re-read under their locks before consumption. A changed definition,
operation, actor, grant revision, proof or storage identity fails closed.

## Challenge start and nonce retention

The existing starter prepares only a qualified defined verification Flow from
an opaque admission. The supplied actor is the actual delegate; the represented
subject and grantor retain their separate roles in the grant. The verifier
client ID is the exact OID4VP identifier, such as
`decentralized_identifier:did:web:verifier.example`; it is distinct from the
operation audience.

The prepared adapter exposes only challenge correlation and original times to
the use ledger. It can shorten an expiry after a current-source recheck, but
cannot extend it or change the challenge, verifier, nonce or creation time.
Persisted times are compared at PostgreSQL's microsecond precision.

In one transaction it inserts the actual Flow instance and a retained binding
whose original snapshot is captured with PostgreSQL `to_jsonb` from that row.
The binding enforces unique organization/verifier/nonce digest. The earlier
internal starter uses this same retention path, so it cannot bypass the new
nonce boundary. Ordinary verification nonce cleanup never releases a delegated
binding; expiry and consumption do not make a nonce reusable.

Request retrieval may record progress and its explicitly bounded derived
metadata. It cannot change the private grant/operation binding, frozen request,
verifier, nonce, actor or other original context. Derived response URI, state
and audience are constrained to the original Flow/verifier; cached signed
requests cannot be replaced. These updates are compatible with later proof
submission against the original retained binding. This database compatibility
does not independently qualify a public wallet retrieval host.

## Proof source and finalization

`record_proof_submission` is an internal ingress for a separately authenticated
and authorized caller. Constructing `DelegationCommandCaller` validates shape;
it does not authenticate a network request. The ingress matches the full typed
actor and tenant to the original Flow, retains bounded exact proof bytes and a
SHA-256 digest, and generates the submission UUID on the server. Repeating the
same bytes recovers the original ID. Raw proof bytes are absent from the return
projection and retained in a restricted source table.

Storing bytes does not verify their signature or create authority. Finalization
resolves those original bytes, checks the actual Core OID4VP proof through the
configured authorizer, and revalidates current grant, consent, exact operation
and policy. The Flow port receives only the sealed evaluation and issued
receipt. It locks the current definition, original instance and proof again,
checks all retained bindings and deadlines, then completes the Flow with:

```json
{
  "kind": "DELEGATED_USE",
  "semantics": "EVIDENCE_ONLY",
  "decision": "PERMIT",
  "receipt_ref": "urn:marty:delegated-receipt:<receipt-id>",
  "receipt_digest": "sha256:<digest-of-exact-compact-jws>"
}
```

A completed policy denial uses the same structure with `DENY`. Invalid proof
and unavailable sources remain errors, not fabricated completed denials.
The adapter appends `delegated_use_evidence_recorded` to Flow state history and
inserts the immutable consumption. The surrounding transaction retains the
exact receipt and original command result. Flow's completion time and the
ledger's later result-recording time are separate observations in that one
transaction; neither refreshes the original authorization deadline.

Ordinary verification finalization remains unable to complete a delegated
instance. There is no callback, outbox or merchant operation in this port.
Rifare owns domain execution, budgets, reservation and business idempotency.

## Commit-time expiry and uncertain work

The adapter samples the database clock after locks and after writes. Deferred
database guards also check the real clock at COMMIT, so a later wait cannot
commit expired start or receipt evidence. Any failure rolls back authoritative
Flow, nonce, receipt and result writes together.

The use service commits the command claim before external preparation/signing.
That earlier claim survives a later rollback. Retrying an unresolved claim
returns `PreparationPending` and does not sign or prepare again. A missing
result does not prove no external work occurred. This candidate supplies no
automatic claim takeover, expiry cleanup, signing retry or reconciliation
override.

Finalization compares the immutable authority projection of the complete Flow
snapshot under its row lock. It permits only the progress fields and bounded
derived context already allowed by migration 0005. Grant/operation binding,
nonce, frozen request, actor, definition, original times and terminal state must
still match; cached signed requests cannot be replaced. Cancellation during
signing remains terminal and leaves the command unresolved.

Benign request retrieval during preparation, signing or the final row-lock wait
therefore preserves the latest history and can complete without another signing
attempt. Completion history, `updated_at`, `completed_at` and consumption use a
fresh database instant sampled after the Flow lock, so they cannot move behind
the accepted retrieval update. Later expiry still rolls back the whole final
transaction. This change does not rewrite migration 0005 or qualify public
wallet ingress.

## Migration and qualification

Additive migration `0005_delegated_use_retention.sql` adds the storage identity,
challenge bindings, proof submissions and consumptions. It installs thirteen
immutability, source-binding, mutation and deferred-commit guard bindings.
Readiness checks their exact table/function association, enabled state,
deferral/security properties and required primary/unique index shapes. Earlier
Flow migrations are unchanged.

A future serving role needs bounded access to the existing Flow definition and
instance tables and these retained tables, with no schema ownership, guard
disablement, evidence UPDATE/DELETE/TRUNCATE or migration privileges. Provisioning
and qualifying that role together with the Delegated Authority use writer is a
separate deployment gate. Existing lifecycle writers and evidence readers do
not gain these proof/Flow privileges.

Local PostgreSQL integration tests compose this real adapter with the actual
Core proof verifier and real ES256 proof/receipt signatures. Current consent,
actor permission and domain policy in those tests are explicit trusted
fixtures. Live workload sources, custody providers, public transport, independent
receipt consumers and production role composition remain separately qualified.

See [the use command contract](../delegated-authority/USE_COMMANDS.md) and
[the upgrade runbook](../../../docs/delegated-authority-upgrade.md).
