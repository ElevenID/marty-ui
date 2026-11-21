# Retained delegated-use command composition

This internal application boundary implements the pinned P03 `START_USE`,
`FINALIZE_USE` and `RECOVER_RESULT` wire intent and response contracts for KEY
grants. The existing human command executable and Gateway continue rejecting use
commands. There is no default allow-all actor source or automatically enabled
use host.

`DelegationUseCommandService` composes separately configured current caller
authorization, the existing grant/consent owner, sealed challenge admission,
proof/constraint/Cedar evaluation, the managed receipt issuer, and the Flow
owner. Enabling a future public host additionally requires operational workload
authentication and deployment qualification of these ports.

## Durable identity before external work

An immutable command claim is committed before Flow request preparation or
receipt signing. The identity is the exact organization, typed actor and command
UUID; its digest covers the original P03 JSON values. The new
`command_identities` registry shares this namespace with existing grant lifecycle
results. A command UUID cannot be reused for another command type or intent.
Migration 0006 backfills existing identities from original results without
rewriting their payloads.

| Retained state | Repeated original command |
| --- | --- |
| No claim/result | May attempt admission after current authorization |
| Claim without result | `PreparationPending`; does not prepare, evaluate or sign again |
| Completed result with matching digest | Original immutable response, `recovered=true`, after current read authorization |
| Same identity, different digest/kind | Conflict |

An absent result does not prove earlier work stopped. Pending claims are retained
even when preparation fails, a process exits, signing is ambiguous, or the final
transaction rolls back. The current candidate deliberately provides no automatic
lease takeover, re-signing, claim deletion, or reconciliation override. An
operator must preserve the original intent and evidence; broader recovery needs
a separately qualified reconciliation design.

## START_USE and the Flow owner

The service first checks the exact active grant revision/terms and operation,
then obtains the existing opaque `DelegationChallengeAdmission`. After reserving
the command, `DelegationUseFlowOwner::prepare_start` builds the Flow-owned nonce
and wallet request using that admission. No public command supplies a nonce,
verifier identity, actor, private Flow snapshot or verified flag.

The retained verifier identifier is the exact Flow-selected OID4VP client ID,
including prefixes such as `decentralized_identifier:did:web:verifier.example`.
It uses the existing proof adapter's bounded opaque-text validation; it is not
reinterpreted as an RFC URI or remapped to the operation's domain audience.

The prepared Flow object holds its sealed original state. It revalidates current
evidence and commits through the `PgConnection` supplied by the use transaction.
The concrete adapter must verify the expected Flow storage identity on that
connection. It must not open its own write transaction or report success from a
different database.

That single local transaction records:

- The authoritative Flow challenge and retained nonce state through the Flow owner.
- Its exact correlation in `use_admissions`, with unique organization/verifier/nonce.
- The immutable P03 `CHALLENGE` response for the original command.

`use_admissions` is retained correlation and replay protection. It does not
replace Flow as the challenge owner. Expired nonces and original command IDs are
not released for reuse. Challenge recovery returns the original timestamps and
does not refresh evidence or create another wallet request.

## FINALIZE_USE, policy denial and receipt persistence

A finalization command names only the original challenge and an immutable proof
submission ID. The configured Flow source resolves the actual stored proof bytes
and exact actor/challenge binding. A caller-selected ID is not proof evidence.

There is one retained finalization identity per original challenge. The service
claims it before evaluating or signing. The existing authorizer checks the
cryptographic proof, current grant/consent, exact scope, domain constraints and
current Cedar policy. The new `evaluate_decision` method can return a sealed
completed PERMIT or DENY; existing `evaluate` remains permit-only for its earlier
callers.

A valid completed Cedar FORBID/ABSTAIN becomes a signed DENY decision and consumes
the original challenge. Retrying it cannot turn that original result into a
PERMIT after a later policy change. Bad proof, unavailable sources, stale
evidence and signer errors remain errors with unresolved claims; they do not
fabricate a completed signed denial.

After signing, the transaction locks the exact command identity, current grant
and retained admission. Current source permission and grant/consent are checked
again without extending earlier deadlines. The concrete Flow finalizer locks
and consumes the original Flow instance/proof state through the same transaction.
The ledger then persists exact compact JWS bytes, payload, proof digest, receipt
digest and original `FINAL_USE` response. Its receipt reference is
`urn:marty:delegated-receipt:<receipt-id>` and its digest is SHA-256 of the exact
compact JWS UTF-8 bytes.

The response carries `semantics: EVIDENCE_ONLY`. It records identity/authority
decision evidence, not merchant execution, payment, resource reservation or a
business outcome. Rifare retains those responsibilities.

## Transaction and clock boundaries

Lock order is command advisory lock, command claim, grant, retained admission,
then the concrete Flow owner’s instance/submission locks. Flow start/finalization
ports must honor that order. The database transaction owns all authoritative
Flow mutation, nonce claim, receipt and result writes; any later failure rolls
them back together while the earlier original command claim remains.

Read-only freshness calls are bounded. External preparation/signing and COMMIT
are not wrapped in a cancellation timeout that could misreport an ambiguous
outcome as known rollback. A deferred PostgreSQL trigger checks the actual
database clock after later commit-time waits and rejects expired results.

Current Organization/consent/policy sources remain independently owned bounded
observations. This local transaction is not a distributed atomic revocation
transaction. Qualification must establish each deployed source's freshness and
fail-closed behavior.

## Migration, privileges and qualification

Migration `0006_retained_use_commands.sql` is additive; migrations 0001–0005 are
unchanged. It adds `command_identities`, `use_command_claims`, `use_admissions`,
`use_receipts` and `use_command_results`, plus immutable, binding, uniqueness and
deferred commit guards. No UPDATE, DELETE or TRUNCATE is part of the use ledger
serving contract.

Existing lifecycle command writers additionally require SELECT/INSERT on
`command_identities`, because the namespace trigger runs as the invoking role.
They do not receive access to the four use-specific evidence tables. Existing
consent/authority producers need no new ledger privileges. The read-only upgrade
preflight verifies that separation and preserves pending/historical evidence.

A separately provisioned use writer requires the bounded ledger privileges and
the qualified concrete Flow adapter's writes in the same PostgreSQL database.
Its production role composition and public host are separate qualification
gates. Do not grant a lifecycle or evidence reader arbitrary Flow, proof,
signing, consent or authority producer writes to make this composition work.

Disable a future use host to stop new admissions, while preserving all command
claims, nonce bindings, consumed outcomes and receipts. Rollback never clears an
ambiguous command or permits nonce reuse. Public MIP, support/discovery and Rifare
business execution remain unchanged by this library milestone.
