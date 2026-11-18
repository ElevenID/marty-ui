# Published Python / native issued-review lifecycle parity

Status: ten sequential stages pass locally through both implementations on
separate freshly migrated databases. Hosted integration and protected landing
remain required. The worker stays unrouted.

The observed baseline is `contracts/canvas-issued-review-oracle.json`, Git blob
`64f7017bbf362679d2a24bca2833d5e90a9124a7`. It was captured from the published
issuance image before implementing the Rust replay. The existing consumer-range
contract pins that image by digest. Its loaded `canvas_routes.py` SHA256 is
`f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943`.
The test reruns the published Python hook and checks the entire observed corpus
before comparing Rust, so an edited expectation cannot silently replace legacy
behavior. The expected corpus is not generated from Rust.

Both sides use the same data-only seed, stage descriptions and snapshot query
in `canvas-issued-review-scenarios.json`. No issuance DDL is substituted. The
existing exact-owned pinned migration runner supplies the actual issuance schema
and its explicitly minimal synthetic organization dependency.

The Python probe calls the published
`process_authoritative_canvas_sync_target` and `PostgresIssuanceRepository`.
Only the HTTP client, OAuth-token acquisition and provider read are controlled;
policy, fact construction, repositories, transactions and the processor are not
replaced. Rust calls the actual native processor through the existing shared
lease/validation/completion test helper and PostgreSQL owners. Its provider port
receives matching normalized observations; this is not an HTTP-adapter test.

## Frozen sequence

1. Permit on an already-issued credential: one fact, no review.
2. New denial: one open review and one creation audit event.
3. Duplicate denial: reuse the fact, without another review or audit event.
4. Unavailable read: return the retryable error and preserve fact/review state.
5. Recovery: resolve the review as `evidence_recovered`.
6. Later denial: create a second review, retaining the resolved history.
7. Recovery while a manual claim is held: keep it open and mark recovery pending.
8. Denial while claimed: retain ownership and clear recovery-pending state.
9. Recovery after release: resolve the second review without a credential action.
10. Older negative observation: record its history without moving the current
    fact pointer or reopening a review.

Every stage compares the whole selected language-neutral result/error and
snapshot: fact counts/current scores, ordered review projections, policy
decisions, ownership and resolution fields, audit event counts, application
state and credential count/status. Both runs independently assert that **all
credential and issuance-transaction rows remain equal as decoded JSON**,
including their timestamps, between every stage. Reconciliation
does not approve, sign, suspend or revoke a credential.

Manual claim/release are synthetic interleavings applied identically through
the published constraints, not assertions that manual resolver endpoints have
been tested. UUIDs and wall-clock timestamps are excluded from the cross-language
projection, but credential/transaction timestamps are included in each side's
unchanged-row invariant. This is a sequential scenario differential, not a
complete concurrency or rollback differential.

## CI and remaining work

The existing mandatory `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1` executable now runs
both the prior real-schema contract and this ten-stage differential. Three
isolated databases are created and retired across the combined run; the Python
and native review runs never share data. An unconfigured workspace invocation
is not evidence. Local combined run: two tests PASS in12.42seconds; all-target
issuance Clippy with warnings denied PASS.

No runtime implementation or frozen expected result changed to make this pass.
Provider HTTP behavior, mixed REST/AGS/NRPS identities, concurrent revisions and
audit rollback, manual resolution endpoints, readiness, all consumers and beta
acceptance remain separate requirements. Reachable Python is retained until the
full worker cutover gate passes. Production is unchanged.
