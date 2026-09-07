# Nonempty OAuth revocation selection cap

The actual published repository and Rust repository now select from the same
509-row fixture, containing 506 eligible connections and the existing future,
connected and active-lease controls. The 501 added due connections have unique
ordered deadlines older than the original queue controls.

Two independently retained captures match exactly (4.58s and 4.92s). Limits
0, 499, 500, 501 and 2147483648 produce counts 1, 499, 500, 500 and 500. Each
selection compares every selected ID in order through SHA256 of the compact
UTF-8 JSON string array (no whitespace, no ASCII escaping). Both implementations
encode their actual returned IDs. This is an exact ordered-result digest, not
a hash of the query or only a first/last/count check. Integrity controls verify
the seeded expected IDs and reject changed order or duplicate membership.

Frozen oracle canonical LF SHA256:
`acdcf6d1bf040bb86dfb2f6bd91e81bed9fd9373c80c7a412c2d662bb2371616`.
The artifact also records the actual published repository source hash; the
existing owner verifies the immutable image and official migration provenance.

Both replays compare the entire connection-row map before/after selection,
including all lease fields, timestamps and secret references. All encrypted
secrets and issued rows remain unchanged; no leases are acquired and no worker
heartbeat is emitted. The published HTTPS owner observes zero requests. The
native test calls only the actual PostgreSQL repository and starts no worker.
No live or external database URL is accepted by the shared fixture owner.

This qualifies the repository's nonempty selection cap locally, not a run of
500 remote revocations or whole-worker completion. The existing actual worker
queue/lease cases and configuration-range corpus remain separate composition
evidence; they are not replaced or relabeled by this repository test.

The selection matrix inherits the queue/original seed and adds only its input
rows. Native replay reuses static matrix loading and fixture preparation. No
runtime, existing oracle, consumer, crypto adapter or feature is changed.
Permanent reference and native repository entries bring configured CI to 88.
Both actual repository gates passed locally in 8.49s; strict all-target Clippy
passed and all 24 Rust behavior tests passed. Exact-head hosted qualification
remains pending. Returned cycle counters and secret-resolution composition
remain named gaps in the [coverage audit](canvas-worker-oauth-revocation-coverage-audit.md).

The final Python suite passed 978 tests with one existing opt-in skip in 47.46s.
The repository-only corpus is explicitly rejected by the native HTTPS runner,
preventing its evidence from being reported as process/transport qualification.
The final sweep passed in 180.68s: all 29 process reference cases, the five-limit
published repository observation and both real Rust repository regressions.
Eight of 18 top-level Windows entries returned early and are not parity evidence.
