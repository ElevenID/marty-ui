# Canvas renewal progress and process-liveness parity

Review against the frozen worker and renewal oracle found two native gaps.
Neither correction changes tenant/lease/attempt/target-generation fences,
provider behavior, routes, deployment consumers or dependency pins.

## Processing must progress during renewal I/O

The legacy worker starts its lease maintainer as an independent async task,
then awaits processing inside the configured wall-clock timeout. The Rust
helper instead awaited the renewal callback inside a select branch. While a
renewal database operation remained pending, neither the processor nor its
timeout future was polled.

Two controlled tests against the actual native helper failed: a ready processor
result could not finish, and the processing deadline could not advance, while
renewal was pending. The corrected helper selects between two independently
polled, parent-owned futures: processing and the complete renewal loop. It does
not detach a task or duplicate MMF ownership. Either terminal result drops the
other future before acknowledgment. Both regressions pass and verify both scopes
are dropped; lease-loss tests remain, and a repository-error regression preserves
the error class while dropping processing.

This is progress during renewal I/O, not proof that later durable job completion
or failure persistence cannot itself wait on a database lock.

## Target CAS loss must not suppress process liveness

The frozen credentials renewal oracle at
`b027e834d71dee0cc3550aac1150cdb0c40946ae` observes continued process liveness
after a target-generation heartbeat CAS rejects the old generation. The native
callback already reloads the canonical target and continues when it still
exists, but returned before persisting the process heartbeat.

The new mandatory PostgreSQL scenario uses the actual worker and production
repositories, reusing the existing two controlled processors and seeding helper.
With both jobs active, it increments both target generations and clears target
heartbeat metadata, then waits for the actual ten-second renewal interval.
Both durable leases renewed, but the original callback failed the process
heartbeat advancement assertion. The correction preserves the target reload
and missing-target stop, then records process liveness for a still-owned job.
The unchanged test now passes.

The test also proves that neither newer target receives stale-generation
heartbeat metadata, both jobs remain active until cancellation, both processor
scopes are then cleaned, and neither leased job is falsely completed. Actual
business-effect generation fences and repository CAS checks remain unchanged.

## Evidence boundary

The existing minimum interval and legacy ordering/fence/error observations remain
in `marty-credentials/docs/CANVAS_WORKER_RENEWAL_ORACLE.md`. Its tests execute
the actual Python maintainer with the real in-memory repository; the native
scenario above adds real PostgreSQL evidence using a synthetic guarded `*_test`
schema. It is not published-migration or whole-worker/provider equivalence.

All earlier configuration, SQL recovery/renewal/fencing and owned-cancellation
assertions remain mandatory in the same PostgreSQL executable. The worker is
still unrouted, Python and production consumers are retained, and remaining
renewal failure/order differentials, provider/privacy/readiness, full-consumer
cutover and aggregate beta acceptance gates are not cleared by these fixes.
