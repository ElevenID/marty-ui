# Actual concurrent scheduler reference

Status: two independent published-process captures agree; mandatory reference
regeneration passes locally. Native concurrent replay qualified at `a329b980e`
(CI34042598584 and RustCodeQL34042598554). No worker cutover, Python deletion or
deployment follows from this reference alone.

Two distinct actual worker processes run on the official published schema with
real HTTPS and encrypted OAuth storage. A transaction owned only by this isolated
fixture holds an exclusive target-table lock. PostgreSQL must report both active
scheduler queries waiting on locks before the fixture releases the transaction.
Neither a job nor a provider request may exist at that barrier. This establishes
actual overlapping scheduler execution rather than assuming two process starts
necessarily contend. The barrier is released on failure as well as success.

After release, exactly one durable job must be leased on attempt one. Its owner
must be one of the two owned worker identities. The real provider response stays
held while one process reports processing and the other idle; both must remain
alive, with no facts and exactly one authenticated request. After releasing the
response, both workers must reach idle while the same job succeeds, retaining
its original start. The exact fact/policy/review outcome, existing issued rows
and encrypted token bytes are checked. Both processes are interrupted and reaped.

Worker heartbeat projections retain every role/metadata field but order by phase
and omit worker identity, because either process can win the lease. Actual process
identities and the lease-owner membership are checked separately. The completed
state requires both heartbeats, not merely the successful owner's heartbeat.
No clock, lease, attempt, job outcome or application query is patched.

Independent raw capture SHA-256:
`cfe6eeaa6e50617fe329ce4d08338bea3224130f01be28278c6bd3e8763ccdcd`.
The frozen artifact uses whitespace-only formatting, preserving numeric tokens
such as `90.0`. Mandatory configured test
`worker_concurrent_reference_matches_published_process` regenerates it from the
immutable reference image. Existing snapshot/startup helpers retain their default
behavior, and all earlier frozen artifacts remain unchanged.

Local verification: all 21 selected configured worker entries passed in 221.59
seconds (36 unrelated entries filtered). These include eight reference/startup
gates and three comparison units; ten native Linux parent/helper entries are
not Windows runtime proof. All 60 affected Python tests pass in 3.45 seconds,
with strict Clippy, Rustfmt, Ruff, Bash syntax and diff checks passing.

## Native replay

The mandatory native parent/child pair reuses the shared HTTPS coordinator and
Rust process, seed, snapshot, generation-fence and preservation helpers. A real
SQLx transaction holds the same fixture table barrier until PostgreSQL reports
both actual scheduler queries waiting. The transaction is committed to release
them; failure cleanup retains rollback and owned-process RAII.

The child requires the two heartbeat phases, one leased job and an owned lease
holder before requesting HTTPS release. Leased-state comparison retains Rust's
exact internal target-generation value. Completed state must match the frozen
reference without exceptions, with the original job/start and both processes
alive. Both native workers must exit 130 after SIGINT, corresponding to the
reference's raw -2 exits. The parent checks the single exact provider request.

Local native compilation and three strict comparison tests pass, as do all 60
affected Python tests (3.33 seconds). Linux job 101511954495 at `a329b980e`
explicitly records the actual concurrent case with one HTTPS request, retained
final/recovery/signals and all 59 configured tests passing in 948.70 seconds.
The separate 0.36-second unconfigured run is not runtime evidence. Subsequent
extensions require their own exact-head qualification.

This case is not evidence for simultaneous crash reclaimers, changed-target
generation, owner-fence loss, final-completion races or application disposal.
Those remain in the [whole-worker inventory](canvas-worker-cutover-readiness.md).
