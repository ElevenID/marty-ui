# Newer-target preservation after final-attempt crash

Status: qualified at df3ed290b19a2cd8e82ef21bfa83355cb2c62a83 in CI34076998603.
All 98 configured tests passed in 2085.34s, including actual native generation
recovery with one HTTPS request and exact newer-target row preservation. All
applicable exact-head checks passed. Later completion-race changes require fresh
qualification; this does not authorize worker routing or Python deletion.

The existing final-attempt owner now also observes this sequence:

1. Seed historical attempts, then run actual attempt eight against held HTTPS.
2. Observe actual lease/heartbeat renewal, kill the worker, and reap it.
3. Commit a validated target/binding configuration change from generation one
   to two. Assert the entire leased job row is unchanged by that edit.
4. Release the held response, wait for real lease expiry, and run the reclaimer.
5. Observe the old job's dead-letter outcome and the newer target's state.

The published worker disables the newer target. Its frozen observation retains
that behavior; the native replay explicitly requires the stronger existing Rust
generation fence instead. It requires the **complete newer target row** to remain
identical to its post-edit state, including enabled state, generation, timestamps,
metadata and next-run time. The published target result is separately checked
exactly, not silently rewritten or normalized into a parity claim.

All other frozen fields remain equal to the original final-attempt reference:
one actual HTTPS GET, renewal, crash exit, exact durable job outcomes, original
start time, encrypted tokens, issued rows and shutdown. Native raw job assertions
retain the internal generation-one fence. No runtime code was changed for this
extension; no existing reference was replaced.

## Evidence and fixture boundaries

Actual capture passed in 46.98s; independent permanent regeneration passed in
46.25s. The reference's canonical LF SHA256 is
`5f241ca0e553c969d3351ed3f3c97682fe6a09a63b7f65527dfc58fe354a4fed`.
Its immutable image and source hashes retain the existing final-attempt provenance.

The first capture failed before recovery because changing binding generation
without its validated generation violated the published activation constraint.
Inspection of actual PostgreSQL constraints led to a valid fixture transaction
that sets both to two. No constraint was disabled. This input represents an
already-completed validated operator edit; it does not execute or qualify the
configuration API or validation workflow. Moving the edited target's next run
into the future prevents unrelated fresh scheduling during recovery.

No running job, lease deadline or clock is rewritten. Attempts one through seven
are seeded history, not seven executed attempts. This case orders configuration
change after actual process loss and before recovery: it does not prove the
separate final-attempt completion-versus-recovery race or all concurrent edits.

The shared database owner, process cleanup, scenario inheritance and HTTPS parent
are reused. Integrity controls reject altered native target fields, altered
published expectations, wrong requests, failed/timed-out children and missing
release state. Pure/mock controls are not whole-process parity evidence.
Windows native early returns are not configured Linux qualification.

Final local checks: 1,011 Python tests passed with one existing opt-in skip in
42.73s; the original final-attempt reference regenerated unchanged in 46.64s.
The expanded mutation/expectation control passed, and strict all-target Clippy
passed in 1.97s. Those local checks alone did not qualify native execution;
the hosted result recorded above supplies that evidence.

The next named gate-five gap remains the normative final-attempt completion race:
one terminal winner and zero stale writes. Broader whole-worker gates remain in
[cutover readiness](canvas-worker-cutover-readiness.md).
