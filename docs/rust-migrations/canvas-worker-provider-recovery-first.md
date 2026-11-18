# Actual recovery-first worker/completion race

Status: qualified at `c3e51a4d58083625aabd50de7fba37ef1ff53d4e`.
CI34082559053/runtime101620519590 passed all 107 configured entries in 2327.12s.
The actual `Native worker active-provider recovery_first passed (1 actual HTTPS requests)`
marker and retained completion-first/generation/reclaimer gates were inspected.
Published capture passed in 36.44s and independent regeneration in 36.20s.
PR #814 remains draft and unrouted; no consumer switch,
feature deletion or whole-worker acceptance is implied.

## Exact boundary

The actual worker receives one HTTPS assignment response and commits valid
provider facts before expiry. A synthetic statement-level trigger then holds its
completion UPDATE before job-row acquisition. An independent successful
`FOR UPDATE NOWAIT` probe proves that the original worker does not own that row.
The trigger is installed after leasing and is restricted to the original fixture
database login; it also holds subsequent renewal UPDATEs. It changes neither
row values nor the worker implementation, HTTP timeout, running lease or clock.

After real 30-second expiry, a distinct actual reclaimer acquires the job row and
waits at the shared terminal-write barrier. Releasing only the original worker's
statement barrier exposes the stale-completion path while recovery still owns the
row. After recovery is released, the journal must contain exactly one terminal
write, `dead_letter`, on attempt eight. The target is disabled without a success
timestamp. Valid facts, their event, policy result, issued rows and ciphertext are
retained. Both actual workers reach idle and exit under SIGINT. Complete job and
target rows and the terminal journal must remain unchanged after exit.

The frozen Python process blocks behind recovery because its UPDATE uses a
previously captured timestamp. Rust's existing query checks `clock_timestamp()`
after the statement wait and must reject the expired lease before row contention.
Only the original heartbeat's phase and leased-job count differ at that precise
intermediate boundary. The expected native generation-one result field is checked
separately. All other snapshot fields must match exactly; there is no generic
normalization or broad exception list. Negative controls reject unrelated state,
fact/event loss, incorrect generations and drift in the frozen Python path.

This proves competition over terminal completion after valid provider effects.
It does **not** prove fencing when a lease expires during an in-flight provider
operation. That remains a separate boundary; prior attempts are seeded history.

## Harness review and evidence

An initial owned-process pause approach failed in 36.49s because it held the HTTPS
response across the fixture's 30-second bound. It is rejected evidence, not a
reference. Inspection also found the published provider's fixed shorter HTTP
timeouts. No production timeout, worker setting or fixture hold was extended.
The statement barrier instead exercises the actual completion/recovery boundary
after the real response, with explicit database lock observations.

The completion-first process/database/HTTPS owners, terminal journal, distinct
reclaimer role, snapshots and cleanup are shared. The old completion reference
still independently matches after the final shared refactor (36.03s). Both Rust
comparison controls pass; strict all-target Clippy passes (4.92s). The full local
Python suite passes: 1,026 tests and one existing opt-in skip in 43.61s. Parent
controls cover release, request mismatch, missing release, failure and timeout
cleanup. These controls and Windows native early returns are not Linux process
qualification. The frozen reference retains immutable image-source provenance.
Canonical LF reference SHA256:
`28d537769ef77b1fd249fe6bb652196c56aeb7431ef112e80d41bb972d6110ff`.

Next: retain this qualified boundary in the new roster-failure extension and
exercise expiry during in-flight provider effects separately. This test commits
valid provider effects before expiry; it does not qualify the latter ordering.
