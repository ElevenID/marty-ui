# Final-attempt completion/recovery lock boundary

Status: both native repository race directions pass against isolated databases
with the official published schema. The new mandatory test raises the local gate
to 99 entries. Hosted qualification and whole-worker/provider composition remain
required; this is not a new Python process oracle or a closed cutover gate.

The language-neutral scenario names both outcomes from the existing normative
`executable_fixtures.postgres_lease_recovery.final_attempt_completion_race`
requirement: one terminal winner, zero stale writes. It reuses the existing
final-attempt history and encrypted-token/issued-row fixture. Attempt eight is
actually leased through the Rust repository; earlier attempts are seeded history.
No running lease, job state or clock is rewritten. Each direction uses its own
fresh published-schema database and an actual 30-second lease.

## Deterministic overlap

- Completion first: a fixture transaction holds the target row. Actual completion
  locks/updates the job and blocks at its target write. PostgreSQL identifies that
  exact blocked query and its barrier PID; a separate NOWAIT probe independently
  proves the job lock is held. After real lease expiry, the actual recovery call
  must return promptly through SKIP LOCKED without leasing or changing any row.
  Releasing the target barrier allows the already-owned completion to commit.
- Recovery first: after actual lease expiry, the real reclaimer locks/updates the
  job and blocks on that target barrier. The same independent lock observations
  are required. Completion runs during recovery's open transaction and must reject
  the expired lease. Releasing the barrier commits one dead-letter outcome.

Assertions cover exact terminal errors/result, attempt and original-start
preservation, released lease, target state and success timestamp. Every field
outside each operation's explicit write set is compared to the original full row.
Afterward, each stale completion, failure and recovery call is checked separately
against the complete committed job/target snapshot. Tokens and issued rows remain
unchanged. No HTTP provider is invoked by these repository tests.

The owned JoinSet aborts outstanding test tasks on unwinding; the target barrier
rolls back and the existing isolated database owner provides cleanup. The first
compile identified a fixture lifetime mismatch with SQLx's static SQL requirement;
the established OnceLock scenario pattern corrected it. No runtime change or
existing expectation was needed. Initial actual execution passed both directions
in 70.97s; final execution with expanded full-row assertions passed in 68.02s.
Full Python integrity/regression tests passed 1,012 with one existing
opt-in skip in 44.62s; final strict all-target Clippy passed in 2.13s.

## Remaining composition

Retain these real locking tests when adding the actual published/native worker
and provider sequence. Source inspection confirms native lease renewal wraps
processor evaluation, while terminal persistence follows it. A composed barrier
must therefore observe the terminal write itself; merely holding a target during
provider work could block an earlier processor read and test a different race.
Use the shared process/HTTPS/database owners and independently capture the
published behavior. Preserve stronger native fencing if the old process differs.
Do not infer process lifecycle, heartbeat, provider effects or Python parity from
the successful repository calls above.
