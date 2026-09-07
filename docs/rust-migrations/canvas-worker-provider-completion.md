# Actual completion-first worker/reclaimer race

Status: actual published-process capture and independent regeneration agree;
native process replay is implemented, awaiting configured Linux qualification.
The local mandatory gate now contains 103 entries, including the preceding
two-direction repository test. Recovery-first whole-process composition remains
open. No consumer switch, feature deletion or whole-worker acceptance is implied.

## Observed published behavior and retained Rust improvement

A real standalone worker leases attempt eight and receives an actual HTTPS
assignment response. A synthetic trigger then blocks only its terminal job UPDATE
on an owned advisory lock. Provider facts and policy effects have already committed;
the job remains externally leased. No worker function, repository query, running
lease deadline or clock is changed. Earlier attempts are seeded history.

After real lease expiry, a second actual worker attempts recovery. PostgreSQL
proves its wait chain leads to the terminal writer. A transactional journal records
exactly one committed terminal update: `succeeded`. Both workers reach idle and
exit normally under SIGINT, with one provider request, unchanged issued rows and
ciphertext, and stable job/target rows and journal after exit.

Despite completion winning the job, the published reclaimer disables the target
and the success timestamp remains unset. That behavior stays in the frozen
reference. Native recovery must retain its existing stronger atomicity: SKIP LOCKED
allows its real reclaimer cycle to reach idle before the completion barrier is
released, with no target change. Completion then leaves the target enabled and
records success. These three differences are asserted explicitly, not generalized
into an exception list that could hide unrelated state changes.

Native replay compares every original snapshot, provider request and terminal
journal value. The exact internal generation-one field is required in pending
job state; successful public result fields match the reference directly. Complete
target rows are compared outside the two legitimate success timestamp fields.
Negative controls reject changes to those frozen differences or other target fields.

## Observer review and independent evidence

The first 37.67s capture was rejected as evidence: its broad lock query could
mistake the original worker's blocked renewal for the reclaimer. A distinct
synthetic database login, inheriting the fixture owner's ordinary privileges,
now identifies the reclaimer. It exists only inside the disposable test database
server. No deployed account or production grant is changed.

The direct-blocker version then failed in 50.16s. Synthetic-only diagnostic
inspection (49.96s) identified a tuple-lock wait: the renewal query occupied the
queue between reclaimer and terminal writer. The corrected observer follows
`pg_blocking_pids` transitively with cycle prevention, starting only from the
distinct reclaimer identity and ending at the exact owned advisory lock. Before
starting the reclaimer it must return false, so renewal cannot impersonate it.
Temporary diagnostic code and the capture-only test were removed.

Corrected actual capture passed in 38.46s; independent permanent regeneration
passed in 36.17s with the same full reference. Canonical LF SHA256:
`e01543a8e40fac645c317a35ca01c39c6182f309a3c1792cb4e28a53bd02e150`.
Immutable image/source provenance is retained in the reference. The rejected
first capture is not one of the matching independent captures.

Shared process/database/HTTPS owners, original history, fixture snapshots and
cleanup are reused. The repository NOWAIT job-lock probe is now shared with the
native process replay. Parent controls cover successful release, wrong requests,
missing release, child failure and timeout/cleanup without claiming those mocks
are process evidence. Full local Python suite: 1,019 passed, one existing opt-in
skip in 60.30s. The atomicity control passes; final all-target Clippy passed in
2.20s. Both real repository race directions still pass after sharing their lock
probe (69.17s). Ruff, shell syntax and patch checks pass.
Windows early-return native entries are not Linux qualification.

Next: retain both repository race directions and this completion-first process
case, qualify the exact native head, then capture/replay recovery-first process
competition with the same strict ownership, expiry and side-effect observations.
