# Actual competing final-attempt reclaimers

Status: two independent published-process captures agree; mandatory reference
regeneration passes locally. Native two-reclaimer replay is implemented and
awaits Linux qualification. This is
not whole-worker cutover or Python deletion/deployment qualification.

The existing final-attempt reference supplies historical queued attempt 7 before
any process starts. The actual worker leases attempt 8, makes authenticated
HTTPS I/O and renews its real lease and both heartbeats. Only that owned worker
is killed. The fixture waits for actual database lease expiry without editing
timestamps, attempts, leases or outcomes.

Two new actual processes then contend at an exclusive fixture-owned **job-table**
barrier. PostgreSQL must report both job queries waiting on locks before release.
This differs from the scheduler reference's target-table barrier. The fixture
does not query the locked job table through a second connection while holding
the barrier. The table lock is released on failure as well as success.

After release, the original job must be dead-lettered on attempt 8 with its lease
cleared and target disabled. Both workers must remain alive and report fresh
idle heartbeats from after restart, not reuse the crashed process's heartbeat.
The second heartbeat is checked explicitly, along with the existing full job,
OAuth and issuance projections. No second provider request or fact creation is
allowed; original job/start, issued rows and ciphertext remain unchanged. Both
idle processes are interrupted and reaped, with raw -2 exits.

Independent raw capture SHA-256:
`77a320d5b7a1b4d48e3f1805989bb0dd2ccc496ebccedf5e4da248aeaa1bb21a`.
The frozen reference preserves exact tokens with whitespace-only formatting.
Mandatory configured test `worker_reclaimers_reference_matches_published_process`
regenerates it from the pinned image.

Local verification: all 24 selected configured worker entries pass in 266.12
seconds (36 unrelated entries filtered). Nine reference/startup gates and three
comparison units execute here; twelve native Linux parent/helper entries are
not Windows runtime proof. All 68 affected Python tests pass in 3.30 seconds,
with strict Clippy, Rustfmt, Ruff, Bash syntax and diff checks passing.

The scheduler and reclaimer references share one process-barrier helper. It
returns process ownership only after verified contention; partial startup,
early exit, timeout or observation failure reaps every started child. Multi-child
cleanup attempts every child even if one cleanup raises. Unit tests cover those
failures, duplicate identities and importing process helpers without a database
library. SQLAlchemy remains needed only for actual database observations; no new
application or CI dependency was introduced.

## Native replay

The mandatory native parent/child extends the shared recovery replay and retains
the exact internal generation fence, all existing positive/negative comparisons
and both fresh heartbeat observations. It uses the same pre-start historical
seed, actual renewal/crash/expiry, and two owned Rust processes behind the job
barrier. Both restart heartbeats must be fresh and idle before the exact state
and target-disabled assertions are accepted. Both workers are interrupted and
reaped; original job/start, issued rows and ciphertext remain preserved.

Scheduler and reclaimer tests share the Rust barrier owner. The pre-release job
count is checked using the lock-owning transaction (zero for the scheduler, one
for reclaimers), avoiding a self-deadlock through a second connection. Bounded
waits, process RAII and transaction rollback remain intact. The HTTPS parent
checks exactly one request and gives this longer child 150 seconds to finish
its additional bounded barrier/heartbeat/exit checks; existing cases retain
their 90-second parent deadline. No individual behavior assertion was relaxed.

Local native compilation, three strict comparison tests and all 68 affected
Python tests pass (3.34 seconds for Python), together with strict lint/format
and CI syntax checks. Actual native two-reclaimer runtime remains unqualified
until the new mandatory Linux parent/child executes successfully.

Changed-target/owner-fence loss, final-completion races, disposal and nonfinal
competing-reclaimer outcomes remain separate requirements in the
[cutover inventory](canvas-worker-cutover-readiness.md).
