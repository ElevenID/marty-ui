# Canvas worker owned-cycle cancellation

Status: native candidate correction; no worker cutover or Python deletion.

The frozen `issuance-canvas-sync-worker.json` shutdown contract requires an
active cycle to finish on graceful stop, but to release its processing and
renewal work on cancellation without falsely completing the leased job. The
actual legacy lifecycle oracle at credentials
`b027e834d71dee0cc3550aac1150cdb0c40946ae` observes this boundary;
`tests/unit/test_canvas_worker_lifecycle_oracle.py` has Git blob
`b3c85cfa7bf03c11c90ed440221f47343ee1ae36`. Its processor-cancellation test
awaits cleanup and leaves the job leased. These observations and the existing
contract predate this native correction; neither fixture is rewritten here.

## Discovered difference and correction

The previous native cycle used spawned `JoinSet` tasks. Dropping the parent
requested cancellation but did not await child cleanup. A deterministic
regression test against the actual Rust worker and PostgreSQL repository
started two processors, cancelled the parent, and checked cleanup before any
yield or database read could hide the difference. Both processors were still
live (`2`, expected `0`).

The cycle now owns a `FuturesUnordered` collection from the existing locked
`futures-util` crate. Processor and lease-renewal futures live inside the parent
scope and are dropped together when it is cancelled. Jobs still progress
concurrently. Per-job unwind catching retains the previous panic isolation,
so a failing job cannot cancel its healthy siblings. Result counts, durable
lease/configuration fences and the safe structured error projection remain.
This is ordinary Rust unwinding behavior; process abort or forced host shutdown
cannot promise cleanup and still requires durable crash recovery.

No parallel worker, custom scheduler or new dependency version is introduced.
The only lockfile change is the issuance crate's direct dependency edge to
the already-locked futures utility. MMF/crypto pins remain unchanged.

## Executable evidence

The existing mandatory PostgreSQL worker contract now runs four additional
scenarios through production worker/repository entry points, reusing the
range oracle's observing/delegating factory and the existing target seeder:

- Two concurrently active processors are cleaned synchronously on parent
  cancellation, before a yield; both durable jobs remain leased and incomplete.
- A deliberate panic in one processor leaves its job leased, while the other
  completes successfully; both processor scopes are cleaned.
- A pre-stopped loop produces no jobs, processor calls or heartbeat writes.
- A graceful stop during active work allows both jobs to finish and then exits,
  instead of cancelling them or starting another cycle.

All four scenarios passed locally on an isolated PostgreSQL 15.17 database,
alongside the unchanged 36 range cycles, three two-cycle loops and existing
recovery/renewal/fencing/race assertions. The expected synthetic panic hook
message is part of the panic-isolation test; the test itself passes. The native
database schema is synthetic, not a claim that published migrations ran.

This does not close the initialized-entry-point engine-disposal gate, every
renewal/provider failure differential, or whole-worker lifecycle/readiness.
The process entry point still needs separate proof that its supported normal,
failure and cancellation paths await database disposal. Full hosted CI and
protected landing remain required. Keep the Python worker and all consumers
unchanged until the complete migration/deletion gates pass. Beta and production
are untouched by this change.
