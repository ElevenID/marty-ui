# DB and Canvas CI timing evidence

The existing database-contract step appends `db-contract-timing.jsonl` to the
two-day `rust-build-evidence` artifact. Each line is `marty.ci.db-phase/v1` with
only `group`, `phase`, `name`, monotonic `duration_ms`, and `status`. CI also
prints these allowlisted fields when a phase finishes; raw contract output
remains in the existing final logs for failure diagnosis. No URL, command,
environment, SQL, oracle value, credential, or exception text belongs in this
timing schema.

`rust-db` emits one `contract` duration per existing serial executable, and
`published-canvas` emits image-pull, exact serial-test, and parallel target
durations. The concurrent composition and worker target durations overlap;
their sum is not the DB-step duration. `group_total` measures each owner's
complete subprocess, including its cleanup. Preflight groups use the same
schema and preserve their existing execution and proof rules.
Parallel target completion is observed by a timing-only log relay at 100 ms
polling resolution. The runner still waits and cancels the actual Rust child
PIDs; if a relay cannot drain, its optional target duration is omitted rather
than estimated from the other target's completion time.
The final target-log replay prefixes already-relayed timing lines with
`[raw-log]`, retaining their diagnostic text without recording them a second
time in the JSONL evidence.

Canvas's exact-owned PostgreSQL fixture emits `container_startup`,
`database_readiness`, `migration_seed`, and `cleanup`, including failed phase
status when unwinding. `migration_seed` is deliberately one combined phase:
the pinned historical producer executes its migrations and fixture seed
internally, and changing it would invalidate the source/oracle pin. The native
REST worker harness separately times each corpus-owned `scenario`, plus its
own HTTPS `fixture_seed` and `cleanup`; that `fixture_seed` is the TLS fixture,
not PostgreSQL seeding. A case's scenario duration includes its nested setup,
worker run, assertions, and cleanup, so these durations must not be added.
The PostgreSQL cleanup duration measures resource removal, not the subsequent
exact-absence verification; a successful removal can still fail that verification
and fail the test. Explicit close and the following Rust destructor produce one
removal phase when the first close succeeds; a failed partial removal can be
timed again if the destructor retries remaining owned resources. The HTTPS
cleanup duration measures server/thread shutdown, not deletion of the temporary
certificate directory; a deletion failure still fails the test.

This is instrumentation, not a speedup or evidence to remove tests. All
existing cases, image/source pins, connection limits, qualification tiers,
deadlines, and success gates remain authoritative. Compare hosted runs only
after this branch is independently reviewed and merged.

## Pre-instrumentation baseline

On 2026-10-06, the same #1129 source passed the [PR run](https://github.com/ElevenID/marty-ui/actions/runs/37503567584)
and its [protected merge-group run](https://github.com/ElevenID/marty-ui/actions/runs/37510218831)
on the Canvas lane. GitHub step durations, in seconds:

| Existing step | PR | Merge group |
| --- | ---: | ---: |
| Compile reusable Rust test executables | 605 | 596 |
| Compile Bookworm-compatible base runtime acceptance | 555 | 563 |
| Build public selfhost image | 738 | 740 |
| Preflight published worker parity in two isolated groups | 122 | 122 |
| Run isolated database contract suites concurrently | 775 | 776 |

These are stage baselines, not an optimization result or a claim that the two
runner caches were identical. Compare later PR and merge-group runs separately
under the same toolchain, target, features, runner class, and qualification
tier; record cache state and required-case completion alongside elapsed time.
The new JSONL explains the DB aggregate but does not by itself shorten it.
