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
it starts before the pinned probe container runs and ends after its case
execution and report validation. It is not a pure migration duration. The
historical producer executes its migrations and fixture seed internally, and
changing it would invalidate the source/oracle pin. The native
fixture labels three fixed constructor origins (`json_consumer`, `json_depth`,
`timeout_consumer`) and the worker-validation repository's single shared
template (`worker_validation_template`). Its 21 published worker matrix
families use bounded `kind.case` labels from the checked-in scenario corpus,
after case-membership validation; the collector accepts only those exact
identities. Other probes retain `published_probe`. These labels identify the
source-owned probe path, not a migration-only duration or proof that an adjacent
parallel test log line owns a particular probe. They contain no fixture
contents, payloads, or dynamic resource identifiers.
These labels appear for whichever matrix cases actually execute. Routine CI
skips 33 historical replays, so those skipped probes emit no case timing;
selected routine cases still receive labels. The prior routine artifact had
602 rows, including 127 `published_probe` records, but those counts are
observations, not an invariant or evidence that skipped cases ran.
The native REST worker harness separately times each corpus-owned `scenario`,
plus its own HTTPS `fixture_seed` and `cleanup`; that `fixture_seed` is the TLS
fixture, not PostgreSQL seeding. A case's scenario duration includes its nested
setup, worker run, assertions, and cleanup, so these durations must not be added.
The four timeout and two lease-expiry borrowed native preflight cases also
emit fixed, individually allowlisted `scenario` IDs through a closed enum.
Each timer starts before its fresh owned PostgreSQL fixture and ends only
after verified close; a panic reports `failed` after fixture Drop. The duration
includes the child HTTPS process and its existing real deadline. Deadline,
body-timeout and historical process replay cases retain aggregate test/group
durations and generic fixture phases, not these case-labelled timings. This
changes no preflight or qualification selection. Nested durations overlap and
must not be added.
The PostgreSQL cleanup duration measures resource removal, not the subsequent
exact-absence verification; a successful removal can still fail that verification
and fail the test. Explicit close and the following Rust destructor produce one
removal phase when the first close succeeds; a failed partial removal can be
timed again if the destructor retries remaining owned resources. The HTTPS
cleanup duration measures server/thread shutdown, not deletion of the temporary
certificate directory; a deletion failure still fails the test.

The ordinary `canvas_sync_worker_postgres_contract` executable also emits
fixed `contract_phase` durations from its stateful composite test. Each timer
writes only its allowlisted marker directly to stderr because libtest
otherwise captures print macros; this does not enable broader test logging.
The outer `composite_total` includes connection, schema setup, all subphases, and pool
close; do not add it to its nested phases or to the executable's `contract`
duration. `initial_schema` is separate from the scheduler/recovery/completion
block. `hinted_retry`, privacy, signing, projections, and consumer ranges each
include their existing destructive schema reset. Lifecycle, actual owned
process signals, renewal generation/write-failure boundaries, and the 60-case
renewal outcome matrix retain their existing order and real deadlines. A
failed assertion marks its active phase failed during unwind; later phases
are absent, and the contract's exit status remains the gate. These timings
are diagnostic only, not proof that any phase can safely overlap another.

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

## Canvas immutable-base reuse

`MARTY_CANVAS_REUSE_PUBLISHED_BASE=1` is enabled only in the Canvas database
step for PR, merge-group, scheduled, and manual CI; every other matrix lane
keeps it off. The existing `canvas_migrated_base_pilot` manual input now runs
additional exact parity, isolation, and failed-restore diagnostics after the
normal full Canvas suite. It is not a release or test-selection switch. The pinned migration/seed probe
runs once per test process; later default-constructor cases restore that base
into fresh owned containers. Case assertions still run against isolated
databases, but repeated per-case execution of the migration producer is
intentionally consolidated. Scoped recovery and oracle-overlay constructors
retain their original setup paths.
Those diagnostics run the eight-case pinned-probe baseline with reuse
explicitly off, then compare complete pre-restore schema/data dumps from the captured base
and an independently fresh pinned probe, excluding only their validated
per-invocation `pg_dump` restriction keys. PostgreSQL reparses twelve pinned
CHECK/index expressions when restoring SQL. The diagnostic requires every
other schema and data line to match byte-for-byte, and verifies both forms of
those twelve lines against fixed digests; unexpected differences fail closed.
The cached restore input retains `pg_dump`'s normal random
key. Dump contents stay in the test process; only fixed mismatch messages are
emitted. The pilot applies only to
`PublishedDatabase::start()` with the fixed `published_probe`
setup. The first call still runs the exact pinned producer and validates its
source digest and migration revisions, then captures a bounded SQL dump in
this test process before returning that same case-owned database. Its caller
retains verified cleanup responsibility. Later calls restore the immutable
dump into new, separately owned tmpfs PostgreSQL containers. Scoped recovery,
oracle-specific fixtures, recovery overlays, and their cleanup remain on the
original path.
PostgreSQL readiness now requires TCP `127.0.0.1`; the entrypoint's temporary
Unix-socket initialization server can otherwise appear ready before the final
server accepts the restore.

On one local Windows/Docker Desktop host, the same ignored eight-case
sequential migration-head test took 39.43 seconds with the switch off and
23.22 seconds with it on. A three-case comparison was 14.90 versus
14.05 seconds. These are local fixture measurements, not CI speedup evidence:
the real Canvas targets run multiple tests concurrently, and runner load and
cache state differ. The opt-in path also passed pinned-Docker revision parity,
case-isolation, and failed-restore cleanup tests. The manual Linux full Canvas
pilot [39395651084](https://github.com/ElevenID/marty-ui/actions/runs/39395651084)
passed at the same source `5be7d6754` as the switch-off baseline
[39231230045](https://github.com/ElevenID/marty-ui/actions/runs/39231230045).
Its `published-canvas` group took 1,203.1s versus 1,353.9s (150.8s, 11.1%
less); the complete database step took 1,204s versus 1,354s. The exact 135
composition, 133 worker, and 9 database cases completed in both runs with no
failure. All five additional diagnostics passed, including fresh/migrated
schema-data parity, concurrent isolation, and failed-restore owned cleanup.
The full Canvas job improved by only 56s (2,395s versus 2,451s) because the
pilot also spent 58s on diagnostics and 26s more compiling. These are two
same-source hosted runs, not a guarantee under other cache or runner loads.
Historical probes, native-process cases, cleanup and required gates remain.
