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

Canvas's exact-owned PostgreSQL fixture emits `container_startup`,
`database_readiness`, `migration_seed`, and `cleanup`, including failed phase
status when unwinding. `migration_seed` is deliberately one combined phase:
the pinned historical producer executes its migrations and fixture seed
internally, and changing it would invalidate the source/oracle pin. The native
REST worker harness separately times each corpus-owned `scenario`, plus its
own HTTPS `fixture_seed` and `cleanup`; that `fixture_seed` is the TLS fixture,
not PostgreSQL seeding. A case's scenario duration includes its nested setup,
worker run, assertions, and cleanup, so these durations must not be added.
Explicit verified close and the following Rust destructor produce one cleanup
phase when the first close succeeds; a failed partial cleanup can be timed
again if the destructor retries remaining owned resources.

This is instrumentation, not a speedup or evidence to remove tests. All
existing cases, image/source pins, connection limits, qualification tiers,
deadlines, and success gates remain authoritative. Compare hosted runs only
after this branch is independently reviewed and merged.
