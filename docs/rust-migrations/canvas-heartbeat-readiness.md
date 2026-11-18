# Published Canvas heartbeat readiness parity

The worker remains unrouted. This gate qualifies the heartbeat component, not
complete binding activation, whole-worker parity, or consumer cutover.

## Frozen evidence

`contracts/canvas-heartbeat-readiness-scenarios.json` supplies sixteen database
states. `scripts/run_canvas_heartbeat_readiness_oracle.py` executes the actual
published Python repository and composite readiness policy on migrations from
the immutable issuance image already pinned by the published-schema runner.
Only the repository wall clock is fixed, so microsecond cutoff cases are stable.
An additional real missing-table case verifies fail-closed readiness. The runner
uses exact-owned disposable databases, synthetic data and read-only test mounts;
it receives no deployment URL or credentials.

Two independent captures produced identical seventeen-observation JSON before
the Rust replay or runtime change. The frozen oracle blob is
`66dadbc3eb5c130fea64840e49426ed241ae23e7`. Each configured run rechecks the full
oracle, including published repository and readiness source SHA-256 values.
Python-selected worker IDs are retained as explanatory evidence; Rust's public
state port exposes a boolean, not a worker identity. The cross-language
comparison is the complete `worker_heartbeat` check: status, component,
blocking flag, remediation and timestamp.

Coverage includes absent/wrong-role rows, inclusive freshness at microsecond
boundaries, latest configured/unconfigured precedence, newer unrelated roles,
strict boolean metadata, missing/null/non-object metadata, legacy future-time
behavior, zero-age clamping, and an actual database lookup error.

## Native correction and verification

The initial valid-fixture replay failed at `zero_age_clamps_to_one_second`:
Python returned `ready`, Rust `failed`. The shared
`PostgresCanvasReadinessStateProvider` now applies the same one-second minimum.
Its current production constructor in `main.rs` supplies 120 seconds, so the
deployed setting is unchanged. This does not widen provider-network policy or
change credential/signing behavior.

The replay uses the existing PostgreSQL state provider, readiness runtime and
pure readiness policy. Unrelated document/signing ports are inert, and only the
heartbeat check is compared. The Python fixture has no evidence requirements;
the native constructor requires a valid course requirement. Neither fixture is
an activation-ready binding, and other readiness checks are not parity claims.

Four additional native write/read checks use the actual worker repository for
scheduling, OAuth revocation, processing and idle phases. They verify exact
metadata, original `started_at` preservation on upsert, database-clock bounds,
and readiness consuming each newly written configured/unconfigured heartbeat.
These writer checks are native integration evidence, not an additional frozen
Python differential or real-process shutdown/soak evidence.

All four configured published-schema tests pass locally (26.87 seconds),
including the unchanged processor, issued-review and mixed-roster gates.
All 255 issuance library tests, strict all-target Clippy, twenty workflow/image
tests, and changed-file formatting/lint checks pass. No owned test containers
remain. The existing mandatory
Linux published-schema step executes the entire target with its Docker gate set
and now checks this test is registered. Hosted full CI, protected integration,
and broader worker/deployment acceptance remain required. Unconfigured test
returns are not database proof.
