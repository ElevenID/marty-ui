# OAuth revocation cycle return counters

Qualification update: All four actual native cycle-return cases
passed at e70e3abccd83b4f6893ea655f9a97b000aa97e54 (CI34074425466,
90 configured tests in 1960.69s; all applicable exact-head checks passed).
This supersedes the initial pending status recorded below, not the scoped
evidence limitations. Later secret/generation additions remain unqualified;
see the [current audit](canvas-worker-oauth-revocation-coverage-audit.md).

Four frozen observations now call the actual published cycle API with the real
PostgreSQL repository, encrypted vault and HTTPS provider. A test-only child
serializes the returned dataclass into a synthetic result table after the cycle
returns. No returned counter is inferred from heartbeat, HTTP status or stored
retry count. Only the fixed disposable fixture database is accepted.

The captures completed in 21.99s and 21.46s. Permanent regeneration compared all
four observations to the frozen artifact and passed in 22.65s. Canonical LF SHA256:
`11069e4e1693295e925f415ff6f9a60566de849164449d3931fdd1370d74b090`.
The existing immutable-image owner and per-module source hashes retain provenance.
This older transport reference is not the separate hardened privacy reference.

| Actual cycle outcome | Returned successes | Returned retries |
| --- | --- | --- |
| Remote success, cleanup committed | 1 | 0 |
| Rate limit, retry committed | 0 | 1 |
| Owner replaced before successful response | 0 | 0 |
| Owner replaced before rate-limit response | 0 | 0 |

All five ordinary-job counters are zero in every case. The owner-loss cases
preserve the replacement owner's complete row, including stored retry count 7;
that value must not become a returned retry counter. The comparisons retain all
HTTP requests, actual heartbeat, durable connection/platform state, retry timing,
encrypted-secret preservation and unchanged issued rows.

Native replay invokes the real Rust `CanvasSyncWorker::run_cycle`, repository,
vault and HTTP adapter in the existing compiled test child. It checks all seven
returned fields against the frozen observations. The no-job processor sentinel
is shared with the range corpus and panics if processing is unexpectedly invoked.
The existing marker/held-response protocol performs committed ownership transfer
before releasing the provider response. No production implementation is patched.

This is cycle-API composition evidence, not standalone-loop, active-job processor
or whole-worker acceptance. The published loader is real but no job is dispatched.
The native sentinel does not qualify the real processor. Linux native HTTPS replay
remains required; Windows early returns are not counted as native parity.

The two permanent entries are registered in the mandatory hosted gate, bringing
the suite to 90 entries. Local strict all-target Clippy, all 24 Rust behavior tests,
and 991 Python tests passed (one existing opt-in skip). Harness integrity controls
cover duplicate/missing reference cases, child failure/timeout, request mismatch,
explicit observer command selection and required fence-response release. A first
all-target check caught missing imports during helper extraction; those were
restored. A registration test caught the missing mandatory shell entries; both
entries were added before the complete Python suite passed.

No consumer switch, feature deletion, deployment or merge is implied. Exact-head
native qualification and the remaining secret-resolution branch observations are
tracked in the [coverage audit](canvas-worker-oauth-revocation-coverage-audit.md).

The final configured local revocation sweep passed in 206.97s: 29 existing
published-process cases, four new actual cycle cases, the five-limit published
repository observation and both real Rust repository regressions. Nine of the
20 top-level Windows entries returned early and are not native parity evidence.
The final focused integrity/registration suite passed 111 tests in 1.65s; shell
syntax and Python lint passed. Existing frozen reference files were not changed.
