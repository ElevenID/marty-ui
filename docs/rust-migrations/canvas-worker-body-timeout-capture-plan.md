# Canvas worker response-body timeout capture plan

Status, 2026-09-08: reviewed reference fixture, runner, and explicit capture
wiring are implemented. No whole-worker body-progress or body-stall capture
has been performed for this plan. The declared schedules and expected outcomes
remain source-derived, not frozen observations, passing native replay, or
permission to change a timeout or deployment consumer.

The implementation is isolated on
`feat/canvas-worker-body-timeout-reference-v1`, based on `395cab656`. Its isolated
worktree lets the already-tested delayed-header branch proceed independently.
Preparing the fixture does not establish any of the worker outcomes below.
The pre-provenance-fix local checkpoint passed: 76 fixture tests, 190
runner/contract controls, and the combined 266 tests in 15.87 seconds. Root-owned verification
passed: full Python suite 2,100 passed / 3 skipped in 155.86 seconds; Rust closed
selector control 1 passed; strict all-target Clippy in 6.65 seconds; final test
build in 5.53 seconds. Independent capture-wiring review found no blockers.
These totals precede the local capture-source newline canonicalization fix.
That fix subsequently passed independent review and 199 focused tests (nine
provenance regressions plus 190 runner controls) in 0.34 seconds, with Ruff
passing. These are not an actual published-worker capture or native body replay.

This supplements the [provider timeout audit](canvas-worker-provider-timeout-audit-2026-09-07.md),
[delayed-header capture](canvas-worker-timeout-capture-plan.md), and
[native timeout replay](canvas-worker-native-timeout-replay.md). Existing frozen
fixtures, oracles, tolerances, and cutover gates remain unchanged.

## Verified authority and existing coverage

### First attempted capture: diagnostic failure, not a reference

At committed input head `44e3dc2fad7e7e1a58f7303536bafc32ba8be566`, the first
capture attempt stopped in `application_body_prompt` after 24.38 seconds. The
strict post-SIGINT output profile rejected 33 stderr lines: two reviewed startup
warnings, 31 other lines, and two traceback headings. No raw output was exposed
and no capture artifact was emitted. Remaining cases were not executed.

The parent verified both exact-owned containers were removed: PostgreSQL
`ad053c9126caeadbd1f01d47ad323ac91510eb69323a61b5ea5ceb7f4541a89c` and probe
`8a05162fb1b6fb1c03a7b29d2ca4466023c8b3d1762a6c9ecbb3e27b816ad717`.
The failure prompted a pinned-source shutdown review and the distinct bounded
profile below. The failed attempt remains diagnostic only. Any runner repair
requires a new A/B sequence with the reviewed inputs fixed before A.

### Reviewed idle-shutdown profile

The source-pinned Python 3.12.13 runner cancels the idle main task on SIGINT and
raises `KeyboardInterrupt` from its `CancelledError` handler. The new
`canvas_worker_shutdown_output.py` recognizes only that exact two-trace chain:
eleven fixed frame tuples, exact code lines from hash-verified worker/stdlib
files, the exact chaining text, and bare exception names. Only one optional
bounded ASCII caret-decoration line per source line is allowed. Quiet output,
other frames, messages, notes, extra traces and unknown lines fail.

Both streams retain the shared 65,536-byte limit and all synthetic-secret
tripwires. The prefix must still pass the unchanged two-warning profile, and
stdout must remain empty. Runtime version and six immutable source-file hashes
are checked without importing or executing application code. This profile is
called only after owned SIGINT and the terminal wait; it does not change or
waive the existing pre-interrupt checks or establish native output equivalence.

Independent source review found no blockers. The 106 new shutdown controls
passed, including every frame mutation and truncated prefix, source/runtime
pin failure, secrets, unknown output, growth bounds and post-wait reads.
Combined focused checks passed 537 tests in 23.31s, including existing deadline
and timeout contracts. The Rust body-only mount/selector check passed and
strict all-target Clippy passed in 5.50s. The full updated Python suite then
passed 2,215 tests with three explicit skips in 158.55s. A fresh actual A/B
capture is still required; none of these checks freezes worker behavior.

The reference image remains:

```text
ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176
```

The parent inspected this immutable image and verified HTTPX 0.26.0 and
httpcore 1.0.9. Installed HTTP/1.1 `_receive_response_body` calls
`_receive_event`; each `NEED_DATA` invokes `network_stream.read` with the read
timeout. `AnyIOStream.read` establishes a fresh `anyio.fail_after` scope for
each read. Consequently successful network progress can reset the inactivity
budget without establishing a new whole-response deadline.

The inspection used two named disposable no-network probes, v1 and v2 (reported
container ID prefixes `b728cc9` and `75ad28a4`). The parent verified removal of
each exact owned container. This is installed-source evidence, not a
whole-worker execution result. Preserve the exact image/source pins already
recorded by the audit and header corpus; do not substitute local dependency
versions or moving source for that authority.

Current evidence has three distinct scopes:

- The [frozen timeout-consumer corpus](../../contracts/canvas-timeout-consumer-oracle.json)
  contains `headers_timeout`, `body_timeout`,
  `progress_exceeds_total_budget`, and gzip progress/stall cases. Its
  [TLS runner](../../scripts/run_canvas_timeout_consumer_oracle.py) exercises
  the published HTTP factory and pinning transport, not the worker. The plain
  progress control delivers six bytes at 0.15-second intervals with a
  0.5-second configured limit and records success.
- [`CanvasOperationHttpClient`](../../rust/services/issuance/src/canvas_operation_http.rs)
  has native socket replay plus connection-cancellation/drop tests.
  `OperationSocket.poll_read` resets its read budget after a completed read.
  These are reusable transport owners, not proof that the worker selects the
  right target-specific client or preserves durable effects.
- The [four-case worker corpus](../../contracts/canvas-worker-timeout-oracle.json)
  records application/empty-roster prompt and delayed-header behavior. Its
  [fixture](../../scripts/canvas_worker_timeout_https_fixture.py) holds before
  headers and then writes the complete body. It does not qualify body progress,
  read-budget resets, or partial-body failure.

## Declared minimum: six actual-worker controls

Use the existing learner-application assignment and authenticated empty-roster
seeds. Capture each target's prompt control again through the new body writer,
so framing and complete JSON parsing have positive controls in this corpus.
Times below are declared offsets from a promptly established body-stream start,
after the initial held-request/leased-state handshake. Record request-relative
times separately; do not hide setup time by redefining the request receipt.

| Case | Body schedule | Source-derived expectation to capture |
| --- | --- | --- |
| `application_body_prompt` | Flush valid JSON pieces at 0 and 0.05 seconds | Successful assignment evidence |
| `roster_body_prompt` | Same 0 and 0.05 schedule | Successful empty roster |
| `application_body_progress` | Flush bounded pieces at 0, 8, 16, 24 seconds | Success: all gaps below 15s although total duration exceeds 15s |
| `roster_body_progress` | Same 0, 8, 16, 24 schedule | Success: all gaps below 20s although total duration exceeds 20s |
| `application_body_stall` | Flush partial JSON at 0 and 8; independently attempt remainder at 31 | Read inactivity failure near 23s, before the final attempt |
| `roster_body_stall` | Same 0, 8, 31 schedule | Read inactivity failure near 28s, before the final attempt |

Send correct `Content-Length`, bounded uncompressed JSON, and flushed headers.
Keep the JSON incomplete until the last piece. Split the existing assignment
response without changing its meaning; for the empty roster, bounded leading
JSON whitespace permits multiple real chunks without manufacturing candidates.
Do not use socket chunks as evidence of application-level partial success.

These schedules distinguish progressing reads from both a total-response
deadline and a permanently disabled timeout. They do not qualify compressed
bodies, pagination, nonempty candidate processing, OAuth refresh, LTI grant/body
handling, revocation, signing, or lease-expiry-during-provider-I/O behavior.

## Implemented reuse boundaries

Reuse the shared seed and exact-worker startup owners used by
[`run_canvas_worker_timeout_oracle.py`](../../scripts/run_canvas_worker_timeout_oracle.py),
the exact HTTPS request observer, and the append-writer/independent-reader
[output owner](../../scripts/canvas_worker_output_capture.py). Keep the initial
job timeout, lease, and poll settings at 120/90/120 seconds unless separately
reviewed before capture; they must outlast the proposed body/late-write windows.
Never edit a running job, lease, schedule, clock, or worker callback.

The [`body fixture`](../../scripts/canvas_worker_body_timeout_https_fixture.py)
reuses [`WorkerHttpsFixture`](../../scripts/canvas_worker_https_fixture.py)
through default-preserving response encoding/writing and request-connection
configuration hooks. Existing GET/DELETE framing and default single-write
behavior remain unchanged. The body fixture is single-use, including after
partial entry failure, and sets a two-second connection timeout before HTTP
request parsing and response headers. This does not qualify the inherited
pre-handler TLS accept/handshake boundary.

The existing request handler independently schedules body writes; there is no
additional controller thread and no outcome-driven release. The initial held
request is released only after exact leased-state verification. Cancellation
and server close join owned handlers. Only the explicitly declared final stall
slot may classify an expected peer-close; header, early-write, and unrelated
TLS failures remain failures. No live capture may read inputs being edited.

The fixture records bounded chunk indices, byte counts, successful-flush
start/end bounds, final-attempt timing, and static transport classifications. A scheduled
write is not a successful flush, and a flush is not an exact client-read
timestamp. Reject missed schedule bounds rather than repairing the record.

## Timing and durable-state gates

Retain both kinds of timing evidence:

1. The observer's original outcome-receipt bounds remain mandatory for existing
   frozen controls. Do not replace them with the new interval or accept a late
   report by declaring the old observed window obsolete.
2. For new body controls, additionally bracket the first terminal **job**
   transition using monotonic query intervals for the same job ID, attempt,
   and start time. Stop advancing the lower bound once the job becomes terminal;
   later idle-heartbeat/full-state queries cannot move completion forward.
   Require the entire conservative interval within the declared case window,
   not midpoint or overlap acceptance. Preserve request/anchor uncertainty.

The [scenario](../../contracts/canvas-worker-body-timeout-scenarios.json) and
[runner](../../scripts/run_canvas_worker_body_timeout_oracle.py) now declare
fixed bounds before capture A. The
existing request-relative 14.5-16.5s header window is not automatically a
request-relative body-stall window after eight seconds of successful progress.
23s/28s outcomes are source-derived centers, not observations. For stalls,
the whole conservative inactivity interval is
`[last leased query START - last successful flush END,
first terminal query END - last successful flush START]`, contained within
14.5–16.5 seconds for applications or 19.5–21.5 seconds for rosters.
For prompt/progress success, the whole first-terminal interval must be contained
within `[actual final write START - 0.5s, actual final write END + 2s]`, with its
upper bound at or after final write start. The separate idle observation and
overall request/body budgets remain mandatory. A broad interval merely
overlapping the window cannot pass. Queries and scheduled-write lateness each
have a 0.5-second maximum; timing uncertainty fails the capture rather than
causing a tolerance adjustment. Negative tests cover early terminal/late idle,
stale broad intervals, exact boundaries, and malformed timing observations.

Require exactly one authenticated GET with the existing path, authorization,
and Accept contract; reject extra/unsupported traffic. Verify the original
captured lease remains current, rather than accepting any later renewed lease.
Keep the one-job/attempt-one invariants and exact target generation checks.

Capture application and roster results independently. In particular, existing
roster failure evidence uses `canvas_authoritative_read_failed` with summary
`Canvas background evidence could not be read`, retaining its cursor and
heartbeat metadata. Application unavailable reads use
`canvas_authoritative_reads_failed`. The current header runner's retry branch
and successful-roster metadata assumptions cannot be applied unchanged to a
new roster body stall. Verify the installed failure path and capture its actual
result; never normalize it to application retry or empty-roster success.

Compare raw facts, heads, policy/review/event rows, application state, roster
candidates/observations, jobs/targets, preserved issued rows, and ciphertext.
Partial unavailable JSON must not create negative evidence, clear a roster
cursor, invent safe counters, or revoke preserved credentials. Successful
application and empty-roster projections must match their actual seeded
behavior, including float/int representation and the four durable roster
counters.

## Late writes, privacy, cleanup, and freeze sequence

After a stall outcome, still attempt the independently scheduled remainder.
Distinguish the expected closed-connection result from unexpected handler
failure without emitting payloads. Observe unchanged durable state through a
declared window after the final write attempt and beyond the relevant pending
read budgets; retain an after-observed-outcome margin as well. Then join the
owned handlers, compare the final request ledger, interrupt only the
owned worker, and compare durable state again after its bounded exit.

Keep control and output directories alive through HTTPS shutdown. Every wait
and cleanup path must be bounded and ownership-checked. Reuse exact process
containment and the surviving disposable-database owner for native replay;
do not claim protection against uncatchable death of that surviving owner.
Check both raw streams with the strict published warning profile and synthetic
secret exclusions before interruption. After the bounded SIGINT wait and
expected Python exit `-2`, apply the separately source-reviewed closed shutdown
profile above, retaining the same bounded-read and secret exclusions. Keep
separate `logs_before_interrupt` and `logs_after_interrupt` observations.
Secrets or unknown output cannot be silently removed. Native output remains
separately classified.

## Explicit immutable capture wiring

The ignored Rust entrypoint
`capture_worker_body_timeout_published_process` is available only for explicit
reference capture, not as a passing native parity gate. It requires
`MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1` and
`MARTY_CANVAS_BODY_CAPTURE_FILE` naming a new absolute output path. Select it
with `--exact --ignored --nocapture`; do not enable it during ordinary tests.
The published-database constructor, probe dispatch, and immutable-image mounts
are wired for all six declared cases. Installed source hashes, runtime versions,
and hashes of fixture/runner/shared contract inputs are checked by the runner.

Local textual input provenance now uses explicit UTF-8/LF
canonicalization (CRLF and standalone CR become LF) so a Windows CRLF checkout and the same Git/Linux LF source
have the same hash. This applies only to local fixture/runner/shared contract
source text. It is not JSON parsing or numeric reserialization: whitespace
other than line endings, JSON numeric spelling, and source content remain
significant. Installed-source hash values and their existing verification
conventions remain unchanged; in particular, the immutable HTTP factory is
still hashed from raw bytes. Invalid UTF-8 fails rather than being replaced.
Full raw observation reports are not newline-normalized or edited.

Each case gets a fresh synthetic database. The entrypoint retains each full raw
JSON probe report, checks the case identity and one-MiB report bound, and requires
verified exact-owned cleanup before retaining that case. Only after all six
cases and cleanups succeed does it create the output with `create_new`, write
an array of those raw reports, and sync the file. Parsing for validation does
not reserialize the reports or their numeric tokens. Existing destinations,
including a concurrently created destination, are rejected. An output-write
failure is not capture success; retain any partial new file as failed evidence
and choose a different new path for a later run.

This wiring has not yet produced a body capture. A and B must use distinct new
absolute output paths and the same frozen inputs; raw full-report equality and
cleanup evidence are required before deriving any frozen corpus.

Before freezing any reference:

1. Review new scenario/fixture/runner/tests, including real loopback transport,
   schedule failures, incomplete-body handling, extra requests, cancellation,
   bounded output, handler joining, and failure cleanup. Focused review and
   controls and aggregate validation passed at the pre-provenance-fix checkpoint
   above; newline canonicalization and the distinct shutdown profile have their
   separate reviewed focused evidence. Retain updated aggregate validation
   before capture.
2. Register the immutable-image mounts and fresh published-database capture
   entrypoint (implemented above). Verify installed source hashes and dependencies; freeze all
   inputs while a capture is running.
3. Run A for all six cases against the actual unchanged Python worker, each in
   a fresh synthetic database. Preserve raw output and exact owned cleanup
   evidence; diagnose any mismatch without changing the observed result.
4. Independently run B with the same frozen inputs and fresh databases.
   Require exact raw A/B equality and provenance before freezing; no JSON
   numeric reserialization, timestamp surgery, or tolerance changes after the
   fact. A source/fixture repair requires restarting the reviewed A/B sequence.
5. Add permanent immutable-reference regeneration, native whole-worker replay,
   and mandatory registration. Only actual Linux execution may qualify native
   behavior. Existing header/deadline and transport gates remain mandatory.

There is no body oracle, actual-worker pass, runtime repair, deployment change,
or cutover authorization produced by this plan.
