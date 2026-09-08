# Canvas worker response-body timeout capture plan

Status, 2026-09-08: proposed reference work only. No whole-worker body-progress
or body-stall capture has been performed for this plan. The schedules and
outcomes below are source-derived proposals, not frozen observations, passing
native replay, or permission to change a timeout or deployment consumer.

Fixture preparation is now in progress separately on
`feat/canvas-worker-body-timeout-reference-v1`, based on `395cab656`. Its isolated
worktree lets the already-tested delayed-header branch proceed independently.
Preparing the fixture does not establish any of the worker outcomes below.

This supplements the [provider timeout audit](canvas-worker-provider-timeout-audit-2026-09-07.md),
[delayed-header capture](canvas-worker-timeout-capture-plan.md), and
[native timeout replay](canvas-worker-native-timeout-replay.md). Existing frozen
fixtures, oracles, tolerances, and cutover gates remain unchanged.

## Verified authority and existing coverage

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

## Proposed minimum: six actual-worker controls

Use the existing learner-application assignment and authenticated empty-roster
seeds. Capture each target's prompt control again through the new body writer,
so framing and complete JSON parsing have positive controls in this corpus.
Times below are proposed offsets from a promptly established body-stream start,
after the initial held-request/leased-state handshake. Record request-relative
times separately; do not hide setup time by redefining the request receipt.

| Proposed case | Body schedule | Source-derived expectation to capture |
| --- | --- | --- |
| `application_body_prompt` | Complete valid JSON promptly | Successful assignment evidence |
| `roster_body_prompt` | Complete valid empty-array JSON promptly | Successful empty roster |
| `application_body_progress` | Flush bounded pieces at 0, 8, 16, 24 seconds | Success: all gaps below 15s although total duration exceeds 15s |
| `roster_body_progress` | Same 0, 8, 16, 24 schedule | Success: all gaps below 20s although total duration exceeds 20s |
| `application_body_stall` | Flush partial JSON at 0 and 8; independently attempt remainder at 31 | Read inactivity failure near 23s, before the final attempt |
| `roster_body_stall` | Same 0, 8, 31 schedule | Read inactivity failure near 28s, before the final attempt |

Send correct `Content-Length`, bounded uncompressed JSON, and flushed headers.
Keep the JSON incomplete until the last piece. Split the existing assignment
response without changing its meaning; for the empty roster, bounded whitespace
inside an array permits multiple real chunks without manufacturing candidates.
Do not use socket chunks as evidence of application-level partial success.

These schedules distinguish progressing reads from both a total-response
deadline and a permanently disabled timeout. They do not qualify compressed
bodies, pagination, nonempty candidate processing, OAuth refresh, LTI grant/body
handling, revocation, signing, or lease-expiry-during-provider-I/O behavior.

## Reuse boundaries and required fixture work

Reuse the shared seed and exact-worker startup owners used by
[`run_canvas_worker_timeout_oracle.py`](../../scripts/run_canvas_worker_timeout_oracle.py),
the exact HTTPS request observer, and the append-writer/independent-reader
[output owner](../../scripts/canvas_worker_output_capture.py). Keep the initial
job timeout, lease, and poll settings at 120/90/120 seconds unless separately
reviewed before capture; they must outlast the proposed body/late-write windows.
Never edit a running job, lease, schedule, clock, or worker callback.

The current [`WorkerHttpsFixture`](../../scripts/canvas_worker_https_fixture.py)
has a pre-header `wait_for_response` hook but writes the whole body directly.
Streaming needs an explicitly reviewed body-writer extension or equivalent
owned fixture seam. Do not treat a longer pre-header wait as a body-stall test.
Do not duplicate certificate, request-observation, or server/process cleanup
owners merely to obtain a streaming handler. Any shared extension must preserve
the default single-write behavior and all existing GET/DELETE, unsupported-verb,
header, release, and cleanup tests. Obtain ownership before changing shared
inputs; no live capture may read files being edited.

A new body fixture must independently schedule writes, without consulting job
outcomes. Record only bounded chunk indices, byte counts, successful-flush
timings, final-attempt timing, and static transport classifications. A scheduled
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

Declare new body-case observer and transition bounds before capture A. The
existing request-relative 14.5-16.5s header window is not automatically a
request-relative body-stall window after eight seconds of successful progress.
The proposed 23s/28s outcomes are source-derived centers, not already-approved
tolerances. Include early-terminal/late-marker and early-terminal/late-idle
negative controls, malformed timing payloads, and broad-interval rejection.

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
controller and handlers, compare the final request ledger, interrupt only the
owned worker, and compare durable state again after its bounded exit.

Keep control and output directories alive through HTTPS shutdown. Every wait
and cleanup path must be bounded and ownership-checked. Reuse exact process
containment and the surviving disposable-database owner for native replay;
do not claim protection against uncatchable death of that surviving owner.
Check both raw streams with the strict published warning profile and synthetic
secret exclusions; new unexpected output must fail capture, not be silently
removed. Native output remains separately classified.

Before freezing any reference:

1. Review new scenario/fixture/runner/tests, including real loopback transport,
   schedule failures, incomplete-body handling, extra requests, cancellation,
   bounded output, controller/handler joining, and failure cleanup.
2. Register the immutable-image mounts and fresh published-database capture
   entrypoint. Verify installed source hashes and dependencies; freeze all
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
