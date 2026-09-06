# Hardened worker privacy replay

The complete `contracts/canvas-worker-privacy-reference.json` is copied unchanged
from Credentials PR271, landed at `948bca975b493285c512c20a13d5abf8ee5e6305`.
Its production-reference source is the earlier protected privacy repair
`d418ac0df283625f43b0c011fb1c72fd7d3013a9`, not Rust-generated expectations.
The SHA256 of the canonical LF text is
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
The replay checks this digest, source revision and all 63 retained cases.
No old immutable oracle or observation is rewritten.

## Newly replayed boundaries

All twelve worker observations now execute through actual Rust worker
cycles/loops and PostgreSQL, using the existing observed-repository owner:

- An escaped target-read error leaves that job leased while a sibling succeeds.
- A first OAuth queue-read error fails the cycle, then the next real cycle
  reaches idle without stopping the loop.
- A failed platform disconnect marker retains one successful revocation, no
  retry, and removal of the connection and both token secrets. Real encrypted
  secret persistence is used; an unrelated tenant's secret must survive. The
  marker-failure adapter asserts the connection is already absent when invoked.
- Unexpected runtime, HTTP 429 and HTTP 503 processor failures retain retry
  status, static code/type-only summary, empty result, released lease and enabled
  target. Native target validation is enabled for these cases.
- Each branch runs once without ambient context and once inside a real tracing
  span carrying a synthetic correlation identifier.

As in the reference, repository failures, processor outcomes and remote
revocation response are controlled. Unexpected token exchange/refresh calls fail
the test, and the revoker asserts the synthetic endpoint and decrypted token.
Other operations use the real native repositories. This is not a
published-process, actual driver-failure or full deployed log-collector test.
No API credential, external signing endpoint or deployment database is used.

The native observer captures every field of every event from the worker producer,
and separately captures its actual JSON formatter output. Both complete maps are
compared; it does not select only known-safe fields. Downstream envelope fields
and optional span metadata are checked exactly before projection. A regression
deliberately emits synthetic extra, exception and backtrace fields in both modes
and proves that the observer retains them and the parity comparison rejects them.
This does not attest log events from every other service/module or a production
collector configuration.

## Explicit language and storage mappings

- The reference's injected `RuntimeError` maps to the payload-free native
  `CanvasSyncRepositoryUnavailable` for cycle/job errors, or
  `CanvasOAuthRepositoryUnavailable` for the disconnect marker. Each case's
  exact native class must match before
  this mapping; severity, event identifiers and static messages are not hidden.
- Unexpected processor categories map `CanvasSyncUnexpectedError` to
  `RuntimeError` and `CanvasSyncHttpStatusError` to `HTTPStatusError`. The exact
  complete native type-only summary is checked before substituting its type
  label. No arbitrary message or diagnostic text is normalized away.
- Generated job identifiers are normalized only after equality with the actual
  failed durable job ID is asserted.
- PostgreSQL retains `target_config_version` in the unfinished job result as an
  internal generation fence. The in-memory reference has no such stored field.
  The replay first asserts that the entire native unfinished result contains
  exactly that field, with the actual target generation, then projects the
  business result. The stored fence and all production fencing code remain intact.
- Completion and lease-state facts replace absolute timestamps, as in the frozen
  reference. No clock is changed and no scheduling, retry or completion code is
  reimplemented by the fixture.

## Failure-first correction

All four cases failed against the unmodified worker. The escaped-job cases
exposed the absent stable event identifier and the explicit storage distinction
above. The loop cases exposed swallowed OAuth queue-read failure: Rust logged a
warning and continued scheduling, unlike the reference's cycle failure/recovery.

The canonical Rust worker now propagates the queue-read error to the existing
loop handler, adds stable event IDs to escaped-job/cycle errors, and preserves
the reference's static cycle message. Queue acquisition, remote revocation,
tenant-atomic cleanup, job concurrency and generation fences are unchanged.
The test also asserts ordered heartbeat writes and exactly one completed
scheduling phase across the two loop attempts. An initial test-only assumption
of one idle write was corrected to the actual post-lease and final idle writes;
the frozen output was never changed.

The two subsequent disconnect-marker baseline cases matched all revocation and
cleanup state but failed only the log projection: warning severity, missing
stable event ID and different static message. The correction restores the
reference's error severity, `canvas_oauth_disconnect_marker_failed` identifier
and static message. It does not change the already-correct cleanup path, atomic
transaction, lease checks or success/retry accounting. Both new cases then
passed alongside the four earlier observations; raw worker logs contain none
of the synthetic access, refresh or retained-control secrets.

All four native observations passed locally. The original three-entry configured
PostgreSQL group passed in 93.43 seconds, including the 28+2 signing guard,
range/lifecycle/disposal and 60 renewal combinations. The subsequent observer
regression passed independently. The final four-entry configured PostgreSQL
group passed in 93.77 seconds, including all four native observation markers
and the observer regression; its loopback-only tmpfs fixture was removed.
Library 332, worker binary 5 and behavior 23
tests passed, as did strict all-target Clippy and 907 Python tests with one
existing opt-in skip. Fresh exact-head hosted checks must pass before treating
this follow-up as qualified. Windows does not attest the Linux process-signal
cases; those remain mandatory in hosted CI.

The expanded six-observation checkpoint passed all four configured PostgreSQL
entries in 93.73 seconds, with all six native markers and the earlier guard,
range, lifecycle, disposal and renewal cases retained. Its isolated loopback
tmpfs database was removed. The new checkpoint also passed 332 library tests,
5 worker-binary tests, 23 behavior tests, strict all-target Clippy, and 907 Python
tests in 42.87 seconds with the same existing opt-in skip. The frozen corpus
hash remains unchanged. This local result still requires fresh exact-head
hosted qualification; it does not close the whole-worker gates.

## Unexpected processing boundary

The preceding six-case checkpoint `5bf3f77ee8841043ef84248d3a24d96b3b8142e4`
subsequently passed CI34062785614 and all applicable exact-head checks, including
Rust CodeQL34062785658. The configured Linux worker database group passed all
four entries in 95.03 seconds; the separate 70-entry published-schema/runtime
group passed in 1534.56 seconds (job101566211338). The image job also passed.
This qualification predates the following processing extension.

The first six worker cases were already passing when the remaining processing
cases were added. With the new typed carrier but before handler integration,
all six processing cases failed because no unexpected-job event was emitted.
The complete reference artifact was unchanged.

The shared worker now accepts an explicit, payload-free unexpected-failure
category: runtime failure or HTTP status. It does not emulate Python exceptions,
inspect an arbitrary exception object, or carry a URL, response body, header or
credential. Known first-party adapter failures remain explicitly classified.
This does not claim every actual driver/provider failure has been composed and
qualified through those adapters; that remains a separate whole-worker gate.

At the worker boundary, unexpected errors are rebuilt from their category before
persistence. All six native cases deliberately overwrite public diagnostic
fields and the retryable flag, proving those cannot bypass the static privacy
policy. The error event is emitted only after successful durable failure
handling. Existing renewal/persistence error precedence and lease fencing remain
unchanged. Runtime/503 map to `canvas_sync_unexpected_error`, 429 to
`canvas_rate_limited`; each retries within the existing attempt/deadline policy.

A shared `with_retry_after` builder replaces three repeated constructions for
known provider errors. Canonical unexpected reconstruction retains that numeric
hint; a unit regression covers zero, ordinary and maximum hints without moving
the existing deadline/clamping policy. Actual worker/SQL retryable and terminal
controls prove known errors retain their codes, summaries, outcomes and lack of
unexpected-error logging. Correlation-mode parsing explicitly handles the
processing cases' additional status suffix; both actual formatter paths execute.

All twelve worker observations and both known-error controls passed in the
final configured PostgreSQL group (four entries, 94.15 seconds), including the
builder refactor. The existing signing guard, range/lifecycle/disposal and 60
renewal combinations remain green. The isolated loopback tmpfs fixture was
removed afterward. Final qualification also passed 333 library, five worker
binary and 23 behavior tests, strict all-target Clippy, and 907 Python tests in
37.17 seconds with the same existing opt-in skip. The immutable 63-case hash is
unchanged. Fresh exact-head hosted qualification remains required; local Windows
results do not attest Linux process-signal behavior.

## Still required

All 51 signing helper/operation observations still need native adoption.
Coordinate overlapping signing-adapter work with the crypto worker. Whole-worker
driver/provider failures, remote OAuth, races, all consumers and aggregate
acceptance remain their own gates. This twelve-case replay does not close gates
6, 13 or 14, authorize deleting live Python, or change production deployment.
