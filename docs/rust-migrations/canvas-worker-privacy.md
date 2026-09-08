# Hardened worker privacy replay

## Current qualification status

The complete twelve-worker-observation follow-up is historically qualified at
`b02b77d13562db717d6e16cdf85ff430edbc2eeb`: parent-verified
[CI34064588338](https://github.com/ElevenID/marty-ui/actions/runs/34064588338)
completed successfully. Exact-head checks, configured PostgreSQL/runtime and
image evidence are recorded below. This qualifies the named allowlisted worker
logging boundary (gate 14) and unexpected-error privacy portion of gate 6.
Fresh hosted qualification of the integrated `a897c18d3` candidate remains
pending. The new missing-target/composed-result regression passed the complete
four-entry configured PostgreSQL suite locally on Windows in 94.81s, including
the 21-value-class, empty-result and orphan marker. Mandatory Linux signal cases
and fresh-head CI remain pending. Historical local-only checkpoints below describe the
order of development, not the current qualification status.

The complete `contracts/canvas-worker-privacy-reference.json` is copied unchanged
from Credentials PR271, landed at `948bca975b493285c512c20a13d5abf8ee5e6305`.
Its production-reference source is the earlier protected privacy repair
`d418ac0df283625f43b0c011fb1c72fd7d3013a9`, not Rust-generated expectations.
The SHA256 of the canonical LF text is
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
The replay checks this digest, source revision and all 63 retained cases.
No old immutable oracle or observation is rewritten.

## Retained qualified boundaries

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
existing opt-in skip. At this historical checkpoint hosted checks were still
required; the subsequent qualifications below supersede that local-only status.
Windows results alone do not attest Linux process-signal cases.

The expanded six-observation checkpoint passed all four configured PostgreSQL
entries in 93.73 seconds, with all six native markers and the earlier guard,
range, lifecycle, disposal and renewal cases retained. Its isolated loopback
tmpfs database was removed. The new checkpoint also passed 332 library tests,
5 worker-binary tests, 23 behavior tests, strict all-target Clippy, and 907 Python
tests in 42.87 seconds with the same existing opt-in skip. The frozen corpus
hash remains unchanged. This was a local-only result until the hosted
qualification below; it did not authorize whole-worker cutover.

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
This covers the named controlled unexpected-error projections, not actual
driver/provider failure injection. Other concrete behavior requirements retain
their own gates; this limitation does not reopen the qualified worker-log
projection or imply an unbounded failure matrix.

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
unchanged. These local results preceded the exact-head hosted qualification
below; they alone did not attest Linux process-signal behavior.

## Hosted qualification and remaining work

The complete twelve-case follow-up subsequently qualified at
`b02b77d13562db717d6e16cdf85ff430edbc2eeb`: CI34064588338 and all applicable
exact-head checks passed, including Rust CodeQL34064588330. Runtime job101571024242
passed the four-entry configured worker PostgreSQL group in 96.51 seconds and
the separate 70-entry published-schema/runtime group in 1449.26 seconds. The
image job passed as well. This qualifies these retained privacy boundaries;
the current candidate must retain them in fresh exact-head CI. Later revocation
qualification is tracked separately in the cutover readiness table.

The isolated signing helper/test implementation below now passes the 45 detail
and six operation-message projections locally. Production signing-adapter
adoption (gate 13) and coordination with the overlapping crypto owner remain
pending; the pure test target does not close that gate.
The new gate 6 missing-target test composes an orphan in the dedicated worker
test schema, not a published-schema FK/deletion race; the complete configured
PostgreSQL suite passed all four entries locally on Windows in 94.81s. Fresh-head
hosted qualification, including mandatory Linux signals, remains pending.
The twelve-case replay already qualifies gate 14's named structured-log boundary
and gate 6's unexpected-error projections. It does not prove signing diagnostics,
all-service/collector logging or whole-worker cutover. Consumer selector removal,
the separate live-provider lease-expiry composition and aggregate beta acceptance
remain explicit work in the [readiness table](canvas-worker-cutover-readiness.md).
No live Python deletion or production deployment is authorized by these passes.

## Isolated signing diagnostic helper (2026-09-08)

The new [signing_error_detail.rs](../../rust/services/issuance/src/signing_error_detail.rs)
implements the pinned Python helper's selection and status/message behavior,
reusing [python_value.rs](../../rust/services/issuance/src/python_value.rs) for
Python truthiness, dictionary representation and frozen Unicode whitespace
semantics. It is not wired into the production library or signing adapters.
No protected signing implementation, cryptographic policy or frozen reference
was changed for this slice.

The isolated [signing_error_detail_contract.rs](../../rust/services/issuance/tests/signing_error_detail_contract.rs)
imports those two modules directly through `#[path]`. Its explicit Cargo test
registration is necessary because the package disables automatic integration
test discovery. It checks the unchanged canonical-LF corpus digest, source
revision and signing helper/test blob identities, then replays all 45 detail
strings and all six operation-message projections. The six frozen HTTP request
counts, methods and paths remain reference metadata: this test performs no
HTTP request and does not manufacture corresponding native observations.

The helper accepts an already parsed `serde_json::Value` and a supplier of
already decoded response text. The operation wrapper calls its JSON supplier
before the text supplier for error statuses. Text is evaluated eagerly even
when a usable JSON detail is available, and text-supplier failures propagate.
Both suppliers are bypassed for the exact existing status short-circuits:
401 rejection, context/resolve 404 absence, and non-error status continuation
(status below 400).
Signing 404 still produces its operation-specific error. Actual JSON parsing,
HTTP byte/charset decoding, response-body ownership and successful-response
parsing remain the future adapters' responsibility; this pure projection does
not establish their HTTPX parity.

Independent controls also retain the non-obvious selection boundaries:

- A truthy whitespace-only first detail does not fall through to a later JSON
  key; it uses the stripped response text or reason fallback.
- The final `error` operand is not truthiness-filtered. An empty dictionary
  there renders as `{}`, while a falsey earlier dictionary can fall through.
- Python dictionary insertion order, quoting, booleans, `None`, large integers
  and Unicode representation survive selection. Unsupported selected scalar
  or list values retain the text fallback rather than being stringified.
- The limit is 500 selected Unicode characters, not bytes or grapheme clusters.
  Operation prefixes and HTTP status text sit outside that detail limit. It is
  neither a response allocation/memory bound nor secret redaction: content
  within those characters can still contain remote diagnostic material.

Parent-executed local verification completed with compilation in 33.64s and
13 tests passing in 0.01s: eleven new helper/corpus controls plus the two
existing `python_value` controls imported by the test target. The separate
registration regression passed one test in 0.11s. Independent source and test
review found no blockers. Strict all-target Clippy passed in 23.02s; fresh
hosted evidence for this slice remained pending at this checkpoint. The runnable target is
`cargo test -p marty-issuance-service --test signing_error_detail_contract`.

Gate 13 remains open until the crypto owner agrees the production integration
scope and the context, DID-resolution and signing adapters actually adopt the
shared behavior. That integration must preserve operation-specific status and
error propagation, exercise the existing reference request method/path/count
observations through real owned adapter calls, and retain their current
successful-response and cryptographic behavior. The local pure passes prove
neither adapter adoption nor signing, whole-worker cutover, deployed logging
privacy or beta acceptance.

Choose `SigningOperation` from the caller's operation, not the URL alone:
the pinned `resolve_remote_issuer_context` uses the context error prefix even
when an `issuer_did` makes it call `/resolve-issuer-did`. A future adapter test
must preserve that caller/route distinction rather than infer `Resolve` from
the endpoint path.
