# Native worker timeout replay

Status: actual native Linux diagnostic preflight at `cf5182ef7` established
application success instead of the required retry; the candidate remains
unqualified. The narrow application REST repair is now implemented separately
and compiled in 65s. After the additional malformed-header regression and test-spy
type alias, final unit execution passed 354 tests in 15.73s (8.94s compilation).
Strict all-target Clippy passed in 21.75s. Hosted parity remains required. Published fixtures, frozen
outcomes, live jobs, leases, clocks, consumer routing and deployments are unchanged.

## Actual Linux preflight — 2026-09-08

### Diagnostic replay establishes the application status mismatch

The follow-up at exact head `cf5182ef73678b5e0d47cacf23c1f5b38150cd5d`
executed in [CI34197335937](https://github.com/ElevenID/marty-ui/actions/runs/34197335937),
runtime job `101967919625`. The prompt application control again passed with
one actual HTTPS request. The delayed application control failed after observing
`TerminalSucceeded`, `TerminalMismatch`, then `CompareOutcome` and differences
in `OutcomeJobs`, `OutcomeFacts`, `OutcomeSnapshot`, and `OutcomeTarget`.
The diagnostic ended at `2026-09-08T07:10:00Z`; the wrapper failed after 49.05s.
No transition-publication category was emitted. Unlike the first byte-count-only
failure below, this establishes success instead of the required retry and
different durable business/target state before publication.

This supplies the negative execution evidence for the reviewed application REST
operation-timeout repair. Preserve the published 15s application/issued-drift
budget, separate roster behavior, and all existing transport/state/cleanup
gates; do not change the frozen reference to match the failing native outcome.
Repair work is isolated on `feat/canvas-operation-timeout-repair-v1`. It is not
yet qualified. Remaining roster cases and later full-suite gates were not
reached by this failing preflight; no deployment or consumer routing changed.

### Earlier byte-count-only preflight

[CI 34195421549](https://github.com/ElevenID/marty-ui/actions/runs/34195421549),
runtime job `101961994076`, executed the new native preflight at exact head
`7ca035d03f1e5bb69c2695c7ad2d9629aff3cb1b`. `application_prompt` passed with one
actual HTTPS request. The next case, `application_delayed_headers`, failed with
`Native timeout child exited during outcome-observed`; the wrapper finished
with one failed test after 49.77s at `2026-09-08T06:43:52Z`. The roster cases and
later mixed/full configured suites were not reached by this preflight.

The failure note exposed only coordinator stdout/stderr byte counts (217/266),
not the child's assertion or observed durable status. The controller can notice
a nonzero child exit even if its marker has just been published. Consequently
that earlier result proved a failed delayed-application replay, not by itself the
predicted 20s-versus-15s cause, an observed `succeeded` status, or successful
failure-path cleanup. Closed categorical diagnostics were the next step; do not
infer hidden state from timing or byte counts or weaken the equality/timing gate.

The follow-up now emits fixed coordinator-only diagnostic categories for the
first observed terminal status, mismatched top-level state fields, and phases
before/after transition publication. The controller reads at most 65,537 bytes
from its independent stderr reader and exposes only exact, newline-terminated
allowlisted records, with duplicate/count/size rejection. Panic text, values,
dynamic field names and worker output are never copied into diagnostic notes.
The original output byte counts, failure, equality and timing checks remain.
Independent review found no blockers. Final focused Python checks passed 201
tests in 4.45s; both new Rust diagnostic controls passed, with strict all-target
Clippy passing in 4.41s. The subsequent `cf5182ef7` Linux replay established the
failure category as recorded above; these controls alone did not establish parity.

The earlier `f0` 137-test/deadline qualification is retained. The PR stays draft
and the worker remains unrouted. The byte-count-only result did not justify a
runtime policy change without further diagnosis. The later diagnostic supplied
that evidence for the narrow repair; neither result authorizes Python deletion
or deployment.

The [published four-case reference](canvas-worker-timeout-capture-plan.md) remains
the independent behavioral authority. The native replay does not derive its
expected state from the Rust implementation.

| Case | Independent response release | Required published outcome |
| --- | --- | --- |
| `application_prompt` | After held-state verification, before 2s | Success |
| `application_delayed_headers` | 17s, independently of worker outcome | Retry at 14.5–16.5s, before release |
| `roster_prompt` | After held-state verification, before 2s | Empty authenticated roster succeeds |
| `roster_delayed_headers` | 17s, independently of worker outcome | Empty authenticated roster succeeds after release |

Each case makes exactly one authenticated GET. The 120s job timeout, 90s initial
lease and 120s polling interval isolate the provider timeout from job cancellation,
lease expiry and a later retry. The first generation and original lease must stay
valid; full held/outcome projections, committed evidence, target metadata, OAuth
projection and raw post-outcome business/job/target rows are compared. Observation
continues through the later of request+22s and outcome+2s, followed by handler join,
owned interruption and unchanged final state. The four safe roster counters and
published removal of roster heartbeat metadata remain part of equality.

## Shared ownership, not duplicated orchestration

- The outer Rust test retains each exact-owned disposable database; native
  coordinators borrow only the closed, inspected ID/scope descriptor.
- Both native families use the same checked borrowed-database setup and per-case
  controller launcher. Mandatory CI registers both timeout wrapper and child.
- `OwnedProcess` retains the inner coordinator's waitable identity until verified
  Linux group cleanup, then reaps it. The surviving-controller scope and its
  uncatchable-termination limitation are unchanged.
- Native quiet/private output lives in the extracted `canvas_worker_output.rs`;
  the existing deadline output tests are retained. The Python controllers share
  only pure marker validation and output-byte counts in
  `canvas_worker_process_control.py`, not either family's timing state machine.
- `TimeoutHttpsFixture` and its independent release controller are unchanged.
  Python-only import warnings are not manufactured in native output.

## Historical local checks before the first native preflight

### Delayed-observer hardening

Independent review found that timing only the coordinator's outcome marker
could hide an early durable completion behind slow database snapshots or idle
bookkeeping. The replay now records the first terminal job transition separately:
the last verified leased query's start and the first terminal query's end bound
that transition. Every leased observation retains the original job, attempt,
start, lease owner, exact expiry and generation fence.

The existing request/held-state handshake brackets the Rust monotonic origin
between two Python monotonic samples. Only bounded numeric offsets are published,
atomically and without overwriting, in the existing outcome marker. Python requires
the entire conservative transition interval within the original timing limits.
The original marker-receipt timing and release-order checks remain mandatory too;
slow reporting is inconclusive, not a reason to widen the published window.
Idle/full-state equality and all late-effect, output and cleanup checks remain
separate requirements. Successful prompt/roster ordering retains the published
observed-outcome-after-release predicate; it does not claim the uncertain lower
transition bound must be later than release.

No database clock, live row or frozen reference is changed. This additional
evidence integrity requirement does not itself qualify actual native behavior.

Integrated local validation passed 1,832 Python tests with three explicit skips
in 138.21s, including 121 timeout controller tests. Five Rust timeout controls
and all seven existing deadline timing/output controls passed; strict all-target
Clippy passed in 8.50s. The two Linux process-containment controls remain skipped
on Windows, with their separate hosted `f0` evidence below. Actual native Linux
timeout replay had not run at that historical checkpoint.

### Prior local checkpoint

The integrated executable compiled in 53.29s. Two new pure timeout controls and
all seven existing deadline timing/output tests passed; strict all-target Clippy
passed in 31.31s. The independent controller suite passed 68 tests. The full local
Python suite passed 1,760 tests with three explicit skips in 116.55s. These results
verify code and harness integrity, **not native timeout parity**.

The separate pushed baseline `f0b600730` has hosted release-test evidence of 1,694
passes and one existing skip, including both actual Linux coordinator/grandchild
cleanup cases. That baseline's larger worker parity CI subsequently passed 137
configured tests, including both native deadline cases, in run `34189450698`.
Neither that earlier head nor those containment tests qualify this new replay.

Before execution, source predicted a failing `application_delayed_headers`
replay: native authoritative and roster calls both used a 20s total-request
timeout, so the application was expected to accept the 17s response instead of
the published 15s timeout. That was initially only a prediction; the later
`cf5182ef7` diagnostic established success instead of retry. The narrow repair
now reuses the existing `CanvasOperationHttpClient` / `CanvasNetworkTimeout`
ownership for application REST. A blanket 20s-to-15s change loses roster behavior;
changing only a total-request deadline does not prove HTTPX phase/inactivity parity.

Pagination, progressing/stalled bodies, token refresh, AGS, revocation, candidate
issuance, signing, whole-worker cutover, UI/demo acceptance and aggregate beta
deployment remain separately gated work.

## Historical pre-implementation design and retained repair constraints

The following design was reviewed before the actual native delayed-header
failure and implementation. The `cf5182ef7` diagnostic above now supplies that
negative evidence. The narrow implementation retains these constraints but is
not yet a qualified parity result; do not alter the frozen reference to
accommodate native behavior. Roster and LTI still use their existing policies;
roster inactivity is not qualified by the application REST repair.
The [provider source audit](canvas-worker-provider-timeout-audit-2026-09-07.md)
records the pinned published client ownership and its separate timeout values.

Select the target scope explicitly at the existing processor/provider `for_run`
boundary: learner application and active issued drift use the application scope;
background roster uses the roster scope. Preserve a fresh job-local token cache
on every invocation, including when starting from an already scoped provider.
Unsupported targets still fail before provider I/O. Do not infer target scope
from optional application resources. Application reads and roster candidate reads
both call `read_requirement`, which shares `rest_record`: an unconditional 15s
change in that helper would also change roster evidence processing. The published
application budget is 15s; roster collection and candidate evidence retain 20s.

After the observed failure, keep the first repair narrow to application REST
evidence and reuse `CanvasOperationHttpClient` / `CanvasNetworkTimeout` for actual
operation/inactivity budgets. A total-response timer set to 15s is insufficient.
Retain the shared origin and transport owners rather than duplicating networking
or timeout logic. Any response adapter must retain these compatibility boundaries:

- Preserve OAuth lookup and rejection side effects, encoded paths and queries,
  bearer/Accept headers, status precedence, Retry-After parsing, JSON validation,
  declared/incremental body limits and collection pagination protections.
- Read operation responses through `CanvasOperationResponse.chunk()` so decoding,
  timeout classification and cancellation remain attached. Do not bypass it via
  the underlying response or replace bounded accumulation with unbounded `bytes()`.
- Preserve validation of the persisted Canvas base URL, including rejection of
  non-root paths, query strings, fragments and credentials. Validating only the
  derived request origin is not equivalent. Retain DNS/private-origin checks,
  destination pinning, no-proxy/no-redirect behavior and verified TLS/SNI.
- Qualify the actual worker's configured CA trust and the operation transport's
  single-request HTTP/1 connections. Its gzip/deflate negotiation and decoded-body
  behavior are not an incidental codec-policy change; compressed responses and
  size/error handling need explicit checks. Decoder allocation before the consumer
  cap is not established to be bounded by this design.
- Preserve cancellation-by-drop and connection-driver cleanup, including after
  header/body stalls and the enclosing worker deadline. DNS resolution currently
  sits outside the operation timeout; this proposal does not claim to fix that
  boundary or establish complete DNS-timeout parity.

OAuth refresh/revocation, LTI grants and collections, and internal signing have
independent ownership and qualification requirements. Do not change those paths
as an incidental consequence of the REST repair. In particular, the source-derived
application AGS 15s requirement is separate from proving application REST parity;
existing trust checks and per-run token reuse must remain intact.

Required evidence includes the unchanged four-case worker replay, explicit
application/drift-versus-roster candidate scope tests, and the forthcoming
[whole-worker body-timeout capture plan](canvas-worker-body-timeout-capture-plan.md).
Progressing bodies must be allowed to exceed one total interval, while stalled
reads must fail at the applicable inactivity boundary. Existing transport-level
body fixtures support reuse but do not qualify worker durable effects. Retain the
exact mixed-roster Canvas/token/signer ledgers and the deadline replay's committed
prefix, current-lease, no-late-effect and cleanup gates. None of these proposed
steps authorizes consumer cutover or deployment.
