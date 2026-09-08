# Native worker timeout replay

Status: implemented and locally tested on `feat/canvas-worker-timeout-replay-v1`,
based on `f0b60073093a89567e43a6fd6452100b2ddc67ec`. Actual native Linux execution
is still required. No runtime timeout policy, published fixture, frozen outcome,
live job, lease, clock, production consumer or deployment was changed.

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

## Local checks and required next evidence

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
timeout replay has still not run.

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

Current source predicts a failing `application_delayed_headers` replay: native
authoritative and roster calls both use a 20s total-request timeout, so the
application is expected to accept the 17s response instead of the published 15s
timeout. This is **a prediction, not an observed native failure**. Run the actual
replay before changing runtime policy. After observing the mismatch, reuse the
existing `CanvasOperationHttpClient` / `CanvasNetworkTimeout` ownership and assess
the narrow application-read path. A blanket 20s-to-15s change loses roster behavior;
changing only a total-request deadline does not prove HTTPX phase/inactivity parity.

Pagination, progressing/stalled bodies, token refresh, AGS, revocation, candidate
issuance, signing, whole-worker cutover, UI/demo acceptance and aggregate beta
deployment remain separately gated work.

## Reviewed repair constraints: design only

The following is a source-reviewed design, not an implemented runtime repair or
qualified parity result. Observe the actual native delayed-header failure before
changing policy; do not alter the frozen reference to accommodate native behavior.
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
