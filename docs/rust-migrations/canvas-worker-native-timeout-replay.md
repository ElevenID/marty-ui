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

The integrated executable compiled in 53.29s. Two new pure timeout controls and
all seven existing deadline timing/output tests passed; strict all-target Clippy
passed in 31.31s. The independent controller suite passed 68 tests. The full local
Python suite passed 1,760 tests with three explicit skips in 116.55s. These results
verify code and harness integrity, **not native timeout parity**.

The separate pushed baseline `f0b600730` has hosted release-test evidence of 1,694
passes and one existing skip, including both actual Linux coordinator/grandchild
cleanup cases. That baseline's larger worker parity CI is still in progress at
this checkpoint; neither it nor those containment tests qualify this new replay.

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
