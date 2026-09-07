# Legacy dispatch and native typed-boundary reconciliation

The two open processor inventory codes cover **three** legacy failure paths,
not two missing Rust business features. The unchanged
[normative contract](../../contracts/issuance-canvas-sync-worker.json) explicitly
allows direct native linking instead of Python imports, but still retains the
failure outcomes and requires loader removal from every consumer at cutover.

| Published dispatch path | Durable contract | Native boundary |
| --- | --- | --- |
| No selected or registered processor | `canvas_sync_processor_unavailable`, retryable | The executable supplies a non-optional `Arc<dyn CanvasSyncProcessor>` built from `NativeCanvasSyncProcessor`. |
| Callable returns a non-awaitable result | `canvas_sync_processor_contract_invalid`, terminal; asynchronous-required summary | The trait requires a future with the declared result type. |
| Awaited result is not a mapping | Same terminal code; invalid-result summary | `CanvasSyncResult` is a `BTreeMap<String, Box<RawValue>>`, not an arbitrary JSON root. |

Source review at UI `8e7f66d46a69cfb21b92e3b989b762485519604e` found direct
construction in `rust/services/issuance/src/bin/canvas_sync_worker.rs:171`, the
required processor in `canvas_sync_worker.rs:556`, its asynchronous typed trait
at line 435 and result type at line 447. The built-in implementation reports
configured at `canvas_sync_processor.rs:741`. The public trait's `configured()`
flag is diagnostic/heartbeat metadata, not an absent-processor dispatch guard;
do not claim a false flag currently causes a missing-processor retry.

The retained Credentials loader oracle
(`tests/unit/test_canvas_worker_loader_oracle.py`, landed through PR #255)
checks empty/malformed selection, importer failures, literal attributes and
callable identity without invoking selected hooks. It therefore does not itself
prove these three durable dispatch outcomes. The actual published dispatch
function is `issuance.application.canvas_sync_service.process_canvas_sync_target`;
the missing, non-awaitable and non-mapping branches are separately observable.

## New controlled-hook worker corpus

[`canvas-worker-dispatch-scenarios.json`](../../contracts/canvas-worker-dispatch-scenarios.json)
defines those three paths plus a valid asynchronous mapping and a rollout-closed
missing-processor control. `scripts/run_canvas_worker_dispatch_oracle.py` runs
the unchanged published `python -m issuance.canvas_worker` on each fresh official
schema. The small `canvas_worker_dispatch_hooks.py` module is selected through
the existing legacy loader; it changes no application source, importer, worker
registration, database behavior or runtime clock.

The shared seed preserves issued credentials, transactions and encrypted OAuth.
One valid target and queued job are prepared before startup. The existing
60-second poll interval permits observation and idle interruption after the
first real cycle, without changing retries or scheduler timestamps. A loopback
HTTPS tripwire must receive zero requests, including through joined fixture
shutdown. This is actual worker/dispatch/PostgreSQL behavior with **controlled
hooks**, not actual-provider or cryptographic signing qualification.

Assertions retain exact code, distinct summary, result, attempt count, exhausted
terminal budget, retry scheduling, idle heartbeat and OAuth non-use. The first
capture exposed a fixture expectation error: the published forced-terminal path
sets `max_attempts=max(1,attempt_count)`, so these terminal cases require exactly
one while retry/success cases retain eight. This was independently confirmed in
the pinned image and the earlier frozen validation corpus; no observed behavior
or implementation was changed to repair the assertion.

Before/after idle SIGINT comparisons retain raw job and target rows, complete
state projections, issued rows and ciphertext. Operational-result sentinel
absence is checked in raw persisted job/target/state, not only a sanitized
projection. Captures record canonical-LF source hashes for the original worker,
route module, dispatch module and explicit synthetic hook. Raw secret material
and unpredictable timestamps/ciphertext are compared locally, never published.

## Qualification boundary

Two independent five-case actual published-worker captures passed in 23.82s and
23.17s. Their raw 8,774-character JSON results were byte-identical and were frozen
directly in
[`canvas-worker-dispatch-oracle.json`](../../contracts/canvas-worker-dispatch-oracle.json),
without an intermediate numeric rewrite. The permanent
`worker_dispatch_reference_matches_published_process` gate passed a third fresh
configured run in 25.13s. The frozen file SHA256 is
`29ec41961a6212536ccc4d1a28eadacd41d5f1694fe0658d580136e1b65d25cc`.
Exact-head hosted Linux qualification remains separate.

The separate compiler-positive/negative suite passed five doctests in 1.96s,
proving native construction, asynchronous and mapping constraints. It does not
claim that Python loader failures execute inside Rust. Registration now totals
120 entries; that is not 120 qualified runtime passes. The two codes remain in
the seventeen-code inventory while evidence and consumer reconciliation are reviewed.
The complete local Python suite passed 1,234 tests with one existing skip in
58.14s; strict all-target Clippy and explicit changed-file Rust formatting passed.

Existing Compose, self-host and Kubernetes consumers still select the Python
worker and retain `CANVAS_SYNC_PROCESSOR`. Remove those selections only with the
qualified native consumer cutover and update their configuration validators at
the same boundary. Do not emulate dynamic imports, weaken typed result handling,
delete the Python oracle, change crypto-owner code, or infer whole-worker/beta
acceptance from these scoped dispatch and compiler proofs.
