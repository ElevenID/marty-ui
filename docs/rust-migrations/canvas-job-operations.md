# Native Canvas job operations (candidate, not routed)

The existing issuance candidate router now implements application enqueue,
dead-letter retry and dead-letter resolution, alongside the four read APIs.
Manual correction-review resolution remains unimplemented. Live issuance,
gateway and deployment consumers are unchanged; all eight operations remain
available through Python until the whole operations/worker cutover is qualified.

## Shared implementation and preserved behavior

Enqueue reuses `PostgresCanvasLtiBootstrapSyncEnqueuer`, extending its shared
transaction to return canonical target/job IDs while preserving both existing
LTI trait APIs. Operations look up the tenant application before checking rollout;
the LTI wrapper retains its existing rollout-first order. Existing active jobs
are reused and issued/learner schedules remain 21600/900 seconds.

Retry performs a tenant-scoped dead-letter compare-and-set and target re-enable
in one transaction. Attempts/max attempts reset to 0/8, result and error fields
clear, and `started_at` is deliberately retained. Resolution compare-and-sets
dead-letter to cancelled, updates completion time, and does not restart or
otherwise modify the target. Resolution remains available with rollout disabled.
Responses use the existing explicit public job projection and sanitized errors.

Review found that the existing enqueue SQL concatenated non-object metadata
into a JSON array, unlike Python's object fallback. A regression first failed
with `[1,2,{"last_requested_from":"application_sync_api"}]`; the shared SQL now
retains object metadata only, then merges the request marker. This correction
applies to operations and both LTI callers without a duplicate enqueue owner.

## Evidence and limits

- The original 46-case published Python HTTP/database golden is unchanged.
  A new replay executes its 25 reads and 10 job-write cases, comparing HTTP
  status/content type/full normalized response and selected job/target state.
  Generated UUID identities retain consistent aliases across responses/state.
- The 11 manual-review cases are explicitly excluded, not silently claimed as
  passing. Job calls must leave initial review/audit state and complete credential/
  transaction rows unchanged. The oracle's later manual-review state is not
  rewritten or used to imply manual lifecycle parity.
- Supplementary native tests use the official disposable PostgreSQL schema:
  competing retries/resolutions yield one winner, competing issued/learner
  enqueues return canonical IDs, target-update failure rolls back retry, and
  job-insert failure rolls back a new target. Both existing LTI interfaces,
  full retry field resets, stopped-target preservation, tenant hiding and
  validation precedence are exercised. These are native invariants, not a new
  published differential corpus.
- A supplementary published capture freezes 28 actual enqueue HTTP/database
  cases and 23 direct identifier conversions before correcting Rust. Two
  independent captures agree. Malformed contexts, missing/empty auth headers,
  tenant/rollout precedence, inactive bindings/platforms, metadata shapes,
  learner scheduling and ignored malformed/empty bodies are covered. Native
  replay compares full normalized HTTP responses, target/job projections and
  unchanged full credential/transaction rows. New golden blob:
  `082a0996d4d33c8dc01012e6da725d81e7212d3c`.
- Negative controls found decimal/exponent conversion (`0.00001` versus Python
  `1e-05`) and control-whitespace-padded IDs (native404 versus Python202).
  The shared Rust value formatter now preserves Python compound repr, nested
  booleans/nulls, quote escaping and number display. Canonical JSON delegates
  number display to the same owner. Enqueue uses its Python whitespace trim.
  The existing LTI helper exports remain intact, avoiding separate conversions.
- `python-text-semantics.json` freezes all printable codepoint ranges and
  whitespace from the published Python Unicode15.0 runtime, independently
  repeated before the fix. Its711 sorted ranges are compiled into Rust and
  loaded once; no runtime Python or new dependency is added. The published
  gate compares the complete table on every run, detecting image-version drift.
  These data rows are a compatibility contract, not additional service logic.
- Ten configured schema tests pass locally (67.27s), as do 260 library tests
  (9.03s), all-target Clippy (38.35s), 51 existing candidate/LTI behavior tests,
  and 20 workflow/image tests (0.82s).
  Ruff, changed Rust formatting and diff checks pass. CI explicitly verifies registration
  of all three new tests before running the configured schema executable. Hosted
  qualification remains required for this increment.

This is not exhaustive input or concurrency coverage. Mismatched bindings,
empty credential IDs where schema-permitted, very-large JSON numbers, arbitrary
compound identifiers used as actual database keys, and all malformed JSON
string representations remain part of broader qualification. The 23 direct
identifier cases do not prove every possible numeric or string representation.
Exact timestamp/wire equality and all interleavings with active workers remain
separate gates. Do not infer complete parity or authorize deletion from this
candidate's current passing cases.

Next implement manual dismiss/suspend/revoke through the shared credential
lifecycle and review-lock/audit owners, qualify recovery against credentials
#266's corrected official schema, and finish provider/whole-worker/all-consumer
gates. Then delete superseded Python, complete recordings/device acceptance,
and perform the aggregate beta-only deployment and governed soak. Production
must remain unchanged; beta217 evidence does not qualify this new candidate.
