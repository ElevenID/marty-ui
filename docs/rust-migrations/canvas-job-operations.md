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
- Nine configured schema tests pass locally (47.40s), as do 258 library tests
  (7.91s), all-target Clippy (25.35s) and 20 workflow/image tests (0.65s).
  Ruff, changed Rust formatting and diff checks pass. CI explicitly verifies registration
  of both new tests before running the configured schema executable. Hosted
  qualification remains required for this increment.

This is not exhaustive input or concurrency coverage. In particular, extend
published enqueue observations for malformed integration contexts, non-string
identifiers/Python string conversion (the existing shared conversion is not an
exact Python repr for compound JSON), Unicode stripping, missing/inactive
bindings, empty credential IDs where schema-permitted, and metadata variants.
Exact timestamp/wire equality and all interleavings with active workers remain
separate gates. Do not infer complete parity or authorize deletion from this
candidate's current passing cases.

Next implement manual dismiss/suspend/revoke through the shared credential
lifecycle and review-lock/audit owners, qualify recovery against credentials
#266's corrected official schema, and finish provider/whole-worker/all-consumer
gates. Then delete superseded Python, complete recordings/device acceptance,
and perform the aggregate beta-only deployment and governed soak. Production
must remain unchanged; beta217 evidence does not qualify this new candidate.
