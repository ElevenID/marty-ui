# Canvas worker cutover readiness — 2026-09-06

Status: latest qualified composed checkpoint `a6826de39d2d34a6163a11e78761353191337815`,
including eight image-preflight cases, 24 packaged startup/configuration cases
and 67 configured runtime tests (CI34051487770 and Rust CodeQL34051487785).
All seven actual native Retry-After cases passed; the newer validation replay
still awaits its own Linux qualification. PR #814 draft and
unrouted. This is a source/test/consumer inventory, not a
whole-worker acceptance result. No deployment or Python deletion is authorized
by this inventory. The normative requirements remain
[`issuance-canvas-sync-worker.json`](../../contracts/issuance-canvas-sync-worker.json).

## What the latest evidence does and does not prove

The JSON-depth implementation passed all 36 configured published-image/schema
tests locally, plus 325 library, 5 binary, 34 managed HTTP, 22 issuance behavior,
102 affected Python and 104 native TLS cases. Native depth replay covers 64
provider, 64 validation and 192 credential-route observations, with 32 additional
follow-up operations. These qualify their recorded boundaries, not worker boot,
complete provider combinations, deployment consumers or runtime acceptance.

The source inspection exposes a composition gap between existing suites:

- `tests/support/canvas_published_processor.rs` uses the real published schema,
  repositories and native processor, but controls `CanvasAuthoritativeProvider`.
  Its helper leases and validates a job and calls the processor and outcome
  repository directly; it does not call `CanvasSyncWorker::run_cycle`.
- `tests/support/canvas_worker_lifecycle_oracle.rs` and
  `canvas_worker_renewal_job_outcomes.rs` execute real worker cycles and durable
  outcomes, but use controlled processors and the worker test schema.
- `tests/support/canvas_authoritative_http.rs` and
  `canvas_authoritative_https.rs` exercise real provider transport, but reuse
  in-memory OAuth repositories and synthetic signing fixtures.
- `tests/support/canvas_worker_process_signals.rs` launches the actual binary
  with PostgreSQL. Its idle/blocked-queue cases do not establish active
  authoritative-provider shutdown or host-crash recovery.

None of these tests should be discarded or recaptured merely to obtain a
whole-worker pass. Reuse their owners and add the missing composed execution.

The [composed REST reference](canvas-worker-rest-reference.md) now independently
executes four nonempty published worker processes with real HTTPS, encrypted
OAuth storage and the official schema. Positive, negative, duplicate and
rate-limited outcomes are frozen twice. Native composed-worker replay is now
implemented using the real binary and native persistence; its mandatory Linux
execution passed at `0982a4a2c` (CI 34033818678, Rust 34033818668). That qualifies the
four assignment stages, not every worker/provider/consumer boundary.

The [all-four-fact reference](canvas-worker-facts-reference.md) extends the same
actual published-process harness across assignment, quiz, module and course
reads, including partial rate limiting. Two independent captures agree; native
adoption passed on Linux at `6977a70ba` (CI 34034992317, Rust 34034992376).
That qualifies these four fact projections for gate 12; broader worker/consumer
requirements and fresh exact-head checks for later extensions remain required.

## Normative legacy-gap reconciliation

The [target-validation reference](canvas-worker-validation.md) captures eleven
actual published-worker cases with identical independent results. It covers
seven terminal codes (including five inactive variants), no Canvas reads and
preserved issued rows/token ciphertext. Native replay is implemented; focused
published-schema tests demonstrated and verified the shared Rust error-summary
correction for all eleven cases. Full Linux qualification and two explicitly
uncovered application/candidate-invalid paths remain pending; gate 9 is open.

The [Retry-After deadline reference](canvas-worker-retry-after.md) freezes seven
actual published-worker scheduling cases, including HTTP dates and oversized
integer clamping. Two captures agree; native replay is implemented. Focused Rust
tests confirmed overflow fallback and the shared lossless parser correction
passes local tests, including actual HTTP provider transport. Correction
`a6826de39` passed all 67 configured Linux tests in 1264.77 seconds, including
all seven actual native HTTPS/deadline cases (runtime job101535819282).
Image job101535819407 passed eight preflight and 24 startup cases; CI34051487770
and Rust CodeQL34051487785 succeeded. This qualifies the frozen scheduling
boundary, not remote OAuth, every header grammar or the whole-worker cutover.

The [retry/rejection reference](canvas-worker-retry-reference.md) adds actual
same-job retry eligibility, recovery and provider failure/OAuth rejection
observations for gates 6/8. Native adoption passed Linux CI at `32ec09029`
(CI34036161060, Rust34036161086), including five actual native HTTPS stages;
remote OAuth revocation,
all error/header variants and race/privacy requirements remain separate gates.

The [active-provider signal reference](canvas-worker-provider-signals.md) now
independently captures SIGINT/SIGTERM/SIGKILL with the real HTTPS response held.
Native SIGINT, graceful SIGTERM and SIGKILL passed configured Linux CI at
`499298659` (CI34038852781, Rust34038852821). Renewal and nonfinal crash/restart
qualification are recorded below; disposal remains open and cannot be inferred
from raw process exit.

The [provider renewal/recovery reference](canvas-worker-provider-recovery.md)
independently records actual lease/heartbeat renewal, then success or forced
process loss followed by real expiry/retry and same-job completion. Two capture
pairs agree and regeneration passes locally. Native replay passed at `d96a45ebe`
(CI34039828427, Rust34039828424; 52 configured tests in 839.16 seconds). Final-attempt recovery,
concurrent scheduler/reclaimer and ownership/generation fences remain separate.

The [concurrent scheduler reference](canvas-worker-concurrent.md) now has two
matching captures. PostgreSQL observes two actual worker scheduler queries
blocked at the owned fixture barrier; after release, one job/request succeeds
while both processes remain alive. Native replay passed at `a329b980e`
(CI34042598584, Rust34042598554; 59 configured tests in 948.70 seconds).
Other reclaimer/changed-target races remain separate; this does not close all of gate 5.

Numbers below preserve the order of all 14 `migration_gates.legacy_oracle_gaps`.
The [retryable two-reclaimer reference](canvas-worker-reclaimers-retry.md) has two
matching captures: both workers reach fresh idle with one durable retry and no
early read, then real eligibility permits same-job attempt-two success with the
target enabled. Native replay passed at `507b0def6` (CI34045421238,
Rust34045421228): 65 configured tests in 1182.10 seconds, with two actual provider
requests for this case. Remaining race requirements stay open.

The [two-reclaimer reference](canvas-worker-reclaimers.md) has two matching
captures after actual final-attempt renewal, process loss and real lease expiry.
Both actual job queries wait at an owned job-table barrier before release; both
workers then reach fresh idle with one dead-letter and no further provider read.
Native adoption passed at `54692c4e4` (CI34043971766, Rust34043971750), including
all 62 configured tests in 1038.42 seconds and the actual one-request reclaimer
case with both fresh idle heartbeat assertions. Other ownership,
nonfinal-reclaimer and final-completion races remain open.

The [final-attempt crash reference](canvas-worker-provider-final.md) now has two
matching independent captures and a mandatory regeneration gate. It seeds
historical attempts before worker startup, then observes actual attempt-eight
renewal, crash, real expiry and dead-letter/target-disable without another read.
Native final-attempt replay passed with exact generation-fence checks at
`e959e113d` (CI34041341592, Rust34041341506; 56 configured tests in 841.38 seconds).
Final-attempt and retryable concurrent reclaimers are qualified above;
changed-generation races remain open.

"Covered boundary" is deliberately narrower than "deletion gate closed".

| Gate | Inspected evidence | Remaining qualification |
| --- | --- | --- |
| 1. Environment parsing, bounds, malformed startup | `canvas_sync_worker_configuration_oracle.rs`: 133 startup vectors; `canvas_worker_range_oracle.rs`: PostgreSQL consumer cycles | Execute deployed entrypoint/configuration shapes, not only the configuration factory. |
| 2. Legacy processor loader and removal | Python `test_canvas_worker_loader_oracle.py` exists; native binary constructs its processor directly | Remove the loader selection from all three consumer definitions only at qualified cutover; retain the frozen Python loader evidence. |
| 3. Loop stop, cancellation, recovery, disposal | Lifecycle, awaited-disposal and actual-process signal suites | Compose the actual processor/provider with the loop; prove active I/O cancellation, recovery and cleanup on the published schema. |
| 4. Renewal heartbeat and fence loss | `canvas_worker_renewal_oracle.rs`, 60 frozen renewal-job combinations, lease unit tests | Carry the same fences and outcome/error ordering through authoritative provider and business effects. |
| 5. Scheduler, reclaim, final-attempt crash races | `canvas_sync_worker_postgres_contract.rs` exercises scheduler conflicts, recovery and generation CAS | Qualify published-schema whole-worker concurrency and crash/restart; process exit alone does not prove disposal. |
| 6. Missing target and unexpected-error privacy | Worker error mapping, result allowlist, durable repository assertions | Cross-language whole-cycle failure/log/state projections, including missing target and 429/non-429 provider outcomes. |
| 7. Safe-result types and truncation | `canvas_worker_result_oracle.rs`: 483 JSON field/value cases plus empty/full allowlists; database exact-number assertion | Preserve these cases through composed worker outcomes; do not claim every non-JSON Python host value from a JSON corpus. |
| 8. Retry-After edges | Frozen worker vectors and `canvas_sync_worker_behavior.rs`; provider-specific transport corpora | Verify durable retry scheduling for the actual worker/provider path, including date, malformed, negative and clamp behavior. |
| 9. Target validation and processor failures | Repository validation, native typed processor, issued-review/mixed-roster and job-authorization tests | Map every frozen validation code to composed-worker outcomes; cover processor failure/no-signing behavior without emulating Python imports. |
| 10. OAuth revocation failure and owner fences | OAuth behavior and PostgreSQL tests cover refresh/revocation, due selection and tenant-atomic cleanup | Whole-worker remote revocation rate-limit/timeout, Retry-After, patch failure and owner-fence-loss matrix; explicitly retain Rust's stronger atomic cleanup. |
| 11. Cursor and terminal candidate preservation | Twelve-stage published/native mixed-roster replay retains cursor, observations, claimed/dismissed states | Execute those transitions through complete worker cycles and real provider adapters, including resume/wrap. |
| 12. All four fact projections | Actual native worker, HTTPS, encrypted OAuth, official schema and durable effects match the independent assignment/quiz/module/course corpus at `6977a70ba` | Retain both complete corpora in fresh exact-head CI; other error, mutation and lifecycle requirements remain in their named gates. |
| 13. Bounded signing error detail | Normative contract requires reference-side hardening; current local Credentials `signing_context.py` bounds text only | Reconcile and land bounded JSON string/object detail plus reference tests before sharing the privacy fixture as parity evidence. |
| 14. Allowlisted worker logs | Normative contract requires reference-side hardening; current local Credentials worker still contains `logger.exception` | Reconcile and land allowlisted logging plus synthetic redaction evidence before declaring this gate closed. |

Reference-side observations above were read from the clean local
`marty-credentials` checkout at `28b53d433031fe46b3f0c0c589d91f2c85d22c6e`.
That is a local source observation, not a new claim about protected main or the
immutable reference image. Check remote branch ownership and provenance before
changing reference source; preserve the other worker's unrelated work.

## Deployment consumer inventory

| Consumer | Current source selection | Required cutover proof |
| --- | --- | --- |
| Base Compose | `docker-compose.base.yml`: immutable issuance image, `python -m issuance.canvas_worker`, `CANVAS_SYNC_PROCESSOR` | Native image/command, equivalent configuration and secrets, both migration dependencies, no ports, database heartbeat and restart behavior. |
| Beta overlay | `docker-compose.beta.yml`: only adds worker environment; inherits the base command/image | Render the exact aggregate beta composition and verify native selection; an environment-only overlay is not a cutover. |
| Self-host production definition | `docker-compose.selfhost.prod.yml`: shell secret loader followed by Python, with loader selection | Preserve file-secret and database-template handling, migration ordering and headless health semantics in source. Do not deploy to persistent self-host. |
| Kubernetes | `k8s/oracle/07-microservices.yaml`: Python command/args; `01-configmap.yaml`: loader selection | Native image provenance/command, ConfigMap cleanup, all secret inputs, migration job ordering and termination policy in rendered artifacts. Do not apply to production. |
| Shared Rust image | `services/Dockerfile` and `rust/services/Dockerfile.ci` contain the worker binary; the shared entrypoint now implements explicit worker selection | Qualify the [image launch gate](canvas-worker-image-entrypoint.md) and [24-case packaged startup gate](canvas-worker-image-startup.md), then remaining consumer configuration/secrets, headless health and migration ordering; startup alone does not prove active worker-cycle acceptance. |

The initial local debug-binary diagnostic confirmed a startup obstacle: with
rollout disabled, synthetic keys, no LTI identity and an unavailable loopback
database, the process exits 1 with
`CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID is required`. Both `postgresql://` and
the deployed `postgresql+asyncpg://` URL reach that same error, so the latter
must not be reported as a reproduced URL-parser rejection. These owned children
had cleared environments and no deployment credentials; both exited normally
before the five-second diagnostic deadline. No database cycle was established.

The subsequent [actual-process startup gate](canvas-worker-startup.md) captures
eight independent published observations twice and reproduces the native early
exit before correction. The canonical signer now retains its deferred validation,
and all eight native processes reach matching idle heartbeats on the published
schema, including both deployed URL forms. The shared test-child helper preserves
Windows's standard OS path without inheriting application credentials. Linux CI
also checks SIGINT; Windows is not POSIX evidence. Actual provider/signing and
complete deployed entrypoint/secret-source behavior remain separate gates.

## Next implementation order

1. Retain the qualified eight-case startup/idle boundary; its exact-head hosted
   CI and security checks passed. Broader secret-source/entrypoint configurations remain consumer gates;
   do not repeat the repaired LTI-identity requirement as an open runtime bug.
2. Retain the qualified REST/facts/retry/signal/renewal and nonfinal recovery
   sequences on the pinned migrations with real native provider/OAuth adapters.
   Retain final-attempt, concurrent scheduler, two-final-reclaimer and retryable
   two-reclaimer qualification, then extend
   the same harness across the remaining crash-reclaimer, mutation, OAuth,
   failure and cleanup requirements above. Do not repeat completed boundaries
   as though their native adoption were still missing.
3. Close the two explicit reference privacy requirements without changing frozen
   expectations to conceal implementation differences. Keep improvements scoped
   and coordinate reference-source ownership before protected landing.
4. Qualify whole readiness/activation and all eight candidate operation routes,
   then switch every intended consumer with executable packaging/configuration
   gates. Require fresh exact-head CI and maintainer review before merging.
5. Satisfy the normative deletion/acceptance ordering, remove only genuinely
   superseded reachable Python, and retain rollback/schema evidence.

The full goal also retains the broader issuance inventory, feature-preserving
branch/worktree cleanup, CSCA lifecycle-manager/monitor follow-up, all demo and
device/wallet evidence, release-pin reconciliation, and aggregate beta-only
acceptance/soak. Production and persistent self-host remain unchanged.
