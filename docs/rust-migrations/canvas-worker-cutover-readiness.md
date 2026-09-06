# Canvas worker cutover readiness — 2026-09-06

Status: candidate implementation at `185af81d59e99982d1bdb9d20b2dacf76ca267db`,
PR #814 draft and unrouted. This is a source/test/consumer inventory, not a
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

## Normative legacy-gap reconciliation

Numbers below preserve the order of all 14 `migration_gates.legacy_oracle_gaps`.
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
| 12. All four fact projections | Published-schema processor replay plus real REST transport tests for assignment, quiz, module and course | Join actual worker, HTTP provider, OAuth storage, fact/policy transaction and durable job effects in one differential. |
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
| Shared Rust image | `services/Dockerfile.ci` contains the worker binary; `services/entrypoint.sh` has no worker service dispatch | Choose and test one explicit worker launch contract; copying a binary does not prove the consumer starts it. |

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

1. Retain the qualified eight-case startup/idle boundary and finish fresh hosted
   checks. Broader secret-source/entrypoint configurations remain consumer gates;
   do not repeat the repaired LTI-identity requirement as an open runtime bug.
2. Add a composed worker-cycle gate on the pinned published migrations using
   real native provider/OAuth adapters and bounded synthetic provider servers.
   Begin with a real REST job through scheduling, leasing, fact/policy effects,
   result persistence and heartbeat; extend the same harness across the named
   failure, mutation, OAuth and active-shutdown requirements above.
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
