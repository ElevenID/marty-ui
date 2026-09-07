# Canvas worker cutover readiness — 2026-09-07

Status: latest qualified composed checkpoint `6914387e563d1043948aaea7a5cc514be6055038`:
115 configured runtime tests passed in 2444.37s (CI34089906961,
runtime101641133956), with four configured worker/PostgreSQL entries in 95.63s.
The configured result is logged at `2026-09-07T07:01:57.0655556Z`; ignore the
earlier unconfigured 115-test result in 0.36s. All applicable exact-head checks
passed, including Rust CodeQL34089906881 and image101641134087 (nine preflight,
24 packaged startup and 16 logging-reference cases). Both native resource-race
markers (`platform_reconfigured`, `application_removed`) made one HTTPS request;
the post-validation resources-unavailable marker made zero. All five native
roster markers remain (0, 0, 1, 1, 1 requests), as does one-HTTPS recovery-first.

The preceding `5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19` roster checkpoint passed
109 configured tests in 2361.53s and four worker/PostgreSQL tests in 96.28s
(CI34085691302). Those historical results are retained, not substituted for
the current resource composition. Later local effect-expiry and mixed-roster
work is not qualified by the 115-entry head or by increased test registration.

The prior qualified checkpoint `c3e51a4d58083625aabd50de7fba37ef1ff53d4e` had
107 configured runtime tests passed in 2327.12s (CI34082559053, runtime101620519590).
All applicable exact-head checks passed, including Rust CodeQL34082559034. Image
job101620519633 passed nine preflight, 24 packaged startup and 16 logging-reference
cases. The separate configured PostgreSQL worker contract passed four entries in
96.94s. All 39 native
OAuth process/cycle markers were inspected: the prior33 plus six zero-request
secret-resolution cases. Real schema rejections, the native empty-token regression,
and both repository comparisons passed. Actual newer-target recovery also passed
with one HTTPS request and Rust's stronger complete-row generation preservation.
Both final-attempt repository race winners, actual completion-first process
atomicity and recovery-first process fencing now pass, including the exact
one-HTTPS-request native markers. Earlier
validation, privacy and startup boundaries remain retained. This qualifies those
scoped boundaries, including recovery-first and the LOG_LEVEL/image-default
repair, not whole-worker cutover.
Earlier worker gates
are retained. PR #814 remains draft and
unrouted. This is a source/test/consumer inventory, not a
whole-worker acceptance result. No deployment or Python deletion is authorized
by this inventory. The normative requirements remain
[`issuance-canvas-sync-worker.json`](../../contracts/issuance-canvas-sync-worker.json).

The [roster-failure extension](canvas-worker-roster-failures.md) adds five
published process captures and narrow Rust parity repairs, now qualified by the
109-entry Linux run and retained in the 115-entry composition. Four more
normative processor codes have actual-process evidence. The frozen HTTP 503
outcome is an additional generic worker error, not the
singular authoritative-read processor error or another normative processor code.

The subsequent [resource-race extension](canvas-worker-resource-races.md) freezes
two real published-worker outcomes: platform reconfiguration and application
removal during a held provider read. It adds a shared native replay and narrow
Rust error-classification repairs while retaining lease, row-lock and update
guards. Both cases now have actual native Linux process qualification at the
115-entry checkpoint; their two codes leave the remaining inventory on that
evidence, not on reference or repository tests alone.

The [resources-unavailable reference](canvas-worker-resources-unavailable.md)
captures the last previously unqualified composed outcome after completed
validation and before resource reload. Independent published regeneration and
the zero-request native process replay passed in the 115-entry run. The
seventeen-code inventory now has fourteen actual-process outcomes, one
controlled signing guard and two open typed-dispatch reconciliations. An empty
remaining-composed list does not close gate 9 or any broader effect/consumer gate.

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

The [validation/failure reference](canvas-worker-validation.md) captures twenty
actual published-worker cases with identical independent results. It covers
nine terminal codes (including five inactive variants), no Canvas reads and
preserved issued rows/token ciphertext. Native replay is implemented; focused
published-schema tests demonstrated and verified the shared Rust error-summary
correction. The two previously uncovered invalid-reference paths now have actual
published-process removal races, with matching independent captures and native
replay implemented through the shared database barrier. Four further cases cover
invalid requirements, missing LTI identity, unsupported candidate processing and
template removal after application read. Three roster-setting cases additionally
freeze job-local configuration errors and non-roster continuation; the native
binary's eager integer parsing has been replaced by deferred, lossless bounded
configuration in the shared processor. The twelve processor outcomes outside
this corpus are tracked separately. All twenty cases passed actual native Linux
replay at `f195ad484`, each with zero requests, including the three roster cases.
The latest cross-corpus accounting above supersedes that original partial
coverage: fourteen processor codes now have qualified process evidence. Gate 9
remains open for its two typed-dispatch reconciliations and broader requirements.

The existing PostgreSQL worker contract now also exercises the normative
no-signing guard through real `run_cycle` calls and durable repositories, using
the existing observed-worker owner with a controlled typed processor. All four
forbidden fields are checked independently with null, false, zero, empty string,
synthetic string, object and array values (28 failures), alongside two successful
controls. Assertions cover exact terminal code/static summary, attempt-one
dead-letter, empty persisted result, lease release, disabled target, no success
timestamp, successful sibling sanitization and no next-cycle retry. All three
configured PostgreSQL contract tests passed locally in 92.93 seconds; strict
all-target Clippy passed. The loopback-only tmpfs database was removed afterward.
The configured Linux PostgreSQL worker group subsequently passed all three
entries in 94.99 seconds at `f195ad484` (runtime job101550215184).
This is native boundary regression coverage, not published-process parity or
proof of signing-service effects/log privacy. No runtime or contract change was
needed for this guard; whole-worker gate 9 remains open.

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
Newer-target recovery after final-attempt crash is now implemented in the
[generation reference](canvas-worker-provider-generation.md), qualified at df3ed290b.
The subsequent final-attempt completion/recovery milestones are recorded below.

The [final completion/recovery repository boundary](canvas-worker-final-completion-race.md)
now executes both lock winners on the published schema with real expiry, observed
job/target locks and full-row preservation after every stale call. Local checks
pass; both directions are now qualified at 29bf8c226 in the 103-entry run above.
This alone does not close gate five.

The [actual completion-first process reference](canvas-worker-provider-completion.md)
now captures a terminal-write barrier, real expiry and the distinct reclaimer's
transitive lock chain. Independent regeneration agrees. The old process disables
the target despite one successful terminal job update; native replay explicitly
requires its stronger atomic completion behavior. The 103-entry extension is now
qualified on Linux at 29bf8c226. The [recovery-first process extension](canvas-worker-provider-recovery-first.md)
now has an actual capture and independent matching regeneration. Its native replay
requires fresh-clock rejection of stale completion while recovery owns the row,
one dead-letter terminal journal and preservation of valid pre-expiry provider
effects. This 107-entry extension is now qualified on Linux at c3e51a4d5, including
the actual one-request recovery_first marker. Expiry during
in-flight provider effects remains separate.

"Covered boundary" is deliberately narrower than "deletion gate closed".

| Gate | Inspected evidence | Remaining qualification |
| --- | --- | --- |
| 1. Environment parsing, bounds, malformed startup | 133 startup vectors and PostgreSQL consumer cycles; [LOG_LEVEL repair](canvas-worker-logging-configuration.md) has 16 frozen threshold cases and seven actual invalid-process checks. Combined runtime and image qualification passed at c3e51a4d5 | Execute remaining deployed entrypoint/configuration shapes, not only configuration factories; retain these gates in the new exact-head run. |
| 2. Legacy processor loader and removal | Python `test_canvas_worker_loader_oracle.py` exists; native binary constructs its processor directly | Remove the loader selection from all three consumer definitions only at qualified cutover; retain the frozen Python loader evidence. |
| 3. Loop stop, cancellation, recovery, disposal | Lifecycle, awaited-disposal and actual-process signal suites | Compose the actual processor/provider with the loop; prove active I/O cancellation, recovery and cleanup on the published schema. |
| 4. Renewal heartbeat and fence loss | `canvas_worker_renewal_oracle.rs`, 60 frozen renewal-job combinations, lease unit tests | Carry the same fences and outcome/error ordering through authoritative provider and business effects. |
| 5. Scheduler, reclaim, final-attempt crash races | Scheduler/reclaimer, newer-target recovery, both repository lock winners, completion-first atomicity and [recovery-first process fencing](canvas-worker-provider-recovery-first.md) qualified above; new [real-time effect transaction regression](canvas-worker-effect-expiry.md) passes locally with a positive control | Qualify the new repository regression in hosted CI and cover real provider I/O expiry separately. Controlled provider calls and process exit alone do not prove whole-worker disposal or parity. |
| 6. Missing target and unexpected-error privacy | Worker error mapping, result allowlist, durable repository assertions | Cross-language whole-cycle failure/log/state projections, including missing target and 429/non-429 provider outcomes. |
| 7. Safe-result types and truncation | `canvas_worker_result_oracle.rs`: 483 JSON field/value cases plus empty/full allowlists; database exact-number assertion | Preserve these cases through composed worker outcomes; do not claim every non-JSON Python host value from a JSON corpus. |
| 8. Retry-After edges | Seven actual native HTTPS/deadline cases and shared parser correction qualified at a6826de39 and retained at 29bf8c226; existing parser vectors remain | Retain date, malformed, negative, zero, clamp and huge-integer durable scheduling evidence in fresh exact-head CI. Full-worker acceptance remains separate. |
| 9. Target validation and processor failures | All nine validation codes have qualified actual-process outcomes. [Cross-corpus audit](canvas-worker-processor-coverage.md): fourteen processor codes have process evidence and one has a controlled-processor worker/PG guard | Two typed-dispatch reconciliations remain open; none of the seventeen codes is waived. Keep the no-signing guard; do not emulate Python imports or mistake an empty composed-code inventory for full worker/provider qualification. |
| 10. OAuth revocation failure and owner fences | 39 native process/cycle observations plus selection/order, schema-rejection and empty-token regressions qualified at df3ed290b | Retain the scoped [coverage audit](canvas-worker-oauth-revocation-coverage-audit.md) and stronger atomic cleanup in future exact-head runs. Repository selection and counting-provider regression are not whole-process HTTPS evidence. |
| 11. Cursor and terminal candidate preservation | Twelve-stage published/native direct-processor replay remains; new [seven-stage complete published-worker reference](canvas-worker-mixed-roster.md) captures twice-identical natural scheduling, one idle restart, resume/wrap, terminal preservation and mixed REST/AGS/NRPS behavior | Replay the frozen seven-stage corpus through a continuously running native worker and exact transport traces. The new published captures and fixture tests are not native process qualification. |
| 12. All four fact projections | Actual native worker, HTTPS, encrypted OAuth, official schema and durable effects match the independent assignment/quiz/module/course corpus at `6977a70ba` | Retain both complete corpora in fresh exact-head CI; other error, mutation and lifecycle requirements remain in their named gates. |
| 13. Bounded signing error detail | Credentials PR269 landed at protected `d418ac0`; landed PR271 freezes 45 helper and six remote-operation observations, with two identical captures | Compare actual Rust diagnostic selection, bounded detail and operation/status handling; capture alone is not native parity. |
| 14. Allowlisted worker logs | All twelve landed reference worker observations now pass native PostgreSQL replay locally, with typed unexpected-failure categories and known-error preservation controls | Qualify the complete worker-reference follow-up and remaining composed driver/provider failures; boundary coverage alone is not aggregate acceptance. |

Reference-side observations above were read from the clean local
`marty-credentials` checkout at `28b53d433031fe46b3f0c0c589d91f2c85d22c6e`.
That is a local source observation, not a new claim about protected main or the
immutable reference image. Check remote branch ownership and provenance before
changing reference source; preserve the other worker's unrelated work.

The scoped repair [Credentials PR269](https://github.com/ElevenID/marty-credentials/pull/269)
landed at protected `d418ac0df283625f43b0c011fb1c72fd7d3013a9` after review of
`9c03b57e5826b7dce430a05eef91ee68e334d825`. CI34058252789 passed, including
1673 tests and 200 subtests on each of Python 3.11 and 3.12, PostgreSQL, Rust,
bindings, security and WASM gates. Merge-queue CI34058846815 and protected-main
CI34059299079 passed. Exact tree comparison confirmed the landed content before
retiring only the completed branch name; source and evidence remain recoverable.
No immutable earlier oracle was changed.

[Credentials PR271](https://github.com/ElevenID/marty-credentials/pull/271) landed at
`948bca975b493285c512c20a13d5abf8ee5e6305`. It adds
the 63-case hardened reference without changing runtime source. Its existing
tests are the single observation owner; two independent captures agree at SHA256
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
Source trees, runtime blobs, test blobs and imported module locations are checked.
Maintainer-review additions bring local affected qualification to 741 tests and
200 subtests, followed by unchanged 63-case regeneration. Exact-head CI34061052204
and protected merge-queue CI34061438212 passed. Post-merge main CI34061898106
also passed. The completed capture branch name was retired only after exact
reviewed/merged tree comparison; source and evidence remain recoverable.

The [native privacy replay](canvas-worker-privacy.md) now compares twelve actual
worker/loop log-state observations through PostgreSQL, including ambient tracing
context. Failure-first tests identified swallowed OAuth queue-read errors and
missing stable event IDs. The disconnect-marker extension preserves real
encrypted-secret cleanup and another tenant's secret while restoring the exact
error event; cleanup behavior already matched. The final six cases use payload-free
unexpected processor categories and preserve known classified error behavior;
they verify all durable outcomes and complete producer/formatter log fields.
The corrections pass locally without removing the private SQL generation fence.
Signing diagnostic adoption and broader complete worker/driver behavior remain
separate gates; do not confuse those requirements with the now-empty remaining
composed processor-code inventory. Fresh exact-head hosted checks are required
for extensions beyond the qualified checkpoint above.

Native adoption must not hide source-inspection differences by changing that
artifact: the resolver currently omits diagnostic detail on non-success, while
the signer bounds raw text instead of sharing JSON-detail selection. Worker
error events also need explicit class/severity/event comparison; existing renewal
tests collect selected job/class fields, not the complete log allowlist. These
are inspection findings, not yet native replay failures. Coordinate signing
adapter ownership with the crypto worker before editing overlapping code; keep
Rust's stronger tenant-atomic OAuth cleanup and generation fences intact.

[Credentials issue270](https://github.com/ElevenID/marty-credentials/issues/270)
retains a separate release-qualification discrepancy. Exact checksum-verified
published Windows Core 0.1.60 and 0.1.61 wheels each pass 141 issuance tests but
fail the same three binding-boundary assertions that pass with the CI-built
Core revision. A simple release-pin bump is not sufficient. Require reviewed
canonical Rust release/artifact qualification before aggregate adoption;
neither the global installed package nor another worker's crypto branch changed.

## Deployment consumer inventory

| Consumer | Current source selection | Required cutover proof |
| --- | --- | --- |
| Base Compose | `docker-compose.base.yml`: immutable issuance image, `python -m issuance.canvas_worker`, `CANVAS_SYNC_PROCESSOR` | Native image/command, equivalent configuration and secrets, both migration dependencies, no ports, database heartbeat and restart behavior. |
| Beta overlay | `docker-compose.beta.yml`: only adds worker environment; inherits the base command/image | Render the exact aggregate beta composition and verify native selection; an environment-only overlay is not a cutover. |
| Self-host production definition | `docker-compose.selfhost.prod.yml`: shell secret loader followed by Python, with loader selection | Preserve file-secret and database-template handling, migration ordering and headless health semantics in source. Do not deploy to persistent self-host. |
| Self-host bundle override | `docker-compose.selfhost.bundle.override.yml` inherits the base issuance API, migrations and worker unchanged: immutable Python issuance image and their secret-loader definitions. The incompatible Rust-only-image/Python-command overrides were removed | Mandatory read-only Compose merge gate compares all three complete service models. At qualified cutover, render both image families and explicitly select the worker rather than the API while preserving the secret loader. Current inheritance is not Rust acceptance. |
| Kubernetes | `k8s/oracle/07-microservices.yaml`: Python command/args; `01-configmap.yaml`: loader selection | Native image provenance/command, ConfigMap cleanup, all secret inputs, migration job ordering and termination policy in rendered artifacts. Do not apply to production. |
| Shared Rust image | `services/Dockerfile` and `rust/services/Dockerfile.ci` contain the worker binary; the shared entrypoint now implements explicit worker selection | Qualify the [image launch gate](canvas-worker-image-entrypoint.md) and [24-case packaged startup gate](canvas-worker-image-startup.md), then remaining consumer configuration/secrets, headless health and migration ordering; startup alone does not prove active worker-cycle acceptance. |

Operational consumers must migrate with these definitions: the local beta release
and rollback runner (`scripts/deploy-local-beta-release.ps1`), beta capability and
OSS evidence checkers (`check_canvas_beta_capabilities.py`,
`check_canvas_oss_portability.py`), self-host preflight
(`check-selfhost-production.py`), deployment catalog and Kubernetes image-update
loop. They still rely on Python processor selection and/or issuance/worker image
identity. Preserve their digest, pilot, signer, timeout and key checks while
introducing reviewed runtime selection; changing manifests alone is insufficient.

The self-host bundle repair is source/render evidence, not an inspection of a
deployed release. `scripts/test_canvas_worker_compose_render.py` rejects the old
merged combination and passes the inherited definition, comparing all worker
fields, including secrets, URL template, migration dependencies, headless health
and restart policy. CI now runs this real read-only rendering check before image
builds. It disables interpolation, environment-file and path resolution; it does
not prove resolved secret values, image startup or the exact beta composition.

The follow-up API audit found the same mismatch: the bundle selected the shared
Rust-only image while retaining the API's Python Uvicorn command and OpenBao
startup wrapper. Removing only that image/selector override restores the base
immutable issuance image shared with `issuance-migrations`; it does not route
the unqualified native API. The expanded real Compose renderer failed before
this repair and passed afterward. All 48 focused deployment tests passed
locally, including mutation tests for both complete API/migration definitions.
This preserves existing functionality while API and worker cutover remain open.

The subsequent [shared-image audit](selfhost-bundle-image-audit-2026-09-07.md)
also found a packaging-only omission for `signing-keys`. The local repair selects
the existing shared image and `SERVICE_NAME=signing_keys`; the read-only merged
renderer now derives all seventeen converted services from base build targets
and compares their complete runtime definitions after the intended packaging
changes. The renderer failed on the omission and passed after repair. This is
source/render evidence, not deployed or exact-head hosted qualification, and
changes no cryptographic implementation. Coordinate any signing implementation
work with its existing crypto owner.

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

The [local-work inventory](post-wave3-local-work-inventory-2026-09-07.md) records
dirty dependency/wallet work, divergent branches, unregistered demo source and
equivalence candidates. Its cached-ref snapshots are preservation leads, not
authority to delete branches or evidence that all work is merged.
