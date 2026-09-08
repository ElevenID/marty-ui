# Canvas worker consumer audit — 2026-09-07

This is a tracked-source audit of the owned `marty-ui` worktree, observed at
`5aa086a1ed20d1990453c434b17cd6b9bb9e3ded`. It supplements the
[readiness inventory](canvas-worker-cutover-readiness.md#deployment-consumer-inventory),
not its qualification results. No environment files, deployed containers or
remote services were inspected; no Compose configuration was applied, and no
consumer selection changed. Risks below are source-derived future-cutover risks,
not claims that current production or beta is broken.

## Missing or underspecified inventory entries

### Generated release image follow-up (2026-09-08)

The generated-overlay gap is now implemented using one pure image plan shared
by the actual runner's overlay rendering, 17 local builds and 19-service image
evidence. Independent review found a mutable-tag provenance race: local
verification could record a newly retagged image instead of the image pinned
before rehearsal. The final plan now retains that original immutable image ID
for the last verification overlay and evidence; other selection is unchanged.

Validation passed 76 focused Python/PowerShell tests and five actual Compose
5.4.0 comparisons: three complete tracked-source models (local, pinned local,
official) and two synthetic image-variable binding models, each with 19
application services. Real secret expressions are not interpolated. Tests check
the actual runner's generation/build/pin/rehearsal/evidence wiring, preservation
of all non-selection fields, and a tag-moving-after-rehearsal negative control.
The generated configuration gate is mandatory before image builds in CI; the
existing 15 consumer and 24 rollback cases remain intact. These are configuration
checks, not a deployment, live rollback or native worker selection qualification.
The complete local repository suite subsequently passed 2,693 Python tests with
three explicit skips in 202.24s; an independent repeat of the five config-model
comparisons passed in 1.77s.

### Reconciliation at `ce19e030c` (2026-09-08)

The original findings below are retained as historical evidence. A parallel
read-only re-audit now confirms the following current implementation boundaries:

- The static renderer now covers all 15 inherited conformance/catalog/beta
  compositions, in addition to its self-host checks. The earlier two-composition
  limitation is repaired. Generated release/image overlays remain explicitly
  outside that matrix: add full effective-model checks for both official and
  local beta release modes before changing their worker artifact association.
- Versioned worker-only rollback capture, validation and rendering are
  implemented, as recorded in the follow-up below. The remaining launch gap is
  narrower: the exact self-host secret-loader shell accepts Python, but not yet
  the equivalent native executable form. Qualify that exact form without
  accepting arbitrary shell text or dropping the retained Python rollback path.
  This exact native form is now implemented at `e93a419a5`: 84 executable
  PowerShell tests and 24 actual Compose 5.4.0 full-model merges passed, retaining
  all prior 21 merges. Independent review passed. The complete repository Python
  suite passed 2,662 tests with three explicit skips in 191.74s. These prove
  rollback contract/configuration support, not live restore or worker cutover.
- The three independent Python launch definitions are still base Compose,
  self-host Compose and Kubernetes. Consumer switching must also update their
  inherited compositions, generated artifact/provenance mapping, operational
  validators and configuration tests together. No command or selector has been
  changed by this audit.
- Kubernetes currently supplies the worker's database, integration master key
  and signing API key. Unlike the retained Python Compose definitions, its
  manifest, secret template and deployment secret creation omit `TOKEN_HMAC_KEY`.
  The deployment test currently pins that three-secret set. The Python repository
  requires `TOKEN_HMAC_KEY` or its file at import; the native worker does not read
  it and has the configured signing/API-key fallback. Treat this as a retained
  Python/rollback source-wiring gap to verify and repair, not a proven native
  startup failure or evidence of deployed production state. Reconcile the same
  secret across issuance/worker rather than inventing an independent value.
- The eight operations routes below remain a separate live-consumer cutover.
  Preserve all UI actions, authorization, tenant hiding, public exports and
  lifecycle effects. Worker selection cannot authorize deleting their Python
  gateway fallback.

For the eventual qualified cutover, preserve the full worker environment,
secret-loader-before-exec ordering and URL expansion, both completed migration
dependencies, headless health/database heartbeat, isolation and resources,
30-second Kubernetes termination behavior, both rollback selectors and immutable
artifact provenance. Keep the five frozen published dispatch observations and
native compiler tests; remove active import selectors rather than emulating
dynamic Python imports. A typed processor's heartbeat flag does not replace a
missing-processor branch. None of this authorizes deployment before worker gates.

| Inventory delta | Tracked evidence | Required future gate |
| --- | --- | --- |
| **Missing: isolated conformance worker consumer.** | [Conformance overlay](../../docker-compose.profile.conformance.yml#L124) changes only `canvas-sync-worker.container_name` to `!reset null`. It inherits the base Python image, command, environment, migration dependencies and headless health configuration. [Conformance runner](../../scripts/conformance_stack.py#L19) composes base + OIDF, a GHCR/immutable-infrastructure or local-build variant, optional HAIP/DIDComm overlays, and isolation last. Its `up` branches start the composed stack, not merely an API-only subset. | Render both runner image modes and the optional profile combinations without resolving real secrets. Compare the entire worker model except the intentional project-name reset. Retain isolated networks/volumes, no worker host ports, both completed-migration dependencies and database-heartbeat health. A conformance overlay is not a fourth independent Python command definition. |
| **Underspecified: inherited catalog beta/demo variants.** | [Service catalog](../../deploy-config/catalog/services.json#L13) places the worker in `app`; [tunnel-beta-dev](../../deploy-config/stacks/tunnel-beta-dev.json), [tunnel-beta-experiments](../../deploy-config/stacks/tunnel-beta-experiments.json) and [tunnel-beta-d11](../../deploy-config/stacks/tunnel-beta-d11.json) all require that group and inherit base Compose. The latter variants add the real Canvas, sandbox and partner-demo profiles. [Self-host tunnel](../../deploy-config/stacks/selfhost-beta-tunnel.json) shares the self-host definition but its explicit `up` operation starts only the two tunnel services. | Derive consumer inclusion from the catalog/group graph and test each effective composition. Do not infer that a tunnel-only operation starts a worker, or that rendering the standalone beta overlay covers every demo/catalog stack. Preserve the demo profile additions. |
| **Underspecified: generated release overlay and image evidence.** | [Beta release runner](../../scripts/deploy-local-beta-release.ps1#L54) uses seven tracked Compose files, then generates another image overlay. It excludes issuance and the worker from source builds at line 83, assigns both the issuance image at line 748, and records that image's digest for both at lines 1020/1028. The catalog similarly declares worker `image_name: issuance` at line 47. | Test generated **effective** image/command/entrypoint/selector combinations for official and local release modes. When a reviewed native selection becomes permitted, bind the worker's provenance to its actual artifact; retain immutable digest and source checks rather than removing image checks wholesale. |
| **Missing/misnamed: separate rollback executable and launch compatibility.** | The readiness prose names the deploy runner for release and rollback, but rollback lives in [restore-local-beta-release.ps1](../../scripts/restore-local-beta-release.ps1#L39). It composes files from its checkout and overlays captured image IDs plus a limited environment subset at lines 201–228. [Predeploy capture](../../scripts/deploy-local-beta-release.ps1#L437) retains DB-driver/gRPC compatibility and release markers, but not `Config.Cmd`, `Config.Entrypoint` or `SERVICE_NAME`. | Before changing a worker command or image family, prove a synthetic cross-runtime capture/restore round trip. Restoring only a Python image digest under a newer Rust launch definition can fail to start or choose the wrong process. Preserve validated launch configuration together with the old image; define explicit compatibility for older manifests that lack it. Do not execute rollback as an audit test. |
| **Underspecified: live UI/gateway operations consumers.** | The [UI API module](../../ui/src/services/canvasIntegrationsApi.js#L196) exposes all eight operations below. The [console](../../ui/src/components/console/deploy/CanvasIntegrationsPage.jsx#L469) loads jobs, candidates and open reviews, and offers retry, job resolve and review resolution. [Gateway routing](../../rust/services/gateway/src/issuance_native.rs#L28) selects Rust only from `native_http` in the coverage contract. None of these eight operations is in that list. | Treat the public UI/gateway/issuance path as a consumer, independently of the worker process. Qualify the real operations router, repository/lifecycle wiring, trusted tenant headers and RBAC before changing routing. Preserve every existing console action and public DTO. Worker parity alone cannot authorize deleting the Python operations API. |

The three independent loader-bearing definitions remain correctly identified:
[base Compose](../../docker-compose.base.yml#L956),
[self-host Compose](../../docker-compose.selfhost.prod.yml#L565), and
[Kubernetes](../../k8s/oracle/07-microservices.yaml#L879) with its
[ConfigMap](../../k8s/oracle/01-configmap.yaml#L104). Beta, conformance, GHCR and
catalog variants inherit those definitions; inheritance does not remove them
from the cutover verification matrix.

## Exact candidate-operations surface

All paths have prefix `/v1/integrations/canvas`. The authoritative behavior list
is [issuance-canvas-operations.json](../../contracts/issuance-canvas-operations.json#L13).

| Method and suffix | UI API export | Current native implementation / source selection |
| --- | --- | --- |
| `POST /applications/{application_id}/canvas-sync` | `enqueueCanvasEvidenceSync` | Candidate router; legacy gateway fallback |
| `GET /canvas-sync-jobs` | `listCanvasSyncJobs` | Candidate router; legacy gateway fallback |
| `GET /canvas-sync-jobs/{job_id}` | `getCanvasSyncJob` | Candidate router; legacy gateway fallback |
| `POST /canvas-sync-jobs/{job_id}/retry` | `retryCanvasSyncJob` | Candidate router; legacy gateway fallback |
| `POST /canvas-sync-jobs/{job_id}/resolve` | `resolveCanvasSyncJob` | Candidate router; legacy gateway fallback |
| `GET /canvas-award-candidates` | `listCanvasAwardCandidates` | Candidate router; legacy gateway fallback |
| `GET /evidence-policy-reviews` | `listCanvasEvidencePolicyReviews` | Candidate router; legacy gateway fallback |
| `POST /evidence-policy-reviews/{review_id}/resolve` | `resolveCanvasEvidencePolicyReview` | Candidate router; legacy gateway fallback |

The [Rust router](../../rust/services/issuance/src/canvas_operations.rs#L325)
explicitly remains separate from live issuance/gateway registration and contains
all eight routes. The UI page directly consumes six operations; the enqueue and
job-detail exports remain part of the public contract even without a direct page
call found in this audit. This is **implemented candidate code, not live Rust
routing**. Source routing labels are not proof of a deployed upstream version.

The audit found a stale implementation count: the operations contract's `status`
listed all eight native candidates while its last `limits` entry still described
only four read candidates. A parallel maintainer follow-up corrected that prose
in [the operations contract](../../contracts/issuance-canvas-operations.json).
This does not change frozen behavior or qualify live routing. The remaining
integration, deployment and external-effect limitations still apply.

Platform readiness and binding activation/deactivation are already present in
the [native coverage allowlist](../../contracts/issuance-native-coverage.json#L303),
unlike these eight operations. Preserve that split until deliberate cutover.
The console gates viewing/editing at lines 398/400 and displays blocking readiness
checks before activation; the [gateway authorization rules](../../rust/services/gateway/src/authorization.rs#L246)
classify readiness as view and activation/job/review mutations as edit. Future
end-to-end tests must retain these distinctions, tenant-hidden not-found outcomes,
the `202` enqueue/retry responses, safe result projections, and manual
`dismiss`/`suspend`/`revoke` actions through the existing lifecycle owner. Do not
turn candidate preparation into credential signing.

## Existing operational guards to adapt, not delete

- [Beta capabilities](../../scripts/check_canvas_beta_capabilities.py#L150)
  requires issuance/worker image equality and a `module:function` processor
  selection at lines 197–199. Its pilot, exact-origin, public signer, readiness
  TTL and 600-second deadline checks remain valuable after runtime selection
  changes. A Rust cutover needs an explicit native launch/provenance alternative,
  not a blanket bypass of validation.
- [OSS evidence validation](../../scripts/check_canvas_oss_portability.py#L36)
  maps the worker to the issuance release artifact and enforces image equality
  at line 504. Preserve complete container/digest/release evidence and update
  only the reviewed artifact association when selection actually changes.
- [Self-host preflight](../../scripts/check-selfhost-production.py#L639)
  requires the Python processor syntax when Canvas is enabled. Its native
  equivalent must remain fail-closed while keeping key/signer/pilot/deadline
  validation. This work does not authorize persistent self-host deployment.
- [Kubernetes image update](../../scripts/deploy-kubernetes.sh#L403) still
  targets the issuance image for the worker. Preserve migration ordering,
  secret references and headless operation. Its existing 30-second termination
  grace needs an explicit interruption/recovery acceptance decision against the
  600-second job deadline, not an assumption that every job drains in 30 seconds.

## Narrow additions to the verification backlog

1. Extend the existing **read-only** Compose renderer with the conformance and
   catalog/beta composition matrix above. Its current
   [run function](../../scripts/test_canvas_worker_compose_render.py#L148)
   renders only self-host base and bundle. The
   [conformance isolation tests](../../tests/test_conformance_stack_isolation.py#L80)
   verify reset tags, not complete worker runtime equivalence.
2. Add synthetic PowerShell capture/restore tests for exact launch selection and
   old-manifest compatibility before editing consumer commands. No Docker,
   persistent volumes, credentials or actual restore operation are needed.
3. Add a method/path inventory assertion linking all eight operations to their
   candidate router, current gateway ownership and UI API exports. Keep the
   existing [organization-scoped UI tests](../../ui/src/services/__tests__/canvasIntegrationsApi.test.ts#L200)
   and add real registered-router/middleware tests before routing changes.
4. Retain current deployment tests that intentionally require Python selection
   while gates are open. At qualified cutover, replace their selection assertion
   with the approved native tuple while keeping all secret, migration, health,
   isolation and provenance assertions. Do not delete tests merely because the
   selected language changes.

This audit adds no new permission to deploy, route candidate operations, delete
Python, change cryptography, or restore beta. Whole-worker qualification and the
goal's aggregate beta-only acceptance remain separate gates.

## Worker-only rollback hardening follow-up

The image-only rollback finding above led to a narrowly scoped implementation in
[the pure launch contract](../../scripts/beta-worker-launch-contract.ps1),
[capture](../../scripts/deploy-local-beta-release.ps1) and
[restore](../../scripts/restore-local-beta-release.ps1). Only worker records gain
`rollback_launch`; unrelated environment values and secrets are not copied.
Versioned records preserve effective Docker entrypoint/command vectors, including
null versus empty arrays, and explicit `SERVICE_NAME` and `CANVAS_SYNC_PROCESSOR`
presence/value. The restore
overlay clears effective empty vectors explicitly and removes an absent selector
with `!reset null`, avoiding host-environment fallback. An absent captured selector
is rejected if the immutable image would reintroduce either baked-in selector.
The processor selector is restricted to the known built-in Canvas callback or
intentional empty/absent state; arbitrary dynamic plugin paths are not persisted.

The launch contract accepts only the supported exact Python/native worker argv,
the tracked shared dispatcher with a worker selector, and the exact tracked
selfhost loader statement. It does not execute or parse arbitrary shell text.
An older manifest without launch metadata is accepted only with a verified
compatible legacy Python Compose command and empty image/current entrypoints;
the inspected immutable image must also have the known published Python Uvicorn
or Python worker default command. A null entrypoint alone cannot distinguish the
shared Rust image. An unknown or switched launch fails with recovery guidance
before stopping beta. Provenance-less old records additionally require the
effective built-in processor from verified source/image configuration; the
helper does not silently invent a missing callback. New complete captures retain
intentional empty/absent selection exactly.
The complete generated image/compatibility/worker overlay and UI image-ID check
now precede the first stop/database/volume mutation. The existing PostgreSQL
container and exact beta Redis/applicant volume identity checks also run before
that first stop, with their validated identifiers reused during restore. This
prevents a missing or mislabeled later data target from being discovered only
after an earlier store has already been restored. Existing backup hashes,
project/volume scope, image IDs and restricted compatibility environment checks
remain in place.

Expanded verification: 70 synthetic PowerShell launch-contract/AST tests passed
again after the data-target preflight change (20.87 seconds). They cover
capture/JSON/YAML round trips, legacy image and processor compatibility,
null/empty distinctions, both ambient selectors, privacy-preserving rejection,
worker-only capture, and unique data identity validation before the first stop.
The test author also reported 116 combined focused tests passing before this
ordering follow-up: these 70 launch tests, 31 local-beta-release-runner tests,
and 15 verification-migration-runner tests. All three PowerShell files passed
parser checks.
[The config-only Compose gate](../../scripts/test_beta_worker_launch_compose.py)
passed all 21 synthetic merges on both Compose 2.38.2 and 5.4, comparing the
complete runtime model and positively checking ordinary null's ambient fallback.
These are synthetic helper/AST and configuration-rendering checks, not a live
restore, deployed-image startup or beta acceptance result. Neither deployment
nor restore was executed. An initial non-elevated inspection did not establish
image availability. The parent subsequently inspected the exact stack-lock image
read-only: `ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`
has a null entrypoint and no image `SERVICE_NAME`. Combined with the tracked base
worker's Python module command, this is a supported legacy launch. No image was
pulled or container started. Real beta restore execution and aggregate beta
acceptance remain separate gates, not claims made by these helper/config tests.
