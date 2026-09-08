# Canvas worker consumer audit — 2026-09-07

## Staged native consumer selection — 2026-09-08

The separate local branch `feat/canvas-worker-native-consumer-cutover-v1`, based
on `14de48dce`, now contains the coordinated worker selection changes below.
They are staged implementation work: **unpushed, unmerged and not deployed**.
Independent review approved the eight source files; PowerShell parser and Bash
syntax checks passed. Configuration-test and validator qualification belong to
their separate lanes and are not inferred from source approval.

The preceding local validation passed **2,821 Python tests with three skips** in
197.91s, plus 218 focused launch/validator controls. Actual Compose 5.4
configuration-only checks passed for all 15 consumer compositions, five
generated 19-service models and 24 rollback merges; the existing 17-service
bundle checks and dedicated worker comparison remain intact. The Kubernetes
image-only transition guard passed 45 controls, including zero image writes
after a rejected legacy launch. Independent source/test review passed.
These results do not qualify a deployment or the current hosted runtime suite.

The shared launch classifier rejects direct native execution with unresolved
`DATABASE_URL_TEMPLATE`; exact loader and dispatcher forms perform expansion.
It does not prohibit native-owned secret files or library-specific file settings.
Tests bind the three native secret-file readers to their actual Rust owners;
accepting other file settings does not claim they are consumed or valid.

**Kubernetes issuance image binding is now implemented locally and independently
reviewed.** Full deployment requires explicit `MARTY_ISSUANCE_IMAGE`; the new
read-only preflight validates it against the eligible checked-in
`release/stack-lock.json` issuance component before any deployment writes. It
captures and exports one validated reference for both the issuance API and
migration manifests. There is no default digest, alternative lock override or
inference from `IMAGE_TAG`. Existing environment-file sourcing and prerequisite
reads remain earlier steps; this is not a claim that all preflight activity is
side-effect-free.

Provider-neutral mirrors are accepted only as fully qualified immutable image
references with the exact canonical issuance digest. The registry and repository
path may differ; the content digest may not. This proves the configured source
association, not mirror availability, a completed registry copy, remote
attestation or a deployed image. The canonical release formatter retains its
existing GHCR policy. Image-only updates now skip external issuance just like
the publisher, preserving its running artifact and leaving migration advancement
to full deployment. The existing native-worker launch guard still precedes every
image write; it is a snapshot check, not a concurrent-operator lock.

The binding repair passed **281 focused tests in 17.03s**. The independent full
suite on the revised source subsequently passed **2,884 tests with three skips
in 202.62s**. Hosted qualification, merge and publication remain pending; this
local pass does not authorize deployment. No Kubernetes deployment, pull or copy
was performed.

**The release-artifact gap remains:** published credentials `v0.1.72`, still
selected by the checked-in lock, predates the merged recovery migration. Correct
immutable binding cannot add that migration to an older image. A separate clean
`0.1.73` release-preparation branch from protected `948bca` contains only version
field changes; 68 release tests passed. The version bump is now committed as
`21ac54c9e0558fe47d626210cd72b38ab8116707` and pushed on the clean
`chore/release-0-1-73` branch. [PR #272](https://github.com/ElevenID/marty-credentials/pull/272)
is open with checks running; no tag, publication or deployment has occurred.
This is not a new available image or a lock update. Publication,
reviewed artifact selection, current-head qualification and cutover acceptance
remain separate gates.

At this checkpoint, remote `afc8bd754` CI `34223397680`, runtime job
`102051657514`, reported successful header (12:02:35–12:04:30 UTC), expiry
(12:04:30–12:06:20 UTC) and body (12:06:20–12:10:33 UTC) preflight steps.
Mixed-roster verification was running from 12:10:33 UTC; full groups remained
pending. These are step-success facts, not inferred test counts or a final CI
result. That run does not include this separate branch's consumer selection.
This section neither qualifies the staged worker runtime nor authorizes
deployment or Python deletion.
All older selection descriptions and counts below are dated historical evidence,
not assertions that the newly edited sources still select Python.

| Consumer | Artifact and exact launch selection |
| --- | --- |
| Base Compose | Local `services/Dockerfile` build with build argument `SERVICE_NAME=canvas-sync-worker`; command `["/usr/local/bin/marty-canvas-sync-worker"]` and runtime `SERVICE_NAME=canvas_sync_worker`. |
| Self-host Compose | The same local build; entrypoint `["/bin/sh", "-c"]` and the exact two-line command `. /app/load-secrets-env.sh` then `exec /usr/local/bin/marty-canvas-sync-worker`, with the final newline retained. Runtime selector is `canvas_sync_worker`. |
| GHCR overlay | Existing immutable `MARTY_SERVICES_IMAGE` shared Rust artifact, explicit `build: !reset null`, and `SERVICE_NAME=canvas_sync_worker`; native launch remains inherited. |
| Self-host bundle | Existing `${SELFHOST_IMAGE_PREFIX}/services:${SELFHOST_IMAGE_TAG}` shared artifact, preserving the existing prefix default and required release tag, explicit build reset and native selector; secret-loader launch remains inherited. |
| Generated beta overlay | Official releases use the shared services reference/digest and native selector. Local releases build `elevenid-local/canvas-sync-worker:${ReleaseVersion}`. Only issuance remains external: **19 application services and 18 local builds**. |
| Kubernetes | `${OCIR_REGISTRY}/marty-ui/canvas-sync-worker:${IMAGE_TAG}`, command `["/usr/local/bin/marty-canvas-sync-worker"]`, no Python arguments, and runtime selector `canvas_sync_worker`. |

The Kubernetes tag is deliberately the **per-service** native artifact, not a
new unresolved `/services` tag. The existing `build-push-registry.sh` app loop
already builds and pushes `canvas-sync-worker` from `services/Dockerfile` with
the corresponding build argument. The service catalog now records that same
image name, Dockerfile, context and selector. The image updater's existing app
loop selects it once; its obsolete second assignment to the issuance image is
removed. GHCR, bundles and official beta releases instead use their existing
shared services artifact. No build or push was executed for this audit.

Worker-only Compose `CANVAS_SYNC_PROCESSOR` entries are removed. Kubernetes
explicitly sets that variable to an empty value on the native worker, overriding
the shared ConfigMap only for this container. The ConfigMap's Python selector
remains available to issuance and rollback. No dynamic native import selector
or new secret is introduced.

The change retains the issuance API and issuance migrations on their Python
artifact, the supported Python/native rollback launch contracts, exact database
URL and loader expansion, all provider/pilot/signer settings, shared issuance
`TOKEN_HMAC_KEY`, secret mounts/references, both completed migration dependencies,
headless database-heartbeat health, network isolation, resources and restart
behavior. Kubernetes retains its 30-second termination grace. Generated image
evidence uses the actual worker artifact, while the verification image remains
pinned before rehearsal. Worker selection does not switch the eight operations
routes or authorize deleting their Python fallback.

The parallel validator changes are now present in
`check_canvas_beta_capabilities.py`, `check_canvas_oss_portability.py` and
`check-selfhost-production.py`. They replace blanket issuance/worker image
equality and Python-only launch assumptions with a closed supported launch and
worker-specific image/provenance checks, rather than removing validation. The
beta capability path checks the running image ID against its configured image
and release/source labels; coordinated local evidence binds the worker's own
image ID to its release marker. Pilot, origin, signer, key and deadline guards
remain required. Their preceding local tests/review and the complete 15-consumer,
five-generated-model and 24-rollback configuration gates are recorded above;
the revised source's full suite result is also recorded above. Exact-head hosted
qualification remains separate acceptance evidence.

## Historical audit scope and follow-ups

This is a tracked-source audit of the owned `marty-ui` worktree, observed at
`5aa086a1ed20d1990453c434b17cd6b9bb9e3ded`. It supplements the
[readiness inventory](canvas-worker-cutover-readiness.md#deployment-consumer-inventory),
not its qualification results. No environment files, deployed containers or
remote services were inspected; no Compose configuration was applied, and no
consumer selection changed. Risks below are source-derived future-cutover risks,
not claims that current production or beta is broken.

## Missing or underspecified inventory entries

### Kubernetes shared token-key repair (2026-09-08)

Both issuance and its retained Python worker now reference the same required
`marty-secrets/TOKEN_HMAC_KEY`. The existing secret catalog entry also requires
the value for Kubernetes; the template and deployment creation path are aligned.
No key is generated or substituted: an eventual deployment must reuse the
existing issuance token key through the supported environment/file input.

The runner validates the exact captured token value before publishing it, in
addition to retaining catalog validation. Synthetic tests cover file changes
between reads: a captured placeholder cannot pass because a later file is valid;
a valid captured value remains the published value if the file changes later.
Both consumers select that same key. The historical three-key wiring snapshot
is retained unchanged, with the test declaring this one explicit additive repair.

Independent review passed, as did 156 focused tests (24 new synthetic controls,
116 deployment checks, 12 frozen-worker contract checks and four existing
Kubernetes checks) in 18.74s. No real Kubernetes commands, key reads, provisioning,
worker selection changes or deployment occurred. Existing namespace/pull-secret
setup still precedes validation; these tests do not claim mutation-free failure.
Follow-up: other keys retain the older resolve/revalidate pattern; centralize
validated snapshots for all keys before claiming race-safe secret publication
for the entire deployer. That wider pre-existing issue is not fixed by this
token-specific guard.

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
