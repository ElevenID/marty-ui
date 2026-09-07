# Canvas worker consumer audit — 2026-09-07

This is a tracked-source audit of the owned `marty-ui` worktree, observed at
`5aa086a1ed20d1990453c434b17cd6b9bb9e3ded`. It supplements the
[readiness inventory](canvas-worker-cutover-readiness.md#deployment-consumer-inventory),
not its qualification results. No environment files, deployed containers or
remote services were inspected; no Compose configuration was applied, and no
consumer selection changed. Risks below are source-derived future-cutover risks,
not claims that current production or beta is broken.

## Missing or underspecified inventory entries

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

There is one stale inventory statement to reconcile without changing frozen
behavior: the operations contract's `status` says all eight native operations
are candidates, but its [last `limits` entry](../../contracts/issuance-canvas-operations.json#L95)
still says only four read candidates exist and write implementation is pending.
The router disproves the latter implementation count; its remaining live-routing,
deployment and external-effect limitations still apply. No contract was edited
by this audit.

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
