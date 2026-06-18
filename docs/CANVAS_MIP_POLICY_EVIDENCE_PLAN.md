# Canvas MIP Policy + Evidence Fact Plan

## Summary

Track the backend-first work to move Canvas evidence handling onto MIP facts, Cedar approval policy, and shared application issuance behavior.

Target flow:

```text
Canvas event -> MipEvidenceReceipt -> EvidenceFact -> Cedar approval PolicySet -> Application/issuance transition
```

Canvas remains a provider adapter. MIP owns normalized evidence facts, policy decisions, auditability, and approval-to-issuance behavior.

## Progress

- [x] Create this tracking plan.
- [x] Add MIP `EvidenceFact` schema and Canvas fixture.
- [x] Add `EvidenceFact` to MIP Cedar schema and approval policy examples.
- [x] Persist issuance evidence facts.
- [x] Add repository methods for saving/listing facts by application.
- [x] Add a Cedar-shaped approval policy evaluation boundary in issuance.
- [x] Convert Canvas evidence receipts into evidence facts.
- [x] Stop Canvas adapter from directly owning application lifecycle approval.
- [x] Reuse shared application approval/issuance behavior for Canvas auto-approval.
- [x] Update targeted Canvas evidence and issuance regression tests.
- [x] Wire `approval_policy_set_id` to the organization PolicySet store/cache for custom approval policies.
- [x] Add gateway/admin surfaces for policy decisions and evidence facts.
- [x] Add background reconciliation for stuck evidence/policy/issuance transitions.
- [x] Expand policy examples beyond Canvas course-completion-style facts.
- [x] Add declarative external API evidence checks that produce MIP `EvidenceFact` records without a custom adapter.
- [x] Refactor Canvas and declarative API evidence onto a shared MIP evidence transition service.
- [x] Surface configured external evidence checks in the application review UI.
- [x] Add Canvas mirror observability hooks for metrics, alerts, audit events, and critical webhooks.
- [x] Add beta.elevenidllc.com Canvas experiment deployment lane separate from production/self-host.
- [x] Seed a complete Canvas MIP Open Badge demo scenario with quiz score evidence, remote DID issuer context, and Canvas credential mirror delivery mode.
- [x] Add beta-safe Canvas Credentials mirror receiver plus automated OID4VCI wallet claim and mirror publish cycle for the Canvas demo.
- [x] Allocate and expose per-credential status-list metadata for the Canvas Open Badge demo issuance path.
- [x] Add MIP Delivery Destination abstraction so Canvas Credentials is represented as an organization-managed destination instead of a holder wallet.
- [x] Add real Canvas Credentials API provider mode for assertion publish and revocation sync.

## Backend Slice

- Add `EvidenceFact` as an immutable normalized fact derived from provider evidence.
- Keep existing `Application.evidence_submissions` as a compatibility/read surface.
- Use `marty_common.CedarEngine` when available, and fail closed on Cedar errors.
- Use bundled approval policies by default; custom `approval_policy_set_id` loading takes precedence when configured.
- Preserve current Canvas event signature verification, dedupe, receipt storage, platform-scoped direct issue behavior, and mirror delivery behavior.
- Keep existing platform/binding policy fields during migration; Cedar decisions take precedence when available.

## Acceptance Gates

- Canvas evidence events create one evidence submission, one evidence fact, and one replay-safe receipt.
- Duplicate Canvas events replay without duplicating facts.
- Changed duplicate payloads still conflict.
- Verified wrong-scope or unrequired facts do not auto-approve.
- A policy permit can approve an application and create/reuse an issuance transaction.
- A policy deny leaves the application pending or under review and records policy metadata.
- Manual approval still creates issuance transactions.
- Direct Canvas credential-event issuance is unavailable; Canvas issuance starts from evidence facts and policy decisions.

## Implemented Backend Slice

- `marty-protocol/schemas/evidence-fact.json`
- `marty-protocol/conformance/valid/evidence-fact.json`
- `marty-protocol/cedar/mip.cedarschema`
- `marty-protocol/cedar/policies/approval_rules.cedar`
- `marty-credentials/services/issuance/application/evidence_policy.py`
- `marty-credentials/services/issuance/application/application_approval.py`
- `marty-credentials/services/issuance/infrastructure/migrations/versions/20260514_1000_add_evidence_facts.py`
- `marty-credentials/services/issuance/infrastructure/adapters/canvas_credentials_adapter.py`
- `marty-ui/packages/marty_common/cedar/approval_rules.cedar`
- `marty-ui/packages/marty_common/cedar_engine.py`

## Implemented PolicySet Slice

- Custom `ApplicationTemplate.approval_policy_set_id` values are loaded through the issuance repository from `organization_service.policy_sets`.
- Policy sets may be raw Cedar text or protocol-style `cedar_policies[]` JSON with enabled `cedar_text` entries.
- Missing, inactive, unsupported-type, or empty policy sets deny approval and record decision metadata.
- Organization PolicySet type support now includes protocol policy types such as `APPROVAL_RULES`.
- Bundled Canvas approval rules remain the default when no policy set is configured.

## Work Plan

### Slice 13 - Real Canvas Credentials API Provider

Goal: make Canvas Credentials mirror delivery work against the real Canvas Credentials API, not only the beta-safe sandbox receiver.

- [x] Keep the sandbox/bridge receiver mode for demos and local safety.
- [x] Add `CANVAS_CREDENTIALS_PROVIDER=badgr_api` to publish assertions through `/v2/badgeclasses/{badgeclass}/assertions`.
- [x] Map canonical ElevenID issuance into a public Canvas Credentials assertion payload with recipient, badgeclass, evidence/provenance URL, and ElevenID extension metadata.
- [x] Store the returned Canvas assertion ID, public Open Badge URL, issuer ID, and request metadata on the delivery record.
- [x] Support real assertion revocation with `DELETE /v2/assertions/{idOrEntityId}`.
- [x] Document required env/secrets and compose wiring.

Gate: an issued ElevenID Open Badge can be mirrored to a real Canvas Credentials badgeclass while issuer keys, DID identity, credential status, and provenance stay canonical in ElevenID.

### Slice 8 - Beta Canvas Experiments Deployment

Goal: demonstrate the Canvas/MIP policy flow on `beta.elevenidllc.com`
without mixing Canvas demo services into production or self-host migration lanes.

- [x] Add `experiments` migration profile aliases and tests.
- [x] Add `tunnel-beta-experiments` deployment catalog stack.
- [x] Add Canvas real LMS services to the experiments service group.
- [x] Add beta env template values for Canvas public host, Marty org, credential template, and application template.
- [x] Add Make targets for planning, starting, resetting, and bootstrapping beta Canvas experiments.
- [x] Extend the real Canvas seeder to create Canvas Platform and Program Binding records.

Gate: `make beta-canvas-experiments-bootstrap` starts the beta experiments stack and seeds the Marty org Canvas platform/binding for the Verified Member Badge flow.

### Slice 3 - Gateway and Admin Visibility

Goal: make evidence facts and policy decisions visible and operable outside backend logs.

- [x] Expose issuance evidence-fact read APIs through gateway routes.
- [x] Expose Canvas evidence event replay/status metadata through gateway routes.
- [x] Add admin-facing read models for:
  - application evidence facts
  - latest policy decision
  - approval policy source
  - issuance transaction created from approval
- [x] Add UI affordances in the existing application/admin surfaces to inspect Canvas evidence and policy outcome.
- [x] Add tests that verify gateway responses preserve `evidence_facts` and `policy_decision` metadata.

Gate: an operator can answer “why was this Canvas-backed application approved or not approved?” without querying the database directly.

### Slice 4 - Canvas Policy Authoring Examples

Goal: give implementers concrete Cedar patterns for common Canvas evidence requirements.

- [x] Add example approval policies for:
  - `canvas.course_completion`
  - `canvas.assignment_completion`
  - `canvas.assignment_score`
  - `canvas.quiz_completion`
  - `canvas.quiz_score`
  - `canvas.module_completion`
  - manual instructor approval fallback
- [x] Add protocol fixtures for typed `EXTERNAL_FACT` requirements with scope and pass rules.
- [x] Add Cedar smoke tests for permit and deny behavior across those examples.
- [x] Document when to use bundled policies vs organization-owned `approval_policy_set_id`.

Gate: a new Canvas program can copy an example policy and adapt scope/pass thresholds without touching adapter code.

### Slice 5 - Background Reconciliation and Stuck-State Recovery

Goal: make the evidence-to-issuance flow self-healing instead of request-only.

- [x] Add a worker/cron lane for applications with verified evidence facts but no recorded policy decision.
- [x] Add a worker/cron lane for policy-permitted applications that failed before issuance transaction creation.
- [x] Add retry/idempotency behavior for approval-to-issuance transitions.
- [x] Add stale receipt/evidence fact reconciliation reports.
- [x] Add metrics and audit events for:
  - evidence fact created
  - policy permit
  - policy deny
  - approval-to-issuance success
  - approval-to-issuance failure

Gate: transient failures do not leave Canvas evidence permanently stuck between receipt, policy, approval, and issuance.

Implemented:

- `marty-credentials/services/issuance/application/evidence_reconciliation.py`
- `POST /v1/applications/evidence/reconcile`
- `GET /v1/applications/evidence/reconciliation-report`
- gateway proxies for both reconciliation endpoints
- repository support for listing Canvas event receipts
- issuance audit event types for evidence fact, policy, and approval-to-issuance transitions
- targeted reconciliation tests in `marty-credentials/tests/unit/test_evidence_reconciliation.py`

### Slice 6 - Productized Canvas Configuration

Goal: move from backend-configured Canvas behavior to product-manageable Canvas programs.

- [x] Split current connector usage into platform-level Canvas trust config and program-level bindings.
- [x] Add admin APIs for Canvas program bindings:
  - application template
  - credential template
  - evidence requirements
  - approval policy set
  - delivery mode
  - issuer mode
- [x] Add admin UI for Canvas platform and program binding management.
- [x] Add validation that Canvas binding scope and evidence requirements are internally consistent.
- [x] Remove legacy connector fallback from evidence and LTI runtime resolution.
- [x] Make Canvas platform/program bindings the required runtime model.

Gate: one Canvas tenant can safely support multiple programs, templates, scopes, and policies.

Implemented so far:

- `CanvasPlatform` domain model and persistence.
- `CanvasProgramBinding` domain model and persistence.
- migration `20260515_1000_add_canvas_platform_program_bindings.py`
- issuance management APIs:
  - `POST/GET/PUT/DELETE /v1/integrations/canvas/platforms`
  - `POST /v1/integrations/canvas/platforms/{platform_id}/program-bindings`
  - `GET/PUT/DELETE /v1/integrations/canvas/program-bindings`
- gateway proxies for the new platform and program-binding APIs.
- UI API helper `ui/src/services/canvasIntegrationsApi.js`.
- Console management page `ui/src/components/console/deploy/CanvasIntegrationsPage.jsx`.
- Console route `/console/org/deploy/canvas`.
- Deploy navigation entry for Canvas.
- duplicate binding validation by application template, credential template, and Canvas scope.
- targeted tests in `marty-credentials/tests/unit/test_canvas_configuration_routes.py`.
- UI production build verified with `npm run build`.
- shared runtime resolver `marty-credentials/services/issuance/application/canvas_runtime.py`.
- Canvas evidence events require platform/program bindings by application template and Canvas scope.
- Older pre-platform Canvas admin APIs are removed from the active API surface.
- Canvas LTI experience sessions now include matched platform/program binding, application template, and credential template context.
- targeted binding-aware evidence and LTI regression tests.

### Slice 7 - LTI Workflow Completion

Goal: turn verified LTI launch state into an in-context application workflow.

- [x] Resolve `canvas_lti_state` into a Canvas program binding.
- [x] Bootstrap or resume the correct application from launch context.
- [x] Pre-seed learner, course, and scope context for the application.
- [x] Scope catalog/application choices to the Canvas launch context.
- [x] Record LTI-derived context in evidence/policy audit metadata when relevant.

Gate: launching from Canvas opens the intended ElevenID application flow, not just a generic catalog handoff.

Implemented so far:

- LTI verification resolves the matching Canvas program binding from platform launch scope.
- LTI experience sessions expose `canvas_platform_id`, `canvas_program_binding_id`, `application_template_id`, and `credential_template_id`.
- LTI launch URLs use platform-based routes: `/v1/integrations/canvas/lti/platforms/{platform_id}/...`.
- `POST /v1/integrations/canvas/lti/experience-sessions/{state}/bootstrap` creates or resumes the issuance-side `Application` for the Canvas learner and binding.
- Bootstrap is idempotent by launch state and by active Canvas subject/program binding.
- Bootstrap records Canvas launch state, learner identity, roles, course/context, platform, binding, template IDs, and application ID in application integration metadata.
- Bootstrap emits `CANVAS_LTI_APPLICATION_BOOTSTRAPPED` for audit history.
- The LTI experience session response now includes the bootstrapped `application_id`.
- The gateway proxies the bootstrap endpoint without requiring management-only headers.
- Canvas launch page routes bound launches directly to `/console/applicant/apply/{credential_template_id}`.
- Catalog fallback launches resolve `canvas_lti_state`, scope choices to the bound Canvas credential template when present, and preserve Canvas launch context into the application route.
- Applicant application submission carries `canvas_lti` metadata with launch state, issuance application ID, binding IDs, Canvas context, learner identity, roles, and subject.
- Targeted LTI route tests, gateway proxy tests, applicant application flow tests, and UI production build verified.

### Slice 8 - Standards Expansion

Goal: add LMS-native Canvas depth without bypassing the MIP evidence/policy spine.

- [x] Add LTI Deep Linking support for placing ElevenID activities in Canvas.
- [x] Add AGS support where grade/submission state should become evidence facts.
- [x] Add NRPS support where roster/role context should shape eligibility or review.
- [x] Add capability negotiation per Canvas platform/program binding.

Gate: Deep Linking, AGS, and NRPS produce or enrich MIP facts/context rather than creating parallel approval logic.

Implemented so far:

- LTI launch responses now expose `lti_capabilities` derived from Canvas LTI claims, platform OpenID metadata, and binding evidence requirements.
- LTI experience session metadata stores capabilities in MIP context so later Deep Linking, AGS, and NRPS work can branch from negotiated facts instead of provider-specific conditionals.
- Capability negotiation detects:
  - resource-link launch
  - Deep Linking settings and accepted types
  - AGS endpoint, line item URLs, and scopes
  - NRPS membership URL
  - platform-supported scopes and claims
  - binding evidence fact types
- Canvas LTI bootstrap stores negotiated capabilities in application Canvas integration metadata.
- Targeted LTI tests cover Deep Linking, AGS, NRPS, and MIP context propagation.
- `POST /v1/integrations/canvas/ags/score-events` accepts signed Canvas AGS score payloads.
- AGS score input normalizes into the existing `CanvasEvidenceEvent -> MipEvidenceReceipt -> EvidenceFact -> Cedar approval` path.
- AGS-derived facts use `canvas.assignment_score` or `canvas.quiz_score`, score/pass assertions, Canvas scope, and `SIGNED_AGS_SCORE` verification metadata.
- Gateway proxy `/v1/integrations/canvas/ags/score-events` preserves the signed payload without management-only headers.
- Targeted tests cover AGS score mapping, replay-safe fact creation, policy permit/auto-approval, and gateway proxying.
- `POST /v1/integrations/canvas/nrps/membership-events` accepts signed Canvas NRPS membership payloads.
- NRPS membership input normalizes into `canvas.nrps_membership` evidence facts with role, membership status, and eligibility assertions.
- Evidence pass rules now support role inclusion, membership status, and eligibility checks for roster-driven review/approval.
- Gateway proxy `/v1/integrations/canvas/nrps/membership-events` preserves the signed payload without management-only headers.
- Targeted tests cover NRPS membership mapping, policy permit/auto-approval, and gateway proxying.
- `POST /v1/integrations/canvas/lti/experience-sessions/{state}/deep-linking-response` creates signed LTI Deep Linking responses for Canvas placement.
- Deep Linking responses use ES256 JWT signing from explicit `CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK` or `CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK_FILE` configuration.
- Deep Linking content items preserve MIP/Canvas binding context through `custom` fields such as LTI state, Canvas account/platform/binding IDs, application template ID, credential template ID, and course ID.
- Deep Linking responses include Canvas `data`, deployment ID, message type, version, resource link content items, and form-post metadata for the Canvas return URL.
- Gateway proxy `/v1/integrations/canvas/lti/experience-sessions/{state}/deep-linking-response` exposes the signed placement flow without management-only headers.
- Targeted tests cover JWT signature validity, Deep Linking payload claims, content item context, session audit metadata, and gateway proxying.

### Slice 9 - Trust and Provenance UX

Goal: make Canvas-mirrored credentials explainable to verifiers and employers.

- [x] Add provenance lookup from Canvas mirror record to canonical issuance record.
- [x] Surface canonical issuer, mirrored distribution channel, and trust basis in verification UX.
- [x] Add public/internal provenance endpoint for mirrored Canvas credentials.
- [x] Add tests for mirror-to-canonical provenance resolution.

Gate: a verifier can understand why a Canvas-discovered badge is trusted and which canonical ElevenID issuance backs it.

Implemented so far:

- `GET /v1/issuance/delivery-records/canvas-credentials/provenance` resolves Canvas mirror provenance by delivery record ID, Canvas external credential ID, or canonical credential ID.
- Provenance responses connect the Canvas mirror delivery record to the canonical issued credential, issuance transaction, issuer DID, issuer profile, distribution channel, credential status, and trust basis.
- Public provenance payloads avoid raw subject identifiers and expose only a stable `subject_id_hash`.
- Delivery-record persistence now supports direct lookup by record ID and indexed lookup by Canvas external credential ID.
- Gateway proxy `/v1/issuance/delivery-records/canvas-credentials/provenance` exposes the provenance endpoint without management-only headers.
- Targeted tests cover repository lookups, provenance payload shape, subject privacy, canonical issuer/trust context, and gateway proxying.
- The standalone `/canvas/provenance` UI and custom public employer provenance page have been removed from the product path; Canvas mirror links are emitted directly as `/console/org/operate/verify` URLs with lookup params preserved.
- The provenance lookup component is embedded in the organization console for operator lookup by Canvas external credential ID, delivery record ID, or canonical credential ID.
- Console lookup surfaces canonical issuer DID, issuer profile, mirrored Canvas distribution channel, canonical credential status, delivery status, subject hash, and trust-basis checks.
- UI tests cover legacy public-route removal, console lookup URL/prop-driven lookups, manual delivery-record lookups, and rendered trust context.

### Slice 10 - Canvas Mirror Automation and Reconciliation

Goal: make Canvas mirror publish/retry/status-sync jobs operable as an automated lane instead of only manual service calls.

- [x] Refactor pending publish and failed lifecycle-sync retries into reusable backend job helpers.
- [x] Add a combined automation cycle endpoint for cron-style execution.
- [x] Add an optional in-process worker controlled by environment flags.
- [x] Expose Canvas mirror ops endpoints through gateway with management service headers.
- [x] Add tests for automation-cycle processing and gateway proxying.
- [x] Add product/admin UI controls for health, retry, and one-cycle run actions.
- [x] Add metrics/alerts around repeated publish or lifecycle-sync failures.

Gate: Canvas mirror drift can be retried automatically or by a cron runner, while product/admin surfacing remains available for the next UI slice.

Implemented so far:

- Backend helpers now run Canvas mirror publish batches, status-sync failure batches, and a combined automation cycle using the same behavior as the manual endpoints.
- `POST /v1/issuance/delivery-records/canvas-credentials/run-automation-cycle` runs pending/failed Canvas publish retries plus lifecycle status-sync retries in one call.
- `CANVAS_MIRROR_WORKER_ENABLED=true` starts an optional in-process worker on issuance service startup.
- Worker controls:
  - `CANVAS_MIRROR_WORKER_ORGANIZATION_ID`
  - `CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS`
  - `CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS`
  - `CANVAS_MIRROR_WORKER_BATCH_LIMIT`
  - `CANVAS_MIRROR_WORKER_RETRY_FAILED`
  - `CANVAS_MIRROR_WORKER_RUN_ON_STARTUP`
- Gateway now proxies Canvas mirror process-pending, process-status-sync-failures, run-automation-cycle, and organization health endpoints with issuance management headers.
- Targeted tests cover the combined automation cycle and gateway access to automation/health surfaces.
- `/console/org/deploy/canvas` now includes a Canvas mirror ops panel with publish, failed-publish, delivered, lifecycle-sync failure, and lifecycle-sync OK counts.
- The Canvas admin UI can refresh health, retry pending/failed publish jobs, retry lifecycle status-sync failures, or run the combined automation cycle.
- UI tests cover mirror health rendering and all three admin retry/automation actions.
- Canvas mirror health responses include repeated-failure metrics, warning/critical alert counts, alert thresholds, and per-delivery-record alert details.
- Repeated failure alerts default to warning at 3 attempts and critical at 5 attempts, configurable through `CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS` and `CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS`.
- The Canvas admin UI surfaces warning/critical mirror alerts with delivery record IDs, attempt counts, error details, and recommended recovery actions.

## Completed Canvas Deployment Slices

### Slice 11 - Deployment Profile Canvas Feature Gates

Goal: make deployment profiles the operational control point for which Canvas modes a program binding may use.

- [x] Add explicit Canvas feature flags to deployment profile configuration:
  - `enable_canvas_evidence`
  - `enable_canvas_lti`
  - `enable_canvas_mirror_publish`
  - `enable_canvas_mirror_ops`
  - `enable_canvas_deep_linking`
  - `enable_canvas_ags`
  - `enable_canvas_nrps`
- [x] Expose Canvas feature gate summaries from deployment profile responses.
- [x] Store `deployment_profile_id` and a Canvas feature flag snapshot on `CanvasProgramBinding`.
- [x] Gate Canvas evidence, LTI launch/bootstrap, Deep Linking, AGS, and NRPS paths from the binding snapshot.
- [x] Treat missing deployment-profile snapshots on program bindings as ungated.
- [x] Add deployment profile gate selection to the Canvas admin binding UI.
- [x] Add targeted tests for binding persistence, deployment profile response shape, and disabled evidence gates.

Gate: Canvas program bindings can be explicitly limited by deployment profile without introducing connector fallback paths.

Implemented:

- deployment profile `FeatureFlags` and `FeatureFlagsModel` now include Canvas gates.
- deployment profile responses include `canvas_feature_flags` without exposing the full generic `feature_flags` object.
- Canvas program bindings persist `deployment_profile_id` and normalized Canvas `feature_flags`.
- inbound Canvas evidence rejects disabled `enable_canvas_evidence` gates before creating receipts/facts.
- AGS and NRPS evidence paths require `enable_canvas_ags` and `enable_canvas_nrps`.
- LTI launch/bootstrap requires `enable_canvas_lti`; Deep Linking requires `enable_canvas_deep_linking`.
- `/console/org/deploy/canvas` lets admins attach a deployment profile to a binding and snapshots its Canvas gate settings.

Slice 11 is complete.

### Slice 12 - Deployment Profile Gates for Canvas Mirror Workers

Goal: make Canvas mirror delivery records and background operations honor the deployment profile snapshot captured on the Canvas program binding.

- [x] Carry binding delivery mode, deployment profile ID, and Canvas feature flags into Canvas application integration context.
- [x] Copy deployment profile context into Canvas mirror delivery records.
- [x] Block Canvas mirror delivery creation when `enable_canvas_mirror_publish` is disabled.
- [x] Block pending/failed Canvas mirror publish workers when `enable_canvas_mirror_publish` or `enable_canvas_mirror_ops` is disabled.
- [x] Block lifecycle status-sync retry workers when `enable_canvas_mirror_ops` is disabled.
- [x] Add `blocked_count` to Canvas mirror publish, status-sync, and automation-cycle responses.
- [x] Surface blocked-by-profile counts in the Canvas admin mirror action summary.
- [x] Add targeted backend and UI tests for blocked mirror operations.

Gate: deployment profiles now control Canvas mirror publishing and worker operations through Canvas program-binding metadata.

Implemented:

- Canvas evidence and LTI bootstrap now store `delivery_mode`, `deployment_profile_id`, and normalized Canvas `feature_flags` in application integration context.
- post-issuance delivery recording snapshots Canvas binding/profile metadata onto Canvas mirror delivery records.
- missing Canvas feature snapshots remain permissive for ungated program bindings; explicit snapshots treat missing or false flags as disabled.
- profile-blocked mirror records are marked failed with `canvas_feature_gate_blocked`, `canvas_feature_gate`, and `retryable=false` metadata.
- worker publish and lifecycle status-sync batches report blocked records through `blocked_count`.
- `/console/org/deploy/canvas` action results include blocked counts when profile gates stop mirror work.

## Completed Follow-On Slices

### Slice 13 - Canvas Mirror Observability Hooks

Goal: move Canvas mirror alerting from health-payload-only visibility into operator-facing observability.

- [x] Emit structured logs/events for warning and critical Canvas mirror alerts.
- [x] Add metrics labels for blocked, failed, delivered, and lifecycle-sync retry outcomes.
- [x] Add optional webhook or notification hook for critical repeated failures.
- [x] Add tests around alert emission and blocked-operation metrics.

Gate: operators can monitor Canvas mirror drift and profile-blocked work outside the admin page.

Implemented:

- Canvas mirror publish, lifecycle status-sync, and automation-cycle responses now include structured metrics for processed, delivered/synced, failed, blocked, and retry outcomes.
- Canvas mirror health metrics now expose blocked records and lifecycle retry buckets alongside existing repeated-failure alert counts.
- Warning and critical mirror alerts emit structured logs plus `CANVAS_MIRROR_ALERT_EMITTED` issuance audit events tied to the delivery transaction.
- Critical alerts can be sent to an optional `CANVAS_MIRROR_ALERT_WEBHOOK_URL` with bounded timeout configuration.
- Worker logs now include blocked counts so profile-gated mirror work is observable outside the admin UI.
- Targeted Canvas mirror tests cover metrics, profile-blocked counts, critical alert event emission, and webhook dispatch.

Slice 13 is complete.

### Slice 14 - Declarative External Evidence API Checks

Goal: make the MIP evidence layer useful for Canvas-like use cases that do not deserve a custom provider adapter, such as passport verification, sanctions checks, employment checks, or license lookups.

- [x] Add a protocol-level `EXTERNAL_API` evidence requirement shape.
- [x] Allow application templates to declare:
  - HTTP method, URL, timeout, headers, and body templates.
  - secret-backed headers by environment secret reference.
  - expected HTTP status codes and JSON response conditions.
  - response-to-`EvidenceFact` mappings for provider, fact type, subject, scope, assertion, verification, and source IDs.
  - pass rules over normalized fact fields such as `assertion.face_match_score >= 0.85`.
- [x] Add an issuance backend service that executes an allowed declarative API check and emits an immutable `EvidenceFact`.
- [x] Reuse the existing MIP Cedar approval evaluation path after the fact is saved.
- [x] Require explicit `auto_approve_on_evidence` or `auto_issue_on_permit` on the requirement before creating an issuance transaction automatically.
- [x] Keep adapters like Canvas for signed/eventful protocols, but let simple provider checks be configured without code.
- [x] Add SSRF/secret-safety guardrails for user-defined API calls.
- [x] Add targeted tests for passport-style API mapping, response expectations, path pass rules, policy permit/deny, and no-code fact creation.
- [x] Update the MIP Application Template spec to define `EXTERNAL_API` contract, safety constraints, mappings, and pass-rule semantics.
- [x] Add generalized UI authoring controls for user-defined external API evidence checks.
- [x] Move fact persistence, compatibility submissions, Cedar evaluation, audit events, and optional approval-to-issuance into a shared issuance application service.
- [x] Refactor the Canvas evidence adapter to call the shared service after provider-specific signature verification and event normalization.
- [x] Expose reviewer-safe configured API check descriptors in the evidence summary.
- [x] Add application review UI controls to run configured external API checks and refresh policy/fact results.

Gate: an organization can define a provider API and expected response contract in an application template, run it for an application, and have MIP produce facts/policy decisions without adding a new adapter.

Implemented so far:

- `marty-protocol/schemas/application-template.json` now supports `EXTERNAL_API`, `api`, `expected_response`, `response_mapping`, and explicit auto-issue flags.
- `marty-protocol/conformance/valid/application-template-external-api-evidence.json` captures a passport verification example.
- `marty-credentials/services/issuance/application/external_evidence_api.py` executes declarative HTTP checks, applies templates, resolves secret-backed headers, validates endpoint safety, evaluates expected responses, and creates `EvidenceFact` objects.
- `marty-credentials/services/issuance/application/evidence_policy.py` now supports provider-neutral path pass rules over `assertion`, `scope`, `verification`, and `source`.
- `POST /v1/applications/{application_id}/evidence/api-checks/{check_id}/run` runs a configured API check, persists the fact, evaluates Cedar, records audit events, and optionally creates/reuses an issuance transaction.
- `marty-credentials/services/issuance/application/evidence_transition.py` owns the shared fact-to-policy-to-issuance transition used by Canvas and no-code provider checks.
- Gateway proxies the external evidence API check endpoint with issuance management headers.
- Applicant/reviewer gateway routes also proxy the external evidence API check endpoint through the existing application review surface.
- Bundled approval rules now permit verified, scope-matched, fully satisfied external evidence from any provider, not only Canvas.
- Targeted tests cover permit/auto-issue and deny behavior for passport-style declarative API checks.
- The Application Template manager now exposes structured `EXTERNAL_API` controls for provider/fact metadata, request details, secret-header references, expected responses, response mappings, scope, and pass rules.
- The application review page now shows generalized Evidence & Policy metadata, configured external checks, and inline run actions.

## Canvas Open Badge Demo Scenario

The beta experiments seeder now creates a course/quiz Open Badge scenario by default:

- Credential template: `Interoperable Credentials Foundations Badge`
- Application template: `Interoperable Credentials Foundations Application`
- Public badge metadata: `https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge`
- Public badge image: `https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge/image.svg`
- Evidence fact type: `canvas.quiz_score`
- Verification method: `SIGNED_AGS_SCORE`
- Pass rule: `assertion.score_percent >= 80`
- Delivery mode: `wallet_plus_canvas_mirror`
- Issuer identity: `did:web:beta.elevenidllc.com:orgs:marty`
- Remote signing service: `managed-openbao-transit` / `cred-issuer-marty-es256`

The issued credential carries pack/backpack-friendly Open Badge fields, including a dereferenceable `achievement`, `criteria`, `image`, `result`, `learning_context`, and canonical status-list metadata.

The intended flow is:

```text
Canvas quiz score -> signed AGS score event -> MipEvidenceReceipt -> EvidenceFact -> MIP/Cedar approval -> issuance transaction -> status-list allocation -> OID4VCI wallet claim -> Canvas mirror publish
```

Issuer private key material stays outside Canvas and outside the beta web host. The issuance transaction resolves the active Marty issuer context through the gateway signing-key registry and signs through the remote OpenBao transit service.

The beta experiments stack now includes the Canvas sandbox service as a Canvas Credentials mirror receiver. It is not the Canvas LMS used for LTI; the real Canvas LMS remains `canvas-test.elevenidllc.com`. The sandbox receiver accepts the same publish/status payloads the issuance service sends to a Canvas Credentials bridge, can be protected by `CANVAS_CREDENTIALS_API_TOKEN`, and returns an external Canvas mirror credential ID for provenance testing.

## Slice 15 - Issued Badge Revocation Status Metadata

Goal: prove that the Canvas Open Badge demo is not only trust-profile linked to a revocation profile, but that each issued badge carries a concrete status-list allocation.

- [x] Add `revocation_profile_id` and `status_list_entries` metadata to issued credential persistence.
- [x] Allocate a status-list index before remote SD-JWT signing when the revocation-profile service is configured.
- [x] Let the remote signing path accept a caller-supplied credential ID so `jti` and the allocated status-list entry refer to the same credential.
- [x] Embed `credentialStatus` in the signed SD-JWT payload when allocation succeeds.
- [x] Surface status-list metadata in issued credential record responses.
- [x] Surface status-list metadata in Canvas mirror provenance responses and Canvas mirror publish payloads.
- [x] Use the stored status-list index/profile for revoke, suspend, and reinstate delegation instead of the previous hard-coded profile/index.
- [x] Serve status-list documents through the public gateway organization path used in `credentialStatus` URLs.
- [x] Print revocation profile, status-list index, and status-list URI in the Canvas demo seeder transition summary.

Gate: a Canvas-issued Open Badge can be traced from Canvas evidence to canonical issuance, remote DID signing, Canvas mirror delivery, and a concrete revocation/status-list entry.

## Slice 16 - Credential Delivery Destinations

Goal: separate holder wallet compatibility from operational delivery destinations so Canvas Credentials can be selected and explained without pretending it is a normal OID4VCI holder wallet.

- [x] Add protocol-level `DeliveryDestinationProfile` schema and conformance fixture.
- [x] Clarify in the Wallet Profile spec that Canvas Credentials institutional publishing is a delivery destination, not a holder wallet.
- [x] Add credential-template service registry APIs for delivery destinations.
- [x] Add system destination entries for ElevenID Wallet, generic OID4VCI wallets, Canvas Credentials institutional mirror, and Canvas/Parchment learner backpack.
- [x] Tag Canvas mirror delivery records with Canvas Credentials delivery destination metadata.
- [x] Add gateway routes for `/v1/delivery-destinations`.
- [x] Route Canvas mirror creation/publish/status-sync through Canvas program-binding and platform metadata instead of connector IDs.
- [x] Add admin UI for organization delivery destinations and Canvas Credentials setup state.
- [x] Update learner claim UI from a wallet-only dialog to a destination selector:
  - `Add to ElevenID Wallet`
  - `Open in compatible wallet`
  - `Show this credential in Canvas Credentials`
- [x] Enforce that students can consent to Canvas display but cannot configure the institutional Canvas Credentials destination.
- [x] Add claim projection policy controls so Canvas receives a public badge verification view, not every credential claim by default.

Implemented:

- Canvas deploy page now shows a Canvas Credentials destination panel with setup readiness, platform/binding counts, projection policy, and org destination override actions.
- Learner claim dialog now uses delivery destinations to choose between ElevenID wallet, generic OID4VCI wallet, and Canvas Credentials display.
- Learner Canvas Credentials consent is sent with the issue request and stored as internal applicant metadata.
- Applicant service strips delivery preferences from credential subject claims before forwarding issuance.
- Canvas Credentials destination creation defaults to the public badge/provenance projection policy.

Gate: Canvas Credentials is visible as an organization-managed destination with explicit setup, consent, projection, delivery status, and provenance, while holder-wallet flows remain standards-based wallet claims.

## Slice 17 - Remove Legacy Pre-Platform Canvas Runtime

Goal: make the current Canvas implementation fail clearly unless it is configured through CanvasPlatform and CanvasProgramBinding.

- [x] Remove the old program-binding compatibility field from the request/response/domain path.
- [x] Remove connector fallback from Canvas evidence runtime resolution.
- [x] Remove connector fallback from evidence reconciliation.
- [x] Require LTI launches to use platform-based routes and to match an enabled program binding.
- [x] Retire direct Canvas credential-event issuance in favor of evidence facts.
- [x] Stop advertising direct credential events in MIP integration plans; expose evidence, AGS score, and NRPS membership event routes instead.
- [x] Remove direct credential-event and older Canvas management/probe/evidence-flow endpoints from the active API surface.
- [x] Stop copying connector IDs into Canvas application integration metadata.
- [x] Queue Canvas Credentials mirror records from program binding/platform metadata.
- [x] Update Canvas LTI/demo docs to use platform + program binding setup.
- [x] Remove historical connector columns/tables from models, migrations, and bootstrap SQL.

Gate: Canvas evidence, LTI, and mirror operations use the MIP platform/binding/fact/policy path only; connector-based fallback is not supported at runtime.

## Slice 18 - Employer Verification Demo

Goal: make the Canvas mirror demo show portability value, not only delivery plumbing.

- [x] Retired the temporary public employer verification route.
- [x] Reuse Canvas mirror provenance so employers resolve Canvas mirror IDs to canonical ElevenID issuance records.
- [x] Show canonical issuer DID, issuer profile, active credential status, Canvas distribution channel, subject hash, and mirror delivery state.
- [x] Add a public Canvas Credentials sandbox display page for mirrored credentials.
- [x] Return Canvas credential display and employer verification URLs from the sandbox mirror receiver.
- [x] Print Canvas display and employer verification links from the Canvas demo seeder after mirror publish.
- [x] Update Canvas demo docs so the story ends with employer verification outside Canvas.
- [x] Remove the temporary public page and emit organization-console verification/provenance links directly.

Gate: a learner can earn a badge from Canvas activity, see it mirrored in Canvas Credentials, and share an employer verification page that proves the badge is backed by external ElevenID issuance infrastructure.

## Slice 19 - Canvas Production Verification Hardening

Goal: remove demo-only runtime assumptions from Canvas Credentials verification and mirror publishing.

- [x] Remove legacy public employer verification entry points once the console-native `/console/org/operate/verify` flow is available.
- [x] Stop generating Canvas sandbox display URLs in the public verification page when the provider response did not include a real display URL.
- [x] Require an explicit public ElevenID base URL for Canvas Credentials verification links instead of silently defaulting to beta.
- [x] Allow Canvas Credentials provider settings to come from delivery-record metadata before service-wide environment variables.
- [x] Support org/template-scoped Canvas Credentials API token references through metadata keys such as `canvas_credentials.api_token_env` or `canvas_credentials.api_token_file`.
- [x] Add org-admin Canvas binding controls for Canvas Credentials provider, issuer, badgeclass, API base URL, and external token references.
- [x] Copy Canvas Credentials provider config from Canvas program bindings into mirror delivery records for publishing.
- [x] Add provider connection validation for Canvas Credentials settings before publish.
- [x] Clarify that Canvas Credentials real-provider settings are organization binding configuration; `CANVAS_CREDENTIALS_*` env values are ops fallbacks/smoke-test inputs, not the production source of truth.
- [x] Add managed organization integration secrets so admins can save/rotate a Canvas Credentials API token and bindings store only `api_token_secret_id`.
- [x] Convert the binding controls into a guided setup wizard.
- [x] Remove local Canvas LMS bridge/private URL allowances from production deployment bundles.
- [x] Replace seeder-owned course/user/quiz assumptions with import/admin setup for real institution Canvas deployments.
- [x] Finalize production lifecycle mapping for revoke, suspend, and reinstate semantics.

Gate: production Canvas mirror links and provider configuration do not depend on demo routes, sandbox URLs, beta defaults, or global-only credentials.

## Slice 20 - Protocol Alignment and Real Canvas Admin Discovery

Goal: close the remaining gap between the Canvas product workflow and MIP protocol documentation/conformance.

- [x] Add a realistic MIP example package for the complete Canvas Open Badge flow:
  - Canvas fact requirement
  - Cedar approval PolicySet
  - remote DID issuer credential template
  - status-list revocation profile
  - Canvas Credentials delivery destination
  - employer verification presentation policy
- [x] Add self-host production checks that reject local/private Canvas public URLs and sandbox/bridge Canvas Credentials providers.
- [x] Add Canvas admin API discovery for courses, assignments, quizzes, and modules using secret references instead of pasted tokens.
- [x] Expose Canvas scope discovery through gateway routes.
- [x] Add binding-wizard controls to import Canvas activity IDs from the institution Canvas API.
- [x] Add targeted backend and UI tests for discovery.
- [x] Add a read-only Canvas Credentials contract checker for real provider sandbox validation.
- [x] Update the browser demo recorder to produce a step log and avoid accidental fallback mirror URLs.

Remaining outside code-only alignment:

- [ ] Validate the real Canvas Credentials assertion/badgeclass contract against an institution or vendor sandbox.
- [x] Run the browser-level end-to-end demo against the real seeded beta scenario and attach the video/step log artifact.
  - Recorded artifacts:
    - `tests/artifacts/canvas-employer-demo/canvas-employer-demo.webm`
    - `tests/artifacts/canvas-employer-demo/canvas-employer-demo-steps.json`

Gate: the protocol examples, admin setup path, and production checks all reinforce the same model: Canvas is a provider/delivery integration, while MIP owns evidence facts, policy, issuer identity, revocation status, and verification.

## Slice 21 - Console-Native Canvas UX Alignment

Goal: replace the demo-shaped Canvas/verification story with the normal ElevenID console model:

```text
Credential template -> destinations -> issuance/claim -> learner My Identity -> verifier org OID4VP flow
```

The beta demo proved the backend path, but the current UX still has two custom surfaces that should not be treated as product architecture:

- The Canvas Credentials sandbox page at `/credentials/{external_credential_id}` is handcrafted HTML in the sandbox receiver. It is useful as a fake external destination, but it is not a real Canvas Credentials page and should remain demo-only.
- The employer badge verification page is a public provenance lookup page. It is useful for explaining value, but employer verification should be performed through the verifier organization's normal verification console and OID4VP/presentation-policy flow.

### Target Product Model

- Learners see the Interoperable Credentials Foundations Badge in **My Identity** like any other issued credential.
  - Canvas evidence and Canvas mirror status appear as delivery/source metadata, not as a separate learner experience.
  - The claim flow still lets the learner consent to Canvas Credentials display when the issuer organization enabled that destination.
- Issuer admins configure Canvas Credentials under **organization destinations/integrations** and at the credential-template level.
  - The badge template should have a **Destinations** area showing Canvas Credentials publishing, projection policy, badgeclass mapping, and readiness.
  - Canvas Credentials is an organization-managed destination, not a holder wallet.
- Verifier organizations verify the badge through **Credential Verification** in the org console.
  - The verifier selects a saved verification flow or presentation policy.
  - ElevenID generates an OID4VP request/QR/deep link.
  - Verification results show canonical issuer DID, trust profile decision, revocation/status-list result, credential claims, and any Canvas mirror provenance.
- Canvas mirror/provenance links are organization-console links. Canvas mirror lookup is an authenticated support/admin workflow; employer verification should use the normal OID4VP flow whenever the holder can present from a wallet.

### Phase 21A - Route and Information Architecture Cleanup

- [x] Inventory demo-only routes and label them explicitly:
  - Canvas sandbox `/credentials/{external_credential_id}`
  - removed public Canvas credential verification route
  - removed legacy employer demo verification route
- [x] Update docs and recorder overlays so the Canvas sandbox page is described as an external destination simulator, not a Canvas product screen.
- [x] Stop describing the public employer provenance lookup as the canonical employer verification flow.
- [x] Remove the public Canvas credential verification route; Canvas mirror/provenance links now target `/console/org/operate/verify` directly.

Gate: demo-only pages are visibly marked as demo/support surfaces and no longer define the product UX.

### Phase 21B - Credential Template Destinations

- [x] Add or repair credential template detail routing for `/console/org/templates/credentials/:id`.
- [x] Add a **Destinations** tab/section to credential template details.
- [x] Reuse the delivery destination registry to show supported destinations:
  - ElevenID wallet
  - generic OID4VCI wallets
  - Canvas Credentials institutional mirror
  - Canvas/Parchment learner backpack when supported
- [x] For Canvas Credentials, show organization destination readiness, projection policy, and active Canvas program bindings using the template.
- [x] Add Canvas badgeclass/entity mapping to credential-template destination detail.
- [x] Add last mirror health / drift summary to credential-template destination detail.
- [x] Move destination-specific setup affordances out of the broad Canvas integration page where they belong to a specific credential template.

Gate: an issuer admin can open the Interoperable Credentials Foundations Badge template and see exactly where that badge can be delivered or mirrored.

### Phase 21C - Learner My Identity Alignment

- [x] Ensure the Canvas-earned badge appears in My Identity as a normal issued credential/application row.
- [x] Improve application/credential details to show credential name, issuer DID when present, issuance/application status, Canvas course/source context, and Canvas Credentials mirror delivery status when present.
- [x] Add credential image rendering in My Identity details and rows when badge artwork is available.
- [x] Add explicit claim status/detail rendering separate from application status.
- [x] Remove Canvas-special wording from the primary learner flow except where it explains source/delivery metadata.
- [x] Keep Canvas Credentials consent in the claim dialog, but phrase it as "Also show this badge in Canvas Credentials" rather than a wallet choice.

Gate: a learner does not experience Canvas issuance as a special one-off application; it behaves like any other credential with Canvas as the source/destination context.

### Phase 21D - Verifier Console Flow for Employers

- [x] Extend `/console/org/operate/verify` so a verifier can start from a saved verification flow, not only a raw presentation policy.
- [x] Add a clear "New verification" path:
  - select verification flow / presentation policy
  - configure purpose/reference
  - generate OID4VP QR/deep link/request URI
  - show polling/status/result
- [x] Add result rendering for Open Badge credentials:
  - badge name/image/issuer
  - trust profile result
  - revocation/status result
  - selected claims
  - Canvas mirror provenance when the credential or presentation references a Canvas mirror
- [x] Support optional provenance lookup by Canvas mirror ID inside the console as a secondary lookup tool.
- [x] Update the demo recording to end in org console verification instead of the public employer page.

Gate: an employer/verifier demonstrates value by using the normal ElevenID verification console and OID4VP request flow.

### Phase 21E - Sandbox and Real Canvas Credentials Boundaries

- [x] Keep the sandbox Canvas Credentials display page only as a fake external destination for beta/local testing.
- [x] Rename visual copy from "Canvas Credentials" to "Canvas Credentials Sandbox" unless running against a real provider response.
- [x] For real Canvas Credentials provider mode, use the provider-returned credential URL/display URL only.
- [x] Remove sandbox-only "Verify with Employer View" calls to action from the product demo narrative.

Gate: the demo makes it obvious what is real Canvas/LTI/MIP/issuance and what is only a local stand-in for an external Canvas Credentials display.

### Phase 21F - Demo and Documentation Refresh

- [ ] Re-record the Canvas demo after UX alignment:
  - Canvas LTI launch
  - learner My Identity badge
  - credential template destination setup
  - org console verification flow/OID4VP request
  - verification result with Canvas provenance metadata
- [x] Update `canvas-real-test-environment.md` so the demo story follows the console-native flow.
- [x] Update the Playwright recorder to include the org console verification surface when an authenticated verifier storage state is supplied.
- [x] Keep a short appendix for the sandbox display/provenance lookup, clearly labeled as non-product/demo support.

Gate: the video, docs, and UI all tell the same story: Canvas supplies learning context and can receive a mirror, while ElevenID owns issuance, wallet claim, destinations, verification flows, trust, and status.
