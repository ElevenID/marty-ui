# Beta UI/UX Improvement Plan

This plan converts `docs/beta-ui-ux-complexity-review.md` into approval-ready work items. Each item is scoped so it can be approved, rejected, or deferred independently.

## Development Goal

Implement all UX improvements in this plan so the beta ElevenID experience becomes an intent-first, MIP-aligned product surface: public paths should resolve to purposeful destinations, console navigation should expose the core MIP primitives clearly, flow creation should use protocol-correct language and values, setup readiness should branch by user intent, and runtime/governance surfaces should make flows, policies, compliance, audit, and integrations easy to find, operate, and verify.

Success means every approved work item from UX-000 through UX-206 is either implemented and tested, explicitly rejected with rationale, or deferred with dependency notes; no remaining beta UX path depends on fallback routing, misleading issuance-only language, hidden Presentation Policy access, stale `/api` examples, or an undocumented divergence from the MIP protocol model.

Use this as a decision ballot. A useful approval reply can be as short as:

```text
Approve UX-001, UX-002, UX-003, UX-004, UX-005.
Defer UX-101 and UX-102.
Reject UX-201.
```

## Decision Summary

| ID | Priority | Recommendation | Dependency | Estimate | Decision |
| --- | --- | --- | --- | --- | --- |
| UX-000 | P0 | Correct beta hostname references | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-001 | P0 | Fix public CTA fallback paths | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-002 | P0 | Remove `/test-harness` from public sitemap | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-003 | P0 | Add Presentation Policies to sidebar | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-004 | P0 | Rename "Issuance Flows" to "Flows" | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-005 | P0 | Fix audit route consistency | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-006 | P0 | Surface empty active Compliance Profiles on beta | None | S/M | [ ] Approve [ ] Reject [ ] Defer |
| UX-101 | P1 | Normalize UI FlowType values to MIP values | UX-004 recommended | M | [ ] Approve [ ] Reject [ ] Defer |
| UX-102 | P1 | Replace freeform protocol step editing with locked MIP sequences and hooks | UX-101 | L | [ ] Approve [ ] Reject [ ] Defer |
| UX-103 | P1 | Replace legacy `/api/issuance/*` examples with `/v1/issuance/*` | None | S | [ ] Approve [ ] Reject [ ] Defer |
| UX-104 | P1 | Split setup readiness by intent | UX-006 recommended | L | [ ] Approve [ ] Reject [ ] Defer |
| UX-105 | P1 | Canonicalize sitemap path and tag variants | UX-002 recommended | M | [ ] Approve [ ] Reject [ ] Defer |
| UX-201 | P2 | Reorganize console IA into Design/Govern/Deploy/Connect/Operate/Org | UX-003, UX-004 | L | Implemented 2026-07-11 |
| UX-202 | P2 | Make Flow Instances the runtime spine | UX-201 recommended | L | Implemented 2026-07-11 |
| UX-203 | P2 | Clean up auth and proxy namespace story | Needs deployment/proxy review | M/L | [ ] Approve [ ] Reject [ ] Defer |
| UX-204 | P2 | Consolidate public learning IA | UX-001, UX-105 | L | [ ] Approve [ ] Reject [ ] Defer |
| UX-205 | P2 | Add Policy Sets to governance UX | UX-201 recommended | M/L | Implemented 2026-07-11 |
| UX-206 | P2 | Add advanced MIP object map to wizards | UX-101, UX-104 recommended | M | [ ] Approve [ ] Reject [ ] Defer |

Estimate scale:

- S: narrow copy, route, nav, or test change.
- M: several components or data-shape changes, but limited product ambiguity.
- L: requires UX decisions, state model changes, or cross-page behavior.

## Implementation Status

| ID | Status | Evidence |
| --- | --- | --- |
| UX-000 | Implemented | Incorrect beta hostname references removed; docs use `beta.elevenidllc.com`. |
| UX-001 | Implemented | `/verification`, `/issuance`, and `/docs/quickstart` now route to canonical destinations with tests. |
| UX-002 | Implemented | `/test-harness` excluded from sitemap and robots output. |
| UX-003 | Implemented | Presentation Policies added as a first-class Design sidebar item with active-nav coverage. |
| UX-004 | Implemented | Generic "Issuance Flows" labels replaced with "Flows"; flow routes unchanged. |
| UX-005 | Implemented | In-app audit links use the canonical `/console/org/audit` route. |
| UX-006 | Implemented | Setup readiness surfaces an empty active Compliance Profiles state from lifecycle data. |
| UX-101 | Implemented | Flow wizard cards now store/submit MIP FlowType values while retaining friendly labels; focused wizard tests pass. |
| UX-102 | Implemented | Standard flows use locked server-resolved MIP sequences and constrained hooks; custom orchestration uses a separate extension builder and schema. |
| UX-103 | Implemented | Flow step endpoint examples use canonical `/v1/issuance/*` paths. |
| UX-104 | Implemented | Dashboard readiness branches by Verify, Issue, Application Approval, Physical Document, and Lifecycle; optional deployments no longer block protocol-valid flows. |
| UX-105 | Implemented | Blog tag URLs now slugify punctuation-heavy labels into canonical ASCII paths, redirect legacy tag variants, and generate sitemap-ready tag routes without encoded punctuation. |
| UX-201 | Implemented | Console navigation is organized into Design, Govern, Deploy, Connect, Operate, Org, Audit, and Billing. |
| UX-202 | Implemented | Operate lands on Flow Instances; the list uses one organization-wide query and detail shows timeline, current step, and safe related-record links. |
| UX-203 | Deferred | Requires production proxy/deployment ownership review before changing auth namespace behavior beyond the local audit/public route fixes. |
| UX-204 | Deferred | Depends on UX-105 plus content/SEO approval for a Learn/Build/Trust public learning IA rewrite. |
| UX-205 | Implemented | Govern includes Policy Sets with guided templates, advanced Cedar authoring, validation, activation, archive, gateway scoping, and migration coverage. |
| UX-206 | Implemented | Flow wizard review includes an expandable MIP object map with bound/missing status and links for compliance, trust, templates, policies, flows, and deployments. |

### MIP 0.3 Program Additions

The approved implementation expanded the original UX ballot where protocol changes were necessary to make the experience truthful:

| Workstream | Status | Delivered contract/product behavior |
| --- | --- | --- |
| Canonical Flow contract | Implemented | MIP 0.3 aligns FlowTypes, fixed sequences, required references, custom extensions, physical document jobs, examples, conformance fixtures, and generated Python/Rust/TypeScript bindings. |
| Applicant API clean break | Implemented; coordinated redeploy pending | Canonical organization review and `/v1/me/*` self-service routes replace all `/v1/applicants/*` routes; persisted organization ownership, immutable applicant-profile scope, target issuer scope, permissions, caller-derived locks, and header stripping are enforced. |
| Application contract | Implemented; coordinated redeploy pending | Creation accepts only organization, active Application Template, form data, and integration context; owner, Credential Template, checks, approval, and issuer behavior are server-derived. |
| Claim readiness and holder inventory | Implemented; coordinated redeploy pending | `claim_state` and `claim_blocker` prevent false Claim actions; `/v1/issued-credentials/mine` replaces `/v1/documents` with a privacy-filtered inventory. |
| Application Template authoring | Implemented; coordinated redeploy pending | Create, advanced-create, detail, edit, preview, validation-gated activation, and deletion routes are registered; catalog visibility requires an active Application Template. |
| Deterministic reviewer | Implemented; coordinated redeploy pending | `reviewer@marty.demo` is provisioned through deployment variables, Keycloak bootstrap, and Marty organization reviewer membership. |
| Protocol bindings | Released 2026-07-12 | MIP 0.3 applicant and holder schemas regenerate Python, Rust, and TypeScript; protocol conformance, codegen drift, and the pinned Rust wheel pass in CD. |
| Clean-break service migration | Implemented | Flow persistence and APIs use `resolved_steps`, explicit extensions, canonical triggers/hooks, DRAFT creation, validation, dry-run, and activation gates; legacy noncanonical graphs migrate to `custom`. |
| Physical document issuance | Implemented | Encrypted intake, data-group generation, remote or explicit test signing, personalization handoff/status, quality verification, activation, webhook updates, safe flow state, capability gating, and production destination authoring. |
| Guided setup | Implemented | Readiness follows protocol-required references, reports service failures as blockers, and exposes physical capability and approval-policy dependencies without treating optional deployment as mandatory. |
| Operational spine | Implemented | Flow Instances is the Operate landing surface and joins runtime state to definitions, applications, credentials, and physical production jobs. |
| Protected wallet promotion | Implemented; execution pending | A protected workflow validates SpruceKit login, seven active app-specific native handoffs, signed-request identity, evidence checksums, exact build/beta run linkage, and is the only path from build-ready to release-ready. |

Remediation and historical deployment verification completed on 2026-07-11/12; the current post-audit revision requires a new coordinated deployment:

- MIP protocol code generation is current; the working revision passes `125` tests, generated-binding drift checks, Rust compile tests, and the TypeScript build.
- The external issuance repository passes `257` tests with 11 explicit skips that require optional integration/runtime facilities.
- The MIP 0.3 deterministic browser gates pass membership, credential login, organization creation/verification, and full credential lifecycle with no unexpected requests or page exceptions.
- The production UI bundle and complete frontend suite pass; `742` UI/service tests pass with one explicit skip, and all `167` CLI tests pass.
- CD rejects unset or mutable repository revisions and records exact 40-character SHAs for UI, protocol, credentials, core, CLI, blog, and subscriptions.
- Atomic CD run `29185132375` passed and published immutable services, public UI, self-host UI, and migration image digests in release `mip-0.3.0-beta-20260712-r6`.
- Live beta canonical applicant and claim probes pass, removed routes return `404`, and the final-spec Marty browser wallet receives fresh holder-bound credentials.
- The 2026-07-12 MIP `0.3.1` lifecycle run completes explicit logout and membership-badge login, Application Template activation, signed DCQL verification, first-class renewal, suspend/deny, reinstate/allow, revoke/deny, issuer-bound status lookup, and cross-org `403` with no unexpected browser or network errors.
- Applicant-to-flow issuance now accepts credential content only through canonical `data.claims`; top-level event metadata is never promoted into a credential. Live Jane Smith evidence shows three applicant-supplied form values and server-derived membership, organization, timestamp, and role claims in the issuance transaction.
- Credential login profile upsert now forwards authenticated organization context, and disabled Keycloak token exchange is configuration-driven rather than discovered through a known-failing request. Post-restart login logs contain no provisioning warning or token-exchange `400`.
- The strengthened migration path was exercised against the preserved pre-cutover beta PostgreSQL dump in an isolated `beta-copy-*` database. All ten migration heads verified, active Credential Templates retained revocation dependencies, applications retained Application Template links, flows retained canonical types, and renewal columns were present; the isolated copy was removed afterward.
- The completion pass fixed cross-organization application ownership, selected-organization reviewer requests, signing-key capability proxying, canonical-only Flow statuses, and removed Credential Template request fields. Focused regressions and the complete suites pass.
- Marty Core now publishes the workspace lockfile, vendored `core2` patch, and browser test-wallet crate required by the beta workflow's locked build. Its dedicated release workflow checks those sources, passes 150 final-spec OID4VCI/wallet tests, and compiles Python bindings against the same locked engine; CD requires that exact-SHA workflow result.
- All eight UI service Alembic trees and the external issuance migration tree resolve to exactly one head. The next protected rehearsal must still use the final pinned migration image and identified beta copy.

Remaining acceptance execution is limited to collecting protected SpruceKit Open Badge login and native-wallet device evidence for the exact build and beta run, then running the wallet-conformance promotion workflow. The repository-side evidence contract and fail-closed promotion gate are implemented. Walt.id is inactive and not advertised because tested community images still fail final OID4VCI proof and signed DCQL presentation contracts.

## Approval Philosophy

Default recommendation:

1. Approve all P0 items first. They remove confusion that looks broken or misleading.
2. Approve UX-101 and UX-103 next. They align visible protocol vocabulary with MIP.
3. Approve UX-104 only after deciding how much the dashboard should become intent-first now versus in the full IA redesign.
4. Treat P2 as product direction. These are valuable, but they should be approved only if the team wants a more opinionated console shape.

Original first-pass non-goals, now superseded by the approved MIP clean break:

- Do not rewrite the full public site in the first pass.
- Removed routes, aliases, dual reads, and mixed MIP versions are not retained.
- Protocol changes are coordinated through MIP `0.3.1`, generated bindings, conformance fixtures, and an atomic deployment.
- Do not touch unrelated blog content or workspace files.

## Dependency Map

```text
P0 cleanup
  UX-000 hostname reference correction
  UX-001 public CTA routes
  UX-002 sitemap test-harness removal
  UX-003 Presentation Policies nav
  UX-004 Flows naming
  UX-005 audit route consistency
  UX-006 compliance profile readiness signal

Protocol alignment
  UX-004 -> UX-101 FlowType normalization
  UX-101 -> UX-102 locked MIP flow sequences
  UX-103 can ship independently

Setup model
  UX-006 -> UX-104 intent-specific readiness
  UX-104 -> UX-206 MIP object map

Information architecture
  UX-003 + UX-004 -> UX-201 console IA
  UX-201 -> UX-202 runtime spine
  UX-201 -> UX-205 Policy Sets governance

Public site
  UX-001 + UX-002 -> UX-105 sitemap canonicalization
  UX-105 -> UX-204 learning IA consolidation
```

## P0 Work Items

### UX-000: Correct Beta Hostname References

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve.

Problem:

Some UI/UX planning docs referenced an incorrect beta hostname. The correct beta host is `https://beta.elevenidllc.com`.

Proposed work:

- Update docs and internal references to consistently use `beta.elevenidllc.com`.
- Remove wording that preserves the incorrect hostname as a historical note, alias, or DNS issue.

Likely repo files:

- `docs/beta-ui-ux-decision-tree.md`
- `docs/beta-ui-ux-complexity-review.md`
- `docs/beta-ui-ux-improvement-plan.md`

Acceptance criteria:

- Internal docs reference `beta.elevenidllc.com` as the beta endpoint.
- Searches for the incorrect hostname return no matches.

Risk:

- Low. This is a documentation-only correction.

Rollback:

- Revert the documentation wording.

### UX-001: Fix Public CTA Fallback Paths

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve redirects now; consider dedicated pages later.

Problem:

Public content links to `/verification`, `/issuance`, and `/docs/quickstart`, but these are not explicit public React routes in the decision tree. The server returns the SPA shell, then client routing falls through instead of presenting a purposeful page.

MIP/UX rationale:

Issuance and verification are two primary MIP user intents. They should be first-class paths, not fallback behavior.

Recommended implementation:

- Add explicit route handling for:
  - `/verification`
  - `/issuance`
  - `/docs/quickstart`
- Short-term behavior:
  - `/verification` redirects to `/what-is-credential-verification` or `/verifiable-credential-api`.
  - `/issuance` redirects to `/open-badges-issuance` or another canonical issuance page.
  - `/docs/quickstart` redirects to `/docs` with a quickstart section if available.
- Add tests that each path lands on a useful page and does not fall through to `/`.

Alternative A:

- Build dedicated landing pages for `/verification`, `/issuance`, and `/docs/quickstart`.
- Better UX, but more content and design work.

Alternative B:

- Change all existing CTAs to point to existing canonical pages and leave these paths unknown.
- Lower implementation cost, but old external links can still fail.

Likely repo files:

- `ui/src/variants/publicSite.public.jsx`
- `ui/src/apps/public/PublicRoutes.jsx`
- `ui/src/apps/public/PublicRoutes.test.tsx`
- `ui/src/variants/__tests__/publicSite.public.test.tsx`
- Possibly `marty-blog/src/components/ProductBridgeCTA.jsx` if CTA source lives in the blog repo.

Acceptance criteria:

- Visiting `/verification` on beta renders or redirects to a relevant verification page.
- Visiting `/issuance` on beta renders or redirects to a relevant issuance page.
- Visiting `/docs/quickstart` on beta renders or redirects to docs/quickstart content.
- None of the three paths end at `/` through the wildcard route.
- Tests cover all three paths.

Risk:

- Low if implemented as redirects.
- Medium if implemented as new pages because content/design quality matters.

Rollback:

- Remove explicit routes or restore CTA targets.

### UX-002: Remove `/test-harness` From Public Sitemap

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve.

Problem:

The live sitemap exposes `/test-harness`, which is a utility/test surface, not a public marketing or product path.

MIP/UX rationale:

The public sitemap should represent production user journeys and public content, not internal test utilities.

Proposed work:

- Exclude `/test-harness` from sitemap generation.
- Keep the route available for test fixtures if tests depend on it.
- Verify `robots.txt` and sitemap output do not invite crawlers to the test harness.

Likely repo files:

- `ui/vite.config.ts`
- Any sitemap route generation data used by Vite.
- Related sitemap tests if present.

Acceptance criteria:

- Built `sitemap.xml` does not include `/test-harness`.
- E2E tests that use `/test-harness` still work in the appropriate environment.
- No production public navigation links to `/test-harness`.

Risk:

- Low. Main risk is accidentally breaking test setup if route removal is confused with sitemap exclusion.

Rollback:

- Re-add route to sitemap config.

### UX-003: Add Presentation Policies To Sidebar

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve.

Problem:

Presentation Policies are a core MIP primitive and the main object for verification rules. The route and quick action exist, but the main admin sidebar does not expose Presentation Policies as a first-class item.

MIP/UX rationale:

MIP says verification behavior is driven by Presentation Policy configuration. Hiding this object makes verifier setup harder to discover.

Proposed work:

- Add "Presentation Policies" under the current Design group.
- Keep the existing route `/console/org/policies/presentation`.
- Ensure active nav matching works for:
  - `/console/org/policies/presentation`
  - `/console/org/policies/presentation/new`
  - `/console/org/policies/presentation/:id`
  - `/console/org/policies/presentation/:id/edit`
- Update navigation tests.

Alternative:

- Add a new "Govern" group now and place Presentation Policies there.
- Better long-term IA, but larger scope and overlaps with UX-201.

Likely repo files:

- `ui/src/config/navigation.js`
- `ui/src/config/__tests__/navigation.test.ts`
- `ui/src/components/navigation/SidebarNavigation.jsx`
- `ui/src/components/navigation/SidebarNavigation.test.tsx`

Acceptance criteria:

- Admin sidebar shows Presentation Policies for users with appropriate permissions.
- Clicking it navigates to `/console/org/policies/presentation`.
- Active state works on list/new/detail/edit routes.
- Existing Credential Templates and Compliance Profiles nav behavior is unchanged.

Risk:

- Low. Permission filtering needs a quick check.

Rollback:

- Remove nav entry.

### UX-004: Rename "Issuance Flows" To "Flows"

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve.

Problem:

The nav label "Issuance Flows" implies flows are only for issuance. MIP uses Flow Definitions for issuance, verification, renewal, revocation, and application approval.

MIP/UX rationale:

Flow is a central MIP primitive. The console should not train users into an issuance-only mental model.

Proposed work:

- Rename nav label from "Issuance Flows" to "Flows".
- Rename nearby description copy to mention "Flow Definitions, Deployment Profiles, Signing Keys" or similar.
- Audit dashboard quick actions for labels like "Create Issuance Flow" and change to "Create Flow" where the wizard supports multiple flow types.
- Keep route paths unchanged: `/console/org/flows/definitions`.

Alternative:

- Label as "Flow Definitions" everywhere.
- More precise for protocol users, slightly colder for normal operators.

Likely repo files:

- `ui/src/config/navigation.js`
- Translation/i18n files if labels are localized.
- `ui/src/components/console/flows/FlowDefinitionsPage.jsx`
- `ui/src/components/console/flows/__tests__/FlowDefinitionWizard.test.tsx`
- Any snapshot or navigation tests.

Acceptance criteria:

- Sidebar no longer says "Issuance Flows".
- Dashboard quick action no longer says "Create Issuance Flow" unless it starts an issuance-only path.
- Flow route paths remain stable.
- Tests and translations are updated.

Risk:

- Low. Main risk is stale i18n copy.

Rollback:

- Restore previous labels.

### UX-005: Fix Audit Route Consistency

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Implemented decision: use one canonical audit route and remove the retired alias.

Problem:

Several components link to `/console/audit`, while the console route table uses `/console/org/audit`. This creates inconsistent navigation and can fall into wildcard behavior.

MIP/UX rationale:

Auditability is a first-class trust signal in MIP. Audit links should be reliable from dashboard, runtime, and policy surfaces.

Recommended implementation:

- Update internal links to `/console/org/audit`.
- Remove the retired `/console/audit` route instead of retaining an alias.
- Update route tests to use only the canonical path.

Likely repo files:

- `ui/src/apps/console/ConsoleRoutes.jsx`
- `ui/src/components/console/ConsoleDashboard.jsx`
- `ui/src/components/console/dashboard/SystemStatusBar.jsx`
- `ui/src/components/console/dashboard/CriticalEventsPanel.jsx`
- `ui/src/components/console/dashboard/RecentActivityPanel.jsx`
- `ui/src/components/console/audit/AuditPage.jsx`
- `ui/src/components/Navigation.jsx`
- Related tests under `ui/src/components/console/audit/` and dashboard tests.

Acceptance criteria:

- All in-app audit links navigate to `/console/org/audit`.
- `/console/audit` is not registered.
- Audit page breadcrumbs use the canonical path.

Risk:

- Low. Any external bookmark to the retired route must be corrected.

Rollback:

- Restore the retired alias only by an explicit product decision.

### UX-006: Surface Empty Active Compliance Profiles

Decision:

- [x] Approve
- [ ] Reject
- [ ] Defer

Implementation status: Complete for the clean-break baseline.

Problem:

Credential Templates were previously able to activate through an inline `CUSTOM` fallback while discovery reported no active Compliance Profile. That made the visible dependency graph disagree with MIP and let clients author format behavior outside the referenced primitive.

MIP/UX rationale:

Users choose an active Compliance Profile; clients do not embed a replacement profile or author wallet compatibility inside a Credential Template.

Proposed work:

- Seed the immutable active system profile `OID4VC Core` and expose it to every organization.
- Require `compliance_profile_id` on Credential Template creation in the UI, gateway, service, schema, examples, and generated bindings.
- Auto-select the sole active profile, show the selector as required, and fail closed when none is available.
- Reject embedded `compliance_profile`, `wallet_configs`, and other removed client-authored compatibility fields.
- Publish active Compliance Profiles in MIP discovery through the canonical schema.
- Keep the empty state actionable:

```text
No active Compliance Profiles. Activate a profile before creating a Credential Template.
```

- Keep `/console/org/policies/compliance` as a read-only inventory until custom profile persistence and lifecycle routes are implemented; remove dead Create/Edit/Detail actions.

Alternative:

- Add organization-authored Compliance Profiles later as a complete draft/validate/activate lifecycle. Do not expose partial actions before persistence exists.

Likely repo files:

- `ui/src/config/dashboardRules.js`
- `ui/src/components/console/dashboard/SetupReadinessPanel.jsx`
- `ui/src/components/console/dashboard/GuidedSetupBanner.jsx`
- Compliance profile API/service files if a count is not already available.
- Tests for dashboard readiness.

Acceptance criteria:

- Discovery lists the active `OID4VC Core` profile.
- A fresh organization can select it and activate a Credential Template.
- Missing, inactive, malformed, embedded, or wrong-organization profile references fail closed.
- No Credential Template request contains `wallet_configs` or an inline Compliance Profile.
- The fresh-organization audit includes the system profile in its dependency-linked inventory.

Risk:

- Low for the system baseline. Custom organization-authored profile lifecycle remains intentionally out of scope.

Rollback:

- Revert the coordinated protocol, service, gateway, UI, and discovery release together; mixed behavior is unsupported.

## P1 Work Items

### UX-101: Normalize UI FlowType Values To MIP Values

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve after UX-004.

Problem:

The UI uses local flow type values such as `verification`, `issuance_oid4vci`, and `issuance`. The backend maps these aliases to MIP values, but the UI should store and submit protocol-aligned FlowType values.

MIP/UX rationale:

MIP defines protocol-aligned FlowType values. The UI can keep friendly names while persisting MIP vocabulary.

Recommended mapping:

| Current UI value | New UI payload value | User-facing label |
| --- | --- | --- |
| `verification` | `oid4vp_presentation` | Verify a credential |
| `issuance_oid4vci` | `oid4vci_pre_authorized` | Issue via OID4VCI |
| `issuance` | `oid4vci_pre_authorized` or remove if duplicate | Issue a credential |
| `combined` | Remove; use `application_approval_issuance` when it means application approval then issue | Application approval then issue |

Implemented product decision:

Replace `combined` with `application_approval_issuance` where the intent is collect application, approve, then issue. Do not retain a backend alias.

Proposed work:

- Update flow type cards to use MIP values.
- Update `ISSUANCE_FLOW_TYPES` and `PRESENTATION_FLOW_TYPES` sets.
- Update payload creation so `flow_type` is already normative before it reaches the backend.
- Reject removed FlowType values at the service boundary.
- Update review labels and tests.

Likely repo files:

- `ui/src/components/console/flows/FlowDefinitionWizard.jsx`
- `ui/src/components/console/flows/steps/FlowTypeStep.jsx`
- `ui/src/components/console/flows/steps/DeploymentBindingStep.jsx`
- `ui/src/components/console/flows/steps/ReviewStep.jsx`
- `ui/src/components/console/flows/steps/PreconditionsStep.jsx`
- `ui/src/components/console/flows/steps/FlowStepsConfigStep.jsx`
- `ui/src/components/console/flows/__tests__/FlowDefinitionWizard.test.tsx`
- Translation/i18n files.

Acceptance criteria:

- Creating a verification flow sends `flow_type: "oid4vp_presentation"`.
- Creating an issuance flow sends `flow_type: "oid4vci_pre_authorized"` unless the user selected another explicit MIP issuance type.
- UI labels remain friendly and do not expose raw enum strings as primary text.
- Backend alias support remains in place.
- FlowDefinitionWizard tests expect normative values.

Risk:

- Medium. Tests and component assumptions currently reference alias strings.

Rollback:

- Restore previous UI values. Backend aliases make rollback straightforward.

### UX-102: Replace Freeform Protocol Step Editing With Locked MIP Sequences And Hooks

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve after UX-101, but design carefully.

Problem:

The flow wizard lets users configure step sequences for protocol flows. MIP defines standard step sequences for each FlowType, so arbitrary protocol step editing can create flows that look valid but are not conformant.

MIP/UX rationale:

MIP says flows are automatable, but protocol behavior should remain data-driven and valid. Users should configure policy, trust, deployment, and hooks, not accidentally reorder OID4VCI/OID4VP internals.

Recommended implementation:

- For normative MIP flow types, show a read-only "MIP sequence preview".
- Add constrained hook slots:
  - Before flow starts
  - After application approval
  - After issuance
  - After verification
  - On failure
- Keep advanced custom sequence editing behind an explicit "Advanced custom flow" mode.
- Validate advanced custom flows server-side before activation.

Alternative:

- Keep the current editor but add warnings and validation.
- Lower scope, but still leaves protocol complexity in the primary path.

Likely repo files:

- `ui/src/components/console/flows/steps/FlowStepsConfigStep.jsx`
- `ui/src/components/console/flows/FlowDefinitionWizard.jsx`
- `ui/src/components/console/flows/steps/ReviewStep.jsx`
- `ui/src/components/console/flows/__tests__/FlowDefinitionWizard.test.tsx`
- Potential backend validation in `services/flow/main.py` if custom advanced flows need stricter activation checks.

Acceptance criteria:

- Selecting `oid4vci_pre_authorized` shows the sequence:

```text
create_offer -> token_exchange -> credential_request -> issue_credential
```

- Selecting `oid4vp_presentation` shows the sequence:

```text
create_request -> wallet_selection -> presentation_submission -> verify_presentation
```

- The primary wizard path does not allow reordering required protocol steps.
- Users can still configure approved hooks where supported.
- Advanced mode is visually distinct and includes validation.

Risk:

- High enough to warrant a dedicated PR. This changes wizard behavior and user expectations.

Rollback:

- Restore freeform editor as primary path.

### UX-103: Replace Legacy `/api/issuance/*` Examples With `/v1/issuance/*`

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve.

Problem:

Some flow step presets and docs/examples reference `/api/issuance/token` and `/api/issuance/credential`, while MIP's canonical resource prefix is `/v1/`.

MIP/UX rationale:

Developers copy endpoint examples. UI examples should teach the canonical protocol surface.

Proposed work:

- Replace visible or stored preset endpoint examples:
  - `/api/issuance/token` -> `/v1/issuance/token`
  - `/api/issuance/credential` -> `/v1/issuance/credential`
- Audit API docs UI for similar examples.
- Remove the legacy endpoint surface; removed paths must return `404`.

Likely repo files:

- `ui/src/components/console/flows/steps/FlowStepsConfigStep.jsx`
- `ui/src/components/ApiDocumentation.jsx`
- Tests that assert preset configs.

Acceptance criteria:

- UI examples show `/v1/issuance/*`.
- No user-facing wizard text teaches `/api/issuance/*` for canonical MIP flows.
- Existing backend routes are not removed.

Risk:

- Low.

Rollback:

- Restore previous strings.

### UX-104: Split Setup Readiness By Intent

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve as a design/implementation epic, but do not bundle into P0.

Problem:

The current readiness model uses a universal setup order:

```text
trust -> template -> policy -> deployment -> flow
```

That order is issuer-biased and makes verifier-only setup depend on objects it may not need.

MIP/UX rationale:

MIP primitives combine differently for issuance, verification, application approval, renewal, and revocation. Readiness should branch by intent.

Proposed readiness model:

```text
Verify
  Compliance Profile -> Trust Profile -> Presentation Policy -> Verification Flow -> Deployment/API key

Issue
  Compliance Profile -> Issuer identity/KMS -> Trust Profile -> Credential Template -> Issuance Flow -> Delivery

Application approval then issue
  Application Template -> Approval PolicySet -> Compliance Profile -> Credential Template -> application_approval_issuance Flow

Revoke/Renew
  Credential Template -> Revocation Profile -> credential_revocation/credential_renewal Flow
```

Open product decisions:

- [ ] Should first-run setup ask the user to choose an intent before showing readiness?
- [ ] Should dashboard show all intents at once or one selected intent?
- [ ] Should Compliance Profile block all intents or only production flow activation?
- [ ] Should verifier-only trust profiles be creatable without issuer identity/KMS?

Recommended subdecisions:

- First-run setup should ask for intent.
- Dashboard should show a selected primary intent plus secondary intent cards.
- Compliance Profile should block production flow activation, not browsing or draft creation.
- Verifier-only Trust Profiles should not require issuer identity/KMS.

Likely repo files:

- `ui/src/config/dashboardRules.js`
- `ui/src/components/console/dashboard/GuidedSetupBanner.jsx`
- `ui/src/components/console/dashboard/SetupReadinessPanel.jsx`
- `ui/src/components/console/dashboard/RuntimeReadinessPanel.jsx`
- `ui/src/components/console/ConsoleDashboard.jsx`
- Dashboard tests.

Acceptance criteria:

- A verifier-only org can progress through trust, presentation policy, and verification flow setup without creating a Credential Template.
- An issuer setup still requires issuer identity/signing readiness before production issuance activation.
- Dashboard copy reflects the selected intent.
- Existing setup data is migrated or interpreted without breaking older orgs.

Risk:

- Medium/high. This affects dashboard mental model and readiness gating.

Rollback:

- Restore single `SETUP_ORDER` model.

### UX-105: Canonicalize Sitemap Path And Tag Variants

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve after UX-002.

Problem:

The live sitemap has 474 raw URL entries but 244 unique normalized paths. Duplicate concepts appear in tag URLs, such as encoded and decoded variants of the same tag.

MIP/UX rationale:

This is less about MIP and more about reducing public-site ambiguity. A clean sitemap makes the product easier to understand and share.

Proposed work:

- Normalize trailing slash behavior in sitemap generation.
- Canonicalize tag slugs.
- Redirect duplicate tag variants to a single canonical tag URL.
- Decide how to handle punctuation-heavy tags such as `x.509` and `bbs+`.

Open product decisions:

- [ ] Keep punctuation in visible tag labels but slugify URL paths.
- [ ] Preserve technical punctuation in URL paths and rely on encoding.
- [ ] Remove low-value tag archive pages from sitemap entirely.

Recommended subdecision:

Keep punctuation in visible tag labels, but slugify URL paths to stable ASCII slugs. Example: visible `X.509`, URL `/blog/tag/x-509`.

Likely repo files:

- `ui/vite.config.ts`
- Blog route/tag generation helpers.
- `marty-blog/src/data/blogPosts.js` if source tags need canonical metadata.
- Sitemap tests or build validation scripts.

Acceptance criteria:

- Sitemap raw URL count is close to normalized unique path count.
- Encoded and decoded duplicate tag variants no longer both appear in sitemap.
- Duplicate tag routes redirect to canonical tag URLs.
- Existing shared article URLs keep working.

Risk:

- Medium. SEO and existing external links need redirects.

Rollback:

- Restore previous sitemap/tag generation.

## P2 Work Items

### UX-201: Reorganize Console IA Into Design/Govern/Deploy/Connect/Operate/Org

Decision:

- [x] Approve
- [ ] Reject
- [ ] Defer

Implemented decision: use Design, Govern, Deploy, Connect, Operate, Org, Audit, and Billing; retain existing resource routes.

Problem:

Current navigation mixes protocol primitives, operations, deployment, and governance in a way that makes MIP's mental model harder to learn.

Proposed IA:

```text
Design
  Credential Templates
  Application Templates
  Flows

Govern
  Trust Profiles
  Revocation Profiles
  Presentation Policies
  Compliance Profiles
  Policy Sets

Deploy
  Deployment Profiles
  Issuer Identity
  Key Management

Operate
  Runs / Flow Instances
  Applications
  Issued Credentials
  Verification Sessions

Connect
  API Keys
  Webhooks
  Canvas / OpenBadges
  Delivery Destinations

Org
  Team
  Settings
  Roles and requests
  Notifications
```

Open product decisions:

- [x] Use "Design" as the first group name.
- [x] Keep "Flow Instances" for runtime.
- [x] Put Compliance Profiles under Govern.
- [x] Put API Keys under Connect.

Implemented subdecisions are recorded above. Deploy remains separate because runtime packaging and signing infrastructure are materially different from integrations.

Likely repo files:

- `ui/src/config/navigation.js`
- `ui/src/components/navigation/SidebarNavigation.jsx`
- Navigation tests and i18n.

Acceptance criteria:

- Admin nav groups match the approved IA.
- Existing routes still work.
- Active nav state remains correct.
- Permission filtering remains correct.
- User-facing labels are clear without relying on protocol jargon.

Risk:

- Medium/high. IA changes can disorient existing users.

Rollback:

- Restore previous nav grouping.

### UX-202: Make Flow Instances The Runtime Spine

Decision:

- [x] Approve
- [ ] Reject
- [ ] Defer

Implemented decision: keep the protocol-accurate "Flow Instances" label and make it the Operate landing surface.

Problem:

MIP defines Flow Instance as one runtime execution of an identity operation. The console splits runtime across Applications, Issued Credentials, Flow Instances, and Verification Sessions without a single primary spine.

Implemented work:

- Make Flow Instances the default Operate landing page.
- Preserve direct filtered views for:
  - Applications
  - Issued Credentials
  - Verification Sessions
- Deep-link instance details to related records present in safe runtime context.

Open product decision:

- [ ] Use "Runs".
- [ ] Use "Activity".
- [x] Keep "Flow Instances".

The detail view exposes only safe runtime context and links to flow definitions, applications, issued credentials, and physical production jobs.

Likely repo files:

- `ui/src/components/console/flows/FlowInstancesPage.jsx`
- `ui/src/components/console/operate/OperatePage.jsx`
- `ui/src/components/console/operate/ApplicationsPage.jsx`
- `ui/src/components/console/operate/IssuancePage.jsx`
- `ui/src/components/console/operate/VerificationSessionsPage.jsx`
- Audit and activity panels.

Acceptance criteria:

- Operate default view is approved runtime spine.
- Each runtime object has a link to audit/history.
- Users can still reach applications, credentials, and verification sessions directly.
- Empty states explain relationship between Runs and filtered views.

Risk:

- High enough for design review and staged rollout.

Rollback:

- Restore Operate routing and nav defaults.

### UX-203: Clean Up Auth And Proxy Namespace Story

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve investigation, defer implementation until proxy/deployment ownership is clear.

Problem:

The decision tree found multiple auth/callback paths and proxy-owned namespaces. `/auth/*` can be backend-owned while `/console/auth/callback` remains React-owned. Public callback routes may behave differently depending on proxy order.

Proposed work:

- Document namespace ownership:
  - React public routes
  - React console routes
  - Gateway `/v1/*`
  - Legacy `/api/*`
  - Keycloak `/realms/*` and `/resources/*`
  - Auth service `/auth/*`
  - Wallet/protocol public endpoints
- Standardize console auth callback on `/console/auth/callback`.
- Redirect or remove unused callback routes.
- Confirm production proxy config does not intercept intended React routes.

Likely repo files:

- `ui/src/apps/public/PublicRoutes.jsx`
- `ui/src/apps/console/ConsoleRoutes.jsx`
- Proxy/tunnel config files.
- Auth service/gateway config where route ownership is defined.

Acceptance criteria:

- One canonical console callback route is documented and tested.
- Public callback routes either work intentionally or redirect intentionally.
- Proxy namespace ownership is documented.
- Auth callback tests cover canonical and legacy paths.

Risk:

- Medium/high because deployment config matters.

Rollback:

- Restore previous routes/proxy behavior.

### UX-204: Consolidate Public Learning IA

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Defer until route and sitemap fixes are complete.

Problem:

The public site has many overlapping learning paths around identity, verification, issuance, protocols, architecture, resources, and blog content.

Proposed IA:

```text
Learn
  What is verifiable identity?
  How MIP works
  Standards and ecosystems

Build
  Issue credentials
  Verify credentials
  API quickstart

Trust
  Compliance
  Privacy and disclosure
  Architecture and auditability
```

Open product decisions:

- [ ] Make these top-level nav groups.
- [ ] Keep current nav but organize landing pages around these buckets.
- [ ] Only apply this structure to docs/resources.

Recommended subdecision:

Start by organizing landing pages and CTAs around these buckets; do not overhaul top nav until analytics support it.

Likely repo files:

- Public route components.
- Marketing content data.
- Blog CTA components.
- Sitemap and structured data generation.

Acceptance criteria:

- Every public product CTA points into Learn, Build, or Trust.
- Issue and Verify have canonical landing paths.
- Duplicate learning pages either redirect, cross-link, or clearly serve distinct jobs.
- Sitemap reflects canonical public IA.

Risk:

- Medium/high because it touches content strategy and SEO.

Rollback:

- Restore previous nav/content links.

### UX-205: Add Policy Sets To Governance UX

Decision:

- [x] Approve
- [ ] Reject
- [ ] Defer

Implemented decision: ship guided authoring with validation rather than a read-only interim surface.

Problem:

MIP uses Cedar Policy Sets for deny-by-default authorization and conditional verification/issuance rules. The current IA does not make Policy Sets prominent.

Proposed work:

- Add Policy Sets under Govern.
- Make clear distinction between:
  - Org roles/RBAC: who can do things in the console.
  - Cedar Policy Sets: rules applied to identity operations.
- Provide read/list/detail first if full authoring is too large.

Open product decisions:

- [ ] Read-only Policy Set viewer first.
- [x] Full Policy Set editor with validation.
- [ ] Link out to docs only for now.

The shipped path provides guided approval, verification, and access templates plus an advanced Cedar editor, then requires validation before activation.

Likely repo files:

- `ui/src/config/navigation.js`
- New or existing policy set components.
- API service for `/v1/policy-sets`.
- Tests.

Acceptance criteria:

- Users can find Policy Sets under Govern.
- UI explains RBAC vs Cedar Policy Sets.
- Policy Set status and validation state are visible.
- No unsafe editing is introduced without validation.

Risk:

- Medium. Policy editing is high-stakes.

Rollback:

- Remove nav entry and route.

### UX-206: Add Advanced MIP Object Map To Wizards

Decision:

- [ ] Approve
- [ ] Reject
- [ ] Defer

Recommended decision: Approve after UX-101 and UX-104.

Problem:

Users need the simple intent-first path, but advanced users still need to understand which MIP objects will be created or bound.

Proposed work:

- Add an advanced review panel in setup/flow wizards.
- Show object dependencies for the selected intent.
- Highlight missing prerequisites and generated objects.
- Link each object to the relevant detail page after creation.

Example:

```text
Verify credential
  Compliance Profile: EUDI PID
  Trust Profile: EU Trusted List
  Presentation Policy: Age over 18
  Flow Definition: OID4VP presentation
  Deployment: Hosted QR verification
```

Likely repo files:

- Flow wizard components.
- Setup wizard components.
- Dashboard readiness components.
- Shared MIP object map component.

Acceptance criteria:

- Users can complete the wizard without reading the map.
- Advanced users can expand the map before final submit.
- Missing dependencies are visible and linked.
- The map uses MIP object names consistently.

Risk:

- Medium. This adds UI surface area but can reduce support confusion.

Rollback:

- Hide or remove the advanced panel.

## Recommended Approval Package

If the goal is to improve beta quickly without committing to a full redesign, approve this package:

- UX-000: Correct beta hostname references.
- UX-001: Fix public CTA fallback paths.
- UX-002: Remove `/test-harness` from sitemap.
- UX-003: Add Presentation Policies to sidebar.
- UX-004: Rename "Issuance Flows" to "Flows".
- UX-005: Fix audit route consistency.
- UX-006: Surface empty active Compliance Profiles.
- UX-103: Replace legacy `/api/issuance/*` examples with `/v1/issuance/*`.

This package removes the most obvious confusion while keeping implementation risk contained.

## Recommended Second Package

After the first package lands, approve this if the goal is protocol alignment:

- UX-101: Normalize UI FlowType values to MIP values.
- UX-102: Replace freeform protocol step editing with locked MIP sequences and hooks.
- UX-104: Split setup readiness by intent.
- UX-105: Canonicalize sitemap path and tag variants.

This package changes deeper product behavior and should get design/product review before implementation.

## Recommended Design Package

Approve these only if the team wants the console to become more intent-first and MIP-native as a product direction:

- UX-201: Reorganize console IA.
- UX-202: Make Runs the runtime spine.
- UX-203: Clean up auth/proxy namespace story.
- UX-204: Consolidate public learning IA.
- UX-205: Add Policy Sets to governance UX.
- UX-206: Add advanced MIP object map to wizards.

## Implementation Order If First Package Is Approved

1. UX-005 audit route consistency.
   - Small, contained, easy to test.
2. UX-003 Presentation Policies nav and UX-004 Flow naming.
   - Same navigation/config area.
3. UX-001 public CTA route handling.
   - Public route tests prove no wildcard fallback.
4. UX-002 sitemap test-harness exclusion.
   - Build artifact validation.
5. UX-006 compliance profile readiness signal.
   - Slightly more data-dependent.
6. UX-103 endpoint string cleanup.
   - Can be bundled with flow wizard test updates or shipped alone.

## Verification Plan

### MIP 0.3 Clean-Break Implementation Evidence

Status: the post-audit MIP `0.3.1` revision passes the complete local development lifecycle. A previous immutable local snapshot proved backup, rehearsal, build, deployment, and marker mechanics; a final snapshot deployment is required after the Compliance Profile correction. Local snapshots are never promotion evidence.

- Canonical self-service and organization-scoped applicant APIs replace the removed router and legacy routes.
- Application Template dependencies, authoritative field validation, reviewer locks, claim readiness, and holder inventory now fail closed.
- `ConsoleContext.activeOrgId` is the sole organization source for org-owned UI requests; the authenticated applicant organization is no longer mutable console state.
- Beta wallet and membership probes use canonical UI/self-service paths. Removed applicant routes are contacted only by explicit 404 contract probes.
- Direct credential links resolve the active linked Application Template before creating an application.
- Blocked approved applications show an issuer-owned waiting state and never expose Claim.
- The authenticated console shrinks correctly at 320px; holder inventory is overflow-free at 320, 390, 768, and 1440px.
- Deterministic Playwright coverage uses no conditional skips or soft assertions and exercises applicant, holder, and reviewer paths.
- Applicant profile ownership remains bound to the authenticated applicant organization while a new Application is persisted under its selected issuer organization; cross-organization regression coverage prevents either organization from being substituted for the other.
- Reviewer detail, evidence, lock, and decision requests use validated `ConsoleContext.activeOrgId`, including when the authentication default organization differs.
- Signing-key purpose and service-capability endpoints proxy to the signing-key service instead of returning a hard-coded unavailable response.
- Flow lifecycle parsing accepts only canonical MIP 0.3.1 statuses. Credential Templates require an active `compliance_profile_id`; gateway/service request models reject removed aliases, embedded profiles, issuer requirement fields, and client-authored wallet configuration.
- The real beta lifecycle workflow replaces the disabled legacy E2E job. It is dispatched after beta deployment, requires protected seeded-user secrets, and fails on mixed MIP versions, canonical-route failures, removed-route compatibility, holder-bound wallet rejection, badge-login failure, template activation failure, or verification decisions other than `allow`.
- The same workflow now begins with a disposable-organization browser gate. It creates and canonically verifies configured signing, active issuer/trust/revocation/Credential/Application/Presentation/Deployment resources, validated active issuance and verification flows, and an enabled API key before seeded lifecycle fixtures are trusted.
- The fresh-org gate returns nonzero for missing coverage, unexpected browser/network failures, incomplete inventory, or incorrect MIP dependency links. Evidence `beta-org-console-audit-20260712210137` passed all `66` checkpoints, selected the active system Compliance Profile, activated every primitive, and recorded no blocker, page exception, or failed request.
- Audit-driven UI fixes preserve `activate_immediately` through the Credential Template service boundary while stripping it from the create payload, and explicitly associate MUI labels with Application Template and Flow authoring selects.
- The beta artifact records the selected CD run and release plus immutable UI/Core revisions, lifecycle run ID, origin, and MIP version. CD embeds that release identity independently in the services and UI images; beta must read matching `/.well-known/marty-release` and `/marty-ui-release.json` markers before browser work begins. Protected promotion revalidates both markers, all seven coordinated repository revisions, exact image sets/digests, checksums, and reports.
- SpruceKit and seven active app-specific native handoffs use clean-break evidence schema v2. Altered signed requests, incorrect badge/issuer display, incomplete disclosure/login, missing device/OS identity, absent handoffs, duplicate attachments, and incomplete fresh-org evidence fail closed.
- Protected recordings, signed-request capture, and the handoff matrix are downloaded over HTTPS and verified byte-for-byte. Promotion is bound to the exact evidence JSON and records only attachment kind, hash, and size plus CD/beta/promotion run IDs.
- Credential Template activation now refreshes the managed issuer context and rejects an active Trust Profile that does not trust that issuer DID.
- Credential renewal is first-class: template validity policy is persisted on issuance, the operator receives a replacement offer, successful redemption revokes the superseded credential, and both records retain directional renewal links.
- The deterministic lifecycle gate verifies organization-owned status lists, renewal, suspend/deny, reinstate/allow, revoke/deny, and wrong-organization `403` behavior.
- The audit found a misplaced renewal-field read in the Canvas receipt mapper; the mapping now belongs to the issuance transaction mapper and has a focused regression assertion.
- Walt.id test images remain digest-pinned for diagnostics, but the registry entry is inactive and carries no supported capabilities until an upstream final-spec pair passes.
- External issuance CI now installs Alembic and requires one migration head; the current local graph resolves to `derive_server_owned_claims`.
- CD requires exact revisions for protocol, credentials, core, CLI, blog, and subscriptions. It runs pinned protocol conformance/binding checks and emits a 90-day atomic release manifest containing repository revisions, immutable image tags, wallet digests, and `mixed_versions_supported: false` before any UI or service image can publish.
- The `beta-migration-rehearsal` job requires a protected database restored from an identified beta snapshot. The URL must contain a `beta-copy-*` safety marker; there is no empty-schema fallback. It verifies every migration head, one-way applicant conversion, backup creation, and image digests before publishing a build-ready manifest that records the snapshot ID.
- Active Credential Template VCTs can no longer use `marty.example`. Migration head `20260712_0004` rewrites only active placeholder VCTs to the configured public origin and preserves deprecated values for historical audit.
- The protected beta-copy rehearsal now requires `MIGRATION_REHEARSAL_PUBLIC_API_URL`, binds that exact HTTPS origin into migrations, and records it in the build-ready manifest. Promotion rejects a rehearsal origin that differs from the tested beta origin.
- The beta lifecycle and protected promotion workflows both run `scripts/check_spruceid_metadata.py`. The probe requires identical canonical/appended metadata, issuer `ElevenID LLC`, `MemberCredential#spruce-sd-jwt`, the canonical membership VCT, badge name `Marty Verified Member Badge`, valid public HTTPS Spruce/mDoc configurations, and no placeholder host.
- The MIP discovery endpoint now validates against the strict 0.3.1 protocol schema. It publishes the required self URL, implementation classes, canonical issuance/verification endpoints, formats, flow types, signing algorithms, and active compliance codes; removed `api_base_url`, profile-object, endpoint-map, wallet-map, and authorization extensions are no longer emitted. The live beta gate asserts this shape rather than checking only the version string.
- Latest local browser evidence: `beta-org-credential-paths-20260713T030439` proves policy-bound issuance, Application Template activation, badge login, and browser-wallet verification allowed; `beta-credential-login-20260713T030427` independently proves badge receipt, logout, and authenticated return; `beta-credential-lifecycle-20260713T030519` proves linked renewal and destructive lifecycle decisions; `beta-membership-probe-20260713030407` proves canonical routes, removed-route `404`s, claim recovery, and zero browser errors.
- Migration evidence includes full pre-change PostgreSQL backups `deployment-mip-0.3.1-beta-20260712T161209/postgres-pre-template-clean-break-20260712T161209.dump` and `postgres-pre-system-claim-migration-20260712T162220.dump`; both one-way migrations were rehearsed on isolated restores before live application.

Local GitHub-independent release lane:

- `scripts/create_local_release_manifest.py` freezes tracked and untracked nonignored inputs for all coordinated repositories into checksum-addressed snapshots.
- `scripts/deploy-local-beta-release.ps1` verifies source and snapshot hashes, backs up stateful stores, rehearses migrations on an isolated beta-copy PostgreSQL database, builds release-tagged images, applies the live migration, recreates the app/UI atomically, and compares local/tunneled runtime markers.
- Every local manifest records `source_kind=local-worktree-snapshot`, `promotion_eligible=false`, and `release_ready=false`; this is a temporary execution path while protected GitHub features are unavailable.
- The earlier immutable run `mip-0.3.1-local-20260713T021224Z` completed successfully. The final post-Compliance-Profile snapshot must replace it before local completion evidence is current.
- Final local candidate `mip-0.3.1-local-20260713T031700Z` is reserved for that frozen snapshot; its deployment manifest and post-deployment browser reports are authoritative only after the run succeeds.
- Current verification: Marty UI/services `746 passed, 1 skipped`; MIP Protocol `125 passed`; generated bindings current; Rust and TypeScript builds pass; complete frontend test/build pass; local release contracts `23 passed`; PowerShell, nginx, and Compose validation pass.

Remaining external/device checks:

- publish every coordinated dirty repository and set all seven CD revision variables to those exact 40-character SHAs;
- rerun CD against an identified protected beta database copy with the exact HTTPS rehearsal origin, deploy the manifest's services/UI/migration image digests as one release, and dispatch beta lifecycle with that `release_version` and `cd_run_id`;
- require the new services/UI runtime markers and rerun all deterministic lifecycle evidence; older local beta reports cannot promote a newly built release;
- collect SpruceKit Open Badge login acceptance evidence in the protected device lane;
- collect all seven active app-specific native wallet handoffs in the device lab;
- run the protected wallet-conformance workflow to publish the first matching release-ready manifest;
- re-evaluate Walt.id only when an upstream image supports final OID4VCI `proofs` and the signed DCQL request without changing the standards-compliant contract.

No historical beta report may satisfy these remaining checks. CD, runtime markers, deterministic lifecycle evidence, protected attachments, and promotion must all name the same final coordinated revisions and immutable image digests.

Current GitHub preflight:

- `beta-lifecycle` and its seeded-user inputs are configured.
- `beta-migration-rehearsal` is missing its protected URL, safety marker, snapshot ID, and public-origin inputs.
- `wallet-conformance` must be created with protected review; configure its evidence bearer token only when attachment URLs require authentication.
- all coordinated revision variables still point at the previous release and must be changed only after the final repository revisions are published.
- CD now enforces this state from `deploy-config/github-release-environments.json` through `scripts/check_github_release_environments.py`; unsafe or incomplete GitHub configuration fails before image builds begin.
- ElevenID is on GitHub Free, the repository is private, branch-protection configuration returns an upgrade-required `403`, and no reviewer team exists. Use GitHub Enterprise for private required-reviewer rules (or explicitly review a public-visibility decision) and assign an independent release reviewer before attempting CD; do not remove the environment protections to fit the current entitlement.

For approved P0/P1 changes, run targeted tests first:

```text
ui/src/config/__tests__/navigation.test.ts
ui/src/components/navigation/SidebarNavigation.test.tsx
ui/src/apps/public/PublicRoutes.test.tsx
ui/src/variants/__tests__/publicSite.public.test.tsx
ui/src/apps/console/ConsoleRoutes.test.tsx
ui/src/components/console/flows/__tests__/FlowDefinitionWizard.test.tsx
```

Then run a production build or sitemap generation check for sitemap items.

Manual browser checks after deploy:

```text
https://beta.elevenidllc.com/verification
https://beta.elevenidllc.com/issuance
https://beta.elevenidllc.com/docs/quickstart
https://beta.elevenidllc.com/console/org/audit
https://beta.elevenidllc.com/sitemap.xml
https://beta.elevenidllc.com/.well-known/mip-configuration
https://beta.elevenidllc.com/.well-known/marty-release
https://beta.elevenidllc.com/marty-ui-release.json
```

## Approval Log

Use this section to record decisions.

| Date | Decision maker | Approved | Rejected | Deferred | Notes |
| --- | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD |

## Demo Publication Completion - 2026-07-15

Status: the two validated first-party scenarios are now recorded, automatically published, and deployed. This completes scenario-level publication, not release-level completeness.

- [x] Rebind draft `v2026.07.0` to beta marker `mip-0.3.1-local-20260714T214333Z` with the prior binding and `DRAFT_RELEASE_REBIND` reason preserved.
- [x] Upgrade public manifests to schema v2 with automated attestations, recording classifications, and revision history.
- [x] Replace manual editorial approval with an idempotent unlisted-to-public transaction and automatic rollback.
- [x] Record synchronized 1920x1080 sources and compose progressive 2560x1440 H.264 High Profile BT.709 masters.
- [x] Enforce reviewed captions, thumbnails, playlist membership, public embedding, OCR/QR/privacy scans, inactive offers, and release-marker/digest matching.
- [x] Publish Membership Badge and Login revision 2 as `ol0VxziVwMU`.
- [x] Publish Credential Lifecycle revision 2 as `DDjyuqs8Wpg`.
- [x] Preserve Organization and MIP Primitives only after an automated unchanged-path attestation and public playback verification.
- [x] Deploy final prerendered demo pages with version selection, chapters, transcripts, evidence summaries, revision history, and click-to-load YouTube playback.
- [x] Package immutable source, master, caption, transcript, chapter, thumbnail, functional, release, privacy, expiration, publication, smoke, and attestation evidence under `marty-demo-recorder/artifacts/2026.07.0-*-r2`.
- [x] Pass 39 recorder tests, the complete frontend suite, production build, final YouTube status checks, and responsive beta smoke checks.
- [ ] Qualify SpruceKit and the EUDI Android reference wallet as separate independent-wallet revisions.
- [ ] Publish the remaining required scenarios and advance release coverage only when every required result passes.

Release state remains `DRAFT` / `PARTIAL`. The public videos are product demonstrations using the ElevenID LLC first-party control wallet and are not represented as independent interoperability evidence.
