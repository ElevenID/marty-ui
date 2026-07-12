# Beta UI/UX Decision Tree and Dependencies

## Scope

The beta source of truth is `https://beta.elevenidllc.com`.

The live beta sitemap is fetched from `https://beta.elevenidllc.com/sitemap.xml`, but its `<loc>` values use the canonical host `https://elevenidllc.com`. Paths are identical on beta unless a proxy namespace intercepts them.

Included here:

- Public React routes from `ui/src/apps/public/PublicRoutes.jsx` and `ui/src/variants/publicSite.public.jsx`
- Console React routes from `ui/src/apps/console/ConsoleRoutes.jsx`
- Live beta sitemap paths, normalized to unique paths
- Source-declared paths that are reachable through SPA fallback but absent from the sitemap
- Non-UI proxy namespaces that affect UX path handling

Not included as UI paths:

- Backend API internals under `/v1/*`, `/api/*`, `/auth/*`, `/.well-known/*`, `/org/*`, `/credentials/*`, and related protocol namespaces
- Static image, JS, CSS, locale, and font assets

Decision-tree annotations used below:

- `[CURRENT]`: implemented and reachable in the current source.
- `[FRICTION]`: reachable, but the interaction creates avoidable work or ambiguity.
- `[MIP GAP]`: current UI behavior or vocabulary does not match the MIP model.
- `[OPPORTUNITY]`: proposed product behavior; not implemented.
- `[RESIDUAL]`: the primary path is implemented, but a follow-on improvement remains.
- `[DEPENDENCY]`: another MIP object, service, or product decision must be ready first.

Implementation baseline: source state after the MIP 0.3 credential-management clean break on 2026-07-11. The path inventories remain exhaustive for source-declared UI routes; live deployment checks still depend on the beta release carrying this source revision.

## Request Decision Tree

```text
Browser request
|
+-- Host is beta.elevenidllc.com?
    |
    +-- Proxy-owned namespace?
    |   |
    |   +-- /v1/*                         -> gateway services
    |   +-- /api/*                        -> gateway or legacy API
    |   +-- /auth/*                       -> backend auth service
    |   +-- /realms/*, /resources/*        -> Keycloak
    |   +-- /.well-known/*                -> OID4VCI/OAuth discovery, except ai-plugin exact static file
    |   +-- /org/*, /orgs/*               -> protocol metadata or JSON 404, not React UI
    |   +-- /oid4vp/*                     -> verifier DID namespace or JSON 404
    |   +-- /credentials/*                -> credential metadata/assets
    |   +-- /openapi.json                 -> OpenAPI schema for /docs
    |   +-- /ready, /health, /health/ready -> service health/readiness
    |
    +-- /console or /console/*?
    |   |
    |   +-- Serve console entry
    |       |
    |       +-- Auth loading?             -> loading state
    |       +-- Not authenticated?        -> /login, preserving attempted path
    |       +-- Authenticated?
    |           |
    |           +-- /console              -> choose landing path
    |           |   |
    |           |   +-- org bootstrap required and no memberships -> /console/org/setup
    |           |   +-- mode=org and activeOrgId exists          -> /console/org
    |           |   +-- otherwise                                -> /console/applicant/catalog
    |           |
    |           +-- /console/org/*         -> requires org:view plus active org
    |           +-- /console/org/setup     -> requires auth only
    |           +-- /console/applicant/*   -> requires auth; works without org memberships
    |           +-- /console/organizations/* -> requires auth
    |
    +-- /canvas/lti/experience?
    |   |
    |   +-- Public React route, but served with iframe-friendly headers in tunnel config
    |
    +-- Any other path?
        |
        +-- Serve public entry
            |
            +-- Public compatibility path?
            |   |
            |   +-- /verification          -> /verifiable-credential-api
            |   +-- /issuance              -> /open-badges-issuance
            |   +-- /docs/quickstart       -> /docs
            |
            +-- Explicit public route?     -> render page or source-declared redirect
            +-- /login?                    -> start SSO or redirect if already authenticated
            +-- protected public utility?  -> route guard, redirect to /login when needed
            +-- unknown public path?       -> React wildcard redirects to /
```

## UX Decision Tree

```text
Visitor enters public site
|
+-- Wants product/commercial info
|   |
|   +-- Home: /
|   +-- Product: /product
|   +-- Solutions: /solutions
|   +-- Pricing: /pricing
|   +-- Pricing checkout: /pricing/checkout
|   |   |
|   |   +-- needs auth context
|   |   +-- setup handoff -> /console-handoff/org/setup
|   |   +-- billing handoff -> /console-handoff/org/billing
|   +-- AI capability: /ai
|
+-- Wants technical docs/resources
|   |
|   +-- Developers: /developers
|   +-- API docs: /docs
|   |   |
|   |   +-- depends on /openapi.json
|   |   +-- quickstart alias: /docs/quickstart -> /docs
|   +-- Verification API alias: /verification -> /verifiable-credential-api
|   +-- Issuance alias: /issuance -> /open-badges-issuance
|   +-- Architecture: /architecture
|   +-- Security: /security
|   +-- Standards: /standards
|   +-- Protocol: /protocol
|   +-- Resources hub: /resources
|   +-- Identity guide pages:
|       |
|       +-- /identity
|       +-- /why-verifiable-identity
|       +-- /from-idv-to-verifiable-identity
|       +-- /what-is-verifiable-identity
|       +-- /what-is-credential-verification
|       +-- /what-is-open-badge
|       +-- /what-is-digital-credential
|       +-- /what-is-marty-protocol
|
+-- Wants blog/learning content
|   |
|   +-- Blog index: /blog
|   +-- Foundations page: /blog/foundations
|   +-- Blog or guide article: /blog/:slug
|   +-- Tag listing: /blog/tag/:tag
|   |   |
|   |   +-- canonical tag slug?        -> render tag archive
|   |   +-- encoded or punctuation tag -> replace with slugified canonical path
|   +-- Authors index: /authors
|   +-- Author detail: /authors/:authorId
|   +-- RSS feed: /blog/rss.xml
|
+-- Wants to sign in or apply
|   |
|   +-- /login
|   |   |
|   |   +-- if unauthenticated -> auth login redirect
|   |   +-- if authenticated -> redirect to next, attempted path, or fallback
|   +-- /apply
|   +-- /apply/:credentialType
|   +-- /invite/accept
|   +-- /organizations
|   +-- /organizations/discover
|   +-- /organizations/join
|
+-- Already authenticated
    |
    +-- Console entry: /console
        |
        +-- Applicant mode
        |   |
        |   +-- Catalog: /console/applicant/catalog
        |   +-- Identity: /console/applicant/identity
        |   +-- Apply: /console/applicant/apply/:credentialType
        |   +-- Devices: /console/applicant/devices
        |   +-- Settings: /console/applicant/settings
        |   +-- Profile: /console/applicant/profile
        |   +-- Credential lifecycle dependency
        |       |
        |       +-- Active Credential Template + active Application Template?
        |       |   +-- no  -> product hidden from catalog [CURRENT]
        |       |   +-- yes -> create via POST /v1/me/applications
        |       +-- Application approved?
        |           +-- claim_state=OFFER_READY and offer live -> Claim [CURRENT]
        |           +-- claim_state=BLOCKED -> issuer-owned waiting state [CURRENT]
        |           +-- claim_state=EXPIRED -> expired state, no Claim action [CURRENT]
        |           +-- claim_state=CLAIMED -> holder inventory [CURRENT]
        |
        +-- Organization mode
            |
            +-- Dashboard: /console/org
            |   |
            |   +-- Setup readiness recipe?
            |       |
            |       +-- Verify -> compliance, verifier trust, presentation policy, flow
            |       +-- Issue -> compliance, issuer/KMS, trust, credential template, flow
            |       +-- Application approval -> compliance, application template, active approval Policy Set, flow
            |       +-- Physical document -> capability, issuer/KMS, trust, credential + application templates, production destination, flow
            |       +-- Lifecycle -> credential template, revocation profile, renewal/revocation flow
            |       +-- Deployment Profile -> optional runtime binding, not a protocol-wide blocker
            |
            +-- Design: Credential Templates, Application Templates, Flows
            |   |
            |   +-- Standard Flow wizard -> all MIP 0.3 standard FlowTypes from capability registry
            |   +-- Standard sequence -> fixed and server-resolved
            |   +-- Supported hooks -> generated from selected FlowType extension points
            |   +-- Create -> always DRAFT
            |   +-- Flow detail -> validate -> dry-run test -> activate
            |   +-- Custom extension builder -> separate route and graph contract
            +-- Govern: Trust, Revocation, Presentation, Compliance, Policy Sets
            |   |
            |   +-- Policy Set wizard -> template-first Cedar authoring or advanced editor
            |   +-- Policy Set detail -> validate, activate, archive
            +-- Deploy: Deployment Profiles, Issuer Identity, Key Management
            +-- Connect: Canvas, API Keys, Webhooks, Delivery Destinations
            |   |
            |   +-- Physical production destination -> approved personalization bureau catalog entry
            +-- Operate: Flow Instances, applications, issued credentials, verification sessions
            |   |
            |   +-- /console/org/operate -> Flow Instances
            |   +-- Instance detail -> runtime timeline, status, current step, safe related-record links
            |   +-- Related records -> flow definition, application, issued credential, physical production job
            +-- Org: settings, team, roles, requests, notifications
            +-- Audit: /console/org/audit
            +-- Billing: /console/org/billing
```

## Improvement Decision Tree

This tree starts with the user's outcome and exposes the shortest MIP-aligned path, current gaps, and the next product decision. It should become the target model for the dashboard, setup guidance, and creation wizards.

```text
Organization user asks: "What do I need to accomplish?"
|
+-- Verify a credential
|   |
|   +-- Choose interaction channel
|   |   |
|   |   +-- Remote wallet presentation -> oid4vp_presentation [CURRENT]
|   |   +-- mDL proximity/online        -> mdl_presentation [CURRENT, capability-gated]
|   |   +-- Wallet authentication       -> siopv2 [CURRENT, capability-gated]
|   |
|   +-- Required MIP chain
|   |   |
|   |   +-- Compliance Profile -> supported format and protocol
|   |   +-- Trust Profile -> explicit issuers, algorithms, revocation, freshness
|   |   +-- Presentation Policy -> minimum claims, predicates, consent text
|   |   +-- Deployment Profile only when a physical/runtime deployment is needed
|   |   +-- Flow -> fixed sequence, trigger, optional supported hooks
|   |
|   +-- Missing dependency?
|   |   |
|   |   +-- [OPPORTUNITY] explain why it is needed and create it inline
|   |   +-- return to the same draft with the new object preselected
|   |
|   +-- Ready?
|       |
|       +-- Run conformance check -> test presentation -> activate -> monitor Flow Instance
|
+-- Issue a credential directly
|   |
|   +-- Choose delivery protocol
|   |   |
|   |   +-- OID4VCI pre-authorized code -> oid4vci_pre_authorized [CURRENT]
|   |   +-- OID4VCI authorization code  -> oid4vci_authorization_code [CURRENT]
|   |   +-- ISO mDL issuance             -> mdl_issuance [CURRENT, capability-gated]
|   |
|   +-- Required MIP chain
|   |   |
|   |   +-- Compliance Profile -> derives compatible credential format
|   |   +-- Issuer Identity + KMS -> signing readiness
|   |   +-- Credential Template -> claims, crypto, compliance, optional trust/revocation
|   |   +-- Flow -> fixed sequence and trigger
|   |   +-- Deployment Profile only when an endpoint/device bundle is required
|   |
|   +-- [OPPORTUNITY] filter every selector to compatible active objects
|   +-- [OPPORTUNITY] preview wallet compatibility and discovery endpoints before activation
|
+-- Collect an application, approve it, then issue
|   |
|   +-- application_approval_issuance [CURRENT]
|   +-- Application Template binding [CURRENT]
|   +-- Approval strategy?
|   |   |
|   |   +-- AUTO
|   |   +-- MANUAL
|   |   +-- RULES_BASED -> approval Policy Set [CURRENT authoring/readiness; binding remains an integration decision]
|   |   +-- EXTERNAL -> trigger/hook integration [CURRENT trigger and constrained hooks]
|   |
|   +-- Credential Template is reached through the Application Template relationship
|   +-- [OPPORTUNITY] preview applicant form and reviewer queue before activation
|
+-- Renew or revoke credentials
|   |
|   +-- credential_renewal    [CURRENT]
|   +-- credential_revocation [CURRENT]
|   +-- Required MIP chain -> Credential Template + Revocation Profile + notification target
|   +-- [OPPORTUNITY] start from an Issued Credential and prefill the lifecycle flow
|
+-- Issue a physical document
|   |
|   +-- physical_document_issuance [CURRENT, fail-closed capability gate]
|   +-- Required chain -> encrypted intake + credential template + application template + physical production destination
|   +-- Runtime -> ICAO data groups -> SOD signing -> bureau personalization -> quality verification -> activation
|   +-- [DEPENDENCY] production signer, artifact encryption key, and bureau URL must all be configured
|
+-- Combine issuance and presentation
|   |
|   +-- combined [CURRENT, but intent and prerequisite semantics are unclear]
|   +-- Required MIP chain -> issuance template + Presentation Policy + compatible trust
|   +-- [OPPORTUNITY] state whether the flow issues-then-verifies or verifies-then-issues
|   +-- [DEPENDENCY] resolve combined-flow requirement differences across MIP sources
|
+-- Govern decisions and trust
|   |
|   +-- Trust Profiles -> who/what is trusted
|   +-- Compliance Profiles -> standards and format abstraction
|   +-- Presentation Policies -> disclosure and verification requirements
|   +-- Policy Sets -> guided Cedar authorization, verification, and approval rules [CURRENT]
|   +-- Revocation Profiles -> lifecycle validation
|   +-- [OPPORTUNITY] dependency graph plus impact preview before changing an active object
|
+-- Operate and troubleshoot
    |
    +-- Start at Flow Instance [CURRENT]
    +-- Timeline -> current step, wait state, retries, hooks, policy decisions, audit events
    +-- Related records -> flow definition, application, issued credential, physical production job [CURRENT]
    +-- [OPPORTUNITY] add policy-decision and hook-attempt events to the normalized timeline
    +-- [OPPORTUNITY] add server-backed retry/cancel actions only where the runtime permits them
```

## MIP Alignment Findings

| Area | Current product behavior | MIP expectation | Product improvement | Priority | Dependencies |
|---|---|---|---|---|---|
| Intent selection | Five setup recipes include physical issuance; the flow chooser groups every standard type by user outcome | Start from an identity operation, then select the compatible protocol binding | Carry the selected dashboard recipe into the flow wizard URL/state | P1 residual | Dashboard-to-wizard handoff |
| Flow coverage | MIP 0.3 schema, runtime, gateway, and UI expose the same standard types plus explicit `custom` | Unsupported capabilities must be visible and fail closed | Keep environment capability reporting authoritative; add integration scenarios for mDL and SIOPv2 services | P1 residual | Runtime services |
| Applicant API | Organization review routes and `/v1/me/*` self-service routes authorize against persisted ownership; old `/v1/applicants/*` routes are absent | Identity and organization scope are server-derived | Keep cross-org, spoofed-header, lock, and resource-enumeration tests as release gates | Complete locally | Beta deployment verification |
| Claim readiness | Application lifecycle is separate from `claim_state`; blocked approvals remain approved and identify the responsible owner | Claim actions must reflect offer readiness, not approval alone | Exercise offer expiry and issuer recovery in Playwright after deployment | P0 beta gate | Active issuance flow |
| Holder inventory | `/v1/issued-credentials/mine` replaces the missing document integration and returns display-safe metadata | Holder reads must omit credential material and signing internals | Add production response privacy assertion to beta smoke | P0 beta gate | Issuance service inventory |
| Application approval | Standard flow binds only `application_template_id`; readiness separately requires an active approval Policy Set | Required references must be type-correct and decision policy auditable | Define a normative Policy Set binding/reference in a future MIP version if runtime evaluation must be flow-specific | Protocol proposal | MIP policy/flow contract |
| Fixed sequences | Standard wizard uses server-resolved sequences; custom graphs use a separate extension builder and schema | Normative sequences are immutable | Keep extension graph conformance tests versioned with generated bindings | Complete | MIP codegen |
| Hooks and triggers | UI derives constrained hooks and supports all MIP trigger types | Extension points must be type-specific | Add integration health previews for selected webhook/hook targets | P1 residual | Connect health API |
| Deployment | Standard flow creation and readiness treat deployment as optional | Deployment bindings are runtime packaging, not universal protocol prerequisites | Add type-specific deployment recommendations without turning them into blockers | P2 residual | Capability metadata |
| Compatibility | Selectors are active-only and activation validates contract references | Cross-object standards, trust, and format compatibility should be proven | Add one compatibility evaluation endpoint and reason-coded selector filtering | P0 residual | Shared compatibility evaluator |
| Activation | Create is DRAFT; validation and dry-run test precede explicit activation | Lifecycle transitions must be truthful | Persist and display conformance report history, not only the latest response | P1 residual | Report persistence |
| Governance IA | Govern includes Trust, Revocation, Presentation, Compliance, and guided Policy Sets | Governance objects must be distinct from intake templates | Add usage/impact links before changing active policies | P1 residual | Reverse-reference API |
| Runtime IA | Operate lands on Flow Instances with timeline and related-record links | Flow execution is the runtime audit unit | Normalize policy, hook, retry, and external callback events into `state_history` | P0 residual | Runtime event schema |
| Integrations IA | Connect owns Canvas, API Keys, Webhooks, and Delivery Destinations | Integration configuration should have one ownership model | Move Canvas route namespace from legacy `/deploy/canvas` to `/connect/canvas` with redirect | P2 residual | Route migration |
| Physical issuance | Capability-gated encrypted intake, signer, bureau handoff, status, quality, and activation are implemented | Sensitive document data must not leak into flow state or ordinary responses | Add production bureau sandbox certification and recovery drills | P0 operational | External bureau and signer |
| Protocol consistency | MIP 0.3 is the canonical schema and generates Python, Rust, and TypeScript bindings with check mode in CI | One versioned source must drive implementations | Publish generated packages and pin services to released package versions | P0 release | Package registries |

## Proposed Product Packages

### Package A: Make Flow Creation Truthful And Conformant

Recommended first. It removes controls that currently imply unsupported behavior and fixes the draft/active lifecycle.

1. Replace the four-card chooser with intent groups backed by a shared FlowType capability registry.
2. Remove manual step editing for normative types and stop submitting UI-only `steps`, `transitions`, and `preconditions`.
3. Serialize hooks with protocol step keys and `hook_type`; expose only supported extension points.
4. Add type-correct object binding: Credential Template, Application Template, Presentation Policy, and optional Deployment Profiles.
5. Add trigger and approval strategy controls where relevant.
6. Create as DRAFT, show validation results, test the flow, then activate explicitly.

Success signal: every submitted field exists in the agreed MIP/gateway contract, every required reference is type-correct, and the success state matches the persisted lifecycle state.

### Package B: Turn Setup Into A Guided MIP Recipe

Build on Package A.

1. Preserve the selected dashboard intent when entering any creation flow.
2. Show one dependency chain for the selected outcome, not a universal setup checklist.
3. Offer inline creation for missing dependencies and return to the original draft.
4. Filter selectors using compliance, format, trust, and deployment compatibility.
5. Add a pre-activation review that explains both friendly concepts and the resulting MIP object graph.

Success signal: a new organization can complete Verify or Issue setup without leaving the guided path or choosing an incompatible object.

### Package C: Make Runs The Operational Spine

Build after object and runtime identifiers are normalized.

1. Use Flow Instances as the Operate landing view.
2. Present status, current protocol step, wait reason, retries, hooks, policy decisions, and audit events in one timeline.
3. Deep-link the related application, verification session, issued credential, flow definition, and deployment.
4. Put retry, cancel, approval, and failure-resolution actions on the instance when MIP state allows them.

Success signal: an operator can answer "what happened, why, and what can I do next?" from one screen.

### Package D: Separate Governance From Integrations

Build after IA and RBAC approval.

1. Introduce Govern for Trust Profiles, Compliance Profiles, Presentation Policies, Policy Sets, and Revocation Profiles.
2. Rename Application Rules back to Application Templates and keep it with credential/application design.
3. Introduce Connect for API keys, webhooks, subscriptions, notification targets, and Canvas.
4. Add "used by" and change-impact views before edits to active governance objects.

Success signal: policy authors, integration engineers, and operators each have a predictable home without learning the full protocol object graph first.

## Recommended Sequence

```text
MIP source consistency decision
        |
        v
Shared FlowType capability registry
        |
        +--> Package A: truthful flow creation
        |         |
        |         v
        |    Package B: guided recipes
        |
        +--> Policy Set API/UX decision --> Package D: Govern + Connect
        |
        +--> Runtime identifier normalization --> Package C: Flow Instance spine
```

The highest-value product move is Package A. The current dashboard now teaches an intent-first model, but the flow wizard can still create false confidence by showing settings that are not persisted as MIP fields and by reporting activation without completing the MIP lifecycle transition. Fixing that boundary makes every later UX improvement more reliable.

## Dependency Map

### Routing And Layout

- Public entry: `ui/src/apps/public/PublicApp.jsx`
- Public route shell: `ui/src/apps/public/PublicRoutes.jsx`
- Public marketing route registry: `ui/src/variants/publicSite.public.jsx`
- Public tabs: `ui/src/variants/publicConfig.public.js`
- Public layout: `ui/src/components/layouts/PublicLayout.jsx`
- Public footer: `ui/src/components/layouts/PublicFooter.jsx`
- Console entry: `ui/src/apps/console/ConsoleApp.jsx`
- Console route shell: `ui/src/apps/console/ConsoleRoutes.jsx`
- Authenticated layout: `ui/src/components/layouts/AuthenticatedLayout.jsx`
- Console sidebar and top bar: `ui/src/components/navigation/SidebarNavigation.jsx`, `ui/src/components/navigation/ConsoleHeaderBar.jsx`
- Navigation model: `ui/src/config/navigation.js`

### Auth, Role, And State Dependencies

- Auth state: `ui/src/contexts/AuthContext.jsx`
- Login entry decisions: `ui/src/application/routing/loginEntry.js`
- Protected route policy: `ui/src/application/routing/guardPolicy.js`
- Route guard component: `ui/src/components/ProtectedRoute.jsx`
- Console mode and active organization: `ui/src/contexts/ConsoleContext.jsx`
- Console bootstrap and mode switch rules: `ui/src/application/session/consoleSession.js`
- Auth capability derivation: `ui/src/application/session/authSession.js`
- Permission checks and sidebar filtering: `ui/src/hooks/usePermissions.js`, `ui/src/config/permissions.js`
- Backend dependencies: preferences API, organizations API, RBAC permissions API, dashboard stats API

### Setup Readiness And Flow Dependencies

- Dashboard readiness rules: `ui/src/config/dashboardRules.js`
- Dashboard data loading: `ui/src/hooks/useDashboardData.js`
- Readiness UI: `ui/src/components/console/dashboard/SetupReadinessPanel.jsx`
- Dashboard shell: `ui/src/components/console/ConsoleDashboard.jsx`
- Flow wizard shell: `ui/src/components/console/flows/FlowDefinitionWizard.jsx`
- MIP FlowType choice: `ui/src/components/console/flows/steps/FlowTypeStep.jsx`
- Locked MIP sequences and hook slots: `ui/src/components/console/flows/steps/FlowStepsConfigStep.jsx`
- Deployment binding by flow type: `ui/src/components/console/flows/steps/DeploymentBindingStep.jsx`
- Preconditions for OID4VCI flows: `ui/src/components/console/flows/steps/PreconditionsStep.jsx`
- Review and MIP object map: `ui/src/components/console/flows/steps/ReviewStep.jsx`
- Flow API client and activation behavior: `ui/src/services/flowsApi.jsx`
- Gateway Flow request contract: `services/gateway/models.py`, `services/gateway/routes/flows.py`
- Runtime Flow model and fixed sequences: `../Marty/src/digital_identity/domain/entities.py`, `../Marty/src/digital_identity/domain/value_objects.py`

### MIP Source Dependencies

- Root principles and object relationships: `../marty-protocol/SPECIFICATION.md`
- Flow entity specification: `../marty-protocol/protocol/flow/SPECIFICATION.md`
- Normative Flow schema: `../marty-protocol/schemas/flow.json`
- FlowType values and sequences: `../marty-protocol/enums/flow-types.json`
- Runtime execution model: `../marty-protocol/protocol/flow-execution/SPECIFICATION.md`
- Policy Set schema: `../marty-protocol/schemas/policy-set.json`
- Presentation, trust, compliance, credential, application, and deployment schemas: `../marty-protocol/schemas/*.json`

### Content Dependencies

- Blog package: `marty-blog`
- Blog route components: `@marty/blog/blog-page`, `@marty/blog/blog-post-page`, `@marty/blog/authors-page`, `@marty/blog/author-page`, `@marty/blog/foundations-page`
- Blog source data: `marty-blog/src/data/blogPosts.js`, `marty-blog/src/data/guideContent.js`, `marty-blog/src/data/blogAuthors.js`, `marty-blog/src/data/articleMeta.js`
- Tag route builder: `marty-blog/src/utils/blogTagRoutes.js`
- Blog assets: `ui/public/images/social/*`, `ui/public/images/authors/*`, `ui/public/blog/rss.xml`
- Pricing and checkout: `@marty/subscriptions`
- API docs: ReDoc plus `/openapi.json`

### Deployment Dependencies

- Vite route generation and prerender/sitemap inputs: `ui/vite.config.ts`
- Public production static server: `ui/nginx.prod.conf`
- Static SPA server: `ui/nginx.spa.conf`
- Beta tunnel proxy: `nginx-tunnel.conf.template`
- Console is a separate HTML entry: `/console/index.html`
- Public app fallback: unknown public paths receive HTML, then React wildcard redirects to `/`
- Console fallback: unknown console paths receive `/console/index.html`, then protected console wildcard redirects to `/console`

## Known UX Path Risks And Deployment Checks

- The active beta host is `beta.elevenidllc.com`.
- The live beta sitemap returns canonical URLs on `elevenidllc.com`, not `beta.elevenidllc.com`.
- Source now resolves `/verification`, `/issuance`, and `/docs/quickstart` with explicit redirects instead of public wildcard fallback. Verify beta deployment after release.
- Source now redirects `/console/audit` to `/console/org/audit`, preserving query parameters for old links.
- Source now excludes `/test-harness` from sitemap and robots output; verify beta deployment after release.
- Source now canonicalizes blog tag paths with slugified ASCII paths. Legacy encoded or punctuation variants should replace to the canonical path in React.
- The Flow wizard's visible activation toggle currently maps to `enabled`, while the MIP Flow lifecycle uses `status` and a separate activate endpoint. Treat the current success message as an implementation risk until the lifecycle is made explicit.
- The Flow wizard shows purpose, audience, deployment-target, precondition, custom-step, and hook controls whose values are absent from or differently shaped in the agreed Flow request contract. Do not expand these controls until contract tests prove persistence.
- The MIP repository has FlowType and step-sequence drift between `enums/flow-types.json`, `schemas/flow.json`, `protocol/flow/SPECIFICATION.md`, and the runtime enum. UI capability expansion depends on choosing one generated source of truth.
- Tunnel config proxies `/resources/` to Keycloak. The exact `/resources` public page is fine, but future nested UI paths under `/resources/*` would collide.
- Tunnel config proxies `/auth/*`, so the source-declared public React route `/auth/callback` may be intercepted by backend auth routing on beta. `/console/auth/callback` remains a console React route.

## Sitemap Path Inventory

The source sitemap target is generated by `ui/vite.config.ts`. After UX-002 and UX-105, the current source behavior is:

- `/test-harness` is excluded from sitemap output and disallowed in robots output.
- Blog tag paths are generated through `marty-blog/src/utils/blogTagRoutes.js`.
- Tag paths use stable ASCII slugs such as `/blog/tag/bbs-plus`, `/blog/tag/x-509`, and `/blog/tag/privacy-disclosure`.
- The live beta sitemap may retain older paths until the current source is deployed; verify `https://beta.elevenidllc.com/sitemap.xml` after release.

### Static And Content Index Paths

```text
/
/ai
/architecture
/authors
/blog
/developers
/docs
/eudi-wallet-verification
/from-idv-to-verifiable-identity
/identity
/iso-18013-5-mdoc-verification
/open-badges-issuance
/open-badges-verification
/pricing
/privacy-policy
/product
/protocol
/resources
/sd-jwt-verification
/security
/solutions
/standards
/terms-of-service
/trust-registry-infrastructure
/verifiable-credential-api
/what-is-credential-verification
/what-is-digital-credential
/what-is-marty-protocol
/what-is-open-badge
/what-is-verifiable-identity
/why-verifiable-identity
```

### Author Paths

```text
/authors/aiko-tanaka
/authors/daniel-ortega
/authors/elena-kovacs
/authors/marcus-vale
/authors/nora-patel
/authors/sofia-rahman
/authors/victor-leclerc
```

### Blog And Guide Article Paths

```text
/blog/building-trust-registries-at-scale
/blog/business-case-for-credential-portability
/blog/cedar-policies-for-identity-governance
/blog/centralized-vs-verifiable
/blog/certificate-chains-and-validation
/blog/compliance-profiles-bridging-regulation
/blog/compliance-profiles-in-practice
/blog/conformance-testing-for-implementers
/blog/credential-lifecycle
/blog/credential-portability-across-wallets
/blog/credential-templates
/blog/credential-templates-designing-what-gets-issued
/blog/credential-templates-explained-deep
/blog/cryptographic-trust-anchors-primer
/blog/data-minimization-in-identity
/blog/deploy-age-verification
/blog/deploy-airline-boarding
/blog/deploy-enterprise-access
/blog/deploy-future-identity
/blog/deploy-membership-credentials
/blog/deployment-profiles
/blog/deployment-profiles-explained-deep
/blog/deployment-profiles-from-design-to-production
/blog/deployment-profiles-in-practice
/blog/device-binding-and-credential-security
/blog/discovering-trusted-issuers
/blog/eudi-wallet-model-explained
/blog/eudi-wallet-readiness
/blog/federation-in-identity-systems
/blog/five-primitives-in-one-picture
/blog/flows-orchestrating-identity-lifecycle
/blog/foundations-credentials
/blog/foundations-identity
/blog/foundations-verification
/blog/four-actors-of-identity-systems
/blog/governing-credential-ecosystems
/blog/holder-binding-beyond-biometrics
/blog/how-credential-issuance-works
/blog/how-everything-works-together
/blog/how-governments-build-identity-pki
/blog/how-passport-pki-works
/blog/identity-governance-models
/blog/impl-icao-dtc
/blog/impl-mdoc
/blog/impl-oid4vci
/blog/impl-oid4vp
/blog/impl-open-badges
/blog/infrastructure-economics-migration
/blog/interoperability-between-credential-formats
/blog/introducing-mip
/blog/issuance-flows
/blog/issuers-holders-verifiers-explained
/blog/minimum-disclosure-is-a-policy-problem
/blog/mip-and-open-badges-education-credentials
/blog/mip-json-schemas-walkthrough
/blog/mobile-driving-licenses-iso-18013-5
/blog/mobile-wallet-architectures
/blog/offline-verification-design-patterns
/blog/offline-verification-guide
/blog/one-protocol-many-ecosystems
/blog/pki-certificate-chains
/blog/policy-engines
/blog/policy-engines-for-identity-systems
/blog/post-quantum-readiness-in-identity
/blog/presentation-flows
/blog/presentation-policies
/blog/presentation-policies-explained-deep
/blog/presentation-policies-minimum-disclosure
/blog/presentation-protocols
/blog/privacy-data-minimization
/blog/privacy-vs-compliance
/blog/public-key-infrastructure-explained
/blog/rbac-vs-abac
/blog/revocation-flows
/blog/revocation-strategies-compared
/blog/same-trust-model-different-runtime
/blog/sd-jwt-selective-disclosure-deep-dive
/blog/secure-enclave-credential-storage
/blog/selective-disclosure
/blog/selective-disclosure-explained
/blog/selective-disclosure-in-wallets
/blog/the-marty-identity-model
/blog/trust-anchors
/blog/trust-profile-evaluation-and-failure-handling
/blog/trust-profiles
/blog/trust-profiles-explained
/blog/trust-registries
/blog/trust-registries-explained
/blog/understanding-csca-certificates
/blog/understanding-trust-anchors
/blog/verifiable-credentials-explained
/blog/verifier-infrastructure
/blog/wallet-ux-design-for-identity
/blog/what-icao-9303-specifies
/blog/what-is-a-digital-identity-wallet
/blog/what-is-digital-identity
/blog/why-identity-depends-on-cryptography
/blog/why-identity-needs-a-protocol
/blog/why-identity-systems-must-protect-privacy
/blog/why-marty-is-ready-for-evaluation
/blog/why-the-marty-protocol-exists
/blog/zero-knowledge-predicates-identity
```

### Blog Tag Paths

```text
/blog/tag/access-control
/blog/tag/announcement
/blog/tag/bbs-plus
/blog/tag/business
/blog/tag/cedar
/blog/tag/compliance
/blog/tag/core-object
/blog/tag/core-objects
/blog/tag/core-protocol
/blog/tag/credential
/blog/tag/credential-format
/blog/tag/credential-issuance
/blog/tag/credential-lifecycle
/blog/tag/credential-presentation
/blog/tag/credential-template
/blog/tag/cryptography
/blog/tag/data-minimization
/blog/tag/deployment
/blog/tag/deployment-patterns
/blog/tag/deployment-profile
/blog/tag/deployments
/blog/tag/device-security
/blog/tag/did
/blog/tag/economics
/blog/tag/ecosystem
/blog/tag/eidas-2
/blog/tag/eudi-arf
/blog/tag/evaluation
/blog/tag/federation
/blog/tag/fido2
/blog/tag/five-primitives
/blog/tag/flow
/blog/tag/flows
/blog/tag/foundation
/blog/tag/foundations
/blog/tag/gdpr
/blog/tag/governance
/blog/tag/government
/blog/tag/government-identity
/blog/tag/holder-binding
/blog/tag/icao
/blog/tag/icao-9303
/blog/tag/identity
/blog/tag/identity-concepts
/blog/tag/implementation
/blog/tag/implementations
/blog/tag/industry
/blog/tag/interoperability
/blog/tag/iso-18013
/blog/tag/iso-18013-5
/blog/tag/issuance
/blog/tag/json-schema
/blog/tag/mdoc
/blog/tag/mdoc-standards
/blog/tag/nist-pqc
/blog/tag/offline
/blog/tag/oid4vci
/blog/tag/oid4vp
/blog/tag/oidc
/blog/tag/opa
/blog/tag/open-badges
/blog/tag/open-badges-v3
/blog/tag/passport-pki
/blog/tag/pki
/blog/tag/pki-for-identity
/blog/tag/policy
/blog/tag/policy-engine
/blog/tag/presentation
/blog/tag/presentation-exchange
/blog/tag/presentation-policy
/blog/tag/privacy
/blog/tag/privacy-disclosure
/blog/tag/protocol-overview
/blog/tag/protocol-vision
/blog/tag/revocation
/blog/tag/runtime
/blog/tag/saml
/blog/tag/sd-jwt
/blog/tag/selective-disclosure
/blog/tag/statuslist2021
/blog/tag/travel
/blog/tag/trust-anchor
/blog/tag/trust-discovery
/blog/tag/trust-governance
/blog/tag/trust-infrastructure
/blog/tag/trust-model
/blog/tag/trust-profile
/blog/tag/trust-registry
/blog/tag/verifiable-credentials
/blog/tag/verification
/blog/tag/w3c-vc
/blog/tag/wallet-architecture
/blog/tag/wallets
/blog/tag/wallet-ux
/blog/tag/webauthn
/blog/tag/x-509
```

## Source-Declared Public UI Routes Not In Sitemap

These are React routes or static public UI paths in source. Some are intentionally excluded from sitemap because they are protected, transactional, duplicated aliases, or utility routes.

```text
/login
/auth/callback
/apply
/apply/:credentialType
/applicant/preview/catalog
/applicant/preview/credentials/:templateId
/applicant/preview/applications/:applicationTemplateId
/applicant/preview/flows/:flowId
/canvas/lti/experience
/catalog
/credentials
/invite/accept
/my-applications
/my-documents
/organizations
/organizations/discover
/organizations/join
/privacy
/terms
/pricing/checkout
/blog/foundations
/blog/rss.xml
/console-handoff/org/setup
/console-handoff/org/billing
/settings/notifications
/wallet/setup
```

### Public Redirect/Alias Routes Not In Sitemap

These are explicit public routes in source, but they resolve to canonical pages and should not create separate sitemap entries.

```text
/verification     -> /verifiable-credential-api
/issuance         -> /open-badges-issuance
/docs/quickstart  -> /docs
```

## Source-Declared Console UI Route Patterns

Console paths are not listed in the sitemap and are disallowed in `robots.txt`, but they are UI paths on beta.

### Console Entry And Auth

```text
/console
/console/login
/console/auth/callback
/login
```

### Organization Console

```text
/console/org
/console/org/setup
/console/org/setup-wizard
/console/org/profile
/console/org/design
/console/org/govern
/console/org/connect
/console/org/trust
/console/org/trust/profiles
/console/org/trust/profiles/new
/console/org/trust/profiles/:id
/console/org/trust/profiles/:id/edit
/console/org/trust/issuers
/console/org/trust/revocation
/console/org/trust/revocation/new
/console/org/trust/revocation/:id
/console/org/templates
/console/org/templates/credentials
/console/org/templates/credentials/new
/console/org/templates/credentials/:templateId
/console/org/templates/applications
/console/org/templates/applications/new
/console/org/templates/applications/:templateId
/console/org/templates/applications/:templateId/edit
/console/org/policies
/console/org/policies/presentation
/console/org/policies/presentation/new
/console/org/policies/compliance
/console/org/policies/sets
/console/org/policies/sets/new
/console/org/policies/sets/:policySetId
/console/org/deploy
/console/org/deploy/profiles
/console/org/deploy/profiles/new
/console/org/deploy/api-keys
/console/org/deploy/issuer-identity
/console/org/deploy/canvas
/console/org/connect/delivery-destinations
/console/org/deploy/issuer-identity/new
/console/org/deploy/key-management
/console/org/deploy/key-management/services
/console/org/deploy/key-management/services/new
/console/org/deploy/dids
/console/org/deploy/signing-keys
/console/org/deploy/signing-keys/settings
/console/org/deploy/signing-keys/services/new
/console/org/deploy/lanes
/console/org/deploy/webhooks
/console/org/flows
/console/org/flows/definitions
/console/org/flows/definitions/new
/console/org/flows/definitions/new/custom
/console/org/flows/definitions/:flowId
/console/org/operate
/console/org/operate/issuance
/console/org/operate/issuance/:credentialId
/console/org/operate/applications
/console/org/operate/applications/:applicationId
/console/org/operate/flow-instances
/console/org/operate/flow-instances/:instanceId
/console/org/operate/verify
/console/org/settings
/console/org/api-keys
/console/org/webhooks
/console/org/team
/console/org/roles
/console/org/notifications
/console/org/membership-requests
/console/org/role-requests
/console/org/audit
/console/org/billing
```

### Applicant Console

```text
/console/applicant
/console/applicant/dashboard
/console/applicant/identity
/console/applicant/credentials
/console/applicant/applications
/console/applicant/catalog
/console/applicant/apply/:credentialType
/console/applicant/devices
/console/applicant/settings
/console/applicant/profile
```

### Console Organizations

```text
/console/organizations
/console/organizations/discover
/console/organizations/join
/console/organizations/create
```

### Console Redirect/Fallback Behavior

```text
/console/audit                               -> /console/org/audit, query preserved
/console/org/setup-wizard                    -> /console/org
/console/org/trust/issuers                   -> /console/org/trust/profiles
/console/org/deploy/api-keys                 -> /console/org/api-keys
/console/org/deploy/key-management/services  -> /console/org/deploy/key-management
/console/org/deploy/dids                     -> /console/org/deploy/issuer-identity
/console/org/deploy/signing-keys             -> /console/org/deploy/key-management
/console/org/deploy/signing-keys/settings    -> /console/org/deploy/key-management/services
/console/org/deploy/signing-keys/services/new -> /console/org/deploy/key-management/services/new
/console/org/deploy/webhooks                 -> /console/org/webhooks
/console/applicant                           -> /console/applicant/catalog
/console/applicant/credentials               -> /console/applicant/identity
/console/applicant/applications              -> /console/applicant/identity
/console/* unknown                           -> /console, behind ProtectedRoute
```

## Linked Fallback Paths

No known linked public paths currently depend on public wildcard fallback for their intended destination.

```text
None
```

## Non-UI Path Namespaces That Affect UX

These are important because a user-facing deep link or wallet browser may hit them, but they are not React pages.

```text
/.well-known/ai-plugin.json
/.well-known/*
/api/*
/auth/*
/credentials/*
/developer-docs/*
/health
/health/ready
/oid4vp/did.json
/oid4vp/*
/openapi.json
/org/:uuid/.well-known/openid-credential-issuer
/org/:uuid/.well-known/oauth-authorization-server
/org/:uuid/spruce/.well-known/openid-credential-issuer
/org/:uuid/spruce/.well-known/oauth-authorization-server
/org/:uuid/credential-manager/.well-known/openid-credential-issuer
/org/:uuid/credential-manager/.well-known/oauth-authorization-server
/org/:uuid/apple-wallet/.well-known/openid-credential-issuer
/org/:uuid/apple-wallet/.well-known/oauth-authorization-server
/org/:uuid/waltid/.well-known/openid-credential-issuer
/org/:uuid/waltid/.well-known/oauth-authorization-server
/org/*
/orgs/:slug/did.json
/orgs/*
/ready
/realms/*
/resources/*
/v1/*
```

## MIP 0.3 Improvement Decision Branches

```text
Applicant opens a credential product
  -> Active Application Template linked?
     -> No: product is absent from the catalog; advancement is blocked
     -> Yes: direct and catalog links resolve the same active template
        -> Form values satisfy template constraints?
           -> No: field-specific correction; no application request
           -> Yes: POST /v1/me/applications with organization, application template, form data, integration context
              -> Submit succeeds
                 -> Reviewer lock available?
                    -> No: read-only "being reviewed" state
                    -> Yes: request information | reject | approve
                       -> Approve
                          -> Active issuance flow produces a live offer?
                             -> No: APPROVED + BLOCKED / NO_ACTIVE_ISSUANCE_FLOW / ISSUER
                                -> Holder sees Waiting for Issuer; no Claim action
                             -> Yes: APPROVED + OFFER_READY
                                -> Holder sees Claim
                                   -> Select one of nine compatible wallet destinations
                                      -> walt.id: browser acceptance release gate
                                      -> Native wallet: handoff gate; device-lab acceptance
                                   -> Offer expired: EXPIRED; Claim removed until a new offer is created
                                   -> Credential accepted: CLAIMED and holder-safe inventory row

Operator opens issued credential
  -> Source application linked?
     -> No: reissue is unavailable with an explicit explanation
     -> Yes: organization-scoped issue action requires issuance:initiate
        -> Fresh wallet offer | typed issuer-owned blocker

Any application resource request
  -> Persisted resource organization matches authorized membership?
     -> No: 403 + privacy-safe denial audit event
     -> Yes: enforce action permission and current server-derived lock holder
```

Implemented local checks expose these improvement boundaries directly: missing dependencies, malformed fields, unavailable flows, expired offers, wrong lock ownership, and cross-organization access are distinct states rather than generic errors or misleading claim actions.

### MIP 0.3 Runtime Contract Branches

```text
Organization resource page mounts
  -> memberships loaded and activeOrgId is a valid membership?
     -> No: no organization-owned request is sent
     -> Yes: activeOrgId is the sole request organization
        -> switching organization: update local context -> cancel stale consumers -> persist preference -> navigate
        -> list response is a direct array?
           -> No: malformed-contract state + Retry
           -> Yes: render organization-owned resources

Application Template opens
  -> DRAFT
     -> Edit | Validate | Delete
     -> validation errors: grouped by contract section; Activate hidden
     -> valid: Activate available
  -> ACTIVE
     -> Preview | Deprecate
     -> Edit and Delete unavailable
  -> DEPRECATED
     -> historical display only; absent from new applications

Verification starts
  -> active Flow Definition selected?
     -> Yes: use its policy, trust, and deployment references
     -> No: active Presentation Policy selected directly
        -> request succeeds: browser-wallet handoff
        -> capability/entitlement unavailable: typed recoverable state

Beta deployment completes
  -> dispatch MIP 0.3 Beta Credential Lifecycle workflow
     -> fixture manifest incomplete: fail before browser execution
     -> deployed MIP header/config is not exactly 0.3.0: fail
     -> canonical applicant route is unavailable or removed route is not 404: fail
     -> digest-pinned walt.id badge acceptance fails: fail
     -> Application Template activation or browser verification fails: fail
     -> pass: preserve redacted evidence artifact for release review
  -> SpruceKit Open Badge login conformance/device evidence attached?
     -> No: release remains blocked
     -> Yes: badge-login acceptance gate satisfied
```

The authenticated applicant organization is not console selection state. It remains fixed for self-service routes; org-console headers, permissions, dashboards, templates, trust, deployment, policy, audit, team, flow, issuance, and verification requests all require a validated `activeOrgId`.
