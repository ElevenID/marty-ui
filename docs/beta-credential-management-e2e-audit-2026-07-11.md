# Beta Credential Management E2E Audit

Date: 2026-07-11
Updated: 2026-07-12
Target: `https://beta.elevenidllc.com`
Method: Chromium Playwright using the repository's configured testing users and live beta services.

## Remediation Status

The clean-break MIP 0.3 remediation was deployed to beta on 2026-07-12. Implementation and deployment evidence covers:

- old `/v1/applicants/*` routes absent and canonical route inventory present;
- persisted organization authorization, explicit review/decision permissions, and caller-held reviewer locks;
- strict application creation, server-derived templates/checks, structured field validation, blocked/ready claim states, and holder inventory;
- registered Application Template create/detail/edit routes and fail-closed Flow capability loading;
- dedicated `reviewer@marty.demo` provisioning and reviewer membership configuration;
- MIP 0.3 generated bindings current, protocol conformance and drift checks passing, and the pinned Rust wheel compiling in CD;
- 646 service tests passing with one existing skip, including 64 focused applicant, gateway, migration, metadata, and policy tests;
- all 1,003 frontend tests passing across 149 test files and a successful production build;
- a five-test deterministic Chromium gate covering canonical applicant creation/claim, all nine selectable wallet destinations, holder blocked/ready states, reviewer lock/request-info/reject/approve actions, and 320/390/768/1440 responsive widths;
- browser assertions for no failed API requests in the applicant/holder gate, no reviewer identity fields in decision payloads, and no horizontal page overflow at the supported widths.

The original observations below remain as the pre-remediation beta baseline. The final deployment evidence and current release boundary are recorded at the end of this audit.

## Executive Summary

The legacy Member Login credential can be issued and received end to end through OID4VCI. A disposable walt.id account accepted the offer, stored the signed credential, resolved its VCT metadata, and displayed the Marty Verified Member Badge.

New credential products cannot complete the same lifecycle. The primary dependency chain breaks in two places:

1. Application Template create, detail, and edit routes are not registered and silently redirect to the org dashboard.
2. The MIP 0.2 flow wizard receives `403 Action not authorized` from `/v1/flows/capabilities`, reports that the issuance flow has no runtime sequence, and cannot advance.

Without an active OID4VCI flow, applicant applications are created and submitted but `/issue` returns `409`. The UI then labels those applications “Ready to Claim,” creating a loop that cannot succeed.

A separate critical authorization issue was observed: a user without reviewer access in the credential's organization could retrieve and lock another applicant's application by ID while operating in a different organization.

## Path Coverage

| User path | Result | Notes |
| --- | --- | --- |
| Vendor login and organization creation | Pass | New audit organization created through the browser. |
| Key management service registration | Pass | OpenBao-compatible service registration reached submit. |
| Issuer identity creation | Pass | Issuer identity reported ready. |
| Trust Profile creation | Pass | Active Trust Profile created. |
| Credential Template creation | Pass | Active template created. |
| Application Template list | Pass | Empty state and create actions render. |
| Application Template create/detail/edit | Blocked | Routes redirect silently to `/console/org`. |
| Presentation Policy creation | Pass | Active policy created. |
| Deployment Profile creation | Pass | Active deployment created. |
| OID4VCI flow creation | Blocked | Capabilities request is forbidden and Next cannot advance. |
| API key creation | Pass | Active API key created; secret evidence was redacted and the audit cleaned up its key. |
| Applicant catalog | Pass | Eleven credentials rendered; ten available application routes opened. |
| One-click applications | Partial | Create and submit succeed; issue fails for mDL, Membership mDoc, and Employee Badge. |
| Structured ICAO application | Degraded | Submission succeeds with invalid date strings. |
| Vendor review and approval | Blocked | Supplied test users have no reviewer role in the seeded Marty organization. |
| My Identity and application history | Degraded | Application state renders, but `/v1/documents` is missing. |
| Wallet selector | Pass with legacy offer | Nine wallet choices render QR/copy/open/email actions. |
| walt.id handoff and acceptance | Pass with legacy offer | Credential stored and VCT metadata resolved successfully. |
| Apple/Google/mobile wallet acceptance | Handoff only | Browser verified each selector state and QR/deep-link UI; native apps were not available in the test environment. |
| Revoke/renew newly issued credential | Not reachable | No new flow and no seeded reviewer account, so a disposable managed credential could not be issued for destructive lifecycle testing. |
| Mobile catalog | Pass | No page-level horizontal overflow. |
| Mobile My Identity and claim dialog | Degraded | Page width expands to 429px on a 390px viewport. |

## Findings

### Critical: Cross-organization application access and lock

The vendor testing user was operating as owner of an audit organization and had only applicant membership in Marty Identity Platform. Navigating directly to another applicant's Marty application ID returned the application and checks, exposed applicant details, and allowed `POST /lock` with status 200.

Expected behavior is a server-side `403` unless the caller has reviewer permission in the application's organization. Authorization must be enforced for application detail, checks, evidence, lock, decisions, issuance offers, and related endpoints using the application's organization, independent of the client-selected organization.

### Blocker: New issuance flows cannot be created

The OID4VCI flow wizard calls `/v1/flows/capabilities`, receives `403 Action not authorized`, displays “This flow type has no runtime sequence,” and leaves Next unavailable. This occurred for the owner of the newly created organization after the preceding MIP artifacts were active.

The downstream effect was reproduced on three applicant products:

- Membership ID (mDoc)
- Employee Access Badge
- Mobile Driving Licence

Each application create and submit request returned 200. Each `/issue` request returned 409 with “No active issuance flow produced an offer for this application.”

### Blocker: Application Template actions point to missing routes

The Application Templates page advertises Build/Create, detail, edit, and advanced-create actions. These live routes all redirect to the organization dashboard:

- `/console/org/templates/applications/new`
- `/console/org/templates/applications/new?mode=advanced`
- `/console/org/templates/applications/:id`
- `/console/org/templates/applications/:id/edit`

This prevents a new issuer from making a Credential Template applicant-facing through the browser.

### High: Invalid date data passes browser and API validation

ICAO claims defined as dates rendered as unrestricted text inputs. Playwright entered `Test Value` for date of birth, date of issue, and date of expiry. The review screen displayed those values and both create and submit requests returned 200.

The form also grouped Issuing State under Address and Surname under Additional Information. The grouping is confusing, but accepting invalid dates is the data-integrity defect.

### High: Failed issuance is presented as ready to claim

After `/issue` returns 409, My Identity and the catalog show the application as Approved / Ready to Claim. Claim retries the same failing operation. Users are given an action-required loop even though only the issuer can resolve the missing flow.

The UI should distinguish `approved_but_issuer_not_ready` from a claimable offer and show an issuer-owned recovery state.

### High: Credential document service is missing

My Identity requests `/v1/documents`, which returns 404. The page still reconstructs issued and pending rows from application data, but it cannot reliably provide the user's stored credential inventory, credential details, or document-level lifecycle state.

### High: No supplied reviewer testing user for the seeded issuer

`TEST_VENDOR_EMAIL` and `TEST_ADMIN_EMAIL` both have applicant-only access in Marty Identity Platform. The vendor owns separate audit organizations, but neither account can legitimately review the seeded applicant's request. This blocks repeatable browser coverage for approve, reject, request-info, issue, revoke, and renew.

Add a stable seeded reviewer/owner account for the Marty organization and assert its organization-scoped permissions during environment setup.

### Medium: Credential labels contradict their formats

- Mobile Driving Licence uses the action “Get Membership ID.”
- Membership ID (mDoc) displays “Open Badge (W3C)” in its footer.
- Employee Access Badge (`vc+sd-jwt`) also displays “Open Badge (W3C).”

Format and action copy should come from normalized credential metadata rather than one-click credential category defaults.

### Medium: Mobile My Identity overflows horizontally

At a 390px viewport, My Identity expands to 429px. The account button, Apply for Credential action, and Action Required tab cross the right viewport edge. The wallet dialog also extends past the viewport while the underlying page remains oversized.

The catalog itself remained at 390px, so the issue is localized to My Identity header/filter composition and the claim dialog.

### Medium: Walt.id cannot identify the issuer in its credential list

The live wallet acceptance succeeds and resolves the VCT metadata, but the wallet credential list displays `Issuer Unknown`. Walt.id also logs `Cannot read properties of null (reading '0')` after acceptance. The credential remains stored and usable, so this is not an issuance blocker, but issuer metadata interoperability needs review.

### Medium: Organization switcher does not scale

The testing vendor has many audit organizations. The organization menu renders the full list without search or grouping, making the seeded Marty organization difficult to locate and pushing choices beyond the visible menu area.

### Low: Repeated capability and entitlement errors add noise

- `/v1/passport/capabilities` repeatedly returns 404 on org pages.
- `/v1/policy-sets` returns the expected free-plan `plan_feature_unavailable` response but is recorded and surfaced like an unexpected failure.
- One transient Cloudflare 502 occurred for organization runtime status.

Unavailable optional capabilities should be represented as supported capability states rather than repeated browser errors.

## Working Reference Path

The seeded Member Login application remains a useful control case:

1. Applicant opens My Identity.
2. Receive Again generates an `OFFERED` OID4VCI offer.
3. All nine configured wallet choices render a ready handoff.
4. Open in Wallet reaches `wallet.demo.walt.id` with the offer intact.
5. A disposable wallet account accepts the offer.
6. Walt.id stores one `jwt_vc_json` credential.
7. The credential uses the beta Marty VCT, not the legacy example VCT.
8. VCT metadata resolves with status 200 and the wallet displays Marty Verified Member Badge.

This proves the OID4VCI issuer and wallet integration can work when an active flow already exists.

## Dependency Order

Recommended correction order:

1. Fix organization-scoped application authorization before expanding testing.
2. Restore owner access to flow capabilities and make the MIP 0.2 issuance sequence selectable.
3. Register and test Application Template create/detail/edit routes.
4. Seed a stable Marty reviewer account with explicit scoped permissions.
5. Enforce claim-type validation in both the UI and API.
6. Restore the documents endpoint or move My Identity to a supported credential inventory contract.
7. Represent missing issuer readiness honestly in applicant status and claim actions.
8. Correct credential-format copy and mobile overflow.
9. Add Playwright release gates for the complete dependency chain and destructive lifecycle actions using disposable records.

## Evidence

- `tests/artifacts/beta-org-console-audit-20260711151128/report.json`
- `tests/artifacts/beta-credential-application-paths-20260711151448/application-paths.json`
- `tests/artifacts/beta-instant-issuance-20260711151616/instant-issuance.json`
- `tests/artifacts/beta-structured-application-20260711151813/structured-application.json`
- `tests/artifacts/beta-vendor-review-20260711151914/vendor-review.json`
- `tests/artifacts/beta-applicant-identity-20260711152125/identity-views.json`
- `tests/artifacts/beta-mobile-credential-ux-20260711152722/mobile.json`
- `tests/artifacts/beta-application-template-routes-20260711152819/routes.json`
- `tests/artifacts/beta-wallet-selector-matrix-20260711152940/wallet-matrix.json`
- Live acceptance command: `WALTID_WALLET_ORIGIN=https://wallet.demo.walt.id node tests/scripts/verify-beta-waltid-acceptance.js`

All screenshots and reports redact API keys and credential-offer secrets where the existing audit harness supports them.

## Post-Cutover Follow-Up - 2026-07-11/12

This follow-up retested the live beta after the MIP 0.3 clean-break frontend changes. The release remains **blocked**. The deployed UI and services are on incompatible contracts, so neither the holder nor issuer lifecycle can complete without legacy diagnostic calls.

### Critical: MIP 0.3 holder UI is paired with the removed applicant API

The live applicant UI calls the canonical MIP 0.3 resources, but beta returns 404 for all of them:

- `GET/PATCH /v1/me/applicant-profile`
- `GET /v1/me/applications`
- `GET /v1/issued-credentials/mine`

The removed applicant service remains deployed: legacy profile and application routes return data, while `GET /v1/applicants/applications` returns 405 because its legacy POST route still exists. Clicking **Add to Wallet** displays `Not Found` before wallet selection. This is the mixed-version deployment the clean-break plan explicitly disallows.

Using the authenticated holder's legacy `/issue` action only as a diagnostic produced a fresh offer. Walt.id accepted and stored the Marty Verified Member Badge as `jwt_vc_json`, resolved the beta VCT metadata with HTTP 200, and displayed the credential. This proves downstream OID4VCI interoperability, but it does not make the supported user journey pass.

### Critical: Badge login does not complete in a browser wallet

The Open Badge login page correctly creates a signed OID4VP request and advertises SpruceKit and Lissi as its intended wallets. A local walt.id browser wallet was used as an additional interoperability probe:

1. Walt.id resolved the signed request and verifier DID.
2. Its DCQL matcher selected the stored Marty badge.
3. The holder saw the requested claims and approved disclosure.
4. Walt.id returned HTTP 400 from its own `usePresentationRequest` operation before submitting to beta.
5. Beta remained pending and `/v1/auth/me` remained unauthenticated.

The walt.id API error says its internal `request` string should be quoted. This is a walt.id presentation-path compatibility defect or a wallet-specific request adaptation gap, not evidence that the SpruceKit/Open Badge target is invalid. Beta cannot currently demonstrate logout and passwordless login with the available browser wallet.

The wallet also shows the credential issuer as `Unknown` and logs a null-reference error after acceptance, despite resolving the VCT metadata successfully.

### Critical: Issuance and verification flows cannot be created

The isolated organization successfully created or exposed the prerequisite KMS service, issuer identity, trust profile, active Credential Template, active Presentation Policy, active Deployment Profile, and API key. Runtime status reported one active credential template, policy, and deployment profile, but zero active flows and `can_issue: false`.

The Flow Definition wizard calls organization-neutral `GET /v1/flows/capabilities`, receives HTTP 403 `Action not authorized`, and disables Next. This blocks both OID4VCI issuance and OID4VP verification flow creation.

The standalone verification page has a second blocker. Its policy request returns a direct array containing one active policy, but `PolicySelectStep` only reads `response.items` or `response.policies`. The Presentation Policy selector is therefore empty and Next remains disabled. No organization verification request can be handed to a browser wallet through the supported UI.

### High: Application Template CRUD is only partially deployed

The previously missing create, detail, edit, and advanced-create routes now render. The advanced editor successfully:

- loaded the isolated organization's active Credential Template;
- derived six form fields, including the date claim;
- created an Application Template through HTTP 200;
- opened its detail route.

The resulting template was immediately `active`, even though the editor says **Save draft** and the clean-break contract requires validation before activation. No Activate action appeared. `DELETE /v1/application-templates/{id}` returned HTTP 405, so the visible Delete action and audit cleanup cannot work against the deployed API. The audit-created template remains because the supported delete contract is unavailable.

### High: Organization context emits wrong-org requests during switching

Before the visible organization menu selection settles, the org console issues requests with the default Marty applicant organization ID. These return multiple 403 responses. A direct preferences update returned 200 but did not update the already-mounted React context; selecting through the visible menu corrected subsequent requests. Product code should suppress org-owned resource loads until `activeOrgId` and the auth context agree.

### Additional UX findings

- The verification tab displays the untranslated key `OPERATE.TABS.VERIFY`.
- `/v1/passport/capabilities` still returns 404 on organization pages.
- Free-plan `/v1/policy-sets` responses are still surfaced as unexpected 403 errors instead of entitlement states.
- Live responses continue to advertise `X-MIP-Version: 0.1` while the UI and planned contracts identify MIP 0.3.

### Updated correction order

1. Atomically deploy the MIP 0.3 applicant service, gateway routes, migration, and holder inventory endpoint; remove the legacy router from beta.
2. Make `/v1/flows/capabilities` authenticated organization-neutral metadata and restore Flow Definition creation.
3. Normalize direct-array policy responses in `PolicySelectStep`, then execute standalone verification through a browser wallet.
4. Make Application Template creation persist `DRAFT`, add explicit validation/activation, and implement the advertised DELETE contract.
5. Prevent org resource requests until active organization selection is synchronized across ConsoleContext and AuthContext.
6. Keep SpruceKit as the Open Badge login conformance target; add walt.id only after its presentation request path is adapted or fixed and covered by a separate compatibility test.
7. Repeat the full holder and issuer lifecycle. Do not release until canonical issuance, inventory, logout, credential login, verification, revocation, and renewal all pass without legacy calls.

### Follow-up evidence

- `tests/artifacts/beta-membership-probe-20260712005222/report.json`
- `tests/artifacts/beta-credential-login-20260712T002854/report.json`
- `tests/artifacts/beta-credential-login-20260712T003547/report.json`
- `tests/artifacts/beta-org-console-audit-20260711181720/report.json`
- `tests/artifacts/beta-org-credential-paths-20260712T004759/report.json`
- `tests/scripts/probe-beta-membership-badge.js`
- `tests/scripts/verify-beta-credential-login.js`
- `tests/scripts/audit-beta-org-credential-paths.js`

All follow-up JSON reports omit credential offers, pre-authorized codes, presentation tokens, passwords, and API key values.

## Local Remediation Evidence - 2026-07-11/12

The mixed-version beta findings above remain historical deployment evidence. The coordinated local implementation now addresses the corresponding product defects:

- Gateway responses and flow capabilities advertise MIP `0.3.0` only.
- Canonical applicant, reviewer, claim readiness, and holder inventory tests pass; the legacy applicant router is not registered.
- Application Templates are draft-first with canonical fields, `PATCH`, validation, activation, deprecation, and draft-only deletion across protocol, gateway, external issuance, API client, and UI.
- Presentation Policy and Flow lists require direct arrays. Malformed contracts show Retry instead of becoming silent empty lists.
- `ConsoleContext.activeOrgId` is the sole source for org-owned UI requests. Permission loading is blocked until memberships are loaded and the selection is valid; the authenticated applicant organization is no longer mutated by console switching.
- Beta membership and walt.id scripts no longer contain legacy diagnostic issuance or discovery fallbacks. Removed routes remain only as explicit 404 probes.
- The Verify tab resolves through the `operate.tabs.verify` localization key.
- Physical-document capability 404s become typed unsupported states at the gateway.
- CD requires an exact `marty-credentials` commit SHA for every external issuance checkout.
- The disabled legacy E2E workflow and obsolete authenticator checkout are replaced by a protected beta lifecycle gate using canonical probes and digest-pinned walt.id `0.5.0` images.
- The membership probe now fails unless canonical profile/application/inventory routes advertise MIP `0.3.0` and every removed applicant route returns `404`.
- External issuance CI requires a single Alembic head; local validation reports `application_template_mip03 (head)`.
- CD verifies an exact protocol commit and an exact external issuance commit, then publishes an atomic release-manifest artifact before any coordinated image build can proceed.
- CD captures actual service/UI/migration image digests and marks a release ready only after a protected, safety-marked beta-copy migration rehearsal applies and verifies successfully.

Verification completed locally:

- Protocol: codegen drift check plus `122 passed`.
- External issuance: `226 passed`, with 11 explicit Rust-extension skips covered by the CD wheel lane.
- Applicant clean break: `12 passed` across canonical routes, migration, ownership, field validation, claim readiness, and profile linkage.
- Application Template issuance lifecycle: `5 passed`; related Canvas configuration: `4 passed`.
- Gateway Application Template and MIP headers: `12 passed`; broader issuance gateway contract: `36 passed`.
- Deployment Profile wizard: `22 passed` under the direct-array MIP 0.3 contract.
- Deterministic Playwright credential gate: `5 passed`, including reviewer actions, wallet selection, and responsive holder inventory.
- Complete service suite: `654 passed, 1 skipped` (Redis integration).
- Complete frontend suite, TypeScript compilation, production Vite build, and generated-binding drift check pass.

At that point, beta deployment, full-stack workflow execution, SpruceKit badge-login acceptance, migration rehearsal, and destructive lifecycle verification remained release gates. The deployment section below supersedes this historical pre-cutover status.

## Live Beta Revalidation - 2026-07-11 22:41-22:50 MDT

This run used fresh applicant and organization sessions, visible UI controls, and a local browser-based walt.id wallet. It confirms that the current beta deployment still cannot complete either required credential lifecycle. The first blocking dependency is the mixed MIP deployment, not wallet request parsing.

### Holder badge and credential login

- Beta advertises only MIP `0.1` in `/.well-known/mip-configuration` and `X-MIP-Version` responses.
- The Membership ID page renders and exposes **Add to Wallet**, but canonical profile, application, and inventory requests return 404. The action ends with `Not Found` before any wallet selector appears.
- Removed applicant routes remain deployed: legacy profile and user-application reads return 200, while other removed routes return 405 or 422 instead of 404.
- My Identity silently converts its failed canonical inventory request into a zero-credential state. At 320px the page no longer overflows, but the empty state is factually misleading.
- Logout succeeds and `/v1/auth/me` returns `{ "authenticated": false }`.
- Credential login advertises SpruceKit and Lissi, includes a nonce, and creates a signed presentation link.
- Walt.id resolves the login presentation request and executes credential matching with HTTP 200. It correctly reports that the wallet has no matching credential. The earlier walt.id `usePresentationRequest` failure was not reached because canonical beta issuance never produced a badge.

Result: the required membership-badge issuance, inventory, logout, and badge-login journey is blocked at canonical application creation. SpruceKit acceptance remains untested because it requires its separate conformance/device lane.

### Organization primitive creation

A new isolated organization (`213e8e2d-78e4-43b4-8517-d0e34009aff6`) was created through the UI. The organization successfully created or exposed:

- KMS service registration;
- issuer identity;
- active Trust Profile;
- active Credential Template;
- active Presentation Policy;
- active Deployment Profile;
- API key.

The Flow Definition wizard cannot advance because `GET /v1/flows/capabilities` returns 403 `Action not authorized`. The organization reviewer queue is also unavailable because the canonical organization applicant route returns 404.

### Application Template lifecycle

The advanced editor loaded the new Credential Template, derived six fields, and created Application Template `d6b39b7f-8199-4574-ac08-8fde91bd18fb` with HTTP 200. Although the visible command was **Save draft**, the resulting template was immediately `ACTIVE`; no explicit validation or activation request occurred. This confirms that the deployed service still violates the draft-first MIP 0.3 lifecycle.

### Browser verification

Standalone verification can select the active Presentation Policy and create an OID4VP request. Walt.id resolves that request and performs credential matching with HTTP 200. Completion is blocked by two independent defects:

- the wallet has no matching badge because holder issuance failed upstream;
- beta returns 403 when the UI polls `GET /v1/flows/instances/{id}`, leaving the verification instance shown as `Unknown` or pending.

The flow instance list records the standalone `__verification__` instance, confirming request creation, but the supported UI cannot observe a terminal result. Policy Sets still return a plan-related 403 as an unexpected error, and passport capabilities still return 404 rather than a typed unsupported state.

### Responsive and runtime observations

- Holder catalog, membership application, and inventory pages have no horizontal overflow at 320px.
- The catalog still displays products whose active Application Template and canonical applicant dependencies are unavailable.
- No Playwright page exceptions occurred in these runs.
- Cloudflare RUM aborts and EventSource aborts during navigation were treated as infrastructure noise; all unexplained product 4xx responses are listed above.
- The running local walt.id stack uses floating `stable` images. It was not replaced during this audit; release acceptance must use the repository's digest-pinned wallet images.

### Revalidation evidence

- `tests/artifacts/beta-membership-probe-20260712044122/report.json`
- `tests/artifacts/beta-org-console-audit-20260711224258/report.json`
- `tests/artifacts/beta-org-credential-paths-20260712T044455/report.json`
- `tests/artifacts/beta-live-operations-20260712T044818/report.json`
- `tests/artifacts/beta-badge-login-entry-20260712T045005/`

### Release decision

**Blocked.** Do not promote the current beta. Deploy the MIP 0.3 protocol, applicant service, issuance service, gateway routes, migration, and UI atomically; then rerun the same fresh-user lifecycle. The release gate must require canonical badge issuance, holder inventory, logout and credential login, flow creation, browser-wallet verification, reviewer operations, and lifecycle controls without legacy calls or unexplained 4xx responses.

## Audit-Driven Development Follow-Up

The live revalidation was used as a dependency-ordered development test. Four additional local defects or gate weaknesses were corrected after the audit:

1. **Holder inventory honesty:** My Identity no longer converts failed inventory and application requests into an empty account. The two sources load independently, successful data remains visible, failures identify the unavailable source, and Retry performs a fresh load. A total failure does not render **No credentials yet**.
2. **Flow instance organization ownership:** Cedar now resolves `/v1/flows/instances/{id}` and `/v1/flows/definitions/{id}` through the flow service before authorization. It uses the resource's persisted `organization_id`, even when the authenticated session's default organization differs. This directly addresses the 403 observed while polling the standalone verification instance.
3. **Flow dependency service routing:** Flow Definition validation now resolves Application Templates from the external issuance service, not the Credential Template service, and supplies the internal issuance management credential. This prevents a valid active Application Template from being misreported as missing after the capabilities blocker is removed.
4. **Lifecycle release assertions:** The beta browser gate now requires Application Template creation to return `DRAFT`, validation to succeed, activation to return `ACTIVE`, wallet presentation submission to succeed, authenticated flow polling to return 200 with a terminal verified state, zero product page exceptions, and zero unexplained beta 4xx/5xx responses.

The catalog implementation already joins active Credential Templates to active Application Templates and hides incomplete products. The live catalog exposed eleven products because the deployed issuance service incorrectly made newly created templates active; no additional catalog fallback was retained.

Development verification:

- My Identity focused suite: `6 passed`.
- Verification, policy selection, Application Template detail, and My Identity UI suites: `14 passed`.
- Cedar, flow routing, proxy headers, Application Template gateway models, and flow capability suites: `52 passed`.
- External issuance Application Template lifecycle: `5 passed`.
- Deterministic canonical reviewer Playwright lifecycle: `3 passed`.
- Browser audit script syntax check: passed.
- Production TypeScript and Vite build: passed.

These results drove the coordinated beta deployment documented below.

## MIP 0.3.0 Beta Deployment - 2026-07-12

### Atomic release

- `https://beta.elevenidllc.com` advertises only MIP `0.3.0`; the discovery response and `X-MIP-Version` header both return `0.3.0`.
- The local beta database, Redis, OpenBao, and applicant store were backed up before the one-way cutover under `tests/artifacts/deployment-mip-0.3.0-beta-20260712/`.
- The applicant store was migrated to `MIP/0.3.0`, all ten relational service migration heads verify, and the Flow trigger migration is at `20260712_0001`.
- CD run `29184445130` passed protocol conformance, generated-binding drift, Rust wheel compilation, services/UI/migration image builds, fresh-schema rehearsal, legacy applicant-store rehearsal, and release-manifest publication.
- The release-ready manifest pins seven repository revisions, four Marty image digests, tested walt.id image digests, `mixed_versions_supported: false`, and migration rehearsal mode `ephemeral-schema`.
- A fresh-install migration defect discovered by the rehearsal was corrected: the historical Flow migration no longer deletes Presentation Policy tables or migration state owned by another service.

### Live beta acceptance

- Canonical applicant profile, applications, holder inventory, and claim routes return `200`; every removed applicant route probed by the gate returns `404`.
- A membership-badge claim generated a fresh canonical offer with no failed requests or page exceptions. Evidence: `tests/artifacts/beta-membership-probe-20260712074553/report.json`.
- Walt.id accepted and stored the Marty Verified Member Badge, resolved its public VCT metadata with `200`, and contained no legacy `marty.example` identifier.
- Organization-selected dashboard authorization returns `200`; Application Templates are draft-first, validation-gated, and activatable; standalone verification session creation and cancellation work.
- All coordinated runtime containers are healthy and the post-deployment migration verifier reports `10` successful services and `0` failures.

### Remaining interoperability boundary

- SpruceKit remains the authoritative Open Badge login conformance target and still requires its protected conformance/device acceptance run.
- Walt.id issuance is accepted, but its presentation API rejects the signed DCQL login request with a wallet-side JSON decoding error for `$.request`. The signed standards request was not weakened to accommodate that parser defect.
- Walt.id `0.5.0` is not accepted for issuance because it emits proof JWT type `JWT` instead of the required `openid4vci-proof+jwt`; the tested stable API and demo-wallet pair is pinned by digest until an upstream versioned release passes.
- Walt.id resolves the credential title and VCT metadata but still renders the issuer label as `Unknown`; issuer display metadata remains an interoperability follow-up.
- Native wallet handoffs and destructive suspend, reinstate, revoke, and renewal scenarios remain device-lab gates.

### Current decision

The MIP `0.3.0` clean-break deployment is live and its canonical issuance path is release-ready. Passwordless badge login is not yet fully accepted until the SpruceKit lane passes; walt.id presentation remains an external compatibility blocker rather than an advertised login path.
