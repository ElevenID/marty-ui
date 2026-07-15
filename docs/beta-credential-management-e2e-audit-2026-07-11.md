# Beta Credential Management E2E Audit

Date: 2026-07-11
Updated: 2026-07-12
Target: `https://beta.elevenidllc.com`
Method: Chromium Playwright using the repository's configured testing users and live beta services.

## Remediation Status

The first clean-break MIP 0.3.1 remediation was deployed to beta on 2026-07-12. Subsequent audit-driven hardening changed the coordinated revision and strengthened release provenance, so that historical deployment is engineering evidence but is not promotion evidence for the current revision. Current implementation evidence covers:

- old `/v1/applicants/*` routes absent and canonical route inventory present;
- persisted organization authorization, explicit review/decision permissions, and caller-held reviewer locks;
- strict application creation, server-derived templates/checks, structured field validation, blocked/ready claim states, and holder inventory;
- registered Application Template create/detail/edit routes and fail-closed Flow capability loading;
- dedicated `reviewer@marty.demo` provisioning and reviewer membership configuration;
- MIP 0.3.1 generated bindings current, protocol conformance and drift checks passing, and Rust/TypeScript bindings building successfully;
- 742 UI/service tests passing with one explicit skip, 257 credential-service tests passing with 11 explicit skips, 125 protocol tests passing, and all 167 CLI tests passing;
- the complete frontend suite and production build passing;
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

- `https://beta.elevenidllc.com` advertises only MIP `0.3.1`; the public `X-MIP-Version` header returns `0.3.1`.
- The local beta database, Redis, OpenBao, and applicant store were backed up before the one-way cutover under `tests/artifacts/deployment-mip-0.3.0-beta-20260712/`.
- The applicant store was migrated to `MIP/0.3.0`, all ten relational service migration heads verify, and the Flow trigger migration is at `20260712_0001`.
- CD run `29185132375` passed protocol conformance, generated-binding drift, Rust wheel compilation, services/UI/migration image builds, fresh-schema rehearsal, legacy applicant-store rehearsal, and release-manifest publication.
- The release-ready manifest pins seven repository revisions, four Marty image digests, tested walt.id image digests, `mixed_versions_supported: false`, and migration rehearsal mode `ephemeral-schema`.
- That historical ephemeral rehearsal no longer satisfies the strengthened promotion contract. Current CD requires an identified protected beta database copy, records its snapshot ID, and has no empty-schema fallback; a new matching CD run is required before the wallet-conformance workflow can publish a release-ready manifest.
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
- Native wallet handoffs remain device-lab gates. The Marty browser-wallet lane now covers renewal, suspension, reinstatement, and revocation deterministically.
- Repository enforcement is complete: `.github/workflows/wallet-conformance.yml` validates protected SpruceKit and native-handoff evidence against the exact build-ready manifest and beta lifecycle run. CD remains `release_ready=false` until that protected workflow publishes the release-ready attestation.

### SpruceKit metadata remediation - 2026-07-12 14:35-14:50 MDT

The release audit found eight active Credential Templates still using
`https://marty.example/credentials/*`; seven appeared in the Spruce-specific
issuer metadata. The prior diagnostic script requested obsolete URLs, disabled
TLS verification, and exited successfully on HTTP 404, so it could not serve as
a release check.

The remediation is a clean one-way change:

- migration `20260712_0004` rewrites only active placeholder VCTs to
  `https://beta.elevenidllc.com/credentials/*` and leaves nine deprecated
  placeholder values intact for audit display;
- Credential Template create, update, and activation reject `marty.example`;
- `scripts/check_spruceid_metadata.py` requires matching canonical and appended
  metadata, issuer display, the membership profile, public HTTPS SD-JWT VCTs,
  and correctly formed Spruce mDoc entries;
- beta lifecycle records the probe as `spruce-metadata.json`, while protected
  promotion rechecks the live endpoint and binds the rehearsed public origin to
  the promoted beta origin.

The current migration image was replayed from the preserved pre-cutover dump in
an isolated database with `PUBLIC_API_URL=https://beta.elevenidllc.com`. All ten
service heads applied and verified, Credential Template reached `20260712_0004`,
active legacy VCTs reached zero, application/template references remained
resolved, and deprecated history remained. A fresh live backup was captured as
`tests/artifacts/deployment-mip-0.3.0-beta-20260712/postgres-pre-vct-20260712T144640.dump`
before applying the same image to beta. The isolated rehearsal database was then
removed.

Live metadata now reports issuer display `ElevenID LLC`, ten Spruce SD-JWT
configurations plus the valid mDL mDoc configuration, and no active placeholder
VCT. Gateway, Credential Template, and issuance services are healthy; Walt.id
diagnostic containers remain stopped. The live migration log also exposed that
the tunnel environment inherited the compose `dev` migration profile. No new
seed migration ran and the public HTTPS origin produced the intended result, but
the beta environment is now explicitly pinned to `MARTY_MIGRATION_PROFILE=beta`
for subsequent deployments. A second migration verification ran under the beta
profile with all ten services successful, zero failures, and every head current.

### MIP 0.3.1 lifecycle acceptance - 2026-07-12

The deterministic final-spec browser journey now passes on beta:

1. The holder claims a fresh membership badge through canonical self-service APIs.
2. The holder explicitly logs out, receives the badge in the Marty browser wallet, presents it to the signed credential-login request, and returns authenticated as `john.doe@marty.demo`.
3. The organization issues a fresh policy credential bound to the holder public key through `cnf.jwk`.
4. The organization creates, validates, and activates an Application Template through the UI.
5. The browser wallet submits a signed DCQL presentation; signature, holder binding, Trust Profile issuer match, and authoritative issuer status all pass.
6. The Flow result is `COMPLETED`, evaluation is `passed`, and decision is `allow`.
7. The operator renews an eligible credential through the UI, the wallet redeems the replacement offer, the source is revoked as superseded, and both credentials retain their renewal links.
8. The replacement verifies as denied while suspended, allowed after reinstatement, and denied after revocation.
9. A wrong-organization lifecycle request returns `403`, and every status-list URI remains owned by the credential organization.

Development fixes driven by this run:

- issuance now returns the cryptographically verified holder public JWK and strips all private key fields before placing it in `cnf.jwk`;
- Credential Template activation refreshes the managed issuer context and rejects a Trust Profile that does not trust that issuer DID;
- authoritative credential status includes `issuer_did`, so non-`did:web` managed identities are accepted only when the stored credential issuer exactly matches the verified presentation issuer;
- the beta setup audit no longer silently creates a fake manual DID when the managed issuer selector is unavailable;
- the focused credential-login script uses the Marty browser wallet rather than the unsupported Walt.id presentation path;
- Credential Template validity policy is copied into issuance transactions, and `/v1/issued-credentials/{id}/renew` creates a linked replacement offer rather than reissuing an application;
- renewal linkage is restored by the real issuance transaction mapper; the browser gate caught and prevented a misplaced Canvas receipt mapping from reaching release;
- a one-way issuance migration adds renewal policy and supersession links at the single `credential_renewal_mip031` migration head.
- the current migration image was rehearsed locally against the preserved pre-cutover beta dump `tests/artifacts/deployment-mip-0.3.0-beta-20260712/postgres-pre.dump`, restored into an isolated beta-copy database. All ten service heads applied and verified with zero failures; post-migration integrity checks found 66 Credential Templates with zero active revocation gaps, 22 applications with zero missing Application Template links, 36 historical Flow Definitions preserved as explicit `custom` extensions, both renewal-link columns, and inactive Walt.id. The isolated database was removed after verification.

Evidence:

- `tests/artifacts/beta-org-credential-paths-20260712T202814/report.json`
- `tests/artifacts/beta-credential-login-20260712T201139/report.json`
- `tests/artifacts/beta-membership-probe-20260712201700/report.json`
- `tests/artifacts/beta-credential-lifecycle-20260712T201804/report.json`
- `tests/artifacts/beta-org-credential-paths-20260712T204857/report.json`
- `tests/artifacts/beta-credential-login-20260712T204955/report.json`
- `tests/artifacts/beta-membership-probe-20260712204839/report.json`
- `tests/artifacts/beta-credential-lifecycle-20260712T204938/report.json`

### Current decision

The MIP `0.3.1` deterministic beta lifecycle is ready for canonical browser issuance, membership-badge logout/login, Application Template lifecycle, organization verification, renewal, suspension, reinstatement, revocation, cross-organization lifecycle denial, and strict SpruceKit issuer metadata. Overall promotion still requires publishing the final coordinated commit, a beta-copy-qualified CD manifest with the exact rehearsal origin, and protected SpruceKit/native evidence for the same commit and beta run. Walt.id remains inactive and unadvertised until an upstream final-spec issuance and presentation pair passes.

## Final Audit-Driven Revalidation - 2026-07-12 16:37-16:48 MDT

The final browser and log pass found and corrected one issuance-boundary defect and two hidden runtime reliability defects:

- Flow webhook orchestration was copying scalar event metadata into credential claims and ignoring canonical `data.claims`. It now consumes only the applicant service's canonical claim map and requires the structured `APPLICATION_APPROVED` trigger; legacy precondition matching and deferred `_application_id` claim resolution were removed.
- Credential login profile upsert omitted the trusted organization header. It now supplies `X-Organization-ID`, so canonical profile synchronization succeeds instead of logging a recoverable `422`.
- Shared gRPC clients pinged idle services every 30 seconds without a limit, causing `ENHANCE_YOUR_CALM / too_many_pings` disconnects. Clients now use a five-minute active-call-only keepalive policy. Disabled Keycloak token exchange is explicit configuration and no longer produces a known `400` probe.

Live claim-boundary proof for Jane Smith:

- application `26ddadcb-9700-4b2f-88d2-252090352f06` stores only `email`, `given_name`, and `family_name` in `form_data`;
- issuance transaction `68dcc65b-2096-4e3d-8c18-ec2588eff3c7` contains those mapped values plus server-derived `member_id`, `organization_id`, `organization_name`, `issued_at`, and `role`;
- no applicant ID, arbitrary form field, integration context, or top-level application event metadata became credential content.

Latest release-ready browser evidence:

- `tests/artifacts/beta-membership-probe-20260712225531/report.json`
- `tests/artifacts/beta-credential-login-20260712T225549/report.json`
- `tests/artifacts/beta-org-credential-paths-20260712T223813/report.json`
- `tests/artifacts/beta-credential-lifecycle-20260712T223855/report.json`

Final automated verification:

- Marty UI/services: `727 passed, 1 skipped`.
- Marty Credentials: `257 passed, 11 skipped`.
- Frontend: `1,016 passed` across `150` files.
- MIP protocol: `110 passed, 3 skipped`; generated bindings are current; Rust tests and TypeScript build pass.
- Latest credential-login and flow logs contain no unexplained error, profile-provisioning warning, token-exchange failure, or gRPC keepalive throttle.

One-way migration evidence is preserved under `tests/artifacts/deployment-mip-0.3.1-beta-20260712T161209/`, including full backups before canonical Application Template conversion and server-owned claim derivation. Both migrations were rehearsed against isolated restores and then applied to beta with all migration services successful.

Release decision: deterministic beta is build-ready and all repository-controlled browser acceptance paths pass. Promotion remains intentionally fail-closed until protected SpruceKit Open Badge login and all required native handoff evidence are attached to the exact coordinated build and beta run.

## Fresh Organization Release Gate - 2026-07-12 17:34-17:38 MDT

The beta lifecycle gate now proves that a new organization can create its own issuance and verification foundation instead of relying only on `BETA_AUDIT_ORG_ID` fixtures. The Playwright owner journey creates a disposable organization and requires canonical active state for signing configuration, issuer identity, Trust Profile, Revocation Profile, Credential Template, Application Template, Presentation Policy, Deployment Profile, OID4VCI issuance flow, OID4VP verification flow, and API key. Both flows must be created as drafts, validate successfully, and activate before final inventory can pass.

The audit drove three corrections:

1. Credential Template creation displayed “now active” while the API resource remained `DRAFT`. The wizard had deleted `activate_immediately` before the service could perform the explicit activation call. The flag now remains in memory, is excluded from the create payload, and triggers `/activate` before success.
2. Application Template and Flow MUI selects had visible labels but no accessible names. Their `InputLabel` and `Select` controls now use explicit `labelId`/`id` associations, with tests covering the required Credential Template, Approval, Trigger, and dependency controls.
3. The old organization audit accepted `submitted-or-blocked` checkpoints and always exited zero. Required checkpoints now represent canonical active state, unexplained failures block, activation reads use bounded convergence polling, final inventory is run-scoped, and a blocked report exits nonzero.

Passing evidence: `tests/artifacts/beta-org-console-audit-20260712174926/report.json`. The run created and activated every required primitive against the final deployed console bundle, validated and activated both flow types, verified all run-created MIP dependency links, observed no page exception or failed browser request, and recorded only typed free-plan Policy Set entitlement responses. The fresh audit is installed in `.github/workflows/e2e-tests.yml` before the seeded membership, credential-login, browser-wallet verification, and destructive lifecycle jobs. The complete frontend suite now passes `1,017` tests across `151` files.

## Protected Promotion Hardening - 2026-07-12

The promotion completion audit found that the fresh-organization artifact and exact Marty Core browser-wallet revision were downloaded but not validated by `promote_release_evidence.py`. It also found that protected attachment SHA strings were accepted without downloading the referenced content. These gaps are closed as breaking evidence schema v2:

- promotion requires the successful CD and beta lifecycle workflow names, conclusions, and exact Marty UI SHA;
- the build manifest must contain exactly all seven coordinated repository SHAs and full lowercase image digests;
- the beta Marty Core revision must match the build manifest;
- the fresh-organization report must pass with no page/request failures and contain the exact 11-resource verified inventory;
- SpruceKit evidence requires exact badge and issuer display names, while every native handoff records its build, platform, device model, and OS version;
- all four protected attachments are downloaded through HTTPS-only redirects, byte-hashed, and bound to the exact wallet evidence JSON;
- the release-ready manifest records CD, beta, and promotion run IDs plus non-sensitive attachment kind/hash/size summaries, without holder email or protected URLs.

Focused release-promotion, manifest, and attachment verification suites pass. Protected SpruceKit/native execution remains a real external device-lab input; the repository no longer accepts metadata-only attachment attestations.

The same completion audit then identified a deployment-provenance gap: the beta
lifecycle artifact recorded the workflow checkout SHA but did not prove that the
running beta services and UI came from that build. CD now embeds release version
and Marty UI SHA into both images. The beta gate downloads the selected
build-ready manifest, verifies the successful CD run at that SHA, and requires
matching runtime markers from `/.well-known/marty-release` and
`/marty-ui-release.json` before Playwright starts. Promotion independently checks
the recorded markers, CD run, release version, exact image set, first-party tags,
external wallet digests, and built-image digests. The expanded focused suite
passes 53 tests, and the complete gateway suite passes 294 tests. Existing local beta evidence remains useful engineering evidence
but cannot promote the next release; the marker-bearing coordinated build must be
published and deployed first.

The audit also compared the live MIP discovery body with
`marty-protocol/schemas/mip-configuration.json`. The gateway was advertising
0.3.1 while still returning a pre-clean-break body that omitted the required
`mip_configuration_endpoint` and added forbidden profile/endpoint/authorization
objects. No first-party consumer depended on those fields. The gateway now emits
the strict canonical document and its generated value passes the protocol JSON
Schema with URI format checks. The beta gate rejects the removed shape even when
the body and header version strings are correct.

Pre-deployment confirmation on 2026-07-12: live beta returns `404` for the
services marker, serves the existing SPA fallback for the UI marker, and still
returns the removed discovery extensions. This is the expected fail-closed state
for the newly strengthened gate and confirms that no existing local evidence can
be mistaken for evidence from the marker-bearing release.

## Repository Completion Pass - 2026-07-12

The post-gate implementation audit found and corrected five additional first-party defects:

1. Self-service Application creation incorrectly searched for the applicant profile inside the target issuer organization and then persisted the Application under the profile organization. The gateway and applicant service now keep the authenticated applicant organization immutable for profile ownership while persisting the requested issuer organization on the Application. A cross-organization regression proves a holder in one default organization can apply to an authorized product in another without moving or duplicating the profile.
2. `ApplicationReviewPage` used the authentication organization after an operator switched console organizations. Review reads, locks, evidence, and decisions now use only validated `ConsoleContext.activeOrgId`; the regression fixture deliberately gives the user a different authentication organization.
3. The canonical signing-key purpose and service-capability endpoints returned hard-coded `503` responses even though the signing-key service implemented them. The gateway now proxies both endpoints through the service registry.
4. Flow status parsing retained removed lifecycle aliases such as `WAITING`, `WAITING_APPROVAL`, and `canceled`. Public and gRPC parsing now accept only canonical MIP 0.3.1 status values.
5. Credential Template requests still exposed deprecated `issuer_requirements`, `artifacts_auto_generate`, and client-selected status behavior. Public gateway/service models now forbid removed fields and use only `auto_generate_artifacts`; historical storage remains readable for audit.
6. The pinned Marty Core revision referenced a vendored `core2` patch that was not tracked and ignored the workspace `Cargo.lock`, while the beta workflow required `cargo build --locked`. Marty Core now treats its lockfile, vendored patch, and `marty-test-wallet` crate as release sources. The beta workflow checks all three and runs locked Cargo metadata before compiling the wallet.

The stale OID4VCI auto-trigger guide was also rewritten around canonical reviewer actions, server-derived claims, explicit custom Flow extensions, and `claim_state` recovery. No source or first-party client teaches a removed applicant route.

Latest local verification:

- Marty UI/services: `746 passed, 1 skipped`.
- Marty Credentials: `257 passed, 11 skipped`.
- Marty Protocol: `125 passed`; generated output is current; Rust compile tests and the TypeScript binding build pass.
- Marty CLI: `167 passed`.
- Frontend: complete test suite and production build pass.
- Deterministic Chromium credential paths: `5 passed`, covering request information, rejection, approval, browser-wallet selection, and responsive holder inventory.
- Marty Core release lane: `150` final-spec OID4VCI/browser-wallet tests pass, with two intentional SIOPv2 skips and three ignored doc examples; the browser-wallet crate contributes two tests and the Python bindings compile against the same locked engine.
- Release/promotion, source-CI, and GitHub environment contract tests: `61 passed`.
- Application Template lifecycle tests: `15 passed`.
- Migration runner/applicant conversion tests: `23 passed`.
- Every one of the eight `marty-ui` Alembic trees resolves to exactly one head; the external issuance tree resolves to `derive_server_owned_claims (head)`.

Current release decision: repository-controlled MIP 0.3.1 work is build-ready. It is not release-ready and must not reuse the historical beta artifacts. The next valid path is to publish one coordinated revision set, run CD against the protected identified beta copy and exact HTTPS origin, deploy the manifest's immutable images atomically, require matching service/UI runtime markers, rerun the full beta lifecycle, and attach SpruceKit plus required native-wallet evidence for that exact build and run. Walt.id remains inactive and unadvertised.

GitHub deployment preflight at this boundary:

- GitHub authentication and package/workflow scopes are available.
- `beta-lifecycle` exists with the beta origin, audit organization, and seeded applicant/vendor credentials.
- coordinated repository variables still name the previous release revisions and must be updated only after the final repositories are published.
- `beta-migration-rehearsal` exists but does not yet contain `MIGRATION_REHEARSAL_DATABASE_URL`, `MIGRATION_REHEARSAL_DATABASE_MARKER`, `MIGRATION_REHEARSAL_SNAPSHOT_ID`, or `MIGRATION_REHEARSAL_PUBLIC_API_URL`; CD will fail closed until an identified beta snapshot is restored to the marked rehearsal database.
- `wallet-conformance` does not yet exist and must be created with protected review rules before device evidence can promote a release. `WALLET_EVIDENCE_BEARER_TOKEN` is required only when protected attachment URLs need bearer authentication.
- CD now runs `scripts/check_github_release_environments.py` before building. The machine-readable manifest requires reviewers, disabled self-review and administrator bypass, restricted deployment branches, required input names, and lowercase 40-character coordinated revision variables; the live configuration currently fails for the blockers above.
- CD also requires successful exact-SHA `CI` workflows for Marty Protocol and Marty Credentials plus the dedicated `MIP Release Wallet` workflow for Marty Core. The broader historical Core CI remains separate from this release authority because it includes unrelated cross-platform, biometrics, and workspace-formatting debt.
- ElevenID is currently on GitHub Free with a private `marty-ui` repository. GitHub rejects branch-protection configuration with an upgrade-required `403`, and no ElevenID reviewer team exists. [GitHub documents](https://docs.github.com/en/rest/deployments/environments?apiVersion=2026-03-10) required reviewers on private repositories as an Enterprise capability; the organization must use an Enterprise plan (or make an explicit, separately reviewed public-visibility decision) and assign an independent reviewer before the enforced environment preflight can pass. The release contract is not weakened around this entitlement.

## Local Release And Compliance Profile Completion - 2026-07-12/13

GitHub execution is temporarily deferred. A repository-controlled local lane now freezes all coordinated worktrees into checksum-addressed snapshots, verifies that neither source nor snapshots change, backs up PostgreSQL/applicant/Redis/OpenBao state, rehearses the exact migration image on an isolated restored beta copy, builds release-tagged images, applies the live migration, recreates all application/UI containers, and compares local and tunneled runtime markers. Every local manifest is permanently marked `source_kind=local-worktree-snapshot`, `promotion_eligible=false`, and `release_ready=false`.

The first complete immutable run, `mip-0.3.1-local-20260713T021224Z`, proved the lane mechanics. Browser-driven development after that snapshot exposed a remaining MIP dependency defect:

1. Discovery reported no active Compliance Profile while Credential Templates silently used an inline `CUSTOM` fallback.
2. Credential Template requests still carried client-authored wallet compatibility fields. The UI removed its obsolete Wallet Compatibility step, but the gateway reintroduced `wallet_configs: []` from a defaulted request model.
3. The Compliance Profiles page exposed Create/Edit/Detail actions with no complete persistent lifecycle behind them.

The clean-break correction now provides immutable system profile `OID4VC Core` (`10000000-0000-0000-0000-000000000001`) as an active discoverable dependency for every organization. Protocol schemas/examples/bindings require lifecycle status, Credential Templates require `compliance_profile_id`, embedded profiles and `wallet_configs` are rejected, wallet compatibility remains server-derived, and dead custom-profile actions are hidden until their full lifecycle exists.

Latest development-stack browser evidence after that correction:

- `tests/artifacts/beta-org-console-audit-20260712210137/report.json`: all `66` fresh-organization checkpoints pass; signing, issuer, trust, system compliance, revocation, Credential/Application templates, Presentation Policy, Deployment Profile, both flows, API key, and final dependency inventory are active; no blocker, page error, or failed request.
- `tests/artifacts/beta-membership-probe-20260713030407/report.json`: canonical profile/application/inventory routes pass, Claim recovers, and all removed applicant routes return `404`.
- `tests/artifacts/beta-credential-login-20260713T030427/report.json`: a fresh membership badge is received by the browser wallet, explicit logout occurs, signed DCQL presentation completes, and `john.doe@marty.demo` is authenticated again.
- `tests/artifacts/beta-org-credential-paths-20260713T030439/report.json`: policy-bound credential issuance, wallet receipt, Application Template draft/validate/activate, and browser-wallet OID4VP verification end in `evaluation=passed`, `decision=allow`.
- `tests/artifacts/beta-credential-lifecycle-20260713T030519/report.json`: linked renewal succeeds; suspend, reinstate, and revoke produce deny, allow, and deny; status-list ownership matches the organization; wrong-organization mutation returns `403`.

Current automated verification is `746 passed, 1 skipped` for Marty UI/services and `125 passed` for MIP Protocol; generated bindings are current, Rust and TypeScript binding builds pass, the complete frontend suite and production build pass, and `23` local release contract tests plus PowerShell/nginx/Compose validation pass.

This evidence is engineering-complete for the mutable development stack. Final local candidate `mip-0.3.1-local-20260713T031700Z` freezes these corrections; its deployment manifest and repeated five browser reports become the authoritative local evidence only when that run succeeds. Public promotion remains blocked by design until coordinated sources are published and protected SpruceKit/native evidence is attached to the exact protected beta run. Walt.id remains inactive and unadvertised.

## Public Demo Publication Run - 2026-07-15

The draft ElevenID LLC Credential Platform `v2026.07.0` demo release was rebound to deployed beta marker `mip-0.3.1-local-20260714T214333Z`. The product marker and container image remained unchanged while the schema v2 demo application and manifest were deployed as a static distribution update.

Published scenario evidence:

- Membership Badge and Login revision 2: `https://www.youtube.com/watch?v=ol0VxziVwMU`, 2560x1440, 25 FPS, 45 seconds.
- Credential Lifecycle revision 2: `https://www.youtube.com/watch?v=DDjyuqs8Wpg`, 2560x1440, 25 FPS, 140 seconds.
- Organization and MIP Primitives: `https://www.youtube.com/watch?v=GK7GbqBCwQ8`, retained after automated unchanged-path rebind evidence.

Both new publication transactions verified public status, completed processing, embedding, reviewed English captions, thumbnail assignment, and release-playlist membership. Final beta checks loaded each public video at 320, 390, 768, and 1440 pixels with no horizontal overflow, page exception, or unexplained request failure. `/demos` exposes the release selector and links to both new public scenarios.

Immutable evidence is stored in:

- `../marty-demo-recorder/artifacts/2026.07.0-membership-badge-login-r2`
- `../marty-demo-recorder/artifacts/2026.07.0-credential-lifecycle-r2`

Each directory contains raw application/wallet sources, final master, captions, transcript, chapters, thumbnail, functional report, release evidence, privacy and offer-expiration reports, source hashes, YouTube publication result, public-page smoke report, and automated publication attestation. Recorder verification passes 39 tests; the complete frontend suite and production build pass.

The demo release remains `DRAFT` and `PARTIAL`. These are `FIRST_PARTY_CONTROL` recordings and do not replace the remaining SpruceKit, EUDI Android, or other independent-wallet qualification work.
