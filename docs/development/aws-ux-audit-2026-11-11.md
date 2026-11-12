# Console device, template, and policy UX audit — 2026-11-11

## Scope and initial environment

The original batch continued the AWS development UX work from main
`b7c7055830722d10512ccac042b1e0abe0e1ecec`. It groups related frontend changes in
one PR and uses the existing local dependency lockfile, test configuration, and
application build. No CI workflow, dependency manifest, or native authorization
changes are included.

The date above is America/Denver. AWS observations occurred on 2026-11-12 UTC.
The initial inspection found a stale public origin and certificate name
mismatch, while the UI and application services were not ready. A separate
supported credential recovery operation was already in progress. Subsequent
read-only reconciliation confirmed all **34 Secrets matched the verified fresh
activation postimages** and all **20 application Deployments were Ready**. The
earlier bounded reload attempt retains its incomplete receipt; current service
readiness is a separate observation.

The authorized environment repair then renewed the public certificate for the
current address and reconciled the serving origin. The origin-only Helm update
preserved the reviewed chart render and image pins, with both setup Jobs
disabled. Only the existing Keycloak client's callback, web-origin, and logout
fields were reconciled; PKCE remained S256. Verified TLS requests from the node
returned **HTTP 200** from `/health/ready`. The browser's public egress matched
the existing single-address ingress rule, which remained unchanged.

An isolated checkout was mounted for live development, preserving the previous
dirty source tree. It was advanced to `408a0f1`, including the policy fixes below,
without moving the PR branch and triggering another CI run. Its locked `npm ci`
completed. Source permissions were repaired for the UID 1000 watcher after a
restrictive administrative umask made newly written files unreadable. The
absolute automatic-stop guard remained in place, with an enabled systemd timer
scheduled for **2026-11-12 10:00 UTC**. The maintenance procedure is recorded in the
[live reload guide](../kubernetes-ui-live-reload.md).

An earlier temporary address triggered Chrome's security warning. That warning
was not bypassed. A separate session subsequently stopped the existing instance;
the authorized restart assigned a new address. The retained K3s certificate
controller then issued a production Let's Encrypt IP certificate using its
existing ACME account and `shortlived` profile. The current-generation Ready
condition, served IP SAN, TLS 1.3 connection and HTTP readiness response were
verified. The issued certificate expires **2026-11-18 20:42 UTC**, with automatic
renewal scheduled for **2026-11-16 20:42 UTC**. No new instance or account plan
upgrade was used.

**Authenticated sign-in and the organization dashboard succeeded** in the
connected Chrome session, without a security warning. The dashboard and expanded
Design navigation were inspected. This established application access, but did
not yet exercise the device, template or policy forms.

At approximately **06:00 UTC**, the Browser connector lost the originating
browser context and could no longer access either the application or the
authenticated AWS CloudShell. A separate cloud browser reported
`ERR_CERT_COMMON_NAME_INVALID`; it did not provide certificate details and its
warning was not bypassed. At that point, this later observation was unresolved
and was not a successful cross-browser TLS check. The November 12 continuation
below records the subsequent verified TLS and connected-Chrome results.

A temporary dashboard-label edit had just been requested for visible HMR
verification when that connection was lost. Its command acknowledgement,
visible result and restoration had not been observed in that session. That
session therefore established no visible HMR result. The November 12
continuation below records a completed edit-and-restore round trip.

The product defects below were confirmed by tracing frontend and native API
contracts and exercising controlled-response component tests. Private hosts,
accounts, credentials, operational receipts, and resource identifiers are
excluded from this report.

## November 12 continuation — America/Denver

The continuation resumed on **2026-11-12 America/Denver (MST, UTC−07:00)**.
The initial integrated source base `cef5524` included main `a309bbc` and the
consolidated UX changes. Source subsequently advanced to `bdfc0a6`, including
main `2a1b1a07`, and was fast-forwarded cleanly onto the AWS live checkout.
The incoming main changes affected only three native compiler trial and
documentation files, with no overlap in UX or application build inputs.
Related corrections remain in one PR, with live reload supporting the local
iterations. The later policy draft navigation correction was applied directly
to the live UI for its targeted replay below.

### Environment and visible live reload

The same existing instance was restarted in the free-plan environment. The
existing installer-managed certificate controller and retained ACME account
obtained a valid production Let's Encrypt certificate for the new public IP.
The served TLS connection passed normal certificate verification. The current
trusted certificate expires **November 19**. Chrome completed authenticated
sign-in without a security warning. These observations
resolve the current environment's TLS/access uncertainty from the earlier
interruption; they do not claim a successful retest of the separate cloud
browser that previously reported a certificate error.

The supported native administrative refresh renewed the expired identities
across exactly **34 Secrets**. The retained original installation state remained
unchanged. The origin-only Helm reconciliation completed, and the resumed
source replay confirmed all **20 application Deployments Ready**.
The existing Keycloak client was reconciled only in its callback, web-origin,
and logout fields; PKCE remained **S256**.
The current automatic-stop deadline is **November 12 at 17:15 America/Denver**
(**November 13 at 00:15 UTC**); the earlier deadline above is historical.

A temporary Dashboard label change appeared in the signed-in Chrome page
through HMR, and restoring the source restored the original label. Both visible
transitions were observed **without reloading the page or losing the signed-in
account**. This resolves the previously pending visible-HMR and label-restoration
check. It does not substitute for replaying each product fix below.

### Manual UX observations

| Flow | Observed in the AWS browser | Verification boundary |
| --- | --- | --- |
| Organization Devices | Empty inventory, search with no match, Clear, and Refresh behaved correctly | There was no real device fixture; populated rows and deactivation were not manually exercised |
| Applicant Devices and navigation | The Devices destination was discoverable | Registration status, inactive history, and deactivation still require a suitable disposable fixture |
| Device page and navigation at 390 px | The inspected page and navigation drawer did not overflow the page | This covers the real empty inventory, not a populated device table |
| Application Templates | An existing active template displayed four fields. A clearly named disposable draft with twelve fields was created, saved, and read back as valid `DRAFT` | This verifies the observed create/save/readback path; failure/retry and scope-transition scenarios remain separate checks |
| Application preview links | The corrected active-template row link included `organization_id`, `target="_blank"`, and `rel="noopener noreferrer"`; a physical click opened its preview in a new tab | Delayed-response scope protection is covered by local tests |
| One-click application preview | The banner explicitly described simulation. **Preview credential request** led to **Preview complete**; its explanation described receiving the credential in a wallet when ready in the live experience. The preview created no application or credential and opened no wallet. Exit Preview closed the popup tab | This verifies the popup path; Exit behavior for a directly opened preview was checked separately |
| Ordinary application form preview | A `MANUAL` draft traversed Personal Information, Additional Information, and Review. Missing Member ID, Organization ID, Role, Badge Name, and Issued At each produced required-field feedback and blocked Next. Dummy values, including native date input, survived into Review. An unchecked confirmation blocked Preview Submit; after checking the simulation-only confirmation, completion stated that live submission follows the template's approval settings and displayed the collected form data | No application was submitted, credential issued, or wallet opened. Exit Preview from this directly opened page returned to the console template list |
| Check configuration | One required Identity Verification check was saved on the disposable draft. The list displayed **1 check**, and reopening retained it | A pending-save dismissal/replacement race was not manually forced; controlled component tests cover the guard |
| Check configuration at 390 px | After the layout correction, the measured dialog width and scroll width both equaled **260 px**, while page width remained **390 px**. The check selector and save flow were usable | Accessible label association is also covered by the focused component test |
| Application Templates table access | The closed-dialog page measured **375/375 px** client/scroll width. The table region measured **343/720 px**, had `tabIndex=0`, and ArrowLeft moved its scroll position **361 → 321 → 281** | Confirms contained keyboard scrolling without outer-page overflow |
| Dashboard | Health Overview now reported **3 active flows**, matching three active native definitions in the flow list. Verify Setup Readiness reported **1**, its narrower verification-flow count. Configuration and runtime-health explanations remained distinct | The counts have different scopes; this does not claim that all three definitions are verification flows or prove service availability |
| Policy input and binding | The Trust → organization credential template → eleven claims → Freshness path was exercised. Blank, `-1`, `0.5`, and `1e3` blocked both Next and Skip. Zero was accepted, and Review displayed **0 seconds**. Keyboard selection worked for None, Device Key, and Authenticated Session; unsupported controls were absent | This records the tested numeric cases and radio options, not every possible input or keyboard sequence |
| Policy durations and persistence | `43200` displayed **12 hours** and `86401` displayed **1 day 1 second**. Tested values survived Back. An inactive draft was saved, and its detail view read back **86401** with **`SESSION_BINDING`** | No policy was activated or used to qualify real credential verification |
| Policy draft destination | The initial save exposed an unconditional redirect to Deployment Profiles. After the focused navigation correction, a second inactive draft landed on its actual detail URL and read back draft state, **43200**, and **`DEVICE_KEY`** | The initially exposed raw success-message key was corrected and replayed separately in the existing session |
| Policy success text with a cached locale | A third inactive draft was created in the same browser session without reloading. Visible text confirmed **Presentation Policy Created**, the saved-as-draft explanation, and **Opening the saved policy draft...**. The subsequent detail URL matched the created draft and its draft state was visible | Readability and navigation were verified through visible text and page state; the stale compositor screenshot was discarded |
| Native flow list | The three existing native definitions now showed green **Active** status, **Auto** approval, their provided template references, and **No applicant URL available**. Enter on the named Details link opened the matching flow detail page | Other lifecycle and approval values, absent references, unknown values, and supplied-URL cases have controlled-test coverage |
| Flow list at 390 px | Page client/scroll width stayed **375/375 px**. Its focusable table region measured **311/720 px**; ArrowRight moved horizontal scroll from **0 to 40**, and Enter opened the matching Details destination | This verifies the observed native rows and contained keyboard scrolling |
| Flow detail | After live reload, the page had a named level-one heading, accessible Credential Template and Presentation policy references with their existing destinations, and neutral **Share an available applicant link to start this flow** guidance. The empty Published by field was removed | This verifies the observed detail presentation and reference labels; it does not establish an applicant URL or runtime availability |
| Flow detail back navigation with a cached locale | In the existing browser session, the corrected **Back to Flows** button was visible and named. Enter returned to the flow list, where its table region was visible | The generic key and default text were replayed after the earlier issuance-only label was found in the cached English catalog |
| Verification-flow preview | The built-in login flow opened a Flow preview banner and **Credential verification preview** heading. The information described using existing credentials, the unavailable interactive preview, and that no verification had started. No application form appeared; Exit Preview closed the popup | This verifies the informational preview boundary, without starting real verification |
| Issuance-flow preview boundary | A separate existing member-badge issuance flow still opened its linked credential template's three-step form | Only the form load was checked through this flow route; its completion is not inferred from the separately completed ordinary application preview above |

### Corrections added during the continuation

| Correction | Local implementation and evidence | AWS/manual status |
| --- | --- | --- |
| Application Templates row preview | Uses the existing public-entry URL contract, encoded template ID and selected organization, with a new-tab `noopener noreferrer` link. Regression coverage checks the public URL and organization changes without stale scope | Applied to AWS; the URL, link attributes, and new-tab interaction were verified |
| Check-configuration save lifetime | Guards the pending save and stale completion so dismissal or a replacement dialog cannot accept the old result; focused tests cover the race | Applied to AWS; the race itself was not manually forced |
| Active resource counts | Normalizes authoritative status casing, including native flow-definition `ACTIVE`, consistently across Health Overview counts. Tests compare the observed flow case with Setup Readiness and exclude inactive states | Applied to AWS; the total of three active definitions and the narrower count of one verification flow were reconciled in the browser |
| Honest preview interaction and completion | The shared banner describes simulation. One-click preview uses a preview-specific button/helper, removes misleading placeholder form data, and explains receiving the credential in a wallet when ready. Ordinary form preview refers to the template's approval settings and retains its collected-data inspection. English/Dutch copy follows the existing fallback pattern | Applied to AWS; both preview paths, validation, completion, and their distinct Exit behavior were verified |
| Narrow check-dialog layout and accessible selector | Stacks narrow layouts, bounds the template chip, and associates each check selector with its label | Applied to AWS; 390 px layout, save, and persisted readback were verified; label association has focused test coverage |
| Application Templates table access on narrow screens | Adds a named, focusable horizontal scroll region and a 720 px minimum table width | Applied to AWS; keyboard scrolling and absence of outer-page overflow were verified |
| Policy draft completion | Sends an inactive draft to its own detail page instead of unconditionally sending it to Deployment Profiles | Applied to AWS; a newly created draft reached its detail page with the expected stored duration and binding |
| Cached policy success translation | Supplies readable default text when an already-loaded locale catalog lacks the new success-message keys | Applied live without a service restart; the existing session displayed the correct text and reached the saved draft without reloading |
| Native flow list presentation and actions | Recognizes native lifecycle and approval values, uses actual template references, and separates activation from an explicitly provided applicant URL. Removes unsupported wallet/QR placeholders and legacy Publish/Disable table controls in favor of named Details links; unknown states remain unknown | Applied live without a restart; native Active/Auto rows, template references, absent URL copy, desktop/mobile keyboard Details, and contained mobile scrolling were verified |
| Flow detail wording and accessibility | Provides a named heading and reference links, neutral entry guidance, and a generic Back to Flows control with readable default text; omits an empty Published by field | Applied to AWS; the detail presentation and cached-locale Back label were verified, and Enter returned to the flow list |
| Verification-flow preview boundary | Distinguishes a verification flow from issuance when a linked credential template is present, showing an informational verification preview instead of an application form | Applied to AWS; the built-in login preview showed the informational boundary and closed on Exit, while a separate issuance flow retained its linked three-step form |

The preview correction preserves both early-return guards. Its focused
component coverage exercises ordinary, member-credential, and Open Badge
previews and checks that simulation produces no applicant/application/evidence
or issuance API operations, direct network request, wallet window, navigation,
or claim dialog. The existing non-preview component test cases also pass.
The later browser replay separately verified the new copy and completion
behavior for both one-click and ordinary forms, including required-field and
confirmation feedback. Independent review accepted the preview correction;
locale JSON and whitespace checks passed.

### Consolidated local validation

The consolidated baseline run passed **265 tests across 17 suites**. The
subsequent **`npm run build:application` passed**, with only the existing
large-chunk warning. These results are separate from the historical batch counts
below. This count describes the tested baseline and does not qualify the later
corrections to policy navigation, cached success text, flow-list status handling,
flow detail, or verification-flow preview.

The missing-catalog fallback regression passed in a separate **one-test run**.
The earlier **30-test run** remains a separate result; these runs are not
combined into a new aggregate or presented as a rerun of the baseline.

The flow-list correction passed **40 tests across three focused suites**, with
independent contract and source review. Targeted ESLint reported no errors and
two pre-existing unused-icon warnings. The flow-detail correction passed a
separate **27-test run**, and the flow-preview correction passed a separate
**31-test run**. Independent native-contract and source review accepted these
corrections. After the final Back-label wording change, the focused regression
for the new generic key, default text, and actual English catalog passed in a
**one-test run** with 26 tests unselected; the earlier 27-test result predates
that last wording change. These focused results are not added to the baseline
count or presented as one full rerun.

The final **`npm run build:application` passed after all source changes**,
including the flow detail, verification-preview, and final Back-label changes.
Only the existing large-chunk warning remained.

### Interruption and subsequent replay

At approximately **2026-11-12 19:06 UTC / 12:06 MST**, the root browser connection
was lost. The prepared invalid-age and keyboard-policy action script was
**never dispatched in that session**. Those actions remained untested at the
interruption. After reconnecting, the targeted replay recorded above completed
the listed policy input, keyboard, persistence, dialog, table, preview, and
dashboard checks. Those outcomes come from the resumed browser work, not from
the earlier Freshness inspection or local tests.

## Corrections from the initial batch

| Area | Defect | Result |
| --- | --- | --- |
| Organization devices | The first render called `filter` on the hook's initial `null` data | Loading is explicit; errors, Retry, successful empty inventory, and filtered results have separate states |
| Organization device contract | The page treated native device registrations as lane summaries and linked to unregistered Add/View/Configure routes | The page displays the signed-in user's registrations in the selected organization, with a labeled search; unsupported lane actions and health claims are removed |
| Applicant devices | The native bare-array response was read as `data.devices`, making populated inventories appear empty | Real registrations, including inactive history, are displayed |
| Applicant navigation | The registered Devices route had no internal navigation entry | Devices is available in the shared applicant desktop and mobile sidebar |
| Unregister device | The request used the client `device_id` instead of the registration `id` | The correct record is deactivated; its inactive history remains visible, matching native soft-deactivation |
| Device confirmation | Pending or failed actions could be dismissed, repeated, or settle into a replacement account | Pending submissions are guarded, failures retain the dialog with Retry, and former account completions are discarded |
| Device labels | The UI inferred public-key security and connection health from fields absent from the native record | Only native registration status is shown; the explanation distinguishes active registration from being online |
| Device inventory | The default native page could omit later registrations | All offset pages are loaded; malformed, duplicate, wrong-scope, and failed later pages do not become a successful partial or empty list |
| Application templates | A failed first load dereferenced `null` while rendering the table | A readable failure with Retry replaces the table; successful empty inventories remain distinct |
| Template details | Failed credential enrichment silently implied zero derived fields | Explicit form-field counts remain available; unknown derived counts display an em dash, with a separate detail Retry |
| Account and organization changes | Previous inventories and the check-configuration dialog could survive a scope change | Content is keyed to the current principal and selected organization, withdrawing old data and rejecting delayed results |

The device tables use contained, keyboard-focusable horizontal scrolling and
wrapping controls. Search and unregister controls have accessible names.
New labels and recovery text are present in English, German, Spanish, French,
Japanese, and Dutch.

### Presentation policy follow-up

Further local source review identified controls and duration handling that did
not agree with the native policy request. These locally validated corrections
were included in the `408a0f1` checkout mounted on AWS during the initial
session. The November 12 continuation above records the later live wizard,
numeric-input, keyboard, and saved-policy readback results.

| Area | Defect | Result |
| --- | --- | --- |
| Unsupported policy controls | Maximum proof age, single-presentation selection, and a compliance-reference field implied effects absent from the submitted native policy | Removed these controls, defaults, and Review claims while retaining supported credential-age, revocation, holder-binding, and predicate settings |
| Credential age | Editing in whole days truncated sub-day values, and blank or invalid input could silently become a different duration | Edit exact integer seconds, including zero; reject blank, negative, fractional, and unsafe numeric values before Next, Skip, or creation |
| Policy Review | Duration summaries discarded remaining hours, minutes, or seconds | Review preserves every unit and uses the selected locale, including an explicit zero-second value |
| Holder binding | Radio inputs lacked the visible option names and descriptions; card and input handlers could duplicate changes | Associate the group and each radio with its text and use one labeled control for pointer and keyboard selection |

The six console locales were updated for the supported controls and precise
duration guidance. Native policy enforcement and authorization are unchanged.

### Dashboard follow-up

The authenticated dashboard showed configuration marked Ready while its setup
summary reported every presentation policy missing required claims. Source
review found two distinct causes:

- Both policy readiness evaluators considered only `required_claims`. The
  native contract also accepts structured credential requirements, alternative
  requirements and required holder binding. A shared predicate now recognizes
  each supported obligation while still blocking policies with none.
- The gateway's runtime flags summarize active resources; they do not probe
  verifier availability or prove complete setup. The panel now says
  **Credential Operation Configuration**, uses **Configured** for those flags,
  and directs users to System Status and Setup Readiness for their respective
  information. The explanation is updated in all six console locales.

The observed Verifier Unknown health label was accurate: the installed
readiness response does not report that service. No service-health result was
invented to replace it. An independent reviewer checked the policy predicate
against the native create/response contract and the runtime labels against
the gateway's actual resource-based calculation.

## Contract boundaries

The native device endpoint lists the authenticated user's registrations; an
organization filter does not grant access to other members' records. The
existing owner and active-membership checks remain authoritative. No device
permission is invented and no grant changes are made.

The native API uses offset pagination ordered by mutable `updated_at`, without
a snapshot token. Duplicate overlap is now detected, but concurrent updates
can still move records between pages. A transactional snapshot requires a
separate native API change.

## Validation

The counts in the following sections record the completed earlier batch runs.
They are historical results, not a final aggregate for the November 12
continuation or every currently modified file.

### Device and application-template batch

- The combined focused run passed **36 tests across five suites**: both device
  pages, the device API, Application Templates, and the existing organization
  scope guards.
- Tests cover native response shapes, loading, errors and Retry, empty and
  filtered inventories, correct unregister addressing, inactive history,
  duplicate submissions, pagination, account and organization transitions,
  stale results, sign-out, and failed credential-template enrichment.
- The TypeScript and Vite application build passed. Its existing large-chunk
  warning remains visible; no warning threshold was changed.
- Targeted ESLint and `git diff --check` passed. All twelve changed locale files
  parse, and unrelated locale content is preserved.
- Two independent source reviewers accepted the device changes; the template
  correction also received independent source review and a separate successful
  run of its eleven component tests.

### Presentation policy follow-up

- The final affected-file run passed **50 tests**. An earlier broader run passed
  **85 additional tests**, for **135 unique tests** across the reported local
  policy coverage.
- Coverage includes exact sub-day and zero durations, invalid input blocking,
  Review/payload agreement, removed unsupported options, accessible binding
  selection, and existing policy recovery and submission guards.
- Production TypeScript, targeted ESLint, locale validation, and whitespace
  checks passed. The application build also passed after all source changes.

### Navigation and dashboard follow-up

- All **22 existing navigation tests** passed across the configuration,
  applicant sidebar and general sidebar suites. Targeted ESLint passed.
- All **117 dashboard tests** passed across three suites: 51 readiness-rule
  tests, 14 runtime-panel tests and 52 dashboard integration tests. These cover
  the four native obligation forms, empty policies, both setup paths and
  downstream flow prerequisites.
- The six locale files parse, with semantic changes limited to the relevant
  runtime panel keys. Targeted source ESLint reports no errors; the existing
  unused `evaluateDeliveryReadiness` warning remains. Whitespace checks pass.
- Independent review accepted the final predicate, native contract alignment,
  resource-status copy and test fixtures. No browser result is inferred from
  these source and component checks.
- The final TypeScript/Vite application build passed with all navigation and
  dashboard changes present. Its existing large-chunk warning is unchanged.

## Remaining coverage limits

The targeted live follow-ups are complete, including the flow detail,
verification-preview boundary, and cached-locale Back label. The remaining
manual coverage limits are:

- Populated device rows, deactivation, inactive history, and action failure/retry
  were not exercised without a disposable real registration.
- Template failure/retry, enrichment recovery, account/organization transitions,
  and pending-save dismissal/replacement races retain their controlled-test
  evidence; the successful live saves do not prove those failure or timing cases.
- This crawl did not activate the disposable policy drafts, issue a credential,
  or qualify credential login against the retained issuer DID at the new origin.
