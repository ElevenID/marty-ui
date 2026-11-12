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
It used integrated source base `cef5524`, which includes the merge of main
`a309bbc` with the consolidated UX changes. The local and AWS work continued
without another PR-branch push or an extra CI run for each correction.
Main subsequently advanced to `2a1b1a07`, changing three native compiler
trial/documentation files with no overlap in UX or build inputs. That clean
integration is being included in the next consolidated branch update; its
final commit and tree will be recorded with that update.

### Environment and visible live reload

The same existing instance was restarted in the free-plan environment. The
existing installer-managed certificate controller and retained ACME account
obtained a valid production Let's Encrypt certificate for the new public IP.
The served TLS connection passed normal certificate verification. Chrome then
completed authenticated sign-in without a security warning. These observations
resolve the current environment's TLS/access uncertainty from the earlier
interruption; they do not claim a successful retest of the separate cloud
browser that previously reported a certificate error.

The supported native administrative refresh renewed the expired identities
across exactly **34 Secrets**. The retained original installation state remained
unchanged. The origin-only Helm reconciliation completed with all
**20 application Deployments Ready**.
The existing Keycloak client was reconciled only in its callback, web-origin,
and logout fields; PKCE remained **S256**.

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
| Device page and navigation at 390 px | The inspected page and navigation drawer did not overflow the page | This result does not cover the later template and check-dialog layout defects |
| Application Templates | An existing active template displayed four fields. A clearly named disposable draft with twelve fields was created, saved, and read back as valid `DRAFT` | This verifies the observed create/save/readback path; failure/retry and scope-transition scenarios remain separate checks |
| Application preview links | The list initially omitted the selected organization while the detail-page preview included it. After the fix reached AWS, the list anchor's organization-scoped public URL was verified | The corrected link's presence was verified; delayed-response scope protection is covered by local tests |
| Application preview interaction | The original preview loaded, Add to Wallet safely simulated completion, and Exit Preview closed its tab | The click exposed contradictory preview copy. The copy correction remains local and has not yet been replayed on AWS |
| Check configuration | Add check was displayed. The pending-save guard correction was present in the AWS source | A pending-save dismissal/replacement race was not manually forced; controlled component tests cover the guard |
| Check configuration at 390 px | The selector collapsed, the title/chip overflowed, and the combobox lacked an accessible name | The focused layout/name correction is local and awaiting HMR verification |
| Dashboard | Health Overview showed zero active flows while Verify Setup Readiness reported one active flow | The status-normalization fix is present on AWS, but the dashboard has not yet been revisited to verify the corrected count |
| Policy wizard | The actual Trust → organization credential template → eleven claims → Freshness path was exercised. Device binding, a credential age of `31536000` seconds, and the revocation check were visible; unsupported controls were absent | Invalid-age entry, zero handling, keyboard radio selection, and the resulting Review behavior were not exercised in this session |

### Corrections added during the continuation

| Correction | Local implementation and evidence | AWS/manual status |
| --- | --- | --- |
| Application Templates row preview | Uses the existing public-entry URL contract, encoded template ID and selected organization, with a new-tab `noopener` link. Regression coverage checks the public URL and organization changes without stale scope | Applied to AWS; the live anchor URL was verified |
| Check-configuration save lifetime | Guards the pending save and stale completion so dismissal or a replacement dialog cannot accept the old result; focused tests cover the race | Applied to AWS; the race itself was not manually forced |
| Active resource counts | Normalizes authoritative status casing, including native flow-definition `ACTIVE`, consistently across Health Overview counts. Tests compare the observed flow case with Setup Readiness and exclude inactive states | Applied to AWS; dashboard replay remains pending |
| Honest preview interaction and completion | The shared banner describes simulation. One-click preview uses a preview-specific button/helper, removes misleading placeholder form data, and explains receiving the credential in a wallet when ready. Ordinary form preview refers to the template's approval settings. English/Dutch copy follows the existing fallback pattern | Local only; not yet applied or manually verified on AWS |
| Narrow check-dialog layout and accessible selector | A focused correction addresses the collapsed selector, title/chip overflow, and missing combobox name observed at 390 px | Local correction pending HMR verification |
| Application Templates table access on narrow screens | Adds a focused horizontal scroll region and a 720 px minimum table width so the columns and row actions remain reachable, including by keyboard | Local correction pending HMR verification |

The preview correction preserves both early-return guards. Its focused
component coverage exercises ordinary, member-credential, and Open Badge
previews and checks that simulation produces no applicant/application/evidence
or issuance API operations, direct network request, wallet window, navigation,
or claim dialog. The existing non-preview component test cases also pass. These
are local controlled-response results, not evidence that the new copy has been observed
in AWS. Independent review accepted the preview correction; locale JSON and
whitespace checks passed.

### Consolidated local validation

The current consolidated UX run passed **265 tests across 17 suites**. The
subsequent **`npm run build:application` passed**, with only the existing
large-chunk warning. These results are separate from the historical batch counts
below and do not establish the pending AWS browser outcomes.

### Second browser interruption

At approximately **2026-11-12 19:06 UTC / 12:06 MST**, the root browser connection
was lost. The prepared invalid-age and keyboard-policy action script was
**never dispatched**. In particular, blank, `-1`, `.5`, exponent notation, `0`,
and radio-keyboard interactions remain untested in the live browser. No result
for those actions is inferred from the earlier Freshness inspection or local
tests. No additional browser actions succeeded after that interruption.

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
session. The November 12 continuation above records the later live wizard
inspection and the interactions still pending.

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

## Remaining browser verification

Current TLS verification, Chrome sign-in, service readiness, and the visible
HMR edit/restore round trip succeeded during the November 12 continuation.
Further live work requires reconnecting the browser and confirming the active
source and automatic-stop deadline. Visible HMR and temporary-label restoration
are completed checks; the product-specific replay below remains pending.

Final targeted browser replay covers the new mobile dialog/table layouts,
preview copy, dashboard-count revisit, and policy input/Review behavior.
Fixture-dependent device, scope-transition, controlled failure, and race
scenarios remain documented coverage limits when suitable fixtures are
unavailable.

| Follow-up area | Targeted replay or recorded coverage limit |
| --- | --- |
| Remaining local corrections | Apply the preview-copy, check-dialog layout/name, and Application Templates scroll-region changes to the live checkout; observe their HMR result |
| Preview copy | Repeat the one-click preview and ordinary form preview; verify the new helper, completion explanation, and Exit Preview behavior |
| Narrow and keyboard layouts | At 390 px, recheck the check selector/title/chip and its accessible name; reach the table scroll region and row actions by keyboard without page overflow |
| Dashboard counts | Revisit Health Overview and Verify Setup Readiness with the applied status-normalization fix; distinguish all active flow definitions from verification-flow definitions where their totals legitimately differ |
| Check-dialog save race | If a controlled pending request is available, exercise dismissal and dialog replacement while saving. Until then, retain the component-test result as the only race verification |
| Device records and deactivation | Populated rows, deactivation, inactive history, and action failure/retry remain manual coverage limits without a disposable real registration; the empty-inventory crawl does not establish these outcomes |
| Template recovery and scope | Failure/retry, enrichment recovery, and account/organization switching remain controlled-test coverage unless suitable live fixtures are available; the successful draft create/save/readback is a separate result |
| Policy input and keyboard handling | Dispatch the previously unrun blank, negative, fractional, exponent, and zero-age cases; exercise the binding radios with the keyboard; verify Freshness and Review behavior and exact duration preservation |

Record each browser result separately from source review, controlled-response
tests, infrastructure checks, and successful sign-in. Keep the PR in draft
pending the final targeted browser replay of the new mobile dialog/table
layouts, preview copy, dashboard counts, and policy input/Review behavior.
Retain unavailable fixture-dependent scenarios as explicit coverage limits.
