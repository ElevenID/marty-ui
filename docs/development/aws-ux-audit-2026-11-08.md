# Console UX audit — 2026-11-08

## Scope

This batch corrects issues found during an authenticated walkthrough of a disposable
development installation. Browser checks exercised the applicant and organization
surfaces, dashboard, membership list, organization settings, resource navigation,
creation form, and verification setup. The audit is bounded; it does not certify
every issuance, wallet, or credential lifecycle journey.

The companion [live reload guide](../kubernetes-ui-live-reload.md) describes the
repeatable, opt-in development configuration. Source changes were applied to the
running development checkout and the affected controls were exercised again.
Private infrastructure addresses and account/resource identifiers, credentials,
operational receipts, and browser screenshots are excluded from this public report.

## Product fixes and browser verification

| Area | Observed defect | Correction and verification |
| --- | --- | --- |
| Dashboard invitations | Invite returned to Dashboard instead of opening an invitation | Both links now open Team with an invitation intent. The intent waits for current-organization roles and permission, then is consumed. Browser verified dialog opening, query cleanup, and Cancel without reopening; no invitation sent |
| Revocation navigation | A ready Revocation Profile row returned to Dashboard | The row now opens the registered Revocation Profiles page; browser retest passed |
| Flow navigation | Flow Instances returned to Dashboard | The tab now opens the operational Flow Instances page and its correct empty state; browser retest passed |
| Verification navigation | Evaluate VP returned to Dashboard; Start QR Verification opened an unconfigured generic flow wizard | Replaced these unsupported shortcuts with Verification Sessions. Browser verified the actual OID4VP session list |
| Missing translation | The build action displayed `Build flows.flowDefinition` | Added the singular label in all six console locales; browser verified Build Flow Definition after locale reload |
| Runtime readiness | Degraded issuance displayed All systems operational despite missing prerequisites | Details and actions now agree with the status. Browser verified the missing deployment explanation and Configure Deployment action |
| Issuer wording | Configuration evidence was described as signing-key validity | The card now describes the active template's issuer DID reference without claiming a cryptographic health check; browser retest passed |
| Service health | All services appeared Unknown despite reported gateway and issuance health | Read the readiness endpoint's actual service observations. Browser verified healthy gateway/issuance and explained Unknown for an unreported verifier |
| Critical events | An empty event feed asserted that all systems were operating normally | Empty state now says only that no critical events were reported; browser retest passed |
| Organization creation | Open membership left Discoverable off while submitting public visibility | UI and payload share the same rule. Browser verified Open/Approval force checked, disabled discovery with accurate copy, and Invite Only restores the prior preference |
| Creation entry point | Membership lists lacked Create Organization when enabled | Added an action using the same runtime flag as the creation route. Browser followed the action into the real form |
| Responsive layout | Creation fields and dashboard cards had uneven widths and ragged rows | Migrated the affected Grid sizing props and explanation spacing. Browser verified equal desktop columns, stacked phone cards, compact membership details, and no horizontal page overflow at phone width |
| Verification setup | Ad hoc mode hid the selectors and left Next disabled with an impossible post-creation editing promise | Removed the unsupported option. Browser verified the missing-policy explanation, disabled Next, and working Manage Presentation Policies action |

Source review also found that the inspection toggle never affected a supported
request field. It and its claims were removed while preserving purpose and issuer
selection. Saved active policies remain usable without a flow; complete catalog
loading prevents later active policies from being hidden by a first page of drafts.
Loading, failure, retry, and missing prerequisites remain distinct.

## Follow-up crawl

A second authenticated pass continued through the applicant catalog, profile,
wallet choices, identity view, organization setup, Team, API Keys, and Webhooks.
The fixes below are included in the same review batch. Browser observations are
distinguished from cases verified with controlled asynchronous test responses.

| Area | Defect and correction | Verification |
| --- | --- | --- |
| Console mode switch | Clearing the selected organization before the router transition let the previous org route redirect Applicant mode to org setup. Mode, selection, and navigation now share one React transition | Reproduced in the browser and in a composed provider/guard test with a suspended destination. Browser retest reached Catalog; switching back reached Dashboard. Tests also cover failed preference persistence |
| Organization setup | Existing members were told to join an organization and that this was necessary to access applicant credentials | Conditional copy now distinguishes choosing an existing console membership from obtaining console access; creation guidance respects the feature flag. Six locales updated and tested |
| Profile settings | Notification switches did not persist, Save Settings implied unrelated settings were saved, and fallback profile data could be submitted after a load failure | Unsupported switches replaced by an availability explanation; Save profile is inside the profile panel. Load failures block saving and offer Retry. Browser saved a temporary development-account display name, confirmed persistence after reload, then restored the original name |
| Wallet choices | Choices lacked accessible names and did not explain their browser-local persistence | Associated checkbox labels, wrapping content, distinct load failure/Retry, and accurate automatic-save copy. Browser verified the labels and guidance; keyboard and failure cases are regression-tested |
| Credential catalog | A genuinely empty catalog told users to adjust filters; loading and failed requests showed a false zero count | Separate unavailable, filtered, loading, and error states; Clear filters preserves Canvas scope, and Retry reloads in place. Browser verified the empty catalog, labeled controls, and phone layout |
| Catalog request scope | Late initial-organization or former-account requests could replace a newer Canvas catalog or application badges | Separate request generations and layout cleanup reject stale success, error, and completion results. Deferred tests cover Canvas transitions, account switches, and current requests still loading |
| Applicant shortcuts and credential actions | Apply opened the identity view, and several credential actions had no implemented operation | Apply now opens Catalog; identity links use the registered route. Removed inert presentation/download/renewal controls while retaining Details and real Claim. Source and regression tests cover populated credential states |
| Integration permissions | API key and webhook controls did not consistently check the exact action grant | Create/revoke and create/edit/delete/test use their native grants. Paired callback creation needs its own grant and rechecks it before the second request. One-time created secrets remain available through same-account permission refresh. Deferred permission tests cover these boundaries |
| Integration dialogs | Old organization/account operations and clipboard results could update replacement dialogs; failed actions lacked recoverable feedback | Account/org isolation, dialog generations, pending submission guards, inline errors, Retry, and accurate no-secret creation completion. Browser opened and canceled the forms; controlled tests cover writes, failures, permission loss, and delayed responses |
| Team and confirmations | Role pickers were not properly keyboard accessible; stale role/removal/revocation completions could affect a replacement organization; rejected confirmations could disappear | Native labeled role checkboxes, scoped completion guards, and retryable shared confirmation errors. Browser toggled an invitation role with Space and canceled without sending; deferred tests cover the mutation lifecycle |
| Native account identity | Permission state keyed legacy identity aliases while the native user response provides `user_id` | Native identity now takes precedence; account changes withdraw old grants immediately and reject late permission responses. Regression-tested |

Development checker fixes remove four ESLint errors without weakening input
validation. Independent exhaustive comparisons over all 65,536 UTF-16
code units confirmed that the three affected control-character rejection sets
remain identical.

### Resumed crawl and additional corrections

The next authenticated browser pass found deprecated MUI styling props leaking
into HTML on loading screens and the catalog. The affected loading containers
rendered as blocks instead of centered flex columns. Those values now use `sx`;
regressions verify actual computed layout and the absence of leaked DOM
attributes. Catalog alignment and details spacing use the same supported API.

Organization discovery also displayed filter-adjustment advice with no filters
selected and exposed two unnamed selection controls. The page now labels every
filter, distinguishes an unavailable catalog from filtered results, provides
Clear filters and Retry, and uses the current Grid sizing API. Its result state
is bound to the current search and retry key; delayed successes and failures
cannot replace the current results or end a newer request's loading state.
Both desktop navigation collapse controls now have accessible names and expose
their expanded state.

The resumed signed-out walkthrough also confirmed that the public discovery
page called an API requiring authentication. The gateway correctly returned
401, but the page hid its message behind a generic error and ineffective Retry.
Discovery now waits for authentication initialization, offers Sign in without
an anonymous request, and uses direct reauthentication for an expired session.
The return destination includes the path, query, and hash. Structured API error
descriptions are retained, other failures still offer Retry, and account changes
discard the previous account's results, errors, and pending requests. Thirteen
Discovery regressions cover these cases and the existing filter behavior. The
live signed-out page now displays the sign-in guidance, and its Sign in action
reaches the expected Keycloak login page.

Independent review then reproduced two related lifecycle defects with six
failing regression cases. Catalog details could retain the previous account,
organization, or Canvas selection; an invitation could be submitted twice, and
its delayed completion could affect a replacement dialog. Catalog details now
close on scope changes, and Apply accepts only a credential in the current
loaded catalog. A route-provided Canvas session also supersedes an older lookup
without leaving the page loading. Invitations now prevent repeated submissions,
retain failed drafts for Retry, and isolate completions by account, organization,
mounted page, and dialog instance.

The additional fixes passed two independent reviews. The current combined UI
result below includes these regressions. The existing development instance
reached its scheduled stop during this resumed pass. It was then resumed with
another bounded automatic stop, and the ten reviewed source/chart files were
applied and verified by digest. UI, auth, gateway, and Keycloak deployments all
completed their rollouts. The new HTTPS origin has a valid certificate, the
discovery controls have accessible labels. At that recovery checkpoint, the live
development checker reported zero errors and 147 existing warnings. Login reached
the expected Keycloak page with username and current-password autocomplete
attributes.

An origin-only update now allows the existing Keycloak configurator Job to be
disabled explicitly; its default behavior is unchanged. This avoids rerunning
account bootstrap during a development replay. Existing client callback and
logout URLs were reconciled for the temporary origin, and PKCE remains S256.
Fresh registration and sign-in at the changed origin were subsequently exercised
in the authorized authenticated continuation below. No real invitation was sent
during the crawl or regression tests.

### Authenticated continuation with disposable accounts

A further user-authorized pass registered two disposable accounts through the
normal sign-up flow. One remained an ordinary applicant. The second created one
private, Invite Only test organization and exercised its owner console. These
accounts and the organization were used only for this development walkthrough;
their identifiers and contact details are excluded from the report.

Three reversible persistence checks completed successfully: a temporary profile
full name was saved, verified after reload, and restored; a browser-local wallet
preference was toggled, verified after reload, and restored; and the private
organization's description was temporarily changed, verified after reload, and
restored. These checks establish persistence for those settings, not a completed
wallet connection or credential workflow.

The authenticated crawl exposed additional permission, rendering, and error-state
defects. The following corrections were implemented and regression-tested.

| Area | Observed defect | Correction |
| --- | --- | --- |
| Applicant sidebar | Applicant pages requested reviewer-only organization statistics and logged `application:review` failures | Removed the obsolete request and badge state; applicant navigation has no corresponding badge. Personal applicant dashboard statistics remain separate |
| Native applicant eligibility | The UI omitted `wallet:view` from the native applicant-only permission set and incorrectly offered organization-console access | Aligned the UI set and fallback membership with the [native membership contract](../../contracts/organization-domain-behavior.json). Native applicant, viewer, owner, and explicit custom-reader cases are covered without changing any grants |
| Dashboard access | Limited roles triggered protected setup, review, audit, team, runtime, and event requests; denied data could look empty or unconfigured | Requests wait for current grants, cards use their native permissions, and composed runtime readiness checks its downstream resource grants. Physical-document capabilities require `issuance:view`; streaming requires `notification:view`. Authorized service errors remain visible, while unavailable sections have a limited-access explanation |
| Dashboard scope and actions | Previous account or permission state could remain visible at the same organization; broad console access was labeled Vendor | Data and completions are scoped to principal, organization, and current permissions. Independent card state resets on account/organization changes. Role labels use actual roles; audit/API-key links, creation quick actions, and purge controls use the relevant grants |
| Event-stream lifecycle | Connection errors repeated about once a second and continued after leaving Dashboard | Retries are bounded, old sources close, pending timers cancel, and stale callbacks cannot reopen a departed scope. Short-lived connections do not reset the retry budget. Genuine connection diagnostics remain available |
| Idle event-stream proxy | A later extended Dashboard check found that an otherwise healthy stream was cut off after 60 quiet seconds | Added an exact event-stream proxy route with buffering disabled and a 3600-second read timeout, preserving the ordinary API route and inherited headers. This permits one quiet hour; the gateway still has no idle heartbeat |
| Native profile identity | Profile read legacy name/account aliases and omitted the native full name and account reference | Uses native name fields and `user_id`, preserving legacy fallbacks. A username fallback is confined to the heading and is not presented as a full name |
| Rendering and navigation labels | Removed MUI props leaked into HTML or dropped layout on Profile, My Identity, Settings, menus, Dashboard, and API-key/Webhook summary cards and rows; two navigation translations and the integration-loading label were absent | Migrated the affected props to supported Grid, slot, and `sx` APIs. Menu tests verify real paper styling and close behavior. Added Console/API documentation labels and integration-metadata loading text in all six supported locales |
| Team identity | The native member list showed the current owner as an opaque identifier without an email | Uses current-session identity only when the row exactly matches the authenticated principal; explicit membership identity fields take precedence |
| Setup explanation | A flow prerequisite repeated the `Blocked:` prefix | Preserves an existing prefix instead of adding it twice |
| Membership and role review requests | Failed inventories could display a false zero/empty result; stale operations and rejected confirmations could affect replacement views; an empty SDK error message could leave an alert without an explanation | Added explicit loading, failure, Retry, malformed-response, pending, and scoped-completion handling. Rejection failures stay inside the dialog with the draft and Retry available. Empty error text now receives a meaningful fallback. The unsupported backend routes remain a separate deployment limitation |
| Webhook event catalog | An owner with an applicant session-default organization received a `webhook:view` failure because the catalog request omitted the selected owner organization | Requires an explicit organization selector in the event catalog service and all three callers. The native gateway still authorizes the selected organization normally; no permissions or backend contracts changed |

The first authenticated-crawl replay applied **11 UI and locale files** through
source checkpoint `88397c3c`. The next replay applied **17 production UI files**
through `1f0e6b1d`. The final replay applied **six production UI files** through
`34409177`. Source digests and original file modes and ownership were verified
for each replay, and the checked core services reported **1/1 ready**. These were
UI updates against the existing signed backend; no backend upgrade was performed.

Fresh browser checks after the second replay established the following:

- The ordinary applicant's Profile, My Identity, Settings, Catalog, My
  Organizations, and Discovery pages produced **zero new console errors or
  warnings**. The applicant had no organization-mode switch, the membership showed
  Applicant Access Only, and the replay exposed neither the owner's organization
  nor the owner's profile data.
- The owner's Dashboard displayed the native welcome name and Owner role, opened
  a healthy event stream, and produced no new application warnings or errors.
  The stream closed when navigating to Team and did not continue reconnecting
  afterward. Gateway observations confirmed successful stream and applicant-stat
  responses without stream permission failures; neither UI container restarted.
- Team displayed the current owner's name and email correctly. Space selected the
  Viewer invitation checkbox, and Cancel closed the dialog without sending an
  invitation or email.
- Membership Requests displayed a failed load with Retry, without a false zero
  count or empty-list claim.
- Organization Settings rendered its profile and form, retained the restored
  description and Private/Invitation settings, and no longer emitted the
  paragraph-prop warning. The known defaults endpoint still returned 404.

The owner replay after the third update confirmed readable failure messages
and Retry on both review pages. Role Requests displayed “Failed to load role
escalation requests” rather than a blank alert, while Membership Requests retained
its failure explanation without a false zero count or empty-list claim.

Webhooks loaded its empty inventory, enabled Add Webhook, and displayed all
**12 native event choices**. The API-key creation form also loaded all 12 callback
event choices, with the previous catalog permission error gone. Both dialogs were
canceled without creating a key or webhook. These final review and integration
page checks produced **zero new console errors or warnings**. The owner Dashboard
also retained the correct native welcome name and Owner role.

### Extended Dashboard idle check

A later, longer Dashboard observation exposed a separate proxy limit: Nginx
closed an idle event stream after 60 seconds. The gateway currently sends no
idle heartbeat frames. The chart now gives the exact event-stream route a
**3600-second timeout between upstream reads** and disables proxy buffering,
while preserving generic API routing and inherited forwarding and security
headers. This is a finite allowance for a quiet stream; it does not establish
indefinite idle connectivity.

The candidate and mounted Nginx configuration passed syntax and digest checks.
The ConfigMap change was applied with a graceful Nginx reload, without a full
Helm upgrade or native-backend rollout. A fresh browser connection then remained
open for **138 seconds**, with **zero reconnects, warnings, or errors**. This
crossed the previous timeout boundary and complements the earlier successful
navigation cleanup check.

The same follow-up found a missing integration-metadata loading translation.
Its correction changes only one key in each of the six console locale files;
JSON parsing, comparison with the previous values, and runtime i18next resolution
passed for every locale. All six files at `9f7e63a9` were applied with digest and
file-mode verification. A fresh Dashboard reload displayed the correct owner
identity, established a new stream, and produced **zero errors, warnings, or
missing-key diagnostics**. The UI and development containers remained ready with
zero restarts, and all four checked core deployments were **1/1 ready**.

### Browser observations

The profile page now separates the working profile save from unsupported
notification preferences and browser-local wallet choices.

The phone catalog has labeled controls and an accurate empty state. Its page
content fits the viewport without horizontal overflow.

## Organization scope and asynchronous behavior

The invitation and verification workflows now reject stale organization data.
The Team action waits for its own resolved permission and current roles, even if
an independent permission gate resolves first. Organization changes close the
verification wizard and clear prior sessions. Delayed session creation, issuer
lookup, and session-list success/error results cannot update a replacement
organization or dialog. Closing during creation also resets loading on reopen.
These cases are covered by deferred-response regressions.

Runtime readiness validates all six required wire flags as actual booleans.
Missing fields and malformed values have distinct diagnostics; a string such as
`"false"` cannot be coerced into a ready state.

## Development support

The Helm development overlay serves Vite and its reload connection through the
installation's existing HTTPS origin. Development mode is opt-in, source mounts
are read-only, temporary volumes are bounded, and Node receives no service-account
or server credentials. The default static serving configuration is preserved.
The public organization-creation flag now reaches the UI explicitly, matching the
backend setting. The development memory limit accommodates the existing code
checkers; checks were not disabled to obtain a working development page.

The follow-up reproduced an out-of-memory termination at the previous 2 GiB
development-container limit during an in-process configuration reload. A process
snapshot then confirmed a native TypeScript watcher leak: two watchers remained
after one reload, each using roughly 1 GiB. Forced termination of the checker's
worker skipped the cleanup that owned its native child.

A version- and digest-checked installation patch now waits for checker startup,
stops and reaps its exact owned child, acknowledges cleanup, and then terminates
the worker. Both TypeScript and ESLint stay enabled; cleanup failures are logged.
The development-only 4 GiB limit on an 8 GiB node also accommodates Vite's
temporary overlap while preparing the replacement server.

After replacing the development pod to install the patch and clear the earlier
processes, the full AWS application had one native watcher. Two successive
configuration reloads each replaced that watcher and returned to exactly one.
Both checkers reported again after each reload, with zero TypeScript/ESLint
errors, 148 existing ESLint warnings, and no container restart or OOM termination.
A browser tab left on a transient gateway timeout during this rollout/reload
exercise recovered on reload; the signed-in identity view and catalog navigation
then worked. This verifies recovery and watcher cleanup, not uninterrupted
availability while replacing the development pod.

## Validation and review

- Final combined UI run at `34409177`: **667 tests passed across 46 files in 93.87 seconds**.
- Production TypeScript build check passed.
- The configured UI ESLint gate passed with **zero errors and 145 existing warnings across 488 files**.
- The full updated Helm suite passed **38 tests**, including normal and development rendering of the bounded event-stream route. Independent review and focused reruns also passed.
- The prior **22 Node tests passed**: 9 development-origin/routing contracts and 13 checker-cleanup regressions. These unchanged checker/origin files were not rerun for the latest UI-only and proxy increments.
- Independent default rendering compared 56 resources; only the intended UI public feature-flag environment entry differed.
- Both independent reviewers cleared the latest Dashboard permission and stream-scoping increment after their findings were corrected.
- All 34 changed production/deployment files in the follow-up matched the local review copy on the development node by digest.
- The resumed increment applied ten additional reviewed source/chart files with before/after digest checks and a successful development rollout.
- The subsequent Discovery authentication correction was also applied by digest and verified through the live sign-in entry point.
- The latest authenticated replays applied the 11-file, 17-file, and six-file UI increments with before/after digest and file-metadata checks; the existing services remained ready.
- The additional event-stream proxy correction passed candidate and mounted configuration validation, followed by a graceful reload and the 138-second live idle check described above.
- The final six-locale loading-label correction passed JSON, semantic-diff, and runtime-resolution checks, then a digest-verified application and clean browser reload.
- Authenticated hot reload, corrected navigation, environment persistence, settings Cancel, dialogs, desktop layout, and phone layout were checked in the browser.

The combined test run includes the composed dashboard, parent verification page,
catalog loader, console-mode transitions, native applicant eligibility,
account/organization and grant changes, event-stream retry/cleanup, request-review
failure states and blank SDK errors, selected-organization event catalogs, and
permission-sensitive forms. Separate reviewer reruns overlap this count and are
not additional unique tests. A timing-dependent Team test now waits for the
router's committed pathname while retaining its permission and no-invitation
assertions.

The checker integration regression retains actual TypeScript and ESLint error
diagnostics through three real Vite restarts, requires one replacement native
watcher after each, and requires zero after closing the server. It also checks
that an unrelated child survives. The Linux fixture uses tmpfs because native
TypeScript's fanotify cannot watch this executor's overlay filesystem; production
watch settings are unchanged. The focused suite is included in CI.

## Verification limits

### Policy review summary follow-up

Source inspection during the next AWS walkthrough found that the final
Presentation Policy review read `trustProfile` while the wizard stored and
submitted `selectedTrustProfile`. The review now shows the actual selection and
omits an empty framework chip when the selected profile has no framework type.
Required claim values also appear in the summary, using the same precedence and
empty-value handling as the native request normalization and template projection.
Zero, false, and structured JSON values remain visible; markup is rendered as
text. The new label is available in all six console locales.

The complete-wizard regression verifies the displayed trust profile and required
value against the actual submitted request. Focused component cases cover native
value precedence, falsy values, missing values, structured values, and escaped
markup. **18 tests passed across two suites**; targeted production ESLint and
`git diff --check` passed. Two independent source reviews found no blockers.
The follow-up was subsequently applied to the resumed AWS development instance.
All nine UI/locale/test files passed before/after digest checks and retained
their file modes and ownership. The same **18 tests passed across two suites on
AWS in 33.86 seconds**. The existing installation completed its serving-origin
rollout; HTTPS certificate validation succeeded, and the UI client's callback,
web-origin, and logout settings were verified with PKCE S256 preserved. Existing
accounts, backend images, and the issuer DID were retained.

The connected browser reached the new origin's normal sign-in page. Chrome then
blocked the Register interaction because another extension interface was open.
Authenticated browser replay remains pending; no new account was submitted.

### Mobile navigation and template editing follow-up

Source review while the live browser was blocked identified five further UX
defects. These corrections are published in PR #1876 at `3a2cc814`.

| Area | Defect | Correction and regression coverage |
| --- | --- | --- |
| Mobile menu content | A saved collapsed desktop preference hid mobile labels, child links, and Sign out, without a mobile expand control | Mobile always renders the expanded menu while retaining the desktop preference. Tests cover the desktop-to-phone-to-desktop transition |
| Mobile navigation | Selecting a destination left the drawer covering the new page | Destination selections close the drawer, including nested and current-route links and console switching. Expanding a section keeps it open; tests check actual drawer visibility and destination content |
| Application Template validity | Clearing the field or entering zero displayed 30 while retaining an invalid value for submission; the input's maximum was also too small | The field retains the editable draft, validates the native whole-number range of 1–3650 days, and submits the exact validated number. Tests cover create/update boundaries, empty correction, invalid values, and a loaded zero |
| Credential claim presets | Changing Required mutated the shared preset, so selecting it again retained the previous edit | Applying a preset clones its claims and toggling Required updates the selected claim immutably. Tests cover preset switching, a new wizard instance, and frozen parent data |
| Credential Template validity | The editing step, Review, and submitted request could show or use different durations | One resolver supplies editable drafts, validation, Review, and numeric native day/offset fields. Invalid values block Next, Skip, and final submission. Review also shows the signed offset; a complete-wizard test compares displayed values with the actual create request |

The credential validity correction retains native alias precedence, whole-day
rounding, signed `i32` offsets, and the existing independence of default and
maximum validity. It does not add an ordering restriction absent from the native
contract. Four validation messages were added in each of the six console locales;
semantic comparison confirmed no unrelated message changes.

The combined local run passed **98 tests across nine suites in 36.47 seconds**.
The production TypeScript check passed, targeted production ESLint reported
**zero errors and seven pre-existing warnings**, and whitespace checks passed.
Each functional delta cleared two independent peer reviews. All 20 published
file blobs and the complete source tree were verified against the reviewed local
commit; the published tree is `8d12fc713a75c0a9f0eba5450a08384f450b5ad6`.

**AWS deployment and browser replay of this new batch remain pending.** The
browser connection became unavailable before the prepared CloudShell apply
command could run. The 18-test AWS result above applies to the preceding policy
summary revision, not this 98-test batch. The source replay is prepared with
all-file preflight checks, private backups, and preservation of file metadata;
it must be executed and verified after browser access returns. No authenticated
click-through or deployed pass is claimed for these five new corrections.

### Installed backend and remaining flows

The installed signed backend remains `v1.1.274`. It predates the native
organization defaults endpoints merged in #1848, and the installed defaults
request still returns **404**. Defaults loading/saving therefore remains
unverified end to end in this deployment. Organization profile details loaded,
display-name Cancel restored the original value, and environment selection
persisted after reload. The later private-organization description save/reload/
restore check also passed.

The legacy Membership Requests and Role Requests endpoints are unsupported by
this installed runtime and are also absent from the current
[native route inventory](../../contracts/gateway-routes.json).
Their UI now distinguishes unavailable requests from an empty inventory and
provides retryable errors. Controlled tests cover successful responses, failures,
and stale completions; a successful live review operation cannot be claimed until
an actual backend contract is available.

The resumed instance received a new temporary serving origin. Its existing
organization and issuer DID were retained for UI replay, so the origin update
does not establish credential issuance or credential-login readiness. Fresh
authenticated applicant checks and the completed owner checks are recorded above.

The earlier Keycloak changes in #1847 were already merged. This audit did not
exercise an actual Bitwarden extension/vault, so theme-level tests are not
reported as an extension autofill pass. Full wallet verification, credential
issuance, and creation/activation of all prerequisite resources remain outside
this bounded walkthrough. The latest authorized pass created two disposable
accounts and one private test organization. No outbound email or invitation was
sent, no API key, webhook endpoint, or verification session was created, and no
credential was issued during the live browser checks.
