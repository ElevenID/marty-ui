# Console device, template, and policy UX audit — 2026-11-11

## Scope and environment

This batch continues the AWS development UX work from main
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
warning was not bypassed. This later observation remains unresolved and is not
represented as a successful cross-browser TLS check. It does not replace the
earlier served-certificate and connected-Chrome observations.

A temporary dashboard-label edit had just been requested for visible HMR
verification when that connection was lost. Its command acknowledgement,
visible result and restoration have not been observed. Before resuming, inspect
the isolated checkout, restore the exact backed-up label if the edit completed,
and repeat the edit/restore round trip. No visible HMR success is claimed.

The product defects below were confirmed by tracing frontend and native API
contracts and exercising controlled-response component tests. Private hosts,
accounts, credentials, operational receipts, and resource identifiers are
excluded from this report.

## Corrections

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
are included in the `408a0f1` checkout mounted on AWS; their browser behavior has
not yet been exercised there.

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

The earlier certificate, readiness and sign-in checks succeeded. Further live
work requires reconnecting to the originating Chrome session, then checking the
current served certificate, source tree and automatic-stop deadline again.
Visible HMR and the temporary-label cleanup are pending. The navigation and
dashboard follow-up changes made after the connection loss also require source
replay onto the AWS checkout.

Replay should cover Devices loading/search/refresh, applicant unregister with
a disposable registration, Application Templates failure/retry and enrichment,
account/organization switching, phone-width table behavior, and the policy
wizard's Freshness and Review steps. Record these outcomes separately from the
source, test, infrastructure and successful sign-in checks above. Keep the PR
in draft until this remaining live verification is completed.
