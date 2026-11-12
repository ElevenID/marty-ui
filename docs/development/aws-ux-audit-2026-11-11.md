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

An isolated checkout of `00ec770` was mounted for live development, preserving
the previous dirty source tree. Its locked `npm ci` completed, and the UI pod
reported both containers Ready. The absolute automatic-stop guard remained in
place. The repeatable maintenance procedure is recorded in the
[live reload guide](../kubernetes-ui-live-reload.md).

**Authenticated browser replay has not yet succeeded.** At the current
checkpoint, Chrome rejected navigation with `ERR_BLOCKED_BY_CLIENT` and a
security error before the application could be attached. Google's primary
[Safe Browsing site-status report](https://transparencyreport.google.com/safe-browsing/search)
also marked the temporary endpoint unsafe and warned about deceptive collection
of personal information. The browser warning was not bypassed, and the serving
origin was not changed to evade it. The existing single-installer secure-IP and
automated Let's Encrypt path is being checked for endpoint or configuration
mismatches before another browser attempt. Successful TLS, service readiness,
and a running Vite container do not establish an authenticated manual
walkthrough or visible HMR in the browser; neither is claimed here.

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
are not part of the `00ec770` checkout mounted on AWS at this checkpoint; their
browser behavior has not yet been exercised there.

| Area | Defect | Result |
| --- | --- | --- |
| Unsupported policy controls | Maximum proof age, single-presentation selection, and a compliance-reference field implied effects absent from the submitted native policy | Removed these controls, defaults, and Review claims while retaining supported credential-age, revocation, holder-binding, and predicate settings |
| Credential age | Editing in whole days truncated sub-day values, and blank or invalid input could silently become a different duration | Edit exact integer seconds, including zero; reject blank, negative, fractional, and unsafe numeric values before Next, Skip, or creation |
| Policy Review | Duration summaries discarded remaining hours, minutes, or seconds | Review preserves every unit and uses the selected locale, including an explicit zero-second value |
| Holder binding | Radio inputs lacked the visible option names and descriptions; card and input handlers could duplicate changes | Associate the group and each radio with its text and use one labeled control for pointer and keyboard selection |

The six console locales were updated for the supported controls and precise
duration guidance. Native policy enforcement and authorization are unchanged.

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

## Remaining browser verification

Current-origin TLS, application readiness, and the isolated development source
mount are restored. The installer endpoint investigation is continuing;
authenticated AWS replay and the visible edit/restore HMR check remain pending.
Replay should cover Devices loading/search/refresh, applicant unregister with a
disposable registration, Application Templates failure/retry and enrichment,
account/organization switching, phone-width table behavior, and the policy
wizard's Freshness and Review steps. These outcomes must be recorded separately
from the source, test, and infrastructure checks above.
