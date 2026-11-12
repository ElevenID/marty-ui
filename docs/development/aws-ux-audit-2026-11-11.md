# Console device and template UX audit — 2026-11-11

## Scope and environment

This batch continues the AWS development UX work from main
`b7c7055830722d10512ccac042b1e0abe0e1ecec`. It groups related frontend changes in
one PR and uses the existing local dependency lockfile, test configuration, and
application build. No CI workflow, dependency manifest, native authorization,
or release configuration changes are included.

The date above is America/Denver. AWS observations occurred on 2026-11-12 UTC.
The retained development instance was running, but its configured public origin
still named its previous IP address. Opening the current HTTPS endpoint failed
with a certificate name mismatch. The Vite container was running, while the UI
pod and application services were not ready. A separate supported credential
recovery operation was already in progress. This batch did not replace its
credentials, replay its operation, or modify its deployment resources.

These observations prevented authenticated browser navigation through the
affected flows. The defects below were confirmed by tracing the actual frontend
and native API contracts and exercising controlled-response component tests;
they must not be described as completed live AWS browser tests. Private hosts,
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

Authenticated AWS replay remains required after the development environment's
credential recovery, current-origin TLS, and application readiness are restored.
Replay should cover Devices loading/search/refresh, applicant unregister with a
disposable registration, Application Templates failure/retry and enrichment,
account/organization switching, and phone-width table behavior.
