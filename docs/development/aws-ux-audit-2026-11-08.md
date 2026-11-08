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
The development instance's private address, account identifiers, credentials,
resource identifiers, receipts, and infrastructure observations are excluded from
this public report.

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

## Validation and review

- Final combined UI run: **203 tests passed across 15 files**.
- Production TypeScript build check passed.
- Scoped production ESLint passed with zero errors and three existing unused-variable warnings.
- **33 Helm tests and 4 development-origin tests passed**.
- Independent default rendering compared 56 resources; only the intended UI public feature-flag environment entry differed.
- Both independent reviewers cleared the complete batch after their findings were corrected.
- The final production/deployment files on the development node matched the local review copy by digest.
- Authenticated hot reload, corrected navigation, environment persistence, settings Cancel, dialogs, desktop layout, and phone layout were checked in the browser.

The combined test run includes the composed dashboard, parent verification page,
and catalog loader. Separate reviewer reruns overlap this count and are not
additional unique tests. A timing-dependent Team test now waits for the router's
committed pathname while retaining its permission and no-invitation assertions.

## Verification limits

The installed signed backend was `v1.1.274`. It predates the native organization
defaults endpoints merged in #1848, so defaults loading/saving could not be
verified end to end in this deployment. Organization profile details loaded,
display-name Cancel restored the original value, and environment selection
persisted after reload.

The earlier Keycloak changes in #1847 were already merged. This audit did not
exercise an actual Bitwarden extension/vault, so theme-level tests are not
reported as an extension autofill pass. Full wallet verification, credential
issuance, and creation/activation of all prerequisite resources remain outside
this bounded walkthrough. No organization, invitation, API key, or verification
session was created during the browser checks.
