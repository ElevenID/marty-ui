# Marty UI Release Readiness

**Last Updated:** April 11, 2026  
**Scope:** Post-login organization console, operational readiness, and launch validation for the current implementation in `marty-ui`

This document is the current go/no-go checklist for shipping the recent console enhancements. It complements `IMPLEMENTATION_PROGRESS.md`, which tracks implementation history and workstream progress.

---

## Current snapshot

The core console work is largely implemented:

- Routing for new console surfaces is in place
- The audit page is wired to the real API and now uses organization-scoped gateway routes
- Notifications are integrated into the layout and routed
- The team management page has full CRUD-style flows
- Signing key management is present and routed
- Guided setup and quick-create drawers exist in the current UI
- Initial automated coverage now extends across dashboard readiness logic, focused RBAC coverage for `TeamPage`, notifications, audit, and signing keys, polling-resilience checks for notification and dashboard refresh surfaces, and gateway-backed service smoke for dashboard and signing-key contracts
- Real CLI binary smoke coverage now exercises API-key auth, health, organization bootstrap, template listing, verification start/status, and the shipped `marty test e2e` health scenario against a live local HTTP surface
- A dedicated CLI + gateway manual smoke task list now exists in `MANUAL_READINESS_TASKS.md`

The remaining work is mostly in documentation, accessibility, scale testing, and real-environment sign-off.

---

## Release gate

### Already complete

- [x] Route configuration for the new console pages is in place
- [x] Audit page uses the real API service
- [x] Notifications UI is present in the application layout
- [x] Team management UI supports invite, role change, revoke, and remove flows
- [x] Signing keys page is routed and available in the console
- [x] Initial unit coverage exists for dashboard readiness logic

### Must complete before production sign-off

- [x] Add targeted component tests for `TeamPage`, notifications surfaces, and `AuditPage`
- [x] Add direct service tests for `auditApi`, `notificationsApi`, and `teamApi`
- [x] Document the permission matrix for operations and support teams (`OPERATIONS_PERMISSION_MATRIX.md`)
- [ ] Normalize role terminology across docs, tests, and UI copy (`admin`, `developer`, `operator`)
- [ ] Update API documentation for the new or expanded endpoints
- [ ] Run an accessibility audit across the new console surfaces
- [x] Add regression coverage for role-based access behavior for `admin`, `developer`, and `operator`
- [x] Add regression coverage for network-failure handling and notification polling interruption behavior
- [ ] Load test large audit-log datasets
- [x] Add gateway-backed smoke coverage for dashboard readiness and signing-key integration paths
- [x] Add route/navigation regression coverage for the new console pages

### Recommended before broader customer launch

- [ ] Add a short support runbook for notifications, audit exports, and team-management failures
- [ ] Add screenshots or walkthroughs for the most important org-console flows
- [ ] Confirm copy and navigation labels are consistent between console, onboarding, and settings

---

## Evidence for completed items

The following files provide the strongest current evidence that the implementation is present:

- `ui/src/App.jsx`
  - Routes for audit, team, notifications, notification preferences, signing keys, and setup wizard
  - Notification bell integrated into the authenticated application layout
- `ui/src/components/console/audit/AuditPage.jsx`
  - Real API-backed audit page with org-scoped routing, filters, exports, local saved views, and empty/error/loading states
- `ui/src/components/console/org/TeamPage.jsx`
  - Team member listing, invitations, role changes, removals, and permission-aware actions
- `ui/src/components/console/dashboard/GuidedSetupWizard.jsx`
  - Multi-step setup flow for initial organization onboarding
- `ui/src/components/console/ConsoleDashboard.jsx`
  - Dashboard integration points and quick-create workflow wiring
- `ui/src/config/__tests__/dashboardRules.test.ts`
  - Unit coverage for readiness computation, blockers, and quick actions
- `ui/src/components/console/org/TeamPage.test.tsx`
  - Focused regression coverage for org-scoped invite and role-change flows
- `ui/src/components/console/org/NotificationsPage.test.tsx`
  - Focused component coverage for unread filtering, mark-all-as-read, alert-rule creation, preference persistence, and read-only notification personas
- `ui/src/components/console/audit/AuditPage.test.tsx`
  - Focused component coverage for audit event rendering, exports, saved-view application, and no-export personas
- `ui/src/components/console/deploy/SigningKeysPage.test.tsx`
  - Focused component coverage for the empty-state upload path and read-only signing-key personas
- `ui/src/components/common/NotificationBell.test.tsx`
  - Polling-resilience coverage that preserves the last unread count on failures and recovers on the next successful refresh
- `ui/src/hooks/__tests__/useDashboardData.test.ts`
  - Dashboard health-refresh resilience coverage that preserves the last healthy status through polling failures and updates on recovery
- `ui/src/services/__tests__/readinessGatewaySmoke.test.ts`
  - Gateway-backed smoke coverage for org-scoped dashboard endpoints and signing-key list, rotate, and config routes
- `ui/src/services/__tests__/auditApi.test.ts`
  - Direct contract coverage for audit-event listing, exports, critical events, and saved views
- `ui/src/services/__tests__/notificationsApi.test.ts`
  - Direct contract coverage for notifications, preferences, unread counts, and alert-rule operations
- `ui/src/services/__tests__/teamApi.test.ts`
  - Direct contract coverage for organization-scoped member, invite, ownership-transfer, and team-snapshot APIs
- `ui/src/components/navigation/SidebarNavigation.test.tsx`
  - Regression coverage for navigation to the key org-console release routes: dashboard, team, notifications, signing keys, and audit
- `ui/src/components/console/__tests__/ConsoleDashboard.test.tsx`
  - Dashboard rendering coverage across empty, partial, operational, degraded, and error states
- `marty-cli/src/commands/__tests__/cliSmoke.integration.test.js`
  - Real `bin/marty.js` smoke coverage for API-key auth, `health`, `orgs list/switch`, `templates list`, `verify start`, `verify status`, and `test e2e --scenario health`
- `MANUAL_READINESS_TASKS.md`
  - Prioritized CLI + gateway task list for manual sign-off and smoke validation

---

## Known gaps in current evidence

These areas may be partially implemented, but they do not yet have enough clear sign-off evidence to treat as production-ready:

- Real-org cross-role sign-off is still pending even though automated RBAC coverage now exists for `TeamPage`, notifications, audit export, and signing keys
- Explicit accessibility sign-off for the newer console pages
- Failure-mode coverage for broader API outages and degraded states beyond the current notification/dashboard polling regressions
- Performance evidence for large audit result sets
- Audit saved views currently persist locally per organization; backend-shared persistence is still not implemented
- Role terminology is not yet fully normalized; see `OPERATIONS_PERMISSION_MATRIX.md` for the current canonical role model and the remaining mismatch

---

## Coordinated checks outside this repo

These are not pure `marty-ui` blockers, but they matter if this release includes end-to-end demos, wallet integrations, or gateway-backed operational flows.

- [ ] Confirm the corresponding gateway integration baseline in `marty-integration-tests`
- [ ] Verify any required external wallet, CLI, inspection, or DIDComm services are available in the target environment
- [ ] Validate host-based test environment settings when reproducing issues locally
- [ ] Document which demo or interop scenarios are expected to work in the release environment

**Current related integration note:** the latest gateway baseline in `marty-integration-tests` is improved, but remaining failures are still infrastructure-dependent rather than pure UI regressions.

---

## Suggested owners

- **Frontend engineering:** component tests, route regressions, copy consistency, UI resilience
- **Platform/backend:** API docs, permission matrix confirmation, operational dependency verification
- **QA / release management:** accessibility audit, role-based validation, audit-log scale checks, sign-off tracking

---

## Exit criteria

A reasonable production sign-off for this work should require all items in **Must complete before production sign-off** to be checked, plus any applicable coordinated checks for environments that depend on gateway-backed demos or external integrations.
