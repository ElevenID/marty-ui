# Marty UI Manual Readiness Tasks

**Last Updated:** April 11, 2026  
**Goal:** move from automated confidence to repeatable manual sign-off using the real gateway plus `marty-cli` where it already provides coverage.

---

## What closed in this pass

- [x] Align `marty-cli` credentials, verify, flows, and E2E commands to the current gateway routes
- [x] Update CLI regression tests so they assert the fixed gateway contract
- [x] Add real CLI binary smoke coverage for auth, health, org bootstrap, template listing, verification status, and `marty test e2e --scenario health`
- [x] Align the console audit service to organization-scoped gateway routes
- [x] Normalize gateway-shaped audit payloads into the UI model used by `AuditPage` and dashboard activity surfaces
- [x] Replace broken audit saved-view API calls with org-scoped local persistence so the feature works during manual testing
- [x] Add sidebar navigation regression coverage for the key org-console release routes
- [x] Add automated RBAC regression coverage for team, notifications, audit export, and signing keys
- [x] Add polling-resilience regression coverage for the notification bell and dashboard health refresh
- [x] Add gateway-backed smoke coverage for org-scoped dashboard endpoints and signing-key service routes
- [x] Re-validate the focused CLI and UI slices after the fixes

## Current validated evidence

- `marty-cli`
	- Command suite plus real CLI binary smoke coverage passes: `95/95`
- `marty-ui/ui`
	- Focused readiness slice for RBAC, polling resilience, dashboard, gateway smoke, and route coverage passes: `47/47`

These runs remove six meaningful blockers for manual smoke work:

1. the CLI now speaks the same route dialect as the gateway, and
2. the audit UI now speaks the same route + payload dialect as the gateway, and
3. the key org-console release routes stay wired through the real sidebar navigation, and
4. role-aware mutation controls are covered for the key org-console release surfaces, and
5. notification and dashboard polling now have executable failure-mode coverage, and
6. dashboard/signing-key gateway service paths have real smoke coverage.

---

## Remaining tasks before manual sign-off

### P0 — do these first

- [ ] Run a gateway-backed smoke pass for one real org using the sequence below
- [ ] Run a manual real-org role check for `admin`, `developer`, and `operator` across:
	- team management
	- notifications
	- audit visibility/export
	- signing keys / deploy surfaces
- [ ] Confirm environment dependencies are actually available in the target stack:
	- gateway
	- auth / Keycloak
	- organization service
	- notification service
	- any wallet / inspection / DIDComm components needed for the release demo
- [ ] Update API docs to reflect the corrected CLI/gateway routes for:
	- issued credentials
	- verification flows
	- flow definitions / instances
	- org-scoped audit export
- [x] Add route/navigation regression coverage for the new console pages beyond the current focused page tests
- [x] Add automated role-behavior regression coverage for `admin`, `developer`, and `operator` across team, notifications, audit export, and signing keys

### P1 — next readiness blockers

- [ ] Validate dashboard readiness signals and signing-key flows end to end against a real org
- [x] Add automated polling-interruption coverage for notifications and dashboard refresh surfaces
- [x] Add gateway-backed smoke coverage for dashboard and signing-key service contracts
- [ ] Run a large audit-log dataset check and confirm pagination/export remain usable
- [ ] Complete an accessibility pass over audit, team, notifications, and dashboard additions
- [ ] Normalize role terminology across docs, copy, and tests (`owner/admin/member/viewer` vs `admin/developer/operator`)

### P2 — should be added soon

- [ ] Add screenshots or short walkthroughs for the top org-console flows
- [ ] Add CLI coverage or smoke helpers for gaps the UI still depends on but the CLI does not cover yet:
	- team operations
	- audit inspection/export helpers
- [ ] Add a short support/ops runbook for:
	- notification delivery failures
	- audit export failures
	- team invite / revoke / role-change failures

---

## Recommended manual smoke sequence

### 1) Session and org bootstrap

- Authenticate with `marty auth login`
- Confirm the target environment with `marty auth whoami`
- Confirm gateway health with `marty health`
- List orgs with `marty orgs list`
- Select the target org with `marty orgs switch <org-id>`

### 2) Seed data the UI should render

- List templates with `marty templates list`
- List flows with `marty flows list`
- List issued credentials with `marty credentials list`
- Start or inspect a verification flow with:
	- `marty verify start`
	- `marty verify status <id>`
- If the environment supports it, run `marty test e2e` for a real smoke scenario

### 3) Validate the UI against that data

- Open the org console dashboard and confirm:
	- recent activity renders
	- critical signals render without console/API errors
	- environment and org context are correct
- Open `Audit` and confirm:
	- event list loads
	- filters apply
	- export opens the gateway-backed download URL
	- saved views persist for the current org
- Open `Notifications` and confirm:
	- unread filtering behaves correctly
	- mark-all-as-read works
	- alert rules and preferences save cleanly for admin users and stay read-only for lower-privilege roles
- Open `Team` and confirm:
	- members and invites load for the active org
	- invite / resend / revoke / role-change actions work with the current permission model
	- lower-privilege roles cannot resend or revoke pending invites
- Open `Signing Keys` and confirm:
	- the empty-state upload action opens correctly for deploy admins
	- lower-privilege roles cannot upload, rotate, or delete keys
- Simulate or observe transient gateway degradation and confirm:
	- the notification bell retains the last unread count until the next successful poll
	- dashboard health retains the last known healthy state until recovery data arrives

### 4) Capture release evidence

- Save screenshots for dashboard, audit, notifications, and team pages
- Record any 4xx/5xx responses from the gateway docs or browser network panel
- Log mismatches as either:
	- UI bug
	- gateway/service contract drift
	- missing dependency / environment issue

---

## Known gaps to watch during manual testing

- Audit saved views are local per organization for now; they are not backend-synced
- The CLI still lacks first-class team and audit command groups, so some smoke steps still rely on the UI or direct gateway inspection
- Role terminology remains mixed across some docs and surfaces
- Automated coverage now exists for RBAC and polling resilience, but manual real-org sign-off is still required
- The broader integration environment still has known infrastructure-dependent gaps outside pure UI correctness

---

## Suggested ownership

- **Frontend:** audit/dashboard/notifications/team UX behavior, route regressions, resilience
- **Platform/backend:** gateway contracts, audit export behavior, API docs, dependency readiness
- **QA / release:** role matrix validation, screenshots, accessibility, sign-off notes
