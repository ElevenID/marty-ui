# Marty UI Operations Permission Matrix

**Last Updated:** April 10, 2026  
**Audience:** Operations, support, QA, and release reviewers  
**Scope:** Organization-scoped RBAC used by the Marty UI console and the backing organization service

This document explains the current permission model used by the org console. It is intended to answer two practical questions:

1. **Which roles actually exist today?**
2. **What can each role do across the main console resources?**

It complements `RELEASE_READINESS.md`, which tracks launch sign-off.

---

## Source of truth

The current RBAC model is defined by the organization service and loaded into the UI as flat `resource:action` permissions.

Primary implementation references:

- [Rust organization permission catalog and role templates](rust/services/organization/src/catalog.rs)
- [Rust organization RBAC routes](rust/services/organization/src/rbac_http.rs)
- [Rust gateway authentication middleware](rust/services/gateway/src/middleware.rs)
- `ui/src/config/permissions.js`
- `ui/src/hooks/usePermissions.js`
- `ui/src/components/console/org/RolesPage.jsx`

---

## Important terminology note

There is a **current terminology mismatch** in the codebase:

- The **backend-seeded system roles** are:
  - `owner`
  - `admin`
  - `member`
  - `viewer`
- Some newer **UI copy and team-management flows** also reference:
  - `admin`
  - `developer`
  - `operator`

For operations and release decisions, treat **`owner/admin/member/viewer` as the canonical roles that are seeded today**.

Use `developer` and `operator` as **product/UI terminology still being normalized**, not as the current authoritative system-role set.

---

## How permissions work

Permissions are stored and evaluated as flat keys in the form:

- `resource:action`

Examples:

- `team:view`
- `role:create`
- `audit:export`
- `deployment-profile:activate`

The UI fetches the effective permission set for the active organization from:

- `GET /v1/organizations/{id}/members/me/permissions`

Custom roles can be created by selecting permission IDs from the permission catalog.

---

## System role summary

| Role | Purpose | Access level | Special notes |
| --- | --- | --- | --- |
| `owner` | Organization owner | Full access to all catalog permissions | Also retains ownership semantics beyond ordinary RBAC; owner transfer is handled outside the flat permission catalog |
| `admin` | Full org administrator | Full access to all catalog permissions | Operationally equivalent to owner for most console actions |
| `member` | General builder/operator role | Can manage most design, deploy, issuance, and verification resources | Cannot manage org settings, team membership, or roles; gets view-only access for those areas |
| `viewer` | Read-only observer | View-only access across resources | No create/edit/delete/invite/approve/export/execute actions |

---

## Practical access summary by resource

In the table below, `owner` and `admin` share the same catalog permissions unless noted otherwise.

| Resource | Owner / Admin | Member | Viewer | Notes |
| --- | --- | --- | --- | --- |
| Trust Profiles | Full | Full | View | Includes activate/suspend |
| Trusted Issuers | Full | Full | View | CRUD only |
| Credential Templates | Full | Full | View | Includes activate/deprecate/version |
| Compliance Profiles | Full | Full | View | Includes activate/suspend |
| Presentation Policies | Full | Full | View | Includes activate/suspend/version/evaluate |
| Revocation Profiles | Full | Full | View | Includes activate; no edit action in current catalog |
| Deployment Profiles | Full | Full | View | Includes activate/suspend |
| Flow Definitions | Full | Full | View | Includes activate |
| Flow Instances | Full | Full | View | Includes start/advance/cancel |
| Issuance | Full | Full | View | Includes initiate |
| Application Templates | Full | Full | View | Includes activate |
| Applications | Full | Full | View | Includes approve/reject |
| Organization Settings | Full | View only | View only | `member` and `viewer` do not get org edit |
| Team | Full | View only | View only | `member` and `viewer` cannot invite/manage members |
| Roles | Full | View only | View only | `member` and `viewer` cannot create/edit/delete/assign roles |
| API Keys | Full | Full | View | Includes revoke/delete |
| Signing Keys | Full | Full | View | Current catalog supports view/create/delete |
| Webhooks | Full | Full | View | Includes test |
| Notifications | Full | Full | View | Current catalog supports view/send |
| Audit | Full (view + export) | View only | View only | `member` does **not** get export |
| Verification | Full | Full | View | Includes execute |

---

## Exact permission catalog

The current catalog seeded by the organization service is:

### Trust

- `trust-profile`: `view`, `create`, `edit`, `delete`, `activate`, `suspend`
- `trusted-issuer`: `view`, `create`, `edit`, `delete`
- `compliance-profile`: `view`, `create`, `edit`, `delete`, `activate`, `suspend`
- `presentation-policy`: `view`, `create`, `edit`, `delete`, `activate`, `suspend`, `version`, `evaluate`
- `revocation-profile`: `view`, `create`, `delete`, `activate`

### Templates and applications

- `credential-template`: `view`, `create`, `edit`, `delete`, `activate`, `deprecate`, `version`
- `application-template`: `view`, `create`, `edit`, `delete`, `activate`
- `application`: `view`, `approve`, `reject`

### Deploy and operate

- `deployment-profile`: `view`, `create`, `edit`, `delete`, `activate`, `suspend`
- `flow-definition`: `view`, `create`, `edit`, `delete`, `activate`
- `flow-instance`: `view`, `start`, `advance`, `cancel`
- `issuance`: `view`, `initiate`
- `verification`: `view`, `execute`

### Organization and access control

- `organization`: `view`, `edit`
- `team`: `view`, `invite`, `manage`
- `role`: `view`, `create`, `edit`, `delete`, `assign`

### Keys, notifications, and observability

- `api-key`: `view`, `create`, `edit`, `revoke`, `delete`
- `signing-key`: `view`, `create`, `delete`
- `webhook`: `view`, `create`, `edit`, `delete`, `test`
- `notification`: `view`, `send`
- `audit`: `view`, `export`

---

## What the seeded system roles include

### `owner`

- Every permission in the catalog
- Plus ownership semantics such as owner protection and transfer workflows

### `admin`

- Every permission in the catalog
- Full operational access to org settings, members, roles, keys, audit export, and runtime actions

### `member`

`member` receives every catalog permission **except** write/admin actions on these areas:

- `organization`
- `team`
- `role`
- `audit:export`

Concretely, `member` keeps:

- `organization:view`
- `team:view`
- `role:view`
- `audit:view`

and gets full action coverage on the other design/deploy/operate resources.

### `viewer`

`viewer` receives only `view` actions for every resource in the catalog.

---

## Console behavior notes

### Navigation gating in the UI

The current sidebar explicitly gates at least these areas by permission:

- Team navigation requires `team:view`
- Roles navigation requires `role:view`

Other pages may still be visible depending on route structure, but backend authorization remains the final gate.

### Fail-closed behavior

The UI denies actions while permissions are still loading.

### Admin fallback behavior

If detailed permissions cannot be loaded, backend authorization helpers fall back to allowing `admin` / `owner` access for protected actions.

### Custom roles

Organizations can create custom roles from the permission catalog. System roles are seeded automatically for each organization and cannot be deleted.

---

## Operational guidance

For support and QA, use the following rules of thumb:

- If a user needs full organization administration, assign `admin`.
- If a user should build and operate credential workflows but not manage people or org settings, `member` is the closest current built-in role.
- If a user should only inspect or review state, use `viewer`.
- If you need a stricter split such as **developer** vs **operator**, create or inspect **custom roles** rather than assuming those are the seeded system roles today.

---

## Known gap to track

The product direction increasingly uses `admin`, `developer`, and `operator` terminology in the UI, but the seeded backend system roles are still `owner`, `admin`, `member`, and `viewer`.

That mismatch should remain tracked as a readiness item until docs, UI copy, tests, and backend defaults all agree on the same canonical role model.

## Organization authorization qualification

The historical `ORG_AUTHORIZATION_PHASE2_MIGRATION.md` report is retired. Its
Python service examples, mutable-image build receipts, endpoint counts and
completion claims are recoverable at UI commit
`83c6ac3da39e515965e9fc3a2ac49f2e155ecd66`; they are not current deployment or
authorization instructions. Use the Rust source owners above and the owning
service's authorization tests, rather than restoring its Python middleware.

Keep these open acceptance requirements when qualifying a release:

- Exercise same-organization success and cross-organization denial for trust,
  flow, compliance, presentation, deployment and revocation resources, including
  reads, lists, creation, mutation, activation, subordinate records and artifacts.
  Prove allowed and denied operations for member, administrator, viewer and
  custom-role principals against the current permission catalog. The old
  report's blanket admin-only labels do not override current role permissions.
- Qualify deployment-profile API-key generation separately from organization
  authentication keys. Verify least privilege and tenant ownership at both the
  gateway and service, including forged/missing caller context and direct
  service requests; UI visibility and database schema separation are insufficient.
- Preserve intended wallet request/submission, presentation evaluation, signed
  webhooks and internal revocation operations through their actual protocol or
  service authentication. Historical descriptions of these as public or
  unauthenticated are not exemptions from current authorization requirements.
- Retain authorization-failure audit events, privacy-safe organization/request
  correlation, denial metrics/alerts, membership-verification rate limits and
  automated cross-organization attack checks as qualification requirements.
- Measure membership lookup behavior under load and permission changes. The
  old `<50 ms p99` membership target is an unqualified historical performance
  goal, not a measured release promise. Review cache lifetime, invalidation and
  revocation behavior with the current owner; fixed old cache TTLs, replicas and
  message-bus suggestions are not required architecture.

Role terminology normalization and these runtime/security/performance checks
remain open until their owners provide current evidence. Removing the report
implements none of them and does not establish complete endpoint coverage.
