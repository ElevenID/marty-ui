# Marty UI Operations Permission Matrix

**Last updated:** November 10, 2026
**Audience:** Operations, support, QA, and release reviewers
**Scope:** Organization-scoped RBAC in the console and organization service

## Source of truth

The console evaluates flat `resource:action` permission keys for the authenticated
principal and selected organization. Use these owners when qualifying a release:

- [Permission catalog](contracts/organization-permission-catalog.json)
- [Rust organization role templates](rust/services/organization/src/catalog.rs)
- [Seeded-role entitlement tests](rust/services/organization/tests/permission_catalog.rs)
- [Rust organization RBAC routes](rust/services/organization/src/rbac_http.rs)
- [Rust gateway authentication middleware](rust/services/gateway/src/middleware.rs)
- [UI permission checks](ui/src/config/permissions.js) and
  [permission loading](ui/src/hooks/usePermissions.js)

The API returns the selected member's effective grants through
`GET /v1/organizations/{id}/members/me/permissions`. Custom roles select
permissions from the same catalog. Persisted grants and current source take
precedence over historical role names or UI labels.

## Seeded system roles

The eight current templates are `owner`, `admin`, `access_admin`,
`catalog_admin`, `reviewer`, `operator`, `viewer`, and `applicant`.
`applicant` is the default for new members. `member` and `developer` are not
current seeded role templates; do not invent those test principals or assume
their historical grants.

| Role | Current template grants | Operational use |
| --- | --- | --- |
| `owner` | Every catalog permission, with separate ownership semantics | Organization ownership and transfer |
| `admin` | Every catalog permission | Full organization administration |
| `access_admin` | All catalog actions on organization, team, role, policy-set, api-key, signing-key, webhook, integration-connector, notification, and audit resources | Access, settings, integration, and key administration |
| `catalog_admin` | All catalog actions on trust-profile, policy-set, trusted-issuer, credential-template, wallet, compliance-profile, presentation-policy, revocation-profile, deployment-profile, flow-definition, application-template, and integration-connector resources | Manage credential and policy configuration |
| `reviewer` | Selected organization/catalog/application views plus application review, approve, and reject | Review applications |
| `operator` | Selected organization/catalog/runtime views plus flow-instance start, advance, and cancel; issuance initiate and revoke; passport-certificate issue; verification execute | Run credential and verification workflows |
| `viewer` | Every catalog permission whose action is `view` | Read-only organization inspection |
| `applicant` | application-template:view, application:view, credential-template:view, issuance:view, organization:view, wallet:view | Catalog and application access without organization console access |

The `reviewer` view set is organization, trust-profile, trusted-issuer,
credential-template, wallet, compliance-profile, presentation-policy,
revocation-profile, deployment-profile, application-template, and application.

The `operator` view set is organization, trust-profile, credential-template,
wallet, application-template, deployment-profile, flow-definition,
flow-instance, issuance, and verification.

These resource sets are exact template inputs. An administrator role for one
area does not grant all actions in another area. In particular, reviewers do
not inherit operational issuance permissions, and operators do not inherit
application approval, team management, or key administration.

## Practical access boundaries

| Operation | Template coverage to exercise |
| --- | --- |
| Organization settings, team membership, role assignment | Full owner/admin and access_admin grants; negative controls for other roles according to their exact view sets |
| Trust, templates, policies, deployment and flow definitions | Full owner/admin and catalog_admin grants; access_admin also owns policy-set; view and denial cases for other roles |
| Application review, approval, rejection | Owner/admin and reviewer positives; operator, viewer, and applicant negatives |
| Issuance and operational flow execution | Owner/admin and operator positives; reviewer, viewer, and applicant execution negatives |
| Signing keys and API keys | Owner/admin and access_admin positives; all other roles checked against explicit grants |
| Passport and mdoc certificate authority actions | Test each distinct catalog permission; operator's passport-certificate:issue does not imply CSCA or mdoc authority |
| Audit export and ingestion | Owner/admin and access_admin positives; viewer receives audit:view only |
| Applicant experience | All six applicant grants and explicit organization-console denial; do not substitute a broad viewer or custom role |

The complete action list lives in the
[shared catalog](contracts/organization-permission-catalog.json). Review it with
the template source when permissions change; do not infer a missing action from
a broad label such as “full access.” The seeded-role tests assert the actual role
names, default membership role, and intended entitlements.

## Console behavior

The permission hook requires an authenticated principal and an actual selected
organization membership. Grants belong to that scope; an organization switch,
logout, or superseding request must not reuse the previous scope's permissions.

While grants are loading, or when permission loading fails, the hook returns no
effective grants. It does not synthesize owner/admin grants after an API failure.
Backend authentication, tenant ownership, and authorization remain required even
when navigation or action controls are hidden.

Use custom roles for requirements outside the seeded templates, then qualify
their allowed and denied operations against the same catalog. Preserve system
role and ownership protections when managing those roles.

## Organization authorization qualification

The historical `ORG_AUTHORIZATION_PHASE2_MIGRATION.md` report is retired. Its
Python service examples, mutable-image build receipts, endpoint counts and
completion claims are recoverable at UI commit
`83c6ac3da39e515965e9fc3a2ac49f2e155ecd66`; they are not current deployment or
authorization instructions. Use the Rust source owners above and the owning
service's authorization tests.

Keep these acceptance requirements when qualifying a release:

- Exercise same-organization success and cross-organization denial for trust,
  flow, compliance, presentation, deployment and revocation resources, including
  reads, lists, creation, mutation, activation, subordinate records and artifacts.
  Prove allowed and denied operations for **all eight seeded roles** and relevant
  custom-role principals. The historical report's blanket admin-only labels do
  not override current permissions.
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
  goal. Review cache lifetime, invalidation and revocation with the current
  owner; historical fixed TTLs, replicas and message-bus suggestions are not
  required architecture.

These runtime, security, and performance checks need current evidence. Retiring
the historical report and documenting the current role model does not establish
complete endpoint or deployed-release qualification.
