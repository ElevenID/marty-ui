# Canonical external-observation authority adapter

## Purpose and boundary

`PostgresObservationAuthority` implements the core-only `ObservationAuthority`
contract used by the transactional journal. It is not a public HTTP endpoint and
is not imported by the Canvas connector. Connector-to-core traffic remains the
Common Gateway with the organization-scoped API key.

The adapter uses the existing shared PostgreSQL database and canonical
`organization_service` and `issuance_service` schemas. It does not create a
second API-key store, accept caller-supplied authorization snapshots, read the
raw API-key secret, or use a remote/stale authorization cache.

## Locked authority records

Every admission transaction loads and locks these canonical records in a
stable order:

0. **Organization** ? `organization_service.organizations` is held `FOR SHARE`;
   only canonical `active` organizations are authorized. Suspension waits for
   an admitted transaction, and later observations/administrative actions fail closed.
1. **Organization API key** — `organization_service.api_keys`, selected by
   authenticated API-key ID and organization ID with `FOR UPDATE`. It checks
   active status, enabled state, organization scope type, absence of a
   deployment-profile binding, scopes and expiry. The exact key ID and
   organization come from the Gateway-authenticated identity, not request JSON.
2. **Producer grant** — `issuance_service.external_observation_producer_grants`,
   selected by exact organization, API-key ID and requested binding membership,
   with `FOR UPDATE`. It must be explicitly approved, active and unexpired.
3. **Grant membership and evidence binding** —
   `external_observation_grant_bindings` membership rows are held `FOR SHARE`;
   the exact `external_observation_bindings` row is held `FOR UPDATE`.
   The binding owns provider, application, subject, fact type, resource scope,
   typed claim rules, freshness and clock-skew limits.
4. **Application** — the canonical `issuance_service.applications` row is held
   `FOR UPDATE`. Organization and applicant identifier must match the binding.
   Only `pending` and `under_review` lifecycle states accept new observations;
   application expiry is carried into the admission planner and checked against
   the journal transaction's database clock.

The journal calls the authority adapter again after staging writes and before
commit. The admission planner rechecks key/grant/application expiry using the
database clock at decision time. Exact retries still require current key, grant
and binding authorization, but return their original receipt without creating
new evidence or reopening a closed/expired application.

## Revocation and update serialization

The existing organization API-key revocation path uses
`api_key_by_id_for_update_in_transaction` and updates the same canonical
`organization_service.api_keys` row. The journal's `FOR UPDATE` lock therefore
serializes key revocation with admission: if revocation commits first, admission
sees the revoked key; if admission acquires the lock first, revocation waits
until that transaction commits or rolls back.

Grant updates and revocations must lock the grant row before changing grant
membership. Membership triggers bump the grant revision. Binding changes bump
the binding revision. Application lifecycle updates use the same application
row lock. The journal's SERIALIZABLE transaction, sequence-head compare-and-set,
and final locked revalidation protect the receipt, audit and sequence head as
one atomic effect.

The required lock order is:

`organization -> api_key -> producer_grant -> grant_membership -> evidence_binding -> application`

Administrative grant/binding handlers must preserve this order. Direct
cross-database calls, stale replicas, cache-only authorization and unlocked
remote validation do not satisfy this contract.

## Candidate core-owned records

The candidate schema now defines:
- `external_observation_producer_grants`: exact organization/source/API-key
  delegation, approver, expiry, active state and revision;
- `external_observation_bindings`: one existing application/subject and
  administrator-approved provider/fact/resource/claim/freshness contract;
- `external_observation_grant_bindings`: explicit grant-to-binding membership;
- the existing receipt, sequence-head and audit journal.

Grant and binding records default inactive. A producer key cannot self-create
or widen its own grant. API-key rotation requires an explicit administrator operation against a current
revision and canonical replacement key ID. Rotation deactivates the grant; fresh
approval is required before the replacement key can submit. The old key loses
its grant immediately, including receipt replay authorization. Binding membership,
source and expiry are not silently widened. No key secret enters this interface. The schema is still a candidate contract and is
not registered in startup migrations.

## Claim-rule encoding

`claim_rules` is a JSON object keyed by approved claim name. Each rule has
exactly:
- `kind`: `boolean`, `number` or `text`;
- `required`: boolean;
- `nullable`: boolean;
- for `number`, finite `minimum` and `maximum`;
- for `text`, `max_bytes` from 1 through 512.

Unknown fields, invalid combinations, empty schemas and more than 32 claims
fail closed. `resource_scope` is a non-empty JSON object of string values.
These records are loaded from core storage; connector claims cannot change them.

## Validation and activation status

The focused PostgreSQL harness compiles the exact authority adapter with
warnings denied and the production lockfile. Its synthetic canonical tables
are test fixtures only. Tests cover valid binding resolution, exact scope
requirements, revoked keys, closed applications, wrong tenants, missing grant
membership and the API-key row lock blocking a concurrent revocation.

The public Gateway implements authenticated original-byte observation ingress and
session-only administrator actions under:
`/v1/organizations/{organization_id}/external-observation-producers/{grant_id}`:
- `POST /revoke` with `expected_revision`;
- `POST /approve` with `expected_revision`, for the current inactive grant/key;
- `POST /rotate-api-key` with `expected_revision` and `new_api_key_id`.

All administrator requests require an actual session, a single allowed Origin,
and a canonical path tenant matching the active session. API-key identities,
including admin scopes, cannot administer grants. Core reloads and locks active
canonical membership and exact `external-observation:manage` permission through
organization-scoped roles. Core authenticates the Gateway service transport;
caller-supplied identity headers are replaced by Gateway trusted context.

Administrator bodies are strict JSON, bounded to 4096 bytes and a 10-second read
deadline. Proxy retries and generic response caching are disabled. A replacement
key must be a current enabled organization key with exact `evidence:submit`
scope and unexpired lifetime. Rotation locks both keys in stable UUID order
before the grant. Approval/rotation audit writes and authority updates commit
atomically; canonical clock expiry is rechecked after all staged writes. Conflicts
are not blindly retried, and an uncertain commit requires reconciliation. The
last approval metadata after rotation is historical only while inactive; fresh
approval replaces it for the replacement key.

Activation remains explicitly disabled by default. The optional startup router
preflights canonical columns, row-lock and mutation/audit privileges and revision
triggers before mounting. It never provisions schema or database roles.

Not yet implemented or activated:
- public grant creation/modification and evidence-binding/membership administration;
- audit read and uncertain-outcome reconciliation operations;
- reviewed migration registration and least-privilege database role grants;
- complete exact-candidate CI and independent security review/protected integration;
- connector worker submission and deployed Gateway/network-denial + OB3 qualification.

Do not enable the candidate schema or route until those gates pass. A journal
receipt remains an unsigned producer attestation, not a VERIFIED EvidenceFact,
approval or credential issuance instruction.

## Membership replacement

Grant membership rows are immutable. Administrative changes must lock the
API key and grant in the documented order, then delete and insert memberships
inside one transaction. The delete and insert triggers bump the affected grant
revisions. In-place UPDATE is rejected even for a no-op, so changes cannot
silently bypass revision fencing. This database constraint also applies to
privileged administrative clients; it does not grant connector database access.

## Gateway activation prerequisites

The current Gateway runtime has shared body buffering and an idempotency cache.
Evidence submission must enforce its 65,536-byte bound before the shared tenant
middleware buffers a body, preserving original bytes and repeated header values
for the strict wire decoder. A later service-side bound alone is insufficient.

The Gateway idempotency middleware can return a cached response before reaching
the journal. Evidence submissions must reach canonical authority revalidation on
every retry, including exact retries after grant revocation or binding changes.
The journal owns observation replay and receipts; the generic response cache
must not bypass that decision. Test a successful receipt followed by revocation
and the same request, and verify the second request is denied.

Require an actual API-key identity with an organization and exact evidence:submit
permission. Session authentication and unrelated administrator scopes do not
establish a producer identity. Strip caller-supplied identity headers and forward
only authenticated identity using the existing trusted internal transport. The
connector accesses only the public Gateway; Gateway-to-service transport does
not authorize connector access to private endpoints or shared PostgreSQL.

## Issuance HTTP adapter

`external_observation_http::observation_router` is the core-side Axum adapter for
POST `/v1/evidence/observations`. Its constructor requires the explicit Gateway
service credential. It validates exactly one service credential, authenticated
API-key ID and organization ID, rejects noncanonical/duplicate identities and
query parameters, bounds body collection to 65,536 bytes with a read deadline,
and passes original bytes/header values to the strict decoder and canonical
transactional journal. Replies are fixed, non-sensitive, no-store errors or
receipt IDs with a replay flag. Uncertain commits explicitly require
reconciliation. It has no generic response-cache shortcut.

This router is not mounted in production by the module. The public Gateway
must first authenticate the real organization API key, enforce exact
evidence:submit permission, strip caller identity and inject the trusted IDs
using its established service-authenticated proxy. The adapter does not trust
an arbitrary caller merely because it sent identity headers; its service
credential must remain Gateway-only, with workload/network isolation. Never
expose this service credential or private endpoint to the connector.

Gateway route registration, early Gateway body/framing enforcement, generic
idempotency-cache bypass, bootstrap mounting, reviewed schema/role/migration
activation and administrator authority management remain required before
activation. A service-side router test cannot establish those public Gateway
or deployed network boundaries. Receipts still confer no evidence verification,
application approval or credential issuance authority.

## Gateway observation route

The Gateway now registers POST `/v1/evidence/observations` as an explicit public
extension routed to issuance with zero transport retries. Its observation guard
runs after actual authentication but before shared content/tenant/body middleware.
It requires an API-key identity with canonical key/organization IDs and the exact
evidence:submit scope; session, admin:full and wildcard permissions do not qualify.
It bounds original bytes to 65,536, validates unique representation/framing and
idempotency headers, rejects query authority, and retains original JSON bytes.
Generic tenant/body and response-cache paths are bypassed only for this guarded
route, so every retry reaches the core journal's canonical authority checks.
The proxy strips caller identity and supplies trusted organization/key IDs plus
the existing issuance service credential. OpenAPI documents unsigned receipt
semantics and the strict envelope. The guard has focused executable tests; full
Gateway runtime integration tests and protected CI still require confirmation.

Issuance bootstrap mounting, reviewed migration/role/admin activation and deployed
network isolation remain incomplete. Registering the Gateway candidate route does
not qualify a deployed public endpoint or authorize connector access to issuance
or PostgreSQL. Do not activate this candidate before those integration gates pass.

## Explicit issuance startup mounting

The issuance bootstrap now composes the observation router when
`MARTY_EXTERNAL_OBSERVATIONS_ENABLED=true` is explicitly configured. It is off
by default. Enabled startup requires the explicit Gateway service credential
and canonical storage preflight before provider/background-worker construction.
Preflight validates required table/column access, authority row-lock privileges,
receipt/audit/head write permissions and enabled revision/membership triggers.
Missing storage or disabled revision triggers stop startup with a fixed error.
Disabled startup performs no observation database access or route mounting.
No migration or privilege is created automatically by this preflight.

This structural/permission preflight is not a schema provenance attestation,
least-privilege grant approval, migration registration or deployment qualification.
Reviewed migration/roles, administrator grants/bindings and full public Gateway
runtime/network-denial tests must pass before enabling it. The startup test uses
canonical-shaped disposable tables, not a production installation. Configuration
and full issuance bootstrap compilation remain part of the full CI gate.

## Canonical grant-revocation service

`external_observation_admin::revoke_grant` is the first administrative mutation.
It requires an authenticated administrator actor from the Gateway's trusted
session transport and reloads current organization membership, role links,
organization-scoped roles and exact external-observation:manage permission
from existing organization_service tables. No role cache, API-key shortcut,
owner-name shortcut or connector authority mirror is used. Active membership
and permission rows remain locked through the serializable transaction.

After authorization locks, it locks the canonical API key before the producer
grant, matching admission lock order. The expected grant revision must match.
The inactive update/revision bump and canonical organization audit event commit
together; an audit failure rolls back revocation. Audit metadata contains only
fixed action/actor/resource identifiers and revisions, not secrets or payloads.
Database conflicts are returned without automatic retry; uncertain commits
require reconciliation before another administrative mutation.

This service is not yet a public administrative HTTP route. Gateway session-only
routing, trusted actor extraction, permission-catalog/role assignment review,
grant creation/approval/modification, evidence-binding administration and audit
read/reconciliation operations remain required. No permission is auto-granted.
The current method can revoke an expired or inactive key's producer grant, since
revocation reduces authority and must remain available for cleanup. It does not
approve evidence, alter application policy or issue credentials.


## Producer grant creation and expiry changes

The public Common Gateway also exposes two session administrator POST operations:

- `/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/create`
  accepts only `api_key_id`, `source_id`, and `expires_at_ms`.
- `/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/change-expiry`
  accepts only `expected_revision` and `expires_at_ms`.

These use the same exact active-session tenant, allowed Origin, bounded original
JSON and current canonical `external-observation:manage` permission checks as
approval/revocation/rotation. API-key authentication cannot administer grants.
The create path UUID is selected by the administrator client before the request,
so an uncertain result has a stable reconciliation identifier. Existing UUID or
organization/source/key uniqueness conflicts never perform an upsert or silently
approve a grant. There is no automatic write retry. Receipt/audit read interfaces
and operator reconciliation are still required before production activation.

Creation writes an inactive grant with null approval metadata and no binding
membership. Expiry modification preserves key, source and membership, clears
approval and deactivates the grant, including when changing an already expired
grant. Both require a current eligible organization-scoped canonical key with the
exact `evidence:submit` scope. Approval remains a separate explicit operation;
active without approval metadata is rejected by the candidate schema. Future
expiry and key eligibility are checked after staged audit insertion, so crossing
expiry while waiting on a trigger/audit write rolls the entire transaction back.
Neither action changes an application, verifies evidence, signs or issues a
credential. Fixed structured audit changes contain revision, expiry and inactive
state, without API-key secret or observation content.

The candidate schema now allows approval metadata to be null as a pair and
requires it for active grants. Router preflight requires both approval columns
nullable, grant INSERT and expiry UPDATE privileges in addition to the previous
checks. This remains a reviewed candidate schema: registered upgrade migration,
least-privilege production role qualification, binding/membership administration
and deployment are unfinished. No startup DDL or automatic privilege grants are
introduced.


## Canonical grant membership replacement

`POST /v1/organizations/{organization_id}/external-observation-producers/{grant_id}/replace-bindings`
uses the same public session administrator boundary. Its body contains only
`expected_revision` and `bindings`, an array of at most 32 unique selections with
`binding_id` and `expected_revision`. Empty explicitly removes all membership.
The existing 4096-byte original-body limit applies, including duplicate-field
and unknown-field rejection. Connector API keys cannot invoke this operation.

Core locks current administrator permission, the canonical eligible organization
key, grant, existing membership rows, and selected binding rows in that order.
Each binding must already exist under the exact organization/source and match
the administrator's selected revision. The operation changes membership only;
it does not create, edit or activate bindings, change application lifecycle or
subject, change key/source, or approve a grant. Inactive bindings may be staged;
admission still requires current active binding and eligible application state.
A successful replacement always deactivates the grant and clears approval,
including when selecting the same set. Membership revision triggers remain in
force. Fresh explicit approval is required before submission can be authorized.

Membership writes, revision fencing and the structured administrator audit are
one SERIALIZABLE transaction. Audit failure, stale binding/grant state, expiry
crossing during staged writes and concurrent changes roll everything back.
After audit insertion, core rechecks key/expiry, grant identity/revision/inactive
state, exact membership set and selected binding revisions before commit. A
failed COMMIT is unknown and requires reconciliation without an automatic write
retry. Audit changes include only selected canonical binding IDs/revisions and
the inactive grant revision, without observation, provider credentials or claims.

Preflight additionally requires membership INSERT/DELETE privileges. Production
least-privilege role and upgrade migration qualification remain unfinished.
Administrator audit/read reconciliation remains a separate missing interface; membership selection does not manufacture
those authorities. The connector continues to own only provider configuration
and credentials, with Common Gateway as its sole Marty integration.


## Binding creation and state administration

Public session administrator POST routes under
`/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}`
provide `/create`, `/activate`, and `/deactivate`. They use the same bounded
original-body, current tenant, allowed Origin and canonical administrator
permission boundary as producer administration. API-key identities cannot use
these operations. The shared HTTP body/authentication reader applies to both
route families. Resource/claim maps reject duplicate keys before normalization;
claim-rule structs reject duplicate or unknown fields. Provider, fact, resource
and claim definitions must meet the existing admission validators, including
reserved authority/secret claim-name exclusions and freshness bounds.

Creation takes a source ID, existing application ID and its exact current
microsecond `updated_at` revision, provider/fact type, resource scope, claim rules
and freshness limits. It derives the subject from the locked canonical
application; caller subject, tenant, active state and approval fields are not
accepted. The application must belong to the current organization, be pending or
under review, and be unexpired. Creation starts inactive without membership.
Duplicate binding IDs conflict rather than overwriting or upserting.

Activation requires both expected binding and application revisions. It validates
the stored definition, current application subject/lifecycle/expiry and repeats
application checks after audit insertion. Deactivation requires only the binding
revision and remains available after application closure/expiry. Both operations
deactivate every linked producer grant and clear its approval, even when the
requested binding state is unchanged. Fresh explicit producer approval is
required; changing binding state never transfers an old approval automatically.
Linked key rows, grant rows, membership rows, binding, and application are locked
in that order under SERIALIZABLE. Keys may already be revoked/expired because
binding deactivation must remain possible. A concurrent membership insertion
absent from initial discovery is fenced by the serializable transaction. Final
checks validate the exact linked set, each inactive grant/key/revision, binding
revision/state and application authority. Audit-trigger changes and expiry during
staged writes roll the transaction back. Unknown commits have no automatic retry.

Audits contain only binding revision/state and affected grant count; no subject,
resource values, claim content or credentials. No application state, evidence
verification, signing or issuance changes. Preflight now requires binding INSERT
and active/updated_by/revision UPDATE privileges in addition to existing checks.
Registered migrations, production least-privilege roles and actual Gateway
runtime qualification remain required. Administrator reads/reconciliation remain unfinished; this is not a deployment
or production readiness claim.


## Binding constraint replacement

`POST /v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/replace-definition`
accepts exact binding/application revisions plus complete resource scope, claim
rules and freshness limits. It rejects organization, source, application,
subject, provider, fact type and active-state fields. Those identity/provenance
columns remain unchanged; changing identity requires a distinct canonical
binding. The same strict nested duplicate/unknown-field decoder, validators,
4096-byte bound, session tenant/Origin and current administrator permission apply.

Replacement uses the shared binding mutation transaction and canonical
key/grant/membership/binding/application lock order. It validates the new
constraints against the current application/subject and writes the binding
inactive. Every linked producer grant becomes inactive with approval cleared.
Explicit binding activation and a fresh producer approval are both required
before new observations can be admitted. The final fence checks immutable
identity, exact replacement constraints, revisions, linked grants/membership,
current application and expiry after audit insertion. A concurrent membership
insertion absent from discovery conflicts under SERIALIZABLE. Audit failure,
post-write revision/constraint changes or elapsed application expiry roll all
staged writes back. There is no automatic uncertain-commit retry.

The administrator audit records binding revision/inactive state and affected
grant count; it does not copy subject, resource values, claim content or secrets.
Storage preflight additionally requires UPDATE privileges on resource_scope,
claim_rules, max_age_ms and max_clock_skew_ms. Production role and registered
migration qualification, administrator reads/reconciliation, actual Gateway and
Canvas-to-wallet qualification, and cross-repository retirement remain open.
