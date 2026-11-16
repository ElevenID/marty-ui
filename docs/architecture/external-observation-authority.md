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

`api_key -> producer_grant -> grant_membership -> evidence_binding -> application`

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
or widen its own grant. API-key rotation requires an administrator to issue a
new grant for the new key ID. The schema is still a candidate contract and is
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

Not yet implemented or activated:
- organization-admin HTTP operations to create/revoke grants and bindings;
- API-key scope provisioning and Gateway route mapping in the main branch;
- startup migration registration and production DB role grants;
- authenticated HTTP/body-streaming integration tests;
- connector worker submission and end-to-end Canvas-to-core qualification.

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
