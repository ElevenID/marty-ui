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
