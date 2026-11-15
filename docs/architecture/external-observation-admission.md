# External observation admission: executable policy candidate

Status: **policy kernel and candidate request schema only**. No public route,
API-key scope provisioning, receipt table or production ingestion is enabled.
This is the next core-side building block for the public Canvas extraction,
not an alternative connector service or a completed Gateway endpoint.

## Ownership and trust

`rust/services/issuance/src/external_observation_admission.rs` has no transport,
provider, SQL, signing, credential or policy-engine dependencies. It accepts
already-authenticated Gateway key identity and current core-owned snapshots,
then either denies, returns an existing receipt, or prepares an unsigned insert.
The Canvas repository must not import this implementation. Its eventual only
core connection remains the common public Gateway using its API key.

The wire envelope is limited to binding ID/revision, observation ID, monotonic
sequence, original observation/effective timestamps and primitive claims. A
core-owned binding determines organization, source, provider, application,
subject, fact type, exact resource scope, permitted claim names/types/ranges and
freshness. The caller cannot supply verification status, policy permission,
issuer selection, application approval, or subject/tenant overrides.

The proposed purpose-specific `evidence:submit` scope is required by this
kernel. It is NOT yet in the API-key provisioning catalog. Existing
`integrations:write`, `applications:approve`, signing permissions, `*` and
`evidence:*` do not implicitly authorize submission through this new boundary.
An active, unexpired administrator-approved producer grant must also bind the
exact authenticated key ID, organization, source and binding ID. Rotation to a
new key ID requires explicit delegation. Do not silently broaden an old key.

Authentication proves who attested, not that the claim is true. Accepted
observations must remain distinguishable from internally verified evidence.
Any later EvidenceFact conversion and Cedar policy evaluation must explicitly
recognize the registered-source attestation and its approved claim authority;
never stamp a caller's assertions `VERIFIED` or bypass application policy.

## Replay and correction semantics

`Idempotency-Key` must equal `observation_id`. IDs and sequences survive retries;
retries do not update timestamps. Receipt uniqueness is organization + source +
observation ID. Receipts retain the authenticated producer key and full validated
normalized envelope. Cross-key or changed-envelope reuse conflicts. No
client-supplied digest is treated as proof of payload equality.

An exact retry rechecks current key/grant/binding authorization before returning
the original receipt. It does not create another fact, refresh evidence, move a
sequence head, or re-run approval. It may return the receipt after the observation
is stale or the application closes, because it performs no new write. Revoked,
expired, out-of-scope and differently bound producers still fail.

New writes require an application currently accepting observations. Issued,
rejected and withdrawn applications must be mapped to false until their explicit
correction workflow is implemented. New IDs must carry a sequence strictly
higher than the current binding head, including across binding revisions.
Sequence gaps are allowed. The connector will need durable per-binding counters;
wall-clock timestamps are not safe substitutes for sequence ordering.

The kernel accepts explicit negative/null observations only when the configured
claim schema permits them. Provider transport/authentication/schema errors are
not observations and must never be converted into false completion claims.

## Atomic persistence contract (NOT implemented here)

The repository adapter must load current key/grant/binding/application authority,
the source-wide receipt identity and binding head within a transaction. It must
call the kernel using those values, not JSON fields or cached principal claims.
Insertion must atomically commit the receipt, admission audit event and head.

The returned fence carries key, grant, binding and application revisions, the
expected previous head, authorization expiry and observation expiry. All
permission/active/schema/identity changes must increment the relevant revision.
Recheck the complete fence and the current clock before commit: elapsed expiry
requires no row update and cannot be protected by revision comparison alone.
Concurrent head or authority changes must roll back and re-evaluate; never
refresh an expired observation or silently overwrite the winning state.

Use unique constraints for receipt identity and per-binding sequence; lock the
binding head or use an equivalent atomic compare-and-swap. Receipt lookup failure
is not absence. Two concurrent deliveries must produce one receipt/audit/head
transition, and a conflicting duplicate must produce none. A receipt is not
returned until commit succeeds. Audit identifiers and producer provenance must
be core-assigned; avoid raw claims/tokens in diagnostics.

Before making a route reachable, implement and qualify:

1. Strict request decoding (duplicate fields, unknown keys, finite numbers,
   request-size bounds and timestamps), real Gateway authentication, tenant
   binding and the purpose-specific scope catalog.
2. Administrator-controlled grants/bindings and transactional PostgreSQL
   receipt/audit/head storage with expiry, revocation and race tests.
3. Public OpenAPI DTOs and customer-created-key HTTP tests for valid, missing,
   revoked, wrong-tenant, wrong-source and insufficient-scope cases.
4. Explicit policy admission for registered-producer attestations, including
   correction rules; no implicit issuance on receipt.
5. Connector envelope/counter/outbox implementation, then isolated OB3 and
   network-denial acceptance on the existing development environment.

## Validation

The kernel uses only Rust's standard library. Its adjacent unit tests can be
compiled directly without resolving the large service workspace:

```sh
rustc --edition=2021 --deny warnings --test \
  rust/services/issuance/src/external_observation_admission.rs \
  -o /tmp/external-observation-admission-tests
/tmp/external-observation-admission-tests
```

The dedicated workflow executes that exact source and its tests without service
credentials, deployment access or provider traffic. Unit tests establish the
policy planner's behavior, not a live Gateway, database transaction or completed
Canvas cutover. The existing `internal_application_evidence.rs` owner and its
policy/issuance transitions are unchanged.
