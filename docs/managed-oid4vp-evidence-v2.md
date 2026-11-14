# Managed OID4VP evidence V2

## Delivered boundary

This W05 increment produces a historical managed verification fact through
Policy's native evaluation and Flow's durable finalization. It supports the
existing opt-in, single-credential, holder-bound SD-JWT DCQL profile described
in [SD-JWT prerequisite evidence](sd-jwt-prerequisite-evidence.md).

It does not authorize issuance. Issuance still needs an immutable issuing
intent and an expiring, single-use continuation, bound to the tenant,
applicant/session, holder, template version, configuration, policy and exact
dataset. That continuation must be consumed under the atomic signing claim,
including all retry and alternate initiation paths.

V2 is explicitly managed-only. It neither reinterprets `FrozenOid4vpRequestV1`
nor relaxes V1's validator, digest domains or API. Legacy successful results
and receipts remain noncanonical; missing evidence is never synthesized from
their public JSON. A denial, unsupported profile or retryable authentication
failure cannot produce positive managed evidence.

## Producer and acquisition

Policy retains the actual native result before its compatibility projection:
the real requirement counts and claim outcomes, selected claim values, issuer
and holder bindings, original credential times, authenticated trust/status
observations, and the request-bound Policy validity deadline. It does not
invent a replacement V1 check inventory or discard an unsatisfied optional
claim. The public `ManagedPolicyEvidenceProjectionV2` is correspondence data.

The new gRPC field `PolicyEvaluationResponse.managed_policy_evidence_json` is
field 17. Direct HTTP evaluation removes that full internal projection. Flow
can acquire it only through the exact client returned by its inspected keyless
workload connection. The client verifies the configured HTTPS target hostname
or IP against the supplied CA and presents its remote-key client certificate.
Policy enforces the Flow client URI and RPC method ACL. The client does not
claim to pin the Policy server's SPIFFE URI; a URI SAN in a test certificate is
not evidence of such a check. Raw clients, ordinary channels and a service
token alone cannot create the acquisition capability.

Flow seals that acquisition to the complete request and returned evaluation.
Cloning it onto a changed result, principal or request fails. Public wire
deserialization cannot manufacture the opaque capability.

## Request and digest correspondence

`ManagedFlowRequestBindingV2` binds the original owner row, frozen query and
trust profile, initiating principal, nonce, verifier client, response URI,
actual state and submitted response. Direct-post state must match the emitted
Flow instance identity. Presentation Exchange and Digital Credentials API
origin binding are outside this profile.

The existing digest families keep their original meanings:

| Binding | Meaning |
| --- | --- |
| Canonical nonce digest | Shared OID4VP nonce domain. |
| Flow nonce digest | Existing raw SHA-256 nonce consumption key. |
| Flow request binding | Digest of the complete original expected Flow record, not the later terminal row. |
| Policy request binding | Existing validity request domain with the original evaluation transport. |
| Submission digest | Existing Flow/MMF digest of the wallet submission. |
| Candidate digest | Exact internal Policy evidence projection before Flow finalization. |
| Final evidence digest | V2 request, candidate and committed Flow receipt. |

The result stores only the candidate digest before receipt construction. The
receipt hashes that result; the final envelope contains the receipt and lives
outside the result. The final digest is never appended to the receipt-bound
stored result or existing callback basis, so there is no digest cycle.

## Atomic persistence and recovery

Flow stores the complete envelope only in reserved private context at
`_marty_managed_oid4vp_evidence_v2`. It uses the existing transaction:

1. Lock and compare the complete tenant-scoped original instance.
2. Consume the nonce and read a fresh database clock after any contention.
3. Attach the receipt and validate the final envelope before the instance write.
4. Write private context and result together; insert the callback outbox row.
5. Read the fresh database clock after the outbox write and roll back on expiry.
6. COMMIT, then expose `AuthenticatedOid4vpEvidenceV2` through private fields.

Nonce conflict, original-row change, exclusive deadline expiry or callback
failure rolls back evidence, result, nonce and outbox together. The in-memory
adapter models the writes but does not return authenticated managed evidence.
Only PostgreSQL finalization or owner repository readback creates that type.

Recovery validates the complete stored receipt basis, candidate digest,
validity, frozen bindings and final envelope. Missing or substituted components
fail closed. It cannot recompute the original full-row digest from the terminal
row; it retains that original sealed digest and verifies the stable frozen
fields. Recovery preserves an authentic historical fact after its recorded
deadline, without renewing it for issuance. Policy observation and nonce
consumption retain distinct microsecond clocks; no exact COMMIT time is claimed.

Generic writes reject reserved owner fields. Artifact replacement additionally
checks the stored row so sanitized input cannot erase a finalized receipt or
private envelope. This boundary trusts the owner repository and database. The
shared application database principal is not isolation against a compromised
service with direct SQL access. No new table, migration or cross-service atomic
lock is claimed.

## Privacy and public results

Before persistence, the complete candidate and request binding are checked
against original presentations, SD-JWT components and encoded or split token
material. Native credential IDs, initiating principals and full owner
observations stay private. For acquired managed results, the adjacent legacy
subject/key and authority projections are removed before result, callback and
receipt sealing. Ordinary selected claims and verification diagnostics retain
their public purpose.

Committed HTTP results and owner readback expose `canonical_evidence_digest`.
The corresponding additive gRPC result field is number 8. Generic DTO
projection cannot invent that field. The callback's existing `evidence_digest`
continues to hash its credential results; it is not renamed to mean the V2
envelope. Debug output for the new authority and committed wrapper is redacted.

## Qualification and rollout

The contract suite preserves all V1 vectors and checks strict parsing, native
parity, binding substitutions, privacy and historical bounds. Flow regressions
cover reserved-field injection, mutation, races, clock waits and rollback.

The exact ignored test
`verification_tests::bounded_sd_jwt_query_evidence::managed_authority::live_keyless_managed_policy_evidence`
is explicitly selected in CI's contracts lane after the Flow database suite.
It uses real signed credentials, isolated OpenBao remote workload keys,
authenticated owner HTTPS, production Policy gRPC, Flow preparation and real
PostgreSQL finalization/readback. CI requires the exact recorded executable,
positive test selection and one successful executed test. The OpenBao 2.5.5
binary comes from the existing reviewed image digest; shared daemon pins do
not change. Local execution and hosted execution are reported separately.

Policy's one explicit Flow development dependency belongs to this joined
private native fixture. The registered dependency guard rejects production or
build dependency variants. This avoids exposing an authority constructor or a
production test feature merely to place the test in another crate.

Deploy the compatible Policy producer before Flow consumers. Existing bounded
receipt rollout requirements still apply, including compatible Auth callback
handling and draining old Flow writers. Issuance remains gated until its
separate intent/continuation consumer is implemented and qualified.
