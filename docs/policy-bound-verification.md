# Policy revision and request binding for Flow verification

## Development scope

This W05 foundation fixes the policy and generated presentation request that a
Flow verification session starts with. It connects that saved policy identity
to the policy service's decision and fences finalization against a changed
session. It extends the signing-authorization work in
[atomic-signing-authorization.md](atomic-signing-authorization.md).

The change does not authorize prerequisite-based issuance. The existing
OID4VP evidence contract still needs a production producer of authenticated
subject and holder-key evidence, native satisfaction of the exact query, and
an issuance-owned continuation bound to one tenant, template and dataset.

## Authoritative policy identity

The policy service produces a `PolicyRevision` containing organization ID,
policy ID, version and content digest. The digest uses the existing shared
canonical JSON implementation through the domain
`marty.oid4vp/policy-snapshot/v1`. It covers the complete serialized saved
`PresentationPolicy`, including requirements, holder/trust configuration,
status and lifecycle timestamps.

The authoritative `policy_document` JSONB preserves serialized timestamp
precision. Legacy records without that document use the policy reconstructed
by the existing persistence adapter. A change to the saved lifecycle timestamp,
including suspension and subsequent reactivation, changes the reference.
Restoring the exact same document restores the same reference: this is a
snapshot identity, not a monotonic database generation.

`GetPolicy` returns that reference. The gRPC evaluator requires the expected
reference and checks the tenant, identity, version, digest and active status
before invoking native verification. It returns a reference derived from the
same loaded policy used for that evaluation. Caller context and native result
JSON cannot replace the service-owned reference.

This comparison happens when evaluation starts. It does not lock policy state
across services, freeze independently resolved trust-profile contents, or
provide atomic revocation at a later credential signing operation.

## Frozen Flow request

At verification start, Flow resolves the active policy and its templates once,
builds the Core Presentation Exchange and DCQL artifacts, and saves them with
the policy reference, tenant, instance ID and nonce in reserved private
context. Each query has a digest from the existing OID4VP contract helper.

Request URI retrieval validates and uses those saved artifacts. It does not
reload a policy or generate a new query identifier. Repeated standard and
supported wallet-specific retrieval therefore retain the original query even
if the backing policy/template providers change or become unavailable.

Before evaluation, Flow verifies that the request representation being used
matches the saved artifact. It sends the exact query as bounded OID4VP
transport metadata over the configured workload-authenticated channel and
requires the returned policy reference to equal the session's saved reference.
Plaintext channels cannot silently discard that metadata for bound Flow
verification. Existing standalone calls without Flow transport metadata remain
separate.

The current production `VerifiedFactsOrchestrator` still evaluates native
credential facts against the saved policy without consuming this typed query
transport to produce a query-bound evidence projection. This patch establishes
request stability and policy identity; native proof that the presentation
satisfies the exact DCQL/Presentation Exchange query remains a subsequent
contract integration task. A policy decision here must not be promoted to an
authenticated prerequisite continuation.

## Atomic finalization

The prepared result retains the original stored instance from before the
asynchronous evaluation. PostgreSQL finalization compares its live status,
tenant/definition identity, `updated_at` and exact JSON context before writing
the result. Context comparison also catches changed request authority when a
timestamp has not advanced. The existing transaction groups that comparison,
nonce consumption and callback insertion; a stale result rolls all of them
back.

Digital Credentials API submission adds origin/response-mode telemetry to the
result context while retaining the unmodified stored instance as its comparison
snapshot. A concurrent request retrieval or context replacement still causes
a conflict. The in-memory repository compares the original instance under its
existing mutex.

The validated policy reference is saved in the result and in the callback
payload before the decision digest is computed. The callback does not expose
the private frozen request. These records identify which policy was evaluated;
they are not independently sufficient issuance authority.

Auth retains the typed revision when reconstructing the callback's digest and
signature basis, and validates its shape and agreement with the callback's
policy ID. Queued legacy callbacks without that field keep their original
canonical representation. A producer-to-consumer test exercises Flow's actual
callback builder, Auth deserialization and verification, revision tampering,
and the legacy form.

## Compatibility and deployment

- Deploy the matching Flow/standalone providers and policy service together.
  Old gRPC callers that omit the required reference fail closed.
- Update Auth's compatible callback consumer before Flow starts emitting the
  revision field. The updated consumer accepts both the new signed payload and
  queued legacy payloads; the earlier consumer would drop the new signed field.
- Active legacy OID4VP sessions with no frozen snapshot require a new session.
  The HTTP boundary reports `verification_restart_required` instead of
  rebuilding a request using current policy state.
- A changed policy reference requires a new session. The producer's typed
  mismatch is preserved through the provider instead of being treated as a
  temporary policy-service outage.
- A changed live session during evaluation returns
  `verification_request_changed`. The client can retrieve the current request
  and submit a matching presentation; the rejected finalization leaves the
  nonce and callback outbox untouched.
- Bound Flow evaluation requires the existing workload mutual-TLS
  configuration. Configure that service channel before enabling these flows.
- SIOP processing retains its separate verification behavior and uses the
  original-instance finalization fence. Existing terminal replay rules remain.
- Standalone Verification fetches and checks the current policy reference at
  evaluation. It does not acquire Flow's request-start snapshot guarantees.
- Direct HTTP policy evaluation remains available and reports the evaluated
  policy reference; it does not create an issuance continuation.

## Review and validation

The test changes cover policy digest and storage stability; tenant, version,
digest and lifecycle substitution; rejection before native verification; stable
request retrieval; private-context projection; authenticated transport;
returned/rejected revision mismatches; callback binding; and stale finalization.
The HTTP/PostgreSQL contract includes DC API success and context replacement
while evaluation is in flight. Direct repository cases separately change
context at the same timestamp and advance the timestamp without changing
context, then verify that a fresh evaluation can still finalize.

The checked-in Envoy descriptor is regenerated with the pinned compiler in
`requirements-proto.txt`. Descriptor parity and field-number checks cover the
new revision message and the additive request/response fields.

Two independent source audits passed after correcting the DC API comparison
snapshot, stale-policy error propagation, callback digest binding and Auth
consumer compatibility. They also checked the descriptor and exact-path CI
registration changes. The PR records the exact local and hosted results.
PostgreSQL tests require
the existing disposable CI databases; compiling them or returning early with
no database environment variable does not count as executing their assertions.

The initial signing-only CI run also exposed a Canvas acceptance fixture using
the prior signing-claim signature and a test-only Clippy type-complexity error.
The fixture now supplies a unique, live synthetic grant through the normal
repository gate, and the mutation table uses a named type. No authorization
check is bypassed to restore those tests.
