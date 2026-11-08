# Native SD-JWT prerequisite evidence and managed authority

## Scope

This W05 increment produces a typed authentication record for one governed
issuer's holder-bound SD-JWT satisfying one frozen DCQL credential query. It
extends [policy and request binding](policy-bound-verification.md) without
changing the reviewed Core, SD-JWT or MMF fork revisions.

The native query record remains partial. The opt-in managed profile now adds
Trust Profile-owned issuer/type authorization and Issuance-owned lifecycle
observations, bound to that native record. Neither record is
`AuthenticatedOid4vpEvidenceV1`, asserts durable replay consumption, or grants
issuance authority. Durable replay evidence and an issuance-owned continuation
remain required before the prerequisite-to-issuance workflow is complete.

## Supported profile

The existing workload-authenticated transport must carry the exact saved DCQL
query, nonce, verifier client ID and response. The selected profile requires:

- One active saved policy with one required `SD_JWT_VC` requirement and no
  alternative requirements or derived/predicate claims.
- One DCQL credential whose ID equals the saved requirement ID, format is
  `dc+sd-jwt`, and metadata contains one exact VCT URI.
- Literal top-level scalar claim paths matching the policy producer's selected
  required claims. If no claim is required, all requested claims are selected.
  Explicitly empty claim arrays, duplicate paths/IDs and unsupported extensions
  are rejected.
- Exactly one response key and one token. Duplicate JSON response keys, extra
  responses, format substitutions and a token different from the selected
  request token are rejected before authentication.
- Normal client-ID OID4VP audience binding and a nonce of at least 32 bytes.
  Digital Credentials API origin-based audience binding requires its own
  adapter and is outside this profile.
- A governed public Ed25519 or P-256 issuer key. The issuer algorithm is chosen
  from that governed key; supported holder algorithms are separately limited
  to EdDSA and ES256.
- An authenticated issuer JWT with protected `typ: dc+sd-jwt`, exact VCT,
  a bounded issuer-scoped subject, an issuance time and a live expiry. The
  issuer-signed `cnf.jwk` must be the unambiguous public holder key.

The VC profile's non-disclosable fields (`iss`, `nbf`, `exp`, `cnf`, `vct`,
`vct#integrity`, `aka_vcts` and `status`) must agree exactly between the
authenticated issuer payload and reconstructed claims. This check prevents the
generic SD-JWT verifier from accepting selectively disclosed security metadata
under this stricter VC profile. `sub` and `iat` may be selectively disclosed.
Requiring an expiry is a local restriction of this bounded profile.

Other credential formats, Presentation Exchange and policies without the new
opt-in field retain their existing behavior. They do not acquire managed
authority guarantees. An opted-in policy rejects missing transport, Presentation
Exchange and Digital Credentials API requests.

## Authentication and correspondence

`SdJwtDcqlRequest` has private fields and is prepared from the saved policy and
typed workload transport. Its verifier calls Core's policy-aware SD-JWT
verification with both expected nonce and audience. Only that call can produce
`AuthenticatedSdJwtQueryEvidence`; neither type has a public JSON constructor.

The prepared request and authenticated record bind the organization, complete
saved policy identity, template, query ID/digest, exact selected response-token
digest, nonce, audience, VCT, selected claim names and observation time. They
also retain the normalized effective trust-profile ID privately. The existing
request override remains supported, but a cached native result or public
projection under a different selected profile is rejected. For the managed
profile described below, the saved policy selects one explicit trust profile,
its owner revision is frozen, and a different request override is rejected.
Returned issuer
provenance must match the actual profile and organization used for that
evaluation. The query record itself does not establish permission to issue a
credential or authorization under an issuance policy.

A private digest binds the adjacent policy claim values to the authenticated
selection. Both the native orchestration boundary and the final production
projection reject genuine evidence attached to a different request, policy,
token or set of claims. The projection attaches the record only to the unique
matching credential result, never to an arbitrary result selected by order.

After awaited trust and status work, the orchestrator rereads its clock and
rechecks the authenticated credential validity window. It also rechecks the
authenticated KB-JWT `iat` using the pinned Core verifier's five-minute maximum
age and sixty-second future-skew window, including fractional NumericDate
values. Optional authenticated KB-JWT `nbf` and `exp` also retain strict live
validity bounds at both observations. Expired credentials, stale holder proofs
and a backwards observation clock cannot acquire a refreshed `checked_at` value.

## Minimal public record

The serialized contract is `marty.sd-jwt-dcql-query-evidence/v1`. It contains
policy and query identity, digests of the exact selected token/nonce/audience,
issuer ID, a domain-separated issuer-scoped subject digest, the holder key's
RFC 7638 thumbprint, VCT, issuer algorithm, matched claim names and final
observation time.

It omits the raw subject, credential, disclosures, holder public key, nonce,
audience and claim values. The internal selected-claims digest, trust-profile
identity and validity/freshness fields are serialization-skipped. The record
has private fields and no deserializer, so caller JSON cannot manufacture or
promote it. It travels in the existing credential-result JSON. The managed
authority extension adds fields to policy authoring, lookup and request
transport, with regenerated descriptor and independent wire-number checks.
Existing Flow callback evidence digests cover the resulting credential records.

The record may accompany a denied policy decision. For example, successful
query and holder authentication does not satisfy a policy requiring durable
replay consumption. No replay pass is inferred from a nonce comparison.

## Opt-in managed issuer and status authority

Set the saved policy's `prerequisite_evidence_profile` to
`managed_sd_jwt_dcql_v1`. This requires one required `SD_JWT_VC` credential
requirement, `accept_derived: false` on its claims, no alternatives or predicates,
one explicit top-level `trust_profile_id`, required holder binding, and
`freshness.require_not_revoked: true`. Challenge, audience and replay checks must
all remain required. An omitted field preserves the existing policy behavior;
clearing the field is an explicit policy edit and changes the policy digest.

The gRPC create operation carries the profile selector, trust-profile ID,
holder-binding JSON and freshness JSON. The update selector uses presence:
omitting it preserves the selection; an explicitly empty value clears it.
The HTTP authoring API uses the same domain validation and accepts null to
clear the selector. GetPolicy refuses to return an opted-in policy to Flow
without a valid matching owner snapshot.

### Trust Profile owner

An issuer relationship must explicitly grant the exact credential type:

```json
{
  "marty_credential_authorizations_v1": [
    {"format": "SD_JWT_VC", "vct": "urn:example:prerequisite-email"}
  ]
}
```

The grant belongs in the existing relationship metadata under its existing
management permission. Absence grants nothing. Unknown fields, duplicate grants,
invalid VCT URIs and different format strings are rejected. VCT matching is
exact; the new path does not perform discovery or wildcard expansion.

The owner serves two service-token-authenticated operations:

| Operation | Purpose |
| --- | --- |
| `POST /internal/v1/trust-profiles/{profile_id}/credential-authority-snapshot` | Freeze a bounded public decision basis and its real owner revision. |
| `POST /internal/v1/trust-profiles/{profile_id}/credential-trust-evaluations` | Assess one native-authenticated issuer, VCT, format, algorithm and public-key thumbprint against the expected revision. |

The additive `credential_authority_revisions` table records a monotonically
increasing version and content digest. PostgreSQL locks the revision row before
reading the profile/issuer/relationship graph in one statement. An unchanged
basis reuses its version; changed keys, grants, lifecycle or applicable policy
controls advance it. The in-memory owner performs the equivalent operation
under its single state lock. Revision changes produce a restart-required error
through Policy and Flow instead of evaluating a replacement profile silently.

Keys must already be persisted and governed. No key resolution or persistence
is triggered by these reads. The selected issuer must have an unambiguous
visible relationship, be live and trusted, and satisfy the profile's format,
algorithm, issuer and credential-type restrictions. Configured key-usage
requirements are enforced on the selected public JWK. A configured mandatory
`nbf` is enforced on the signed issuer payload by the native producer; native
expiry and time comparisons remain strict.

This first profile rejects unsupported operator settings, including configured
system issuer overrides, extra external rule/registry authority, unsupported
credential freshness rules and external OCSP, CRL or status-list checks. Their
configuration contributes to the owner revision; rejecting an unsupported
setting never falls back to a different key or a generic issuer boolean.
Operators must select settings compatible with this explicitly managed-record
status mode. Existing generic trust APIs retain their existing behavior.

### Issuance status owner

`POST /internal/issuance/sd-jwt-status/observe` uses the existing management API
key and an exactly matching trusted organization header. It reads one record
by organization and credential ID and returns no credential bytes. Its scope
includes the issuer, credential template, credential ID, exact issuer compact
JWS digest and native request-binding digest. The issuer JWS digest excludes
wallet-selected disclosures and the KB-JWT, so selective presentation does
not change the identity of the stored signed artifact.

The owner checks the stored issuer credential structure, signed issuer and ID,
record issuer/template, lifecycle consistency and both signed and stored
expiry. The observation uses the database statement time, has a maximum
60-second lifetime, and is capped by credential expiry. Active, suspended and
revoked states remain distinct. Unknown, expired, mismatched, unsupported or
unavailable records fail closed. The operation is read-only and cannot publish
a status update or issue a credential.

### Native association and deployment boundary

The native SD-JWT verifier retains the authenticated credential ID and issuer
JWS digest privately. Both owner requests are derived from those fields and
the exact tenant/policy/template/query/token/nonce/audience/subject/holder/key
binding. Public kernel status IDs and caller JSON are not authority inputs.
After all owner awaits, the orchestrator rechecks the native credential and
holder proof and both complete owner responses against the final clock.

Only that path constructs `VerifiedManagedCredentialAuthority`, serialized as
`marty.managed-sd-jwt-authority/v1` on the unique matching credential result. It
has no deserializer or public constructor. The status projection omits the raw
credential ID and full request; it retains the state, authority, binding and
artifact digests, observation window and response digest. Opted-in policy
results cannot be accepted from a facts-only provider or reused native material
bound to another request. Owner denial and revoked status may still carry
authenticated query evidence, but deny the policy decision.

These wire DTOs and their digests establish correspondence, not a signature.
The implementation relies on the configured deployment-trusted owner channel;
a service token authenticating the requester alone does not cryptographically
authenticate a plaintext response. Stronger owner-response transport or signed
authority receipts remain an activation consideration for a full canonical
evidence producer. Flow-to-Policy transport retains its existing workload-mTLS
requirement.

An observation deadline is a freshness bound, not a promise that trust or status
cannot change after the read. No cross-service atomic lock is claimed. Flow's
existing finalization still commits nonce consumption, original request context,
result and callback together after evaluation. Its precommit replay flag is not
a durable consumption receipt. Converting that commit into canonical replay
evidence, and then into an issuance-owned continuation, remains separate work.

## Review and regression coverage

Real signed issuer and holder fixtures exercise selective disclosure and the
actual native kernel, policy evaluator and wire projection. Coverage includes
signature/issuer/holder substitution, missing or incorrect protected type,
nonce and audience mismatch, malformed or ambiguous queries/responses, caller
JSON promotion, cached native evidence, changed policy claims, crossed policy
and request identity, selected trust-profile correspondence, credential expiry
and holder-proof staleness during awaited evaluation, and non-disclosable VC
metadata. The compile-fail example checks the absence of a JSON constructor.

Two independent source audits are required for this PR. Exact local test
counts, reviewed publication head and hosted gates are recorded in PR 1845 and
the [development checkpoint](fork-protocol-development-checkpoint-2026-11-07.md).

The managed extension also covers configured owner authentication, every
response-scope field, digest-consistent substitutions, stale observations,
revoked and suspended records, explicit VCT authorization, persisted key and
grant changes, mandatory signed `nbf`, mutable public status-ID substitution,
and Flow mode/revision changes. Loopback HTTP tests exercise the actual native
client adapters and their distinct owner credentials. Registered PostgreSQL
tests cover the additive ledger, concurrent first observers, a reader blocked
on the revision row observing the subsequently committed graph, and exact
tenant/artifact status reads. Compiling these executables is recorded separately
from actual hosted database execution.

## Related CI corrections

The preceding published head exposed three independent integration failures:

1. Auth's Flow dev dependency violated the registered service-dependency
   boundary. The exact production callback serializer now lives in the shared
   OID4VP contract crate and accepts the existing MMF digest function. Auth
   tests retain independent DTO/HMAC verification, including a frozen legacy
   canonical-event and HMAC vector.
2. The Envoy descriptor contract still expected the hash preceding the
   reviewed policy-revision fields. Its expected hash now matches the generated
   descriptor; RPC, route and field assertions remain intact.
3. Canvas renewal's historical-schema fixture lacked the native authorization
   expiry columns. It now runs the existing native extension migration in its
   isolated scenario database before seeding through the normal repository.

These fixes do not relax the dependency rule, alter production migrations or
bypass live signing authorization. Actual PostgreSQL assertions remain a
separate gate from compilation and tests that return early without a database.

## Next implementation boundary

Complete the canonical evidence producer with authenticated owner-channel
provenance and a durable replay receipt for this selected profile. Policy
observation time and Flow commit time must remain distinct; do not label a
precommit timestamp as nonce consumption. Then bind
that evidence to one tenant, issuing template and exact dataset through an
issuance-owned single-use continuation with expiry. Revalidate and consume
that continuation under the existing atomic signing claim before enabling the
prerequisite-to-issuance workflow.
